#!/bin/sh
set -eu

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }
require() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }
prefix() { printf '%s%s' "$DEST" "$1"; }

# VANE_ROOT is for staging/isolated tests; never alter host systemd or accounts then.
DEST=${VANE_ROOT:-}
case "$DEST" in
  '') ;;
  /*) case "$DEST" in
        /|//|*/../*|*/./*|*/..|*/.|*/ ) fail 'unsafe VANE_ROOT path' ;;
      esac ;;
  *) fail 'VANE_ROOT must be empty or an absolute directory path' ;;
esac
[ "$(id -u)" = 0 ] || fail 'run as root'
for c in rm rmdir; do require "$c"; done

BIN_DIR=$(prefix /usr/local/bin)
CONFIG_DIR=$(prefix /etc/vane)
SHARE_DIR=$(prefix /usr/local/share/vane)
DOC_DIR=$(prefix /usr/local/share/doc/vane)
SYSTEMD_DIR=$(prefix /etc/systemd/system)
SERVICE_FILE=$SYSTEMD_DIR/vane.service

if [ -z "$DEST" ]; then
  for c in systemctl getent id userdel groupdel; do require "$c"; done
  # Never remove the executable while a known active service is still running.
  if systemctl is-active --quiet vane.service; then
    systemctl stop vane.service || fail 'unable to stop vane.service; no files removed'
  fi
  systemctl disable vane.service >/dev/null 2>&1 || true
  systemctl is-active --quiet vane.service && fail 'vane.service is still active; no files removed' || true
fi

# Remove the installed executable, any old diagnostic binary, and incomplete
# installer transaction files. Other programs in /usr/local/bin are untouched.
rm -f -- "$BIN_DIR/vane" "$BIN_DIR/vane_udp_offload_probe" \
  "$BIN_DIR"/.vane.new.* "$BIN_DIR"/.vane.old.* \
  "$BIN_DIR"/.vane_udp_offload_probe.new.* "$BIN_DIR"/.vane_udp_offload_probe.old.*
rm -f -- "$SERVICE_FILE" "$SYSTEMD_DIR"/.vane.service.new.* "$SYSTEMD_DIR"/.vane.service.old.*
# Explicitly delete ALL configuration, including user edits and additional files.
rm -rf -- "$CONFIG_DIR" "$SHARE_DIR" "$DOC_DIR"

if [ -z "$DEST" ]; then
  # Only our systemd unit enablement link is removed; never vacuum shared journals.
  rm -f -- "$SYSTEMD_DIR/multi-user.target.wants/vane.service"
  systemctl daemon-reload || fail 'systemd daemon-reload failed'
  systemctl reset-failed vane.service >/dev/null 2>&1 || true

  # The installer uses this exact system identity. If another application owns
  # a different 'vane' identity, refuse to delete it rather than guessing.
  entry=$(getent passwd vane || true)
  if [ -n "$entry" ]; then
    oldIFS=$IFS; IFS=:
    read -r username pw uid gid gecos home login_shell <<EOF
$entry
EOF
    IFS=$oldIFS
    if [ "$username" = vane ] && [ "$home" = /nonexistent ] && [ "$login_shell" = /usr/sbin/nologin ]; then
      userdel vane || fail 'failed to remove the dedicated vane account'
    else
      fail 'vane account does not match the installer-created system identity; preserved for safety'
    fi
  fi
  if getent group vane >/dev/null 2>&1; then
    groupdel vane || fail 'could not delete vane group (it may be in use by other accounts)'
  fi
fi
say 'Vane removed, including installed config, service and the legacy UDP probe'
if [ -z "$DEST" ]; then
  say 'Historical messages in the shared systemd journal are intentionally untouched'
else
  say "staged uninstall completed under VANE_ROOT=$DEST"
fi
