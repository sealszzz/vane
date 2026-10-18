#!/bin/sh
set -eu

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }
require() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }
prefix() { printf '%s%s' "$DEST" "$1"; }

case "$0" in */*) ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) ;; *) ROOT=$(pwd -P) ;; esac
DEST=${VANE_ROOT:-}
START=${VANE_START:-auto}
case "$DEST" in ''|/*) ;; *) fail 'VANE_ROOT must be empty or an absolute path' ;; esac
case "$START" in auto|true|false) ;; *) fail 'VANE_START must be auto, true, or false' ;; esac
[ "$(id -u)" = 0 ] || fail 'run as root'
for command_name in install mv rm uname; do require "$command_name"; done

machine=$(uname -m)
case "$machine" in
  x86_64|amd64) machine=amd64; default_target=linux-amd64-v3 ;;
  aarch64|arm64) machine=arm64; default_target=linux-arm64 ;;
  *) fail "unsupported architecture: $machine" ;;
esac

PACKAGE_MODE=false
if [ -n "${VANE_BINARY:-}" ]; then
  BINARY=$VANE_BINARY
elif [ -x "$ROOT/bin/vane" ]; then
  PACKAGE_MODE=true
  BINARY=$ROOT/bin/vane
elif [ -x "$ROOT/build/$default_target/vane" ]; then
  BINARY=$ROOT/build/$default_target/vane
else
  fail 'no Vane binary found; use a binary package or set VANE_BINARY'
fi
EXAMPLE_CONFIG=$ROOT/configs/vane.json
[ -x "$BINARY" ] || fail "missing executable: $BINARY"
[ -f "$EXAMPLE_CONFIG" ] || fail "missing configuration: $EXAMPLE_CONFIG"

if [ "$PACKAGE_MODE" = true ]; then
  require sha256sum
  [ -f "$ROOT/SHA256SUMS" ] || fail 'binary package is missing SHA256SUMS'
  (cd "$ROOT" && sha256sum -c SHA256SUMS >/dev/null) || fail 'package checksum verification failed'
  [ -f "$ROOT/TARGET_ARCH" ] || fail 'binary package is missing TARGET_ARCH'
  expected=$(tr -d '[:space:]' < "$ROOT/TARGET_ARCH")
  case "$expected" in amd64|arm64) ;; *) fail "invalid package architecture metadata: $expected" ;; esac
  [ "$machine" = "$expected" ] || fail "package architecture is $expected; detected $machine"
  say 'package checksums and architecture verified'
fi

BIN_DIR=$(prefix /usr/local/bin)
CONFIG_DIR=$(prefix /etc/vane)
CONFIG_FILE=$CONFIG_DIR/vane.json
SYSTEMD_DIR=$(prefix /etc/systemd/system)
SERVICE_FILE=$SYSTEMD_DIR/vane.service

config_existed=false
if [ -e "$CONFIG_FILE" ]; then config_existed=true; CONFIG_TO_CHECK=$CONFIG_FILE; else CONFIG_TO_CHECK=$EXAMPLE_CONFIG; fi
# The new payload must accept the effective configuration before any installed file is replaced.
"$BINARY" --check "$CONFIG_TO_CHECK" >/dev/null
say 'configuration validated before installation'

service_was_active=false
service_was_enabled=false
if [ -z "$DEST" ]; then
  for command_name in getent groupadd id systemctl useradd; do require "$command_name"; done
  getent group vane >/dev/null 2>&1 || groupadd --system vane
  if ! id -u vane >/dev/null 2>&1; then useradd --system -g vane -M -d /nonexistent -s /usr/sbin/nologin vane; fi
  fs_group=vane
  systemctl is-active --quiet vane.service && service_was_active=true || true
  systemctl is-enabled --quiet vane.service && service_was_enabled=true || true
else
  fs_group=root
fi

install -d -o root -g root -m 0755 "$BIN_DIR" "$SYSTEMD_DIR"
install -d -o root -g "$fs_group" -m 0750 "$CONFIG_DIR"
tmp_binary=$BIN_DIR/.vane.new.$$
tmp_service=$SYSTEMD_DIR/.vane.service.new.$$
tmp_config=$CONFIG_DIR/.vane.json.new.$$
backup_binary=$BIN_DIR/.vane.old.$$
backup_service=$SYSTEMD_DIR/.vane.service.old.$$
published_binary=false; published_service=false
installed_config=false; newly_enabled=false; committed=false; activation_attempted=false

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  rm -f "$tmp_binary" "$tmp_service" "$tmp_config"
  if [ "$committed" = false ]; then
    if [ -z "$DEST" ] && [ "$activation_attempted" = true ]; then
      systemctl stop vane.service >/dev/null 2>&1
    fi
    rollback_failed=false
    if [ -e "$backup_binary" ]; then mv -f "$backup_binary" "$BIN_DIR/vane" || rollback_failed=true; elif [ "$published_binary" = true ]; then rm -f "$BIN_DIR/vane"; fi
    if [ -e "$backup_service" ]; then mv -f "$backup_service" "$SERVICE_FILE" || rollback_failed=true; elif [ "$published_service" = true ]; then rm -f "$SERVICE_FILE"; fi
    [ "$installed_config" = false ] || rm -f "$CONFIG_FILE"
    if [ -z "$DEST" ]; then
      [ "$newly_enabled" = false ] || systemctl disable vane.service >/dev/null 2>&1
      systemctl daemon-reload >/dev/null 2>&1
      if [ "$service_was_active" = true ] &&
         { [ "$published_binary" = true ] || [ "$published_service" = true ] || [ "$activation_attempted" = true ]; }; then
        systemctl restart vane.service >/dev/null 2>&1
      fi
    fi
    if [ "$rollback_failed" = true ]; then
      printf 'error: rollback incomplete; retained backup files for recovery\n' >&2
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

install -o root -g root -m 0755 "$BINARY" "$tmp_binary"
cat > "$tmp_service" <<'UNIT'
[Unit]
Description=Vane pass-through TCP/QUIC SNI router
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=30s
User=vane
Group=vane
UMask=0027
ExecStartPre=/usr/local/bin/vane --check /etc/vane/vane.json
ExecStart=/usr/local/bin/vane /etc/vane/vane.json
Restart=always
RestartSec=2s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
chown root:root "$tmp_service"; chmod 0644 "$tmp_service"
if [ "$config_existed" = false ]; then install -o root -g "$fs_group" -m 0640 "$EXAMPLE_CONFIG" "$tmp_config"; fi

if [ -e "$BIN_DIR/vane" ]; then mv -f "$BIN_DIR/vane" "$backup_binary"; fi
if [ -e "$SERVICE_FILE" ]; then mv -f "$SERVICE_FILE" "$backup_service"; fi
published_binary=true
mv -f "$tmp_binary" "$BIN_DIR/vane"
published_service=true
mv -f "$tmp_service" "$SERVICE_FILE"
if [ "$config_existed" = false ]; then installed_config=true; mv -f "$tmp_config" "$CONFIG_FILE"; fi
"$BIN_DIR/vane" --check "$CONFIG_FILE" >/dev/null

if [ "$config_existed" = true ]; then say "preserving existing configuration: $CONFIG_FILE"; else say "installed example configuration: $CONFIG_FILE"; fi
if [ -n "$DEST" ]; then
  # The former standalone UDP offload diagnostic is no longer installed.
  rm -f "$BIN_DIR/vane_udp_offload_probe"
  committed=true
  rm -f "$backup_binary" "$backup_service"
  trap - EXIT HUP INT TERM
  say "staged Vane under VANE_ROOT=$DEST; account and systemd operations skipped"
  exit 0
fi

chown root:vane "$CONFIG_DIR" "$CONFIG_FILE"; chmod 0750 "$CONFIG_DIR"; chmod 0640 "$CONFIG_FILE"
systemctl daemon-reload
if [ "$service_was_enabled" = false ]; then systemctl enable vane.service >/dev/null; newly_enabled=true; fi
start=$START
if [ "$start" = auto ]; then if [ "$config_existed" = true ]; then start=true; else start=false; fi; fi
if [ "$start" = true ]; then
  activation_attempted=true
  if ! systemctl restart vane.service; then
    systemctl status vane.service --no-pager -l >&2 || true
    command -v journalctl >/dev/null 2>&1 && journalctl -u vane.service -n 120 -o cat --no-pager >&2 || true
    fail 'vane.service failed to start; previous installation restored'
  fi
  say 'started vane.service'
else
  say 'installed and enabled vane.service without starting it'
  say "edit $CONFIG_FILE, then run: systemctl restart vane"
fi

# Remove the legacy test helper only after activation has succeeded.
rm -f "$BIN_DIR/vane_udp_offload_probe"
committed=true
rm -f "$backup_binary" "$backup_service"
trap - EXIT HUP INT TERM
