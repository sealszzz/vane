#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 4 ]] || fail "usage: $0 PACKAGE SOURCE_ARCHIVE <linux-amd64-v3|linux-arm64> SOURCE_COMMIT"
PACKAGE=$1
SOURCE_ARCHIVE=$2
TARGET=$3
EXPECTED_COMMIT=$4
ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"

case "$TARGET" in
  linux-amd64-v3) ARCH=amd64; CPU=x86-64-v3 ;;
  linux-arm64) ARCH=arm64; CPU=armv8-a ;;
  *) fail "unsupported target: $TARGET" ;;
esac

for cmd in cmp diff file find grep python3 readelf sha256sum sort tar; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
done
[[ -f "$PACKAGE" ]] || fail "package not found: $PACKAGE"
[[ -f "$SOURCE_ARCHIVE" ]] || fail "source archive not found: $SOURCE_ARCHIVE"
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "source commit must be a 40-character hexadecimal value"
[[ "$(basename "$PACKAGE")" == "vane-${VERSION}-${TARGET}.tar.xz" ]] || fail "unexpected package filename"
[[ "$(basename "$SOURCE_ARCHIVE")" == "vane-${VERSION}-src.tar.xz" ]] || fail "unexpected source archive filename"

validate_archive_members() {
  local archive=$1 expected_root=$2 label=$3 member
  while IFS= read -r member; do
    [[ -n "$member" ]] || continue
    [[ "$member" != /* ]] || fail "absolute $label archive member: $member"
    [[ "/$member/" != *"/../"* ]] || fail "parent traversal $label archive member: $member"
    [[ "$member" == "$expected_root" || "$member" == "$expected_root/"* ]] || \
      fail "unexpected $label archive root: $member"
  done < <(tar -tJf "$archive")
}

expected_root="vane-${VERSION}-${TARGET}"
source_root_name="vane-${VERSION}-src"
validate_archive_members "$PACKAGE" "$expected_root" package
validate_archive_members "$SOURCE_ARCHIVE" "$source_root_name" source

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/package" "$tmp/source"
tar -xJf "$PACKAGE" -C "$tmp/package"
tar -xJf "$SOURCE_ARCHIVE" -C "$tmp/source"
root="$tmp/package/$expected_root"
source_root="$tmp/source/$source_root_name"
[[ -d "$root" ]] || fail "package root is missing"
[[ -d "$source_root" ]] || fail "source root is missing"

for tree in "$root" "$source_root"; do
  unexpected="$(find "$tree" -mindepth 1 ! -type f ! -type d -print -quit)"
  [[ -z "$unexpected" ]] || fail "archive contains a non-regular entry: $unexpected"
done
python3 "$source_root/scripts/check-release-consistency.py"

cat > "$tmp/expected-files" <<EOF_FILES
BUILDING.md
CHANGELOG.md
DEPENDENCIES
LICENSE
README.md
SECURITY.md
SHA256SUMS
SOURCE_COMMIT
TARGET_ARCH
TARGET_CPU
THIRD_PARTY_NOTICES.md
VERSION
bin/vane
configs/vane.json
docs/ARCHITECTURE.md
docs/CONFIG.md
docs/FEATURES.md
install.sh
uninstall.sh
third_party/licenses/AWS-LC-LICENSE
third_party/licenses/AWS-LC-NOTICE
third_party/licenses/json-c-COPYING
vane-${VERSION}-src.tar.xz
EOF_FILES
# Normalize both inventories before comparison. Keeping only the actual list
# sorted caused false release failures when uninstall.sh was added.
LC_ALL=C sort -o "$tmp/expected-files" "$tmp/expected-files"
find "$root" -type f -printf '%P\n' | LC_ALL=C sort > "$tmp/actual-files"
diff -u "$tmp/expected-files" "$tmp/actual-files" || fail "package file set is not exact"

[[ -x "$root/bin/vane" ]] || fail "vane is not executable"
[[ -x "$root/install.sh" && -x "$root/uninstall.sh" ]] || fail "installer is not executable"
[[ "$(tr -d '[:space:]' < "$root/VERSION")" == "$VERSION" ]] || fail "package VERSION mismatch"
[[ "$(tr -d '[:space:]' < "$root/TARGET_ARCH")" == "$ARCH" ]] || fail "TARGET_ARCH mismatch"
[[ "$(tr -d '[:space:]' < "$root/TARGET_CPU")" == "$CPU" ]] || fail "TARGET_CPU mismatch"
[[ "$(tr -d '[:space:]' < "$root/SOURCE_COMMIT")" == "$EXPECTED_COMMIT" ]] || fail "SOURCE_COMMIT mismatch"
cmp "$SOURCE_ARCHIVE" "$root/vane-${VERSION}-src.tar.xz" || fail "embedded source archive mismatch"
cmp "$source_root/LICENSE" "$root/LICENSE" || fail "packaged project license mismatch"
cmp "$source_root/THIRD_PARTY_NOTICES.md" "$root/THIRD_PARTY_NOTICES.md" || \
  fail "packaged third-party notices mismatch"
for path in \
  third_party/licenses/AWS-LC-LICENSE \
  third_party/licenses/AWS-LC-NOTICE \
  third_party/licenses/json-c-COPYING; do
  [[ -s "$root/$path" ]] || fail "third-party license is missing or empty: $path"
done
[[ "$(grep -c '^' "$root/DEPENDENCIES")" -eq 4 ]] || fail "dependency manifest must contain four lines"
grep -Eq '^aws-lc-ref=v[0-9]+\.[0-9]+\.[0-9]+$' "$root/DEPENDENCIES" || \
  fail "invalid AWS-LC dependency ref"
grep -Eq '^aws-lc-commit=[0-9a-f]{40}$' "$root/DEPENDENCIES" || \
  fail "invalid AWS-LC dependency commit"
grep -Eq '^json-c-ref=json-c-[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9]{8})?$' \
  "$root/DEPENDENCIES" || fail "invalid json-c dependency ref"
grep -Eq '^json-c-commit=[0-9a-f]{40}$' "$root/DEPENDENCIES" || \
  fail "invalid json-c dependency commit"
(cd "$root" && sha256sum -c SHA256SUMS >/dev/null)

verify_binary() {
  local binary=$1 needed library stack
  file "$binary" | grep -q stripped || fail "binary is not stripped: $binary"
  readelf -h "$binary" | grep -q 'Type:.*DYN' || fail "binary is not PIE: $binary"
  readelf -l "$binary" | grep -q GNU_RELRO || fail "GNU_RELRO is missing: $binary"
  readelf -d "$binary" | grep -Eq 'BIND_NOW|FLAGS_1.*NOW' || fail "BIND_NOW is missing: $binary"
  stack="$(readelf -W -l "$binary" | awk '/GNU_STACK/ {print; exit}')"
  [[ -n "$stack" ]] || fail "GNU_STACK is missing: $binary"
  [[ "$stack" != *RWE* ]] || fail "executable stack detected: $binary"

  needed="$(readelf -d "$binary" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')"
  printf '%s\n' "$needed" | grep -Fqx libc.so.6 || fail "glibc dependency is missing: $binary"
  while IFS= read -r library; do
    [[ -n "$library" ]] || continue
    case "$library" in
      libc.so.6|ld-linux-x86-64.so.2|ld-linux-aarch64.so.1) ;;
      *) fail "unexpected dynamic dependency in $binary: $library" ;;
    esac
  done <<< "$needed"

  case "$TARGET" in
    linux-amd64-v3)
      file "$binary" | grep -q 'ELF 64-bit.*x86-64' || fail "AMD64 binary architecture mismatch: $binary"
      readelf -h "$binary" | grep -Eq 'Machine:.*(Advanced Micro Devices X86-64|X86-64)' || \
        fail "AMD64 ELF machine mismatch: $binary"
      readelf -n "$binary" | grep -Eq 'x86 ISA needed:.*x86-64-v3' || \
        fail "x86-64-v3 ELF property is missing: $binary" ;;
    linux-arm64)
      file "$binary" | grep -q 'ELF 64-bit.*ARM aarch64' || fail "ARM64 binary architecture mismatch: $binary"
      readelf -h "$binary" | grep -q 'Machine:.*AArch64' || fail "ARM64 ELF machine mismatch: $binary" ;;
  esac
}

verify_binary "$root/bin/vane"
printf 'package verification passed: %s\n' "$TARGET"
