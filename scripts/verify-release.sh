#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 2 ]] || fail "usage: $0 BUILD_DIR <linux-amd64-v3|linux-arm64>"
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
BUILD="$(cd -- "$1" && pwd -P)"
TARGET=$2
BINARY="$BUILD/vane"
PROBE="$BUILD/vane_udp_offload_probe"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
SOURCE_COMMIT="${VANE_GIT_COMMIT:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf unknown)}"

case "$TARGET" in
  linux-amd64-v3)
    ARCH=amd64; CPU_TARGET=x86-64-v3; EXPECTED_FLAG=-march=x86-64-v3; RUNNER=() ;;
  linux-arm64)
    ARCH=arm64; CPU_TARGET=armv8-a; EXPECTED_FLAG=-march=armv8-a
    ARM64_SYSROOT="${VANE_ARM64_SYSROOT:-/usr/aarch64-linux-gnu}"
    QEMU_AARCH64="${QEMU_AARCH64:-qemu-aarch64}"
    RUNNER=("$QEMU_AARCH64" -L "$ARM64_SYSROOT") ;;
  *) fail "unsupported target: $TARGET" ;;
esac

for command_name in file grep python3 readelf sed; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done
if [[ ${#RUNNER[@]} -gt 0 ]]; then
  command -v "${RUNNER[0]}" >/dev/null 2>&1 || fail "required command not found: ${RUNNER[0]}"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "VERSION must contain exactly one x.y.z value"
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "release source commit is not a 40-character Git commit"
[[ -x "$BINARY" && -x "$PROBE" ]] || fail "release executables are missing"
for path in CMakeCache.txt compile_commands.json dependency-revisions.env aws-lc-compile_commands.json json-c-compile_commands.json; do
  [[ -f "$BUILD/$path" ]] || fail "$path is missing"
done
for path in \
  third-party-licenses/AWS-LC-LICENSE \
  third-party-licenses/AWS-LC-NOTICE \
  third-party-licenses/json-c-COPYING; do
  [[ -s "$BUILD/$path" ]] || fail "$path is missing or empty"
done

grep -Fqx 'CMAKE_BUILD_TYPE:STRING=Release' "$BUILD/CMakeCache.txt" || fail "build type is not Release"
grep -Fqx 'VANE_SANITIZE:BOOL=OFF' "$BUILD/CMakeCache.txt" || fail "release build unexpectedly enables sanitizers"
grep -Fqx "VANE_CPU_TARGET:STRING=$CPU_TARGET" "$BUILD/CMakeCache.txt" || fail "build CPU target is not $CPU_TARGET"
grep -Eq '^OPENSSL_CRYPTO_LIBRARY:FILEPATH=.*libcrypto\.a$' "$BUILD/CMakeCache.txt" || fail "crypto library is not static"
grep -Eq '^VANE_JSONC_LIBRARY:FILEPATH=.*libjson-c\.a$' "$BUILD/CMakeCache.txt" || fail "json-c library is not static"
if grep -Eq -- '-fsanitize(=| )' "$BUILD/compile_commands.json"; then
  fail "release compile commands contain sanitizer flags"
fi
for expected in \
  "target=$TARGET" "source_commit=$SOURCE_COMMIT" \
  'aws_lc_build=source' "aws_lc_cpu=$CPU_TARGET" \
  'json_c_build=source' "json_c_cpu=$CPU_TARGET"; do
  grep -Fqx "$expected" "$BUILD/dependency-revisions.env" || fail "dependency metadata mismatch: $expected"
done

metadata_value() {
  local key=$1
  sed -n "s/^${key}=//p" "$BUILD/dependency-revisions.env" | head -n1
}
AWSLC_VERSION="$(metadata_value aws_lc_version)"
AWSLC_COMMIT="$(metadata_value aws_lc_commit)"
JSONC_VERSION="$(metadata_value json_c_version)"
JSONC_COMMIT="$(metadata_value json_c_commit)"
[[ "$AWSLC_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid AWS-LC version metadata"
[[ "$JSONC_VERSION" =~ ^json-c-[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9]{8})?$ ]] || \
  fail "invalid json-c version metadata"
for commit in "$AWSLC_COMMIT" "$JSONC_COMMIT"; do
  [[ "$commit" =~ ^[0-9a-f]{40}$ || "$commit" == unavailable-local-source ]] || \
    fail "invalid dependency commit metadata: $commit"
done
AWSLC_SOURCE="$(metadata_value aws_lc_source)"
JSONC_SOURCE="$(metadata_value json_c_source)"
[[ -d "$AWSLC_SOURCE" && -d "$JSONC_SOURCE" ]] || fail "dependency source metadata is invalid"

python3 "$ROOT/scripts/verify-compile-flags.py" "$BUILD/compile_commands.json" "$ROOT" "$EXPECTED_FLAG"
python3 "$ROOT/scripts/verify-compile-flags.py" "$BUILD/aws-lc-compile_commands.json" "$AWSLC_SOURCE" "$EXPECTED_FLAG"
python3 "$ROOT/scripts/verify-compile-flags.py" "$BUILD/json-c-compile_commands.json" "$JSONC_SOURCE" "$EXPECTED_FLAG"

version_output=$("${RUNNER[@]}" "$BINARY" --version)
printf '%s\n' "$version_output" | grep -Fqx "vane $VERSION" || fail "binary version does not match VERSION"
printf '%s\n' "$version_output" | grep -Fqx "commit $SOURCE_COMMIT" || fail "binary commit does not match source"
printf '%s\n' "$version_output" | grep -Fqx "cpu $CPU_TARGET" || fail "binary CPU metadata does not match"
"${RUNNER[@]}" "$BINARY" --check "$ROOT/configs/vane.json" >/dev/null

verify_architecture() {
  local binary=$1
  case "$ARCH" in
    amd64)
      file "$binary" | grep -q 'ELF 64-bit.*x86-64' || fail "$binary is not x86-64"
      readelf -h "$binary" | grep -Eq 'Machine:.*(Advanced Micro Devices X86-64|X86-64)' || fail "$binary machine is not x86-64"
      readelf -n "$binary" | grep -Eq 'x86 ISA needed:.*x86-64-v3' || fail "$binary does not declare x86-64-v3" ;;
    arm64)
      file "$binary" | grep -q 'ELF 64-bit.*ARM aarch64' || fail "$binary is not AArch64"
      readelf -h "$binary" | grep -q 'Machine:.*AArch64' || fail "$binary machine is not AArch64" ;;
  esac
}

verify_hardening() {
  local binary=$1 stack
  readelf -h "$binary" | grep -q 'Type:.*DYN' || fail "$binary is not PIE"
  readelf -l "$binary" | grep -q GNU_RELRO || fail "$binary is missing GNU_RELRO"
  readelf -d "$binary" | grep -Eq 'BIND_NOW|FLAGS_1.*NOW' || fail "$binary is missing BIND_NOW"
  stack="$(readelf -W -l "$binary" | awk '/GNU_STACK/ {print; exit}')"
  [[ -n "$stack" ]] || fail "$binary has no GNU_STACK header"
  [[ "$stack" != *RWE* ]] || fail "$binary requests an executable stack"
}

verify_dependencies() {
  local binary=$1 needed library
  needed=$(readelf -d "$binary" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')
  printf '%s\n' "$needed" | grep -Fqx libc.so.6 || fail "$binary does not depend on glibc"
  while IFS= read -r library; do
    [[ -n "$library" ]] || continue
    case "$library" in
      libc.so.6|ld-linux-x86-64.so.2|ld-linux-aarch64.so.1) ;;
      *) fail "unexpected dynamic dependency in $binary: $library" ;;
    esac
  done <<< "$needed"
}

for binary in "$BINARY" "$PROBE"; do
  verify_architecture "$binary"
  verify_hardening "$binary"
  verify_dependencies "$binary"
done
printf 'release verification passed: %s\n' "$TARGET"
