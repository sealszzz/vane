#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
TARGET="${1:?usage: package-release.sh <linux-amd64-v3|linux-arm64> [build-dir] [output-dir] <source-archive>}"
BUILD_DIR="${2:-build/$TARGET}"
OUTPUT_DIR="${3:-dist}"
SOURCE_ARCHIVE="${4:?source archive is required}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ROOT_DIR"
VERSION="$(tr -d '[:space:]' < VERSION)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "VERSION must contain exactly one x.y.z value"

case "$TARGET" in
  linux-amd64-v3)
    ARCH=amd64; CPU_LEVEL=x86-64-v3; DEFAULT_STRIP=x86_64-linux-gnu-strip; RUNNER=(); TEST_RUNNER='' ;;
  linux-arm64)
    ARCH=arm64; CPU_LEVEL=armv8-a
    ARM64_TRIPLE="${VANE_ARM64_TRIPLE:-aarch64-linux-gnu}"
    ARM64_SYSROOT="${VANE_ARM64_SYSROOT:-/usr/aarch64-linux-gnu}"
    QEMU_AARCH64="${QEMU_AARCH64:-qemu-aarch64}"
    DEFAULT_STRIP="${ARM64_TRIPLE}-strip"
    RUNNER=("$QEMU_AARCH64" -L "$ARM64_SYSROOT")
    printf -v TEST_RUNNER '%q -L %q' "$QEMU_AARCH64" "$ARM64_SYSROOT" ;;
  *) fail "unsupported target: $TARGET" ;;
esac
STRIP_TOOL="${STRIP_TOOL:-$DEFAULT_STRIP}"
for cmd in "$STRIP_TOOL" cmp file git python3 readelf sed sha256sum tar xz; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
done
if [[ ${#RUNNER[@]} -gt 0 ]]; then command -v "${RUNNER[0]}" >/dev/null 2>&1 || fail "required command not found: ${RUNNER[0]}"; fi
[[ -f "$SOURCE_ARCHIVE" ]] || fail "source archive not found: $SOURCE_ARCHIVE"
[[ -x "$BUILD_DIR/vane" && -x "$BUILD_DIR/vane_udp_offload_probe" ]] || fail "release executables are missing"

# Authoritative packaging gate: rejects Debug, sanitizer, baseline AMD64,
# dynamic crypto/json-c, wrong source commit, and unexpected ELF dependencies.
scripts/verify-release.sh "$BUILD_DIR" "$TARGET"
SOURCE_COMMIT="$(git rev-parse HEAD)"
DEPENDENCY_METADATA="$BUILD_DIR/dependency-revisions.env"
metadata_value() {
  local key=$1
  sed -n "s/^${key}=//p" "$DEPENDENCY_METADATA" | head -n1
}
AWSLC_VERSION="$(metadata_value aws_lc_version)"
AWSLC_COMMIT="$(metadata_value aws_lc_commit)"
JSONC_VERSION="$(metadata_value json_c_version)"
JSONC_COMMIT="$(metadata_value json_c_commit)"
[[ "$AWSLC_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid AWS-LC version metadata"
[[ "$JSONC_VERSION" =~ ^json-c-[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9]{8})?$ ]] || \
  fail "invalid json-c version metadata"
[[ "$AWSLC_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "AWS-LC release commit is not exact"
[[ "$JSONC_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "json-c release commit is not exact"
EXPECTED_SOURCE="vane-${VERSION}-src.tar.xz"
[[ "$(basename "$SOURCE_ARCHIVE")" == "$EXPECTED_SOURCE" ]] || fail "source archive must be named $EXPECTED_SOURCE"

# Prove the supplied source archive is byte-for-byte the current Git commit.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
scripts/package-source.sh "$tmp"
cmp "$tmp/$EXPECTED_SOURCE" "$SOURCE_ARCHIVE" || fail "source archive does not match current Git commit"

tar -xJf "$SOURCE_ARCHIVE" -C "$tmp"
SOURCE_ROOT="$tmp/vane-${VERSION}-src"
[[ -f "$SOURCE_ROOT/VERSION" ]] || fail "source archive root is invalid"
[[ "$(tr -d '[:space:]' < "$SOURCE_ROOT/VERSION")" == "$VERSION" ]] || fail "embedded source VERSION does not match"

PKG="vane-${VERSION}-${TARGET}"
PACKAGE_ROOT="$OUTPUT_DIR/$PKG"
rm -rf "$PACKAGE_ROOT"
mkdir -p "$PACKAGE_ROOT/bin" "$PACKAGE_ROOT/configs" "$PACKAGE_ROOT/docs" \
  "$PACKAGE_ROOT/third_party/licenses"
install -m 0755 "$BUILD_DIR/vane" "$PACKAGE_ROOT/bin/vane"
"$STRIP_TOOL" --strip-unneeded "$PACKAGE_ROOT/bin/vane"
for binary in "$PACKAGE_ROOT/bin/vane"; do
  file "$binary" | grep -q stripped || fail "packaged binary is not stripped: $binary"
done

install -m 0755 install.sh uninstall.sh "$PACKAGE_ROOT/"
install -m 0644 VERSION README.md SECURITY.md CHANGELOG.md BUILDING.md LICENSE \
  THIRD_PARTY_NOTICES.md "$PACKAGE_ROOT/"
install -m 0644 docs/ARCHITECTURE.md docs/CONFIG.md docs/FEATURES.md "$PACKAGE_ROOT/docs/"
install -m 0644 configs/vane.json "$PACKAGE_ROOT/configs/vane.json"
install -m 0644 "$BUILD_DIR/third-party-licenses/AWS-LC-LICENSE" \
  "$PACKAGE_ROOT/third_party/licenses/AWS-LC-LICENSE"
install -m 0644 "$BUILD_DIR/third-party-licenses/AWS-LC-NOTICE" \
  "$PACKAGE_ROOT/third_party/licenses/AWS-LC-NOTICE"
install -m 0644 "$BUILD_DIR/third-party-licenses/json-c-COPYING" \
  "$PACKAGE_ROOT/third_party/licenses/json-c-COPYING"
install -m 0644 "$SOURCE_ARCHIVE" "$PACKAGE_ROOT/$EXPECTED_SOURCE"
cat > "$PACKAGE_ROOT/DEPENDENCIES" <<EOF_DEPENDENCIES
aws-lc-ref=$AWSLC_VERSION
aws-lc-commit=$AWSLC_COMMIT
json-c-ref=$JSONC_VERSION
json-c-commit=$JSONC_COMMIT
EOF_DEPENDENCIES
printf '%s\n' "$ARCH" > "$PACKAGE_ROOT/TARGET_ARCH"
printf '%s\n' "$CPU_LEVEL" > "$PACKAGE_ROOT/TARGET_CPU"
printf '%s\n' "$SOURCE_COMMIT" > "$PACKAGE_ROOT/SOURCE_COMMIT"

version_output=$("${RUNNER[@]}" "$PACKAGE_ROOT/bin/vane" --version)
printf '%s\n' "$version_output" | grep -Fqx "vane $VERSION" || fail "stripped binary version does not match"
printf '%s\n' "$version_output" | grep -Fqx "commit $SOURCE_COMMIT" || fail "stripped binary commit does not match"
printf '%s\n' "$version_output" | grep -Fqx "cpu $CPU_LEVEL" || fail "stripped binary CPU metadata does not match"
"${RUNNER[@]}" "$PACKAGE_ROOT/bin/vane" --check "$PACKAGE_ROOT/configs/vane.json" >/dev/null

# Repeat all process-level tests against the stripped payload.
VANE_TEST_RUNNER="$TEST_RUNNER" python3 tests/integration/integration_smoke.py "$PACKAGE_ROOT/bin/vane"
VANE_TEST_RUNNER="$TEST_RUNNER" python3 tests/integration/udp_diagnostics.py "$PACKAGE_ROOT/bin/vane"
VANE_TEST_RUNNER="$TEST_RUNNER" python3 tests/integration/tcp_half_close.py "$PACKAGE_ROOT/bin/vane"
VANE_TEST_RUNNER="$TEST_RUNNER" python3 tests/integration/tcp_backpressure.py "$PACKAGE_ROOT/bin/vane"
VANE_TEST_RUNNER="$TEST_RUNNER" python3 tests/integration/maintenance_regressions.py "$PACKAGE_ROOT/bin/vane"
if [[ ${#RUNNER[@]} -eq 0 ]]; then
  python3 tests/integration/installer_regressions.py \
    "$PACKAGE_ROOT/bin/vane"
fi

(
  cd "$PACKAGE_ROOT"
  find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  -C "$OUTPUT_DIR" -cf - "$PKG" | xz -T1 -9e > "$OUTPUT_DIR/$PKG.tar.xz"
printf '%s\n' "$OUTPUT_DIR/$PKG.tar.xz"
