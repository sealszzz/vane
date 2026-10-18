#!/usr/bin/env bash
set -Eeuo pipefail

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

TARGET="${1:-linux-amd64-v3}"
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
BUILD_DIR="${2:-$ROOT/build/$TARGET}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2\n')}"
DEPS_ROOT="${VANE_DEPS_ROOT:-$ROOT/.deps/$TARGET}"
SOURCES="$DEPS_ROOT/sources"
METADATA="$DEPS_ROOT/dependency-revisions.env"

AWSLC_REF="${AWSLC_REF:-latest}"
JSONC_REF="${JSONC_REF:-latest}"
AWSLC_REQUESTED_REF="$AWSLC_REF"
JSONC_REQUESTED_REF="$JSONC_REF"

case "$TARGET" in
  linux-amd64-v3)
    TRIPLE=x86_64-linux-gnu
    PROCESSOR=x86_64
    CPU_TARGET=x86-64-v3
    CPU_FLAGS='-march=x86-64-v3 -mtune=generic'
    CROSS=false
    EMULATOR=()
    ;;
  linux-arm64)
    TRIPLE="${VANE_ARM64_TRIPLE:-aarch64-linux-gnu}"
    PROCESSOR=aarch64
    CPU_TARGET=armv8-a
    CPU_FLAGS='-march=armv8-a'
    CROSS=true
    ARM64_SYSROOT="${VANE_ARM64_SYSROOT:-/usr/aarch64-linux-gnu}"
    QEMU_AARCH64="${QEMU_AARCH64:-qemu-aarch64}"
    EMULATOR=("$QEMU_AARCH64" -L "$ARM64_SYSROOT")
    ;;
  *) fail "unsupported target: $TARGET" ;;
esac

CC="${CC:-${TRIPLE}-gcc}"
CXX="${CXX:-${TRIPLE}-g++}"
AR="${AR:-${TRIPLE}-ar}"
RANLIB="${RANLIB:-${TRIPLE}-ranlib}"
STRIP="${STRIP:-${TRIPLE}-strip}"

for command_name in cmake ctest git ninja python3 tar xz "$CC" "$CXX" "$AR" "$RANLIB" "$STRIP"; do
  require "$command_name"
done
if [[ "$CROSS" == true ]]; then
  require "$QEMU_AARCH64"
  [[ -d "$ARM64_SYSROOT" ]] || fail "ARM64 sysroot not found: $ARM64_SYSROOT"
fi

VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  fail "VERSION must contain exactly one x.y.z value"
GIT_HEAD="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"
SOURCE_COMMIT="${VANE_GIT_COMMIT:-$GIT_HEAD}"
[[ "$GIT_HEAD" =~ ^[0-9a-f]{40}$ ]] || fail "release build must run from a Git commit"
[[ "$SOURCE_COMMIT" == "$GIT_HEAD" ]] || fail "VANE_GIT_COMMIT does not match the checked-out source commit"
if [[ -n "${VANE_BUILD_TIME:-}" ]]; then
  BUILD_TIME="$VANE_BUILD_TIME"
elif git -C "$ROOT" rev-parse HEAD >/dev/null 2>&1; then
  BUILD_TIME="$(git -C "$ROOT" show -s --format=%cI HEAD)"
else
  BUILD_TIME=unknown
fi

resolve_latest_ref() {
  local label="$1" url="$2" glob="$3" regex="$4"
  local ref
  ref="$(
    git ls-remote --tags --refs "$url" "$glob" \
      | awk '{sub("refs/tags/", "", $2); print $2}' \
      | grep -E "$regex" \
      | sort -V \
      | tail -n1
  )"
  [[ -n "$ref" ]] || fail "cannot resolve latest stable release for $label"
  printf '%s\n' "$ref"
}

resolve_ref() {
  local label="$1" url="$2" requested="$3" glob="$4" regex="$5"
  if [[ "$requested" == latest ]]; then
    requested="$(resolve_latest_ref "$label" "$url" "$glob" "$regex")"
  fi
  [[ "$requested" =~ $regex ]] || fail "$label ref is not an exact stable tag: $requested"
  printf '%s\n' "$requested"
}

clone_ref() {
  local label="$1" url="$2" ref="$3" destination="$4"
  rm -rf "$destination"
  git clone --depth 1 --branch "$ref" \
    --recurse-submodules --shallow-submodules \
    "$url" "$destination"
  git -C "$destination" submodule update --init --recursive --depth 1 || \
    git -C "$destination" submodule update --init --recursive
  printf '%s: %s (%s)\n' "$label" "$ref" "$(git -C "$destination" rev-parse HEAD)"
}

copy_source() {
  local input="$1" destination="$2" marker="$3"
  rm -rf "$destination"
  mkdir -p "$destination"
  if [[ -d "$input" ]]; then
    cp -a "$input"/. "$destination"/
    return
  fi

  local unpack="$DEPS_ROOT/.extract-$$"
  rm -rf "$unpack"
  mkdir -p "$unpack"
  case "$input" in
    *.tar.gz|*.tgz) tar -xzf "$input" -C "$unpack" ;;
    *.tar.xz|*.txz) tar -xJf "$input" -C "$unpack" ;;
    *.tar) tar -xf "$input" -C "$unpack" ;;
    *) fail "unsupported dependency source: $input" ;;
  esac

  local source_root
  source_root="$(find "$unpack" -mindepth 1 -maxdepth 3 -type f -name "$marker" -printf '%h\n' | LC_ALL=C sort -u | head -n1)"
  [[ -n "$source_root" ]] || fail "cannot find $marker in $input"
  cp -a "$source_root"/. "$destination"/
  rm -rf "$unpack"
}

source_commit() {
  local directory="$1" top
  if top="$(git -C "$directory" rev-parse --show-toplevel 2>/dev/null)" &&
     [[ "$(realpath -m "$top")" == "$(realpath -m "$directory")" ]]; then
    git -C "$directory" rev-parse HEAD
  else
    printf '%s\n' unavailable-local-source
  fi
}

validate_expected_commit() {
  local label="$1" expected="$2" actual="$3"
  [[ -z "$expected" ]] && return
  [[ "$actual" == "$expected" ]] || \
    fail "$label commit $actual does not match resolved commit $expected"
}

mkdir -p "$SOURCES"
AWSLC_SOURCE_SET=${AWSLC_SOURCE+x}
JSONC_SOURCE_SET=${JSONC_SOURCE+x}
[[ "$AWSLC_SOURCE_SET" == "$JSONC_SOURCE_SET" ]] || \
  fail "AWSLC_SOURCE and JSONC_SOURCE must be provided together"

if [[ "$AWSLC_SOURCE_SET" == x ]]; then
  copy_source "$AWSLC_SOURCE" "$SOURCES/aws-lc" CMakeLists.txt
  copy_source "$JSONC_SOURCE" "$SOURCES/json-c" CMakeLists.txt
  AWSLC_RESOLVED_REF="$AWSLC_REQUESTED_REF"
  JSONC_RESOLVED_REF="$JSONC_REQUESTED_REF"
else
  AWSLC_RESOLVED_REF="$(resolve_ref \
    AWS-LC https://github.com/aws/aws-lc.git "$AWSLC_REF" \
    'v*' '^v[0-9]+\.[0-9]+\.[0-9]+$')"
  JSONC_RESOLVED_REF="$(resolve_ref \
    json-c https://github.com/json-c/json-c.git "$JSONC_REF" \
    'json-c-*' '^json-c-[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9]{8})?$')"
  clone_ref AWS-LC https://github.com/aws/aws-lc.git \
    "$AWSLC_RESOLVED_REF" "$SOURCES/aws-lc"
  clone_ref json-c https://github.com/json-c/json-c.git \
    "$JSONC_RESOLVED_REF" "$SOURCES/json-c"
fi

[[ "$AWSLC_RESOLVED_REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  fail "AWS-LC ref is not an exact stable tag: $AWSLC_RESOLVED_REF"
[[ "$JSONC_RESOLVED_REF" =~ ^json-c-[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9]{8})?$ ]] || \
  fail "json-c ref is not an exact stable tag: $JSONC_RESOLVED_REF"

AWSLC_SOURCE="$SOURCES/aws-lc"
JSONC_SOURCE="$SOURCES/json-c"
[[ -f "$AWSLC_SOURCE/CMakeLists.txt" ]] || fail "invalid AWS-LC source"
[[ -d "$AWSLC_SOURCE/include/openssl" ]] || fail "AWS-LC OpenSSL headers are missing"
[[ -f "$AWSLC_SOURCE/LICENSE" ]] || fail "AWS-LC license file is missing"
[[ -f "$AWSLC_SOURCE/NOTICE" ]] || fail "AWS-LC notice file is missing"
[[ -f "$JSONC_SOURCE/CMakeLists.txt" ]] || fail "invalid json-c source"
[[ -f "$JSONC_SOURCE/COPYING" ]] || fail "json-c license file is missing"

AWSLC_COMMIT="$(source_commit "$AWSLC_SOURCE")"
JSONC_COMMIT="$(source_commit "$JSONC_SOURCE")"
validate_expected_commit AWS-LC "${AWSLC_EXPECTED_COMMIT:-}" "$AWSLC_COMMIT"
validate_expected_commit json-c "${JSONC_EXPECTED_COMMIT:-}" "$JSONC_COMMIT"

cat > "$METADATA" <<EOF_METADATA
aws_lc_version=$AWSLC_RESOLVED_REF
aws_lc_commit=$AWSLC_COMMIT
json_c_version=$JSONC_RESOLVED_REF
json_c_commit=$JSONC_COMMIT
dependency_build=source
target=$TARGET
source_commit=$SOURCE_COMMIT
aws_lc_build=source
aws_lc_cpu=$CPU_TARGET
json_c_build=source
json_c_cpu=$CPU_TARGET
aws_lc_source=$AWSLC_SOURCE
json_c_source=$JSONC_SOURCE
EOF_METADATA

TOOLCHAIN="$DEPS_ROOT/toolchain.cmake"
{
  if [[ "$CROSS" == true ]]; then
    echo 'set(CMAKE_SYSTEM_NAME Linux)'
    echo "set(CMAKE_SYSTEM_PROCESSOR $PROCESSOR)"
    echo 'set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)'
  fi
  echo "set(CMAKE_C_COMPILER $CC)"
  echo "set(CMAKE_CXX_COMPILER $CXX)"
  echo "set(CMAKE_ASM_COMPILER $CC)"
  echo "set(CMAKE_AR $AR)"
  echo "set(CMAKE_RANLIB $RANLIB)"
  echo "set(CMAKE_STRIP $STRIP)"
  echo "set(CMAKE_C_FLAGS_INIT \"$CPU_FLAGS\")"
  echo "set(CMAKE_CXX_FLAGS_INIT \"$CPU_FLAGS\")"
  echo "set(CMAKE_ASM_FLAGS_INIT \"$CPU_FLAGS\")"
  if [[ "$CROSS" == true ]]; then
    echo "set(CMAKE_FIND_ROOT_PATH $ARM64_SYSROOT)"
    echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)'
    echo 'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)'
    echo 'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)'
    echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)'
    echo "set(CMAKE_CROSSCOMPILING_EMULATOR $QEMU_AARCH64;-L;$ARM64_SYSROOT)"
  fi
} > "$TOOLCHAIN"

AWSLC_BUILD="$DEPS_ROOT/build/aws-lc"
AWSLC_PREFIX="$DEPS_ROOT/install/aws-lc"
JSONC_BUILD="$DEPS_ROOT/build/json-c"
JSONC_PREFIX="$DEPS_ROOT/install/json-c"
RELEASE_C_FLAGS="-O3 -DNDEBUG $CPU_FLAGS -flto -ffunction-sections -fdata-sections"
rm -rf "$AWSLC_BUILD" "$AWSLC_PREFIX" "$JSONC_BUILD" "$JSONC_PREFIX" "$BUILD_DIR"

cmake -S "$AWSLC_SOURCE" -B "$AWSLC_BUILD" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_FLAGS_RELEASE="$RELEASE_C_FLAGS" \
  -DCMAKE_CXX_FLAGS_RELEASE="$RELEASE_C_FLAGS" \
  -DCMAKE_ASM_FLAGS_RELEASE="$CPU_FLAGS" \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_PREFIX="$AWSLC_PREFIX" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF \
  -DBUILD_LIBSSL=ON -DDISABLE_GO=ON
cmake --build "$AWSLC_BUILD" --parallel "$JOBS"
cmake --install "$AWSLC_BUILD"
[[ -f "$AWSLC_PREFIX/lib/libcrypto.a" ]] || fail "AWS-LC static libcrypto was not installed"
[[ -f "$AWSLC_PREFIX/include/openssl/crypto.h" ]] || fail "AWS-LC headers were not installed"

cmake -S "$JSONC_SOURCE" -B "$JSONC_BUILD" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_FLAGS_RELEASE="$RELEASE_C_FLAGS" \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_PREFIX="$JSONC_PREFIX" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
cmake --build "$JSONC_BUILD" --target install --parallel "$JOBS"

cmake -S "$ROOT" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DVANE_BUILD_TESTS=ON \
  -DVANE_CPU_TARGET="$CPU_TARGET" \
  -DVANE_CRYPTO_ROOT="$AWSLC_PREFIX" \
  -DVANE_JSONC_ROOT="$JSONC_PREFIX" \
  -DVANE_GIT_COMMIT="$SOURCE_COMMIT" \
  -DVANE_BUILD_TIME="$BUILD_TIME" \
  -DVANE_STATIC_JSONC=ON \
  -DVANE_WERROR=ON
cmake --build "$BUILD_DIR" --parallel "$JOBS"
ctest --test-dir "$BUILD_DIR" --output-on-failure
install -m 0644 "$METADATA" "$BUILD_DIR/dependency-revisions.env"
install -m 0644 "$AWSLC_BUILD/compile_commands.json" "$BUILD_DIR/aws-lc-compile_commands.json"
install -m 0644 "$JSONC_BUILD/compile_commands.json" "$BUILD_DIR/json-c-compile_commands.json"
THIRD_PARTY_LICENSES="$BUILD_DIR/third-party-licenses"
install -d -m 0755 "$THIRD_PARTY_LICENSES"
install -m 0644 "$AWSLC_SOURCE/LICENSE" "$THIRD_PARTY_LICENSES/AWS-LC-LICENSE"
install -m 0644 "$AWSLC_SOURCE/NOTICE" "$THIRD_PARTY_LICENSES/AWS-LC-NOTICE"
install -m 0644 "$JSONC_SOURCE/COPYING" "$THIRD_PARTY_LICENSES/json-c-COPYING"
"$ROOT/scripts/verify-release.sh" "$BUILD_DIR" "$TARGET"

if [[ "$CROSS" == true ]]; then
  "${EMULATOR[@]}" "$BUILD_DIR/vane" --version
else
  "$BUILD_DIR/vane" --version
fi
