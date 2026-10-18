#!/usr/bin/env bash
set -euo pipefail
OUTPUT_DIR="${1:-dist}"
VERSION="$(tr -d '[:space:]' < VERSION)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'error: VERSION must contain exactly one x.y.z value' >&2; exit 1; }
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo 'error: source packaging must run from a Git checkout' >&2; exit 1; }
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || { echo 'error: source packaging requires a clean Git checkout' >&2; exit 1; }
SOURCE_COMMIT="$(git rev-parse HEAD)"
PACKAGE="vane-${VERSION}-src"
mkdir -p "$OUTPUT_DIR"
git archive --format=tar --prefix="${PACKAGE}/" "$SOURCE_COMMIT" | xz -T1 -9e > "$OUTPUT_DIR/${PACKAGE}.tar.xz"
printf '%s\n' "$OUTPUT_DIR/${PACKAGE}.tar.xz"
