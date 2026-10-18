#!/usr/bin/env bash
set -Eeuo pipefail

OUTPUT_FILE="${1:-}"

fail() { echo "error: $*" >&2; exit 1; }

resolve_latest_stable() {
  local label="$1" url="$2" glob="$3" regex="$4" prefix="$5"
  local tag tag_ref peeled_ref commit

  tag="$(
    git ls-remote --tags --refs "$url" "$glob" \
      | awk '{sub("refs/tags/", "", $2); print $2}' \
      | grep -E "$regex" \
      | sort -V \
      | tail -n1
  )"
  [[ -n "$tag" ]] || fail "cannot resolve latest stable release for $label"

  tag_ref="$(git ls-remote "$url" "refs/tags/$tag" | awk 'NR==1 {print $1}')"
  peeled_ref="$(git ls-remote "$url" "refs/tags/$tag^{}" | awk 'NR==1 {print $1}')"
  commit="${peeled_ref:-$tag_ref}"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "cannot resolve commit for $label $tag"

  printf -v "${prefix}_REF" '%s' "$tag"
  printf -v "${prefix}_COMMIT" '%s' "$commit"
}

resolve_latest_stable \
  AWS-LC \
  https://github.com/aws/aws-lc.git \
  'v*' \
  '^v[0-9]+\.[0-9]+\.[0-9]+$' \
  AWSLC

resolve_latest_stable \
  json-c \
  https://github.com/json-c/json-c.git \
  'json-c-*' \
  '^json-c-[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9]{8})?$' \
  JSONC

if [[ -n "$OUTPUT_FILE" ]]; then
  {
    echo "awslc_ref=$AWSLC_REF"
    echo "awslc_commit=$AWSLC_COMMIT"
    echo "jsonc_ref=$JSONC_REF"
    echo "jsonc_commit=$JSONC_COMMIT"
  } >> "$OUTPUT_FILE"
fi

cat <<EOF_SUMMARY
Resolved latest stable dependencies:
  AWS-LC $AWSLC_REF $AWSLC_COMMIT
  json-c $JSONC_REF $JSONC_COMMIT
EOF_SUMMARY
