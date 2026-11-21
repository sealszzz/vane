#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
CC=${CC:-cc}
probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/vane-x86-64-v3-probe.XXXXXX")
probe=$probe_dir/probe
trap 'rm -rf -- "$probe_dir"' EXIT

"$CC" -std=c17 -O2 -Wall -Wextra -Werror \
  "$ROOT/tools/x86_64_v3_probe.c" -o "$probe"
"$probe"
printf '%s\n' 'x86-64-v3 host support confirmed'
