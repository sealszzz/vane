#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
CC=${CC:-cc}
TMP=${TMPDIR:-/tmp}/vane-x86-64-v3-probe.$$
trap 'rm -f "$TMP"' EXIT HUP INT TERM

"$CC" -std=c17 -O2 -Wall -Wextra -Werror \
  "$ROOT/tools/x86_64_v3_probe.c" -o "$TMP"
"$TMP"
printf '%s\n' 'x86-64-v3 host support confirmed'
