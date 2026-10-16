#!/usr/bin/env bash
# The desktop's C tools that need only libc compile with the stage's hardening flags, as stage 04
# builds them (build/recipes/desktop.sh), and answer no arguments with their usage: a change to
# one is checked here, not first in a Distro build.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
command -v cc >/dev/null 2>&1 || { echo "desktop-tools.sh: no C compiler here"; exit 77; }
# shellcheck source=/dev/null
. "$REPO/build/config/hardening.env"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

fail=0
for t in wlprobe kryptik-launch; do
    # shellcheck disable=SC2086
    if ! cc ${CFLAGS} ${LDFLAGS} -o "$W/$t" "$REPO/tools/desktop/$t.c"; then
        echo "FAIL: tools/desktop/$t.c does not compile with the stage's flags"
        fail=1
        continue
    fi
    out="$("$W/$t" 2>&1)"
    if [[ "$out" == *usage:* ]]; then
        echo "PASS: $t compiles with the stage's flags and prints its usage"
    else
        echo "FAIL: $t with no arguments: ${out:0:200}"
        fail=1
    fi
done
exit "$fail"
