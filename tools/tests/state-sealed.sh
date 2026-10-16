#!/usr/bin/env bash
# build/service-scripts/state-sealed.sh against stand-in /sys trees: sealed only while
# kryptik-state's mapping is suspended, not while it runs, not for another mapping's suspension,
# and not with no mapping at all. Under each POSIX shell here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
X="$ROOT/build/service-scripts/state-sealed.sh"
PASS=0; FAIL=0
check() {
    if [[ "$2" == "$3" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1))
    else printf '  FAIL  %s (got %q, want %q)\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mapping() {   # mapping N NAME SUSPENDED
    mkdir -p "$T/sys/class/block/dm-$1/dm"
    echo "$2" > "$T/sys/class/block/dm-$1/dm/name"; echo "$3" > "$T/sys/class/block/dm-$1/dm/suspended"
}
for sh in sh bash dash; do
    command -v "$sh" > /dev/null 2>&1 || continue
    sealed() { KRYPTIK_SYSFS="$T/sys" "$sh" "$X" 2>&1; echo "$?"; }
    rm -rf "$T/sys"; mkdir -p "$T/sys/class/block"
    check "$sh: no mapping is no seal" "$(sealed)" 1
    mapping 0 kryptik-root-a 0; mapping 1 kryptik-state 0; mapping 2 kryptik-zone-work 1
    check "$sh: kryptik-state running, a zone's volume waiting, is no seal" "$(sealed)" 1
    echo 1 > "$T/sys/class/block/dm-1/dm/suspended"
    check "$sh: kryptik-state suspended is sealed" "$(sealed)" 0
done
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
