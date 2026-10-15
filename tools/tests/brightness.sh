#!/usr/bin/env bash
# build/service-scripts/brightness.sh against stand-in /sys trees: the backlight it picks, its
# steps, the ends of the range, and what it refuses.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
B="$ROOT/build/service-scripts/brightness.sh"
PASS=0; FAIL=0
check() {
    if [[ "$2" == "$3" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1))
    else printf '  FAIL  %s (got %q, want %q)\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fresh() { rm -rf "$T/sys"; mkdir -p "$T/sys/class/backlight"; }
light() {   # light NAME TYPE MAX NOW
    local d="$T/sys/class/backlight/$1"
    mkdir -p "$d"; echo "$2" > "$d/type"; echo "$3" > "$d/max_brightness"; echo "$4" > "$d/brightness"
}
level() { cat "$T/sys/class/backlight/$1/brightness"; }
run() { KRYPTIK_SYSFS="$T/sys" "$B" "$@" 2>/dev/null; }

echo "-- steps"
fresh; light intel_backlight raw 1000 500
run up; check "up a twentieth" "$(level intel_backlight)" 550
run down; run down; check "down two" "$(level intel_backlight)" 450
light intel_backlight raw 1000 980; run up
check "up stops at the top" "$(level intel_backlight)" 1000
light intel_backlight raw 1000 30; run down
check "down stops short of dark" "$(level intel_backlight)" 10
light intel_backlight raw 7 1; run down
check "a short range steps by one and keeps one" "$(level intel_backlight)" 1

echo "-- which backlight"
fresh; light intel_backlight raw 1000 500; light acpi_video0 firmware 100 50
run up
check "firmware over raw, as the kernel's documentation asks" "$(level acpi_video0)/$(level intel_backlight)" 55/500

echo "-- refusals"
fresh
run up; check "no backlight" "$?" 1
light panel raw 0 0; run up; check "a range of nothing" "$?" 1
light panel raw 100 bright; run up; check "a level that is no number" "$?" 1
fresh; light intel_backlight raw 1000 500
run sideways; check "an unknown step" "$?" 2
check "... which leaves the level alone" "$(level intel_backlight)" 500

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
