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
run() { KRYPTIK_SYSFS="$T/sys" XDG_CONFIG_HOME="$T/config" "$B" "$@" 2>/dev/null; }
kept() { cat "$T/config/kryptik/brightness" 2>/dev/null; }

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

echo "-- kept for the next login"
fresh; rm -rf "$T/config"; light intel_backlight raw 1000 500
run up; check "a step keeps the level, the panel and its range" "$(kept)" "intel_backlight 550 1000"
light intel_backlight raw 1000 1000; run restore
check "restore puts the kept level back" "$(level intel_backlight)" 550
light intel_backlight raw 2000 2000; run restore
check "a panel whose range changed takes the same share" "$(level intel_backlight)" 1100
echo "intel_backlight 0550 01000" > "$T/config/kryptik/brightness"; light intel_backlight raw 1000 1000; run restore
check "a record with leading zeros reads as decimal" "$(level intel_backlight)" 550
light intel_backlight raw 2000 2000
echo "intel_backlight 0 1000" > "$T/config/kryptik/brightness"; run restore
check "never restored to dark" "$(level intel_backlight)" 20
echo "acpi_video0 50 100" > "$T/config/kryptik/brightness"; light intel_backlight raw 1000 700; run restore
check "another panel's level is left alone" "$(level intel_backlight)" 700
rm -rf "$T/config"; run restore; check "with nothing kept, restore does nothing and says nothing wrong" "$?/$(level intel_backlight)" 0/700
fresh; run restore; check "nor on a machine with no backlight" "$?" 0
light intel_backlight raw 1000 700
echo "-- not kept while a sleep seals the state partition"
mkdir -p "$T/sys/class/block/dm-1/dm"; echo kryptik-state > "$T/sys/class/block/dm-1/dm/name"
echo 1 > "$T/sys/class/block/dm-1/dm/suspended"; rm -rf "$T/config"
run up; check "the step is taken" "$(level intel_backlight)" 750
check "and not written where it would wait" "$(kept)" ""
echo 0 > "$T/sys/class/block/dm-1/dm/suspended"; run up
check "kept again once the partition is back" "$(kept)" "intel_backlight 800 1000"
rm -rf "$T/sys/class/block"

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
