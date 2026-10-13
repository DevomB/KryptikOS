#!/bin/bash
# The screen's backlight a step up or down (docs/design/laptop.md), as dwl's brightness keys run
# it for the session's user, whose group udev lets write it (70-kryptik-backlight.rules).
#
#   brightness.sh up|down     a twentieth of the range, and never dark
#   KRYPTIK_SYSFS names another /sys, for the tests
set -u
SYS="${KRYPTIK_SYSFS:-/sys}"

# The kernel's order of preference when a panel has several (sysfs-class-backlight).
device() {
    local t d
    for t in firmware platform raw; do
        for d in "$SYS"/class/backlight/*; do
            [ "$(cat "$d/type" 2>/dev/null)" = "$t" ] && { echo "$d"; return 0; }
        done
    done
    return 1
}

case "${1:-}" in
    up|down) ;;
    *) echo "usage: brightness.sh up|down" >&2; exit 2 ;;
esac
d="$(device)" || { echo "brightness: no backlight" >&2; exit 1; }
max="$(cat "$d/max_brightness" 2>/dev/null)"; now="$(cat "$d/brightness" 2>/dev/null)"
if ! [[ "$max" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]] || [ "$max" -eq 0 ]; then
    echo "brightness: ${d##*/} gives no level to step from" >&2
    exit 1
fi
step=$(( max / 20 )); [ "$step" -gt 0 ] || step=1
if [ "$1" = up ]; then new=$(( now + step )); else new=$(( now - step )); fi
# Never dark: on some panels 0 turns the light off, and nothing on screen then shows the way back.
floor=$(( max / 100 )); [ "$floor" -gt 0 ] || floor=1
[ "$new" -gt "$max" ] && new="$max"
[ "$new" -lt "$floor" ] && new="$floor"
echo "$new" > "$d/brightness"
