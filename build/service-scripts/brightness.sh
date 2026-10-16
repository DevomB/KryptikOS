#!/bin/bash
# The screen's backlight a step up or down (docs/design/laptop.md), as dwl's brightness keys run
# it for the session's user, whose group udev lets write it (70-kryptik-backlight.rules).
#
#   brightness.sh up|down     a twentieth of the range, and never dark; the level is kept
#   brightness.sh restore     the level kept by the last step, as the session starts
#   KRYPTIK_SYSFS names another /sys, for the tests
set -u
SYS="${KRYPTIK_SYSFS:-/sys}"
# The level kept for the next login, beside the lock's minutes: "NAME LEVEL MAX", so a panel
# that changed its range takes the same share of it, and another panel none.
KEPT="${XDG_CONFIG_HOME:-${HOME:-/nonexistent}/.config}/kryptik/brightness"

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

# Whether the state partition is sealed by a sleep: the kept level, in the home directory there,
# would wait on it until the passphrase, so a step under that lock is not kept.
sealed() {
    local m n s
    for m in "$SYS"/class/block/dm-*; do
        n="" s=""
        read -r n 2>/dev/null < "$m/dm/name"
        [ "$n" = kryptik-state ] || continue
        read -r s 2>/dev/null < "$m/dm/suspended"
        [ "$s" = 1 ]
        return
    done
    return 1
}

case "${1:-}" in
    up|down|restore) ;;
    *) echo "usage: brightness.sh up|down|restore" >&2; exit 2 ;;
esac
# A machine with no backlight has nothing to restore, and says so only for a step.
d="$(device)" || { [ "$1" = restore ] && exit 0; echo "brightness: no backlight" >&2; exit 1; }
max="$(cat "$d/max_brightness" 2>/dev/null)"; now="$(cat "$d/brightness" 2>/dev/null)"
if ! [[ "$max" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]] || [ "$max" -eq 0 ]; then
    echo "brightness: ${d##*/} gives no level to step from" >&2
    exit 1
fi
# Never dark: on some panels 0 turns the light off, and nothing on screen then shows the way back.
floor=$(( max / 100 )); [ "$floor" -gt 0 ] || floor=1
if [ "$1" = restore ]; then
    # Nothing kept, or kept for another panel: the level the firmware chose stays.
    name="" level="" was=""
    read -r name level was 2>/dev/null < "$KEPT" || :
    [[ "$name" == "${d##*/}" && "$level" =~ ^[0-9]+$ && "$was" =~ ^[1-9][0-9]*$ ]] || exit 0
    new=$(( level * max / was ))
else
    step=$(( max / 20 )); [ "$step" -gt 0 ] || step=1
    if [ "$1" = up ]; then new=$(( now + step )); else new=$(( now - step )); fi
fi
[ "$new" -gt "$max" ] && new="$max"
[ "$new" -lt "$floor" ] && new="$floor"
echo "$new" > "$d/brightness"
[ "$1" = restore ] && exit 0
sealed && exit 0
mkdir -p "${KEPT%/*}" 2>/dev/null && printf '%s %s %s\n' "${d##*/}" "$new" "$max" > "$KEPT.new" 2>/dev/null \
    && mv -f "$KEPT.new" "$KEPT" 2>/dev/null
exit 0
