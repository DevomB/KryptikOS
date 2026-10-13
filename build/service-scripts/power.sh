#!/bin/bash
# The power source (docs/design/laptop.md). The processors' energy preference follows it,
# balance_power on battery and balance_performance on mains, where cpufreq offers one; and on
# battery a charge at 3% or under, seen twice 30 s apart, stops every zone, so each volume is
# closed, and powers the machine off before the battery dies under them.
#
#   power.sh           the service
#   power.sh --once    one look, said as "source=mains|battery charge=N|none critical=yes|no",
#                      with the preference set as the service sets it; KRYPTIK_SYSFS names
#                      another /sys
set -u
SYS="${KRYPTIK_SYSFS:-/sys}"
CRITICAL=3

supplies() {
    local d
    for d in "$SYS"/class/power_supply/*; do
        [ -r "$d/type" ] && printf '%s\n' "$d"
    done
}

# A mains adapter or a USB charger online: any one powers the machine.
on_mains() {
    local d
    while read -r d; do
        case "$(cat "$d/type")" in
            Mains|USB) [ "$(cat "$d/online" 2>/dev/null)" = 1 ] && return 0 ;;
        esac
    done < <(supplies)
    return 1
}

# The charge of the fullest of the machine's own batteries, not a mouse's (scope Device);
# nothing without one.
charge() {
    local d c best=""
    while read -r d; do
        [ "$(cat "$d/type")" = Battery ] || continue
        [ "$(cat "$d/scope" 2>/dev/null)" = Device ] && continue
        [ "$(cat "$d/present" 2>/dev/null || echo 1)" = 1 ] || continue
        c="$(cat "$d/capacity" 2>/dev/null)"
        [[ "$c" =~ ^[0-9]+$ ]] || continue
        if [ -z "$best" ] || [ "$c" -gt "$best" ]; then best="$c"; fi
    done < <(supplies)
    printf '%s' "$best"
}

# Each policy that offers the preference takes it; one that does not keeps its own.
prefer() {
    local p
    for p in "$SYS"/devices/system/cpu/cpufreq/policy*; do
        [ -f "$p/energy_performance_preference" ] || continue
        grep -qw -- "$1" "$p/energy_performance_available_preferences" 2>/dev/null || continue
        echo "$1" > "$p/energy_performance_preference" 2>/dev/null \
            || echo "power: ${p##*/} kept its energy preference" >&2
    done
}

look() {   # sets SOURCE, CHARGE and LOW
    CHARGE="$(charge)"
    if [ -n "$CHARGE" ] && ! on_mains; then SOURCE=battery; else SOURCE=mains; fi
    LOW=no
    if [ "$SOURCE" = battery ] && [ "$CHARGE" -le "$CRITICAL" ]; then LOW=yes; fi
}

preference() { [ "$1" = battery ] && echo balance_power || echo balance_performance; }

if [ "${1:-}" = --once ]; then
    look
    prefer "$(preference "$SOURCE")"
    echo "source=${SOURCE} charge=${CHARGE:-none} critical=${LOW}"
    exit 0
fi

# Each running zone stopped as `kryptikd stop` does, its launcher closing its volume, then off.
shut_down() {
    local z
    for z in /run/kryptik/zones/*/; do
        [ -d "$z" ] || continue
        z="${z%/}"; z="${z##*/}"
        /usr/bin/kryptikd stop "$z" || echo "power: zone ${z} did not stop" >&2
    done
    exec /sbin/poweroff
}

last="" low=0
while :; do
    look
    if [ "$SOURCE" != "$last" ]; then
        prefer "$(preference "$SOURCE")"
        echo "power: on ${SOURCE}${CHARGE:+, the battery at ${CHARGE}%}"
        last="$SOURCE"
    fi
    # Twice running, so one odd reading does not end the session.
    if [ "$LOW" = yes ]; then low=$((low + 1)); else low=0; fi
    if [ "$low" -ge 2 ]; then
        echo "power: the battery is at ${CHARGE}%: stopping the zones and powering off before it runs out"
        shut_down
    fi
    sleep 30
done
