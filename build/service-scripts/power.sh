#!/bin/bash
# The power source (docs/design/laptop.md). The processors' energy preference follows it,
# balance_power on battery and balance_performance on mains, where cpufreq offers one. On
# battery the charge is warned of at 10% and again at 5%, once each a discharge, and at 3% or
# under, seen twice 30 s apart, every zone is stopped, so each volume is closed, and the machine
# powers off before the battery dies under them. Each look is written to
# /run/kryptik-power/state, which the chrome's menu and its warning windows read: one decision.
#
#   power.sh           the service
#   power.sh --once    one look, written to the state file and said as one line; KRYPTIK_SYSFS
#                      names another /sys, KRYPTIK_POWER_RUN another /run/kryptik-power
set -u
SYS="${KRYPTIK_SYSFS:-/sys}"
RUN="${KRYPTIK_POWER_RUN:-/run/kryptik-power}"
CRITICAL=3
WARNINGS="10 5"

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

look() {   # sets SOURCE, CHARGE, LOW and WARNING, which the last look's state carries on
    local was w
    CHARGE="$(charge)"
    if [ -n "$CHARGE" ] && ! on_mains; then SOURCE=battery; else SOURCE=mains; fi
    LOW=no; WARNING=""
    [ "$SOURCE" = battery ] || return 0
    [ "$CHARGE" -le "$CRITICAL" ] && LOW=yes
    # The lowest threshold this discharge has reached, so each is warned of once; mains clears it.
    was="$(sed -n 's/^warning=//p' "$RUN/state" 2>/dev/null)"
    [[ "$was" =~ ^[0-9]+$ ]] && WARNING="$was"
    for w in $WARNINGS; do
        if [ "$CHARGE" -le "$w" ] && { [ -z "$WARNING" ] || [ "$w" -lt "$WARNING" ]; }; then WARNING="$w"; fi
    done
}

write_state() {
    printf 'source=%s\ncharge=%s\ncritical=%s\nwarning=%s\n' "$SOURCE" "${CHARGE:-none}" "$LOW" "$WARNING" \
        > "$RUN/state.tmp" && mv -f "$RUN/state.tmp" "$RUN/state"
}

preference() { [ "$1" = battery ] && echo balance_power || echo balance_performance; }

if [ "${1:-}" = --once ]; then
    mkdir -p "$RUN"
    look
    prefer "$(preference "$SOURCE")"
    write_state
    echo "source=${SOURCE} charge=${CHARGE:-none} critical=${LOW} warning=${WARNING:-none}"
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

install -d -m 0755 "$RUN" || exit 1
rm -f "$RUN/state"
last="" low=0
while :; do
    look
    write_state || echo "power: ${RUN}/state was not written" >&2
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
