#!/bin/bash
# The power source (docs/design/laptop.md). The processors' energy preference follows the
# charger, balance_power without one and balance_performance with one, where cpufreq offers one.
# On battery, plugged in to a charger too weak for the machine included, the charge is warned of
# at 10% and again at 5%, once each a discharge, and at 3% or under, seen twice 30 s apart, every
# zone is stopped, so each volume is closed, and the machine powers off before the battery dies
# under them. Each look is written to /run/kryptik-power/state, which the chrome's menu and its
# warning windows read: one decision.
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

# The machine's own batteries, not a mouse's (scope Device), that are there.
batteries() {
    local d
    while read -r d; do
        [ "$(cat "$d/type")" = Battery ] || continue
        [ "$(cat "$d/scope" 2>/dev/null)" = Device ] && continue
        [ "$(cat "$d/present" 2>/dev/null || echo 1)" = 1 ] && printf '%s\n' "$d"
    done < <(supplies)
}

# A battery's charge in percent: its capacity, or where it gives none that reads, the energy
# (uWh) or the charge (uAh) it holds against what it holds full; nothing from neither.
percent() {
    local c k now full
    c="$(cat "$1/capacity" 2>/dev/null)"
    if [[ "$c" =~ ^[0-9]+$ ]]; then printf '%s' "$c"; return; fi
    for k in energy charge; do
        now="$(cat "$1/${k}_now" 2>/dev/null)"; full="$(cat "$1/${k}_full" 2>/dev/null)"
        [[ "$now" =~ ^[0-9]+$ && "$full" =~ ^[0-9]*[1-9][0-9]*$ ]] || continue
        c=$(( 10#$now * 100 / 10#$full )); [ "$c" -le 100 ] || c=100
        printf '%s' "$c"; return
    done
}

# The charge of the fullest of them; nothing without one.
charge() {
    local d c best=""
    while read -r d; do
        c="$(percent "$d")"
        [ -n "$c" ] || continue
        if [ -z "$best" ] || [ "$c" -gt "$best" ]; then best="$c"; fi
    done < <(batteries)
    printf '%s' "$best"
}

# Whether the battery runs down. One that says it discharges does, plugged in or not: a charger
# that gives less than the machine uses leaves it running down all the same. One that says it
# charges, is full or holds its charge does not; and with no word from any, the adapter decides.
draining() {
    local d heard=""
    while read -r d; do
        case "$(cat "$d/status" 2>/dev/null)" in
            Discharging) return 0 ;;
            Charging|Full|"Not charging") heard=1 ;;
        esac
    done < <(batteries)
    [ -z "$heard" ] && ! on_mains
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

look() {   # sets SOURCE, CHARGER, CHARGE, LOW and WARNING, which the last look's state carries on
    local was w
    CHARGE="$(charge)"
    # A machine without a battery runs on mains, whatever its supplies say.
    if [ -z "$CHARGE" ] || on_mains; then CHARGER=yes; else CHARGER=no; fi
    if [ -n "$CHARGE" ] && draining; then SOURCE=battery; else SOURCE=mains; fi
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
    printf 'source=%s\ncharger=%s\ncharge=%s\ncritical=%s\nwarning=%s\n' "$SOURCE" "$CHARGER" "${CHARGE:-none}" \
        "$LOW" "$WARNING" > "$RUN/state.tmp" && mv -f "$RUN/state.tmp" "$RUN/state"
}

# By the charger, not by whether the battery runs down: a machine that outdraws its charger under
# load would otherwise swing between the two every look.
preference() { [ "$1" = no ] && echo balance_power || echo balance_performance; }

if [ "${1:-}" = --once ]; then
    mkdir -p "$RUN"
    look
    prefer "$(preference "$CHARGER")"
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
last="" plugged="" low=0
while :; do
    look
    write_state || echo "power: ${RUN}/state was not written" >&2
    if [ "$CHARGER" != "$plugged" ]; then
        prefer "$(preference "$CHARGER")"
        plugged="$CHARGER"
    fi
    if [ "$SOURCE $CHARGER" != "$last" ]; then
        weak=""
        [ "$SOURCE $CHARGER" = "battery yes" ] && weak=": the charger gives less than the machine uses"
        echo "power: on ${SOURCE}${CHARGE:+, the battery at ${CHARGE}%}${weak}"
        last="$SOURCE $CHARGER"
    fi
    # Twice running, so one odd reading does not end the session.
    if [ "$LOW" = yes ]; then low=$((low + 1)); else low=0; fi
    if [ "$low" -ge 2 ]; then
        echo "power: the battery is at ${CHARGE}%: stopping the zones and powering off before it runs out"
        shut_down
    fi
    sleep 30
done
