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

# A look starts no program: each file is read by bash's own read and matched with [[ ]]. While
# the state partition waits for its passphrase, a program started waits on it too (sealed,
# below), and the state the chrome reads at the prompt would stop changing.

# A file's first line in REPLY; empty where it does not read.
get() { REPLY=""; read -r REPLY 2>/dev/null < "$1"; }

# The power supplies, in SUPPLIES.
supplies() {
    local d
    SUPPLIES=()
    for d in "$SYS"/class/power_supply/*; do
        [ -r "$d/type" ] && SUPPLIES+=("$d")
    done
}

# A mains adapter or a USB charger online: any one powers the machine.
on_mains() {
    local d
    supplies
    for d in "${SUPPLIES[@]}"; do
        get "$d/type"
        case "$REPLY" in
            Mains|USB) get "$d/online"; [ "$REPLY" = 1 ] && return 0 ;;
        esac
    done
    return 1
}

# The machine's own batteries, not a mouse's (scope Device), that are there, in BATTERIES.
batteries() {
    local d
    BATTERIES=()
    supplies
    for d in "${SUPPLIES[@]}"; do
        get "$d/type"; [ "$REPLY" = Battery ] || continue
        get "$d/scope"; [ "$REPLY" = Device ] && continue
        get "$d/present"; [ "${REPLY:-1}" = 1 ] && BATTERIES+=("$d")
    done
}

# A battery's charge in percent, in PCT: its capacity, or where it gives none that reads, the
# energy (uWh) or the charge (uAh) it holds against what it holds full; empty from neither.
percent() {
    local k now
    get "$1/capacity"; PCT="$REPLY"
    [[ "$PCT" =~ ^[0-9]+$ ]] && return
    PCT=""
    for k in energy charge; do
        get "$1/${k}_now"; now="$REPLY"; get "$1/${k}_full"
        [[ "$now" =~ ^[0-9]+$ && "$REPLY" =~ ^[0-9]*[1-9][0-9]*$ ]] || continue
        PCT=$(( 10#$now * 100 / 10#$REPLY )); [ "$PCT" -le 100 ] || PCT=100
        return
    done
}

# The charge of the fullest of them, in CHARGE; empty without one.
charge() {
    local d
    CHARGE=""
    batteries
    for d in "${BATTERIES[@]}"; do
        percent "$d"
        [ -n "$PCT" ] || continue
        if [ -z "$CHARGE" ] || [ "$PCT" -gt "$CHARGE" ]; then CHARGE="$PCT"; fi
    done
}

# Whether the battery runs down. One that says it discharges does, plugged in or not: a charger
# that gives less than the machine uses leaves it running down all the same. One that says it
# charges, is full or holds its charge does not; and with no word from any, the adapter decides.
draining() {
    local d heard=""
    batteries
    for d in "${BATTERIES[@]}"; do
        get "$d/status"
        case "$REPLY" in
            Discharging) return 0 ;;
            Charging|Full|"Not charging") heard=1 ;;
        esac
    done
    [ -z "$heard" ] && ! on_mains
}

# Each policy that offers the preference takes it; one that does not keeps its own.
prefer() {
    local p
    for p in "$SYS"/devices/system/cpu/cpufreq/policy*; do
        [ -f "$p/energy_performance_preference" ] || continue
        get "$p/energy_performance_available_preferences"
        [[ " $REPLY " == *" $1 "* ]] || continue
        echo "$1" > "$p/energy_performance_preference" 2>/dev/null \
            || echo "power: ${p##*/} kept its energy preference" >&2
    done
}

look() {   # sets SOURCE, CHARGER, CHARGE, LOW and WARNING, which the last look's state carries on
    local was="" l w
    charge
    # A machine without a battery runs on mains, whatever its supplies say.
    if [ -z "$CHARGE" ] || on_mains; then CHARGER=yes; else CHARGER=no; fi
    if [ -n "$CHARGE" ] && draining; then SOURCE=battery; else SOURCE=mains; fi
    LOW=no; WARNING=""
    [ "$SOURCE" = battery ] || return 0
    [ "$CHARGE" -le "$CRITICAL" ] && LOW=yes
    # The lowest threshold this discharge has reached, so each is warned of once; mains clears it.
    while read -r l; do
        [[ "$l" == warning=* ]] && was="${l#warning=}"
    done 2>/dev/null < "$RUN/state"
    [[ "$was" =~ ^[0-9]+$ ]] && WARNING="$was"
    for w in $WARNINGS; do
        if [ "$CHARGE" -le "$w" ] && { [ -z "$WARNING" ] || [ "$w" -lt "$WARNING" ]; }; then WARNING="$w"; fi
    done
}

# The state partition waits for its passphrase, read with builtins alone: a program started now
# can wait on it. Then kryptikd keeps the 3% rule (suspend.rs), as neither the zones' stop nor
# the shutdown's sync and unmounts could finish.
sealed() {
    local d n s
    for d in "$SYS"/block/dm-*/dm; do
        read -r n 2>/dev/null < "$d/name" && [ "$n" = kryptik-state ] || continue
        read -r s 2>/dev/null < "$d/suspended" && [ "$s" = 1 ] && return 0
    done
    return 1
}

# Renamed into place, as the chrome reads it whole; but mv is a program, so while the state
# partition waits it is written in place, in one write.
write_state() {
    local s
    printf -v s 'source=%s\ncharger=%s\ncharge=%s\ncritical=%s\nwarning=%s\n' "$SOURCE" "$CHARGER" \
        "${CHARGE:-none}" "$LOW" "$WARNING"
    if sealed; then printf '%s' "$s" > "$RUN/state"; return; fi
    printf '%s' "$s" > "$RUN/state.tmp" && mv -f "$RUN/state.tmp" "$RUN/state"
}

# By the charger, not by whether the battery runs down: a machine that outdraws its charger under
# load would otherwise swing between the two every look.
preference() { [ "$1" = no ] && echo balance_power || echo balance_performance; }

if [ "${1:-}" = --once ]; then
    [ -d "$RUN" ] || mkdir -p "$RUN"
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
# The rounds wait in bash's own sleep, loaded once here, as watchdog.sh's do.
enable -f /usr/lib/bash/sleep sleep || echo "power: bash's sleep did not load; each round starts sleep(1)" >&2
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
    if [ "$low" -ge 2 ] && ! sealed; then
        echo "power: the battery is at ${CHARGE}%: stopping the zones and powering off before it runs out"
        shut_down
    fi
    sleep 30
done
