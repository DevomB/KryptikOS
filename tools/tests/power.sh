#!/usr/bin/env bash
# build/service-scripts/power.sh --once against stand-in /sys trees: the power source it reads,
# the charge, when the charge is critical, and the energy preference it sets.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
P="$ROOT/build/service-scripts/power.sh"
PASS=0; FAIL=0
check() {
    if [[ "$2" == "$3" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1))
    else printf '  FAIL  %s (got %q, want %q)\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fresh() { rm -rf "$T/sys"; mkdir -p "$T/sys/class/power_supply"; }
supply() {   # supply NAME TYPE [ATTR=VALUE...]
    local d="$T/sys/class/power_supply/$1" kv
    mkdir -p "$d"; echo "$2" > "$d/type"; shift 2
    for kv in "$@"; do echo "${kv#*=}" > "$d/${kv%%=*}"; done
}
policy() {   # policy N PREFERENCES: a cpufreq policy offering them, at its default
    local d="$T/sys/devices/system/cpu/cpufreq/policy$1"
    mkdir -p "$d"; echo "$2" > "$d/energy_performance_available_preferences"
    echo default > "$d/energy_performance_preference"
}
pref() { cat "$T/sys/devices/system/cpu/cpufreq/policy$1/energy_performance_preference"; }
once() { KRYPTIK_SYSFS="$T/sys" "$P" --once; }
ALL="default performance balance_performance balance_power power"

echo "-- the source"
fresh
check "no supply at all, as in a VM" "$(once)" "source=mains charge=none critical=no"
supply AC Mains online=1
supply BAT0 Battery capacity=50 status=Charging present=1
check "a laptop on mains" "$(once)" "source=mains charge=50 critical=no"
echo 0 > "$T/sys/class/power_supply/AC/online"
check "the same laptop unplugged" "$(once)" "source=battery charge=50 critical=no"
supply ucsi USB online=1
check "a USB charger powers it" "$(once)" "source=mains charge=50 critical=no"

echo "-- the charge"
fresh
supply AC Mains online=0
supply BAT0 Battery capacity=3 status=Discharging
check "3% on battery is critical" "$(once)" "source=battery charge=3 critical=yes"
supply BAT1 Battery capacity=60 status=Discharging
check "but not while a second battery is full enough" "$(once)" "source=battery charge=60 critical=no"
fresh
supply hidpp_battery_0 Battery capacity=1 scope=Device
check "a mouse's empty battery is not the machine's" "$(once)" "source=mains charge=none critical=no"
fresh
supply BAT0 Battery capacity=2 present=0
supply BAT1 Battery capacity=fail
check "an absent battery and a bad reading count for nothing" "$(once)" "source=mains charge=none critical=no"
fresh
supply AC Mains online=1
supply BAT0 Battery capacity=2 status=Charging
check "2% charging on mains is not critical" "$(once)" "source=mains charge=2 critical=no"

echo "-- the energy preference"
fresh
supply AC Mains online=1
supply BAT0 Battery capacity=80
policy 0 "$ALL"; policy 1 "default performance"
once > /dev/null
check "on mains, balance_performance" "$(pref 0)" balance_performance
check "a policy without it keeps its own" "$(pref 1)" default
echo 0 > "$T/sys/class/power_supply/AC/online"
once > /dev/null
check "on battery, balance_power" "$(pref 0)" balance_power

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
