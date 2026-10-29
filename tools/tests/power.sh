#!/usr/bin/env bash
# build/service-scripts/power.sh --once against stand-in /sys trees: the power source it reads,
# the charge, when it warns and when the charge is critical, the state it writes for the chrome,
# and the energy preference it sets.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
P="$ROOT/build/service-scripts/power.sh"
PASS=0; FAIL=0
check() {
    if [[ "$2" == "$3" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1))
    else printf '  FAIL  %s (got %q, want %q)\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fresh() { rm -rf "$T/sys" "$T/run"; mkdir -p "$T/sys/class/power_supply"; }
supply() {   # supply NAME TYPE [ATTR=VALUE...]
    local d="$T/sys/class/power_supply/$1" kv
    mkdir -p "$d"; echo "$2" > "$d/type"; shift 2
    for kv in "$@"; do echo "${kv#*=}" > "$d/${kv%%=*}"; done
}
set_attr() { echo "$3" > "$T/sys/class/power_supply/$1/$2"; }   # set_attr NAME ATTR VALUE
policy() {   # policy N PREFERENCES: a cpufreq policy offering them, at its default
    local d="$T/sys/devices/system/cpu/cpufreq/policy$1"
    mkdir -p "$d"; echo "$2" > "$d/energy_performance_available_preferences"
    echo default > "$d/energy_performance_preference"
}
pref() { cat "$T/sys/devices/system/cpu/cpufreq/policy$1/energy_performance_preference"; }
once() { KRYPTIK_SYSFS="$T/sys" KRYPTIK_POWER_RUN="$T/run" "$P" --once; }
charger() { sed -n 's/^charger=//p' "$T/run/state"; }
ALL="default performance balance_performance balance_power power"

echo "-- the source"
fresh
check "no supply at all, as in a VM" "$(once)" "source=mains charge=none critical=no warning=none"
supply AC Mains online=1
supply BAT0 Battery capacity=50 status=Charging present=1
check "a laptop on mains" "$(once)" "source=mains charge=50 critical=no warning=none"
set_attr AC online 0; set_attr BAT0 status Discharging
check "the same laptop unplugged" "$(once)" "source=battery charge=50 critical=no warning=none"
check "with no charger" "$(charger)" no
supply ucsi USB online=1; set_attr BAT0 status Charging
check "a USB charger powers it" "$(once)" "source=mains charge=50 critical=no warning=none"
fresh
supply AC Mains online=1
supply BAT0 Battery capacity=9 status=Discharging
check "plugged in to a charger that gives less than the machine uses, it runs down" "$(once)" "source=battery charge=9 critical=no warning=10"
check "with a charger all the same" "$(charger)" yes
fresh
supply BAT0 Battery capacity=40 status=Charging
check "a battery that charges with no adapter seen is on mains" "$(once)" "source=mains charge=40 critical=no warning=none"
set_attr BAT0 status 'Not charging'
check "and one that holds its charge" "$(once)" "source=mains charge=40 critical=no warning=none"
set_attr BAT0 status Unknown
check "with no word from the battery, the adapter decides" "$(once)" "source=battery charge=40 critical=no warning=none"

echo "-- the charge"
fresh
supply AC Mains online=0
supply BAT0 Battery capacity=3 status=Discharging
check "3% on battery is critical" "$(once)" "source=battery charge=3 critical=yes warning=5"
supply BAT1 Battery capacity=60 status=Discharging
check "but not while a second battery is full enough" "$(once)" "source=battery charge=60 critical=no warning=5"
fresh
supply hidpp_battery_0 Battery capacity=1 scope=Device
check "a mouse's empty battery is not the machine's" "$(once)" "source=mains charge=none critical=no warning=none"
fresh
supply BAT0 Battery capacity=2 present=0
supply BAT1 Battery capacity=fail
check "an absent battery and a bad reading count for nothing" "$(once)" "source=mains charge=none critical=no warning=none"
fresh
supply AC Mains online=1
supply BAT0 Battery capacity=2 status=Charging
check "2% charging on mains is not critical" "$(once)" "source=mains charge=2 critical=no warning=none"
fresh
supply AC Mains online=0
supply BAT0 Battery capacity=fail energy_now=5130000 energy_full=57000000 status=Discharging
check "with no capacity that reads, the energy against full" "$(once)" "source=battery charge=9 critical=no warning=10"
fresh
supply AC Mains online=0
supply BAT0 Battery charge_now=120000 charge_full=4000000 status=Discharging
check "or the charge against full" "$(once)" "source=battery charge=3 critical=yes warning=5"
supply BAT1 Battery charge_now=1 charge_full=0 status=Discharging
check "a battery that says it holds nothing when full counts for nothing" "$(once)" "source=battery charge=3 critical=yes warning=5"

echo "-- the warnings, once each a discharge"
fresh
supply AC Mains online=0
supply BAT0 Battery capacity=12
check "12% warns of nothing" "$(once)" "source=battery charge=12 critical=no warning=none"
set_attr BAT0 capacity 9; once > /dev/null
check "9% warns at 10%" "$(sed -n 's/^warning=//p' "$T/run/state")" 10
set_attr BAT0 capacity 8
check "8% stays at that warning" "$(once)" "source=battery charge=8 critical=no warning=10"
set_attr BAT0 capacity 4
check "4% warns at 5%" "$(once)" "source=battery charge=4 critical=no warning=5"
set_attr BAT0 capacity 7
check "a charge that rises again does not take a warning back" "$(once)" "source=battery charge=7 critical=no warning=5"
set_attr AC online 1
check "mains clears it" "$(once)" "source=mains charge=7 critical=no warning=none"
set_attr AC online 0
check "and the next discharge warns again" "$(once)" "source=battery charge=7 critical=no warning=10"
check "the state the chrome reads" "$(tr '\n' ' ' < "$T/run/state")" "source=battery charger=no charge=7 critical=no warning=10 "
echo "warning=\$(reboot)" > "$T/run/state"
check "a state that is not the service's own is read as no warning" "$(once)" "source=battery charge=7 critical=no warning=10"

echo "-- the energy preference"
fresh
supply AC Mains online=1
supply BAT0 Battery capacity=80
policy 0 "$ALL"; policy 1 "default performance"
once > /dev/null
check "on mains, balance_performance" "$(pref 0)" balance_performance
check "a policy without it keeps its own" "$(pref 1)" default
set_attr AC online 0
once > /dev/null
check "on battery, balance_power" "$(pref 0)" balance_power
set_attr AC online 1; echo Discharging > "$T/sys/class/power_supply/BAT0/status"
once > /dev/null
check "plugged in, it follows the charger even while the battery runs down" "$(pref 0)" balance_performance

echo "-- the state partition waiting for its passphrase"
# sealed() alone, from the service: it decides whether the 3% power-off is the service's or kryptikd's.
eval "$(sed -n '/^sealed() {/,/^}/p' "$P")"
dm() {   # dm N NAME SUSPENDED: a device-mapper device in the stand-in /sys/block
    mkdir -p "$T/sys/block/dm-$1/dm"
    echo "$2" > "$T/sys/block/dm-$1/dm/name"; echo "$3" > "$T/sys/block/dm-$1/dm/suspended"
}
is_sealed() { if SYS="$T/sys" sealed; then echo yes; else echo no; fi; }
fresh
check "no device-mapper device" "$(is_sealed)" no
dm 0 kryptik-zone-work 1; dm 1 kryptik-state 0
check "the state partition up, a zone's volume waiting" "$(is_sealed)" no
dm 1 kryptik-state 1
check "the state partition waiting for its passphrase" "$(is_sealed)" yes
if grep -qF '[ "$low" -ge 2 ] && ! sealed; then' "$P"; then r=yes; else r=no; fi
check "then the 3% power-off is kryptikd's, not the service's" "$r" yes

# A program started then would wait on the partition, so a look must start none: with PATH
# leading nowhere, any it started would fail and say so.
fresh
supply AC Mains online=0
supply BAT0 Battery capacity=4 status=Discharging
policy 0 "$ALL"
dm 1 kryptik-state 1
mkdir -p "$T/run"
said="$(KRYPTIK_SYSFS="$T/sys" KRYPTIK_POWER_RUN="$T/run" PATH=/nonexistent "$BASH" "$P" --once 2>&1)"
check "a look while it waits starts no program" "$said" "source=battery charge=4 critical=no warning=5"
check "its state, written in place" "$(tr '\n' ' ' < "$T/run/state")" "source=battery charger=no charge=4 critical=no warning=5 "
check "and the preference" "$(pref 0)" balance_power
check "the rounds wait in bash's own sleep" "$(grep -c '^enable -f /usr/lib/bash/sleep sleep ' "$P")" 1

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
