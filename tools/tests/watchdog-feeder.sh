#!/usr/bin/env bash
# build/service-scripts/watchdog.sh against stand-in timers: on a machine that sleeps to idle it
# leaves AMD's TCO timer and the software watchdog unfed, as both would count through a sleep,
# and feeds the rest; elsewhere it feeds every one. The script runs with its paths under a
# scratch directory, files for its devices, and one round of its loop. Offline.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/build/service-scripts/watchdog.sh"
PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

mkdir -p "$T/dev"
timer() {   # timer N IDENTITY: /dev/watchdogN and its sysfs entry
    : > "$T/dev/watchdog$1"
    mkdir -p "$T/sys/class/watchdog/watchdog$1"
    echo "$2" > "$T/sys/class/watchdog/watchdog$1/identity"
    echo 60 > "$T/sys/class/watchdog/watchdog$1/timeout"
}
timer 0 "Software Watchdog"
timer 1 "SP5100 TCO timer"
timer 2 "iTCO_wdt"
sed -e "s|/dev/watchdog|$T/dev/watchdog|g" \
    -e "s|/sys/class/watchdog/|$T/sys/class/watchdog/|g" \
    -e "s|/sys/power/mem_sleep|$T/mem_sleep|g" \
    -e 's|\[ -c "\$dev" \]|[ -e "$dev" ]|' \
    -e 's|^while :; do$|for _ in 1; do|' \
    -e 's|^    sleep 10$|    :|' \
    -e 's|exec sleep infinity|exit 0|' \
    "$SCRIPT" > "$T/watchdog.sh"
grep -q 'for _ in 1; do' "$T/watchdog.sh" && grep -q '\[ -e "\$dev" \]' "$T/watchdog.sh" \
    || { echo "watchdog.sh changed shape: its loop or its device test was not found"; exit 1; }
feeds() {   # feeds MEM_SLEEP: what the feeder says
    echo "$1" > "$T/mem_sleep"
    timeout 20 bash "$T/watchdog.sh" 2>&1
}

said="$(feeds '[s2idle] deep')"
grep -q "not feeding $T/dev/watchdog0 (Software Watchdog)" <<<"$said" \
    && green "sleeping to idle, the software watchdog is not fed" || red "s2idle, softdog: $(tr '\n' '|' <<<"$said")"
grep -q "not feeding $T/dev/watchdog1 (SP5100 TCO timer)" <<<"$said" \
    && green "nor AMD's TCO timer" || red "s2idle, SP5100: $(tr '\n' '|' <<<"$said")"
grep -q "feeding $T/dev/watchdog2 (iTCO_wdt" <<<"$said" && ! grep -q "not feeding $T/dev/watchdog2" <<<"$said" \
    && green "and Intel's, which stops across that sleep, is" || red "s2idle, iTCO: $(tr '\n' '|' <<<"$said")"
said="$(feeds 's2idle [deep]')"
n="$(grep -c "^watchdog: feeding $T/dev/watchdog" <<<"$said")"
[[ "$n" -eq 3 ]] && ! grep -q 'not feeding' <<<"$said" \
    && green "sleeping deep, where the firmware stops them, all three are fed" || red "deep: $(tr '\n' '|' <<<"$said")"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
