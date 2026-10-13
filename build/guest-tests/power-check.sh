#!/usr/bin/env bash
# Power suite, run as root in the installed guest by tools/image/power-test.sh. The kernel's
# test_power module stands in for a battery, a mains adapter and a USB charger. The host acts on:
#   GT CRITICAL    the battery is set to 2% with nothing plugged in: the power service stops the
#                  zones and powers off, and the host reads the state partition afterwards
#   power-check.sh USER    USER is the session's, whose chrome is run
# Verdicts: "GT PASS|FAIL name - detail".
set -u
cd / || exit 1
USER_NAME="${1:-tester}"
KD=/usr/bin/kryptikd
LOG=/var/log/kryptik/power-check
TP=/sys/module/test_power/parameters
mkdir -p "$LOG" /root/pt
PASS=0; FAIL=0
pass() { echo "GT PASS $1${2:+ - $2}"; PASS=$((PASS + 1)); }
fail() { echo "GT FAIL $1${2:+ - $2}"; FAIL=$((FAIL + 1)); }
wait_for() {   # wait_for SECONDS CMD...
    local n="$1"; shift
    while [[ "$n" -gt 0 ]]; do "$@" >/dev/null 2>&1 && return 0; n=$((n - 1)); sleep 1; done
    return 1
}
uncaught() { cat /run/uncaught-logs/@* /run/uncaught-logs/previous /run/uncaught-logs/current 2>/dev/null; }
said() { uncaught | grep -ac "power: $1"; }
more() { [[ "$(said "$1")" -gt "$2" ]]; }
# The power service's last look, which the chrome reads.
state() { sed -n "s/^$1=//p" /run/kryptik-power/state 2>/dev/null; }
looked() { [[ "$(state source)" == "$1" && "$(state charge)" == "$2" ]]; }   # looked SOURCE CHARGE
warned_at() { [[ "$(state warning)" == "$1" ]]; }
# The menu's Power line, as the session's user sees it.
power_line() { su -s /bin/sh "$USER_NAME" -c "printf 'q\\n' | /usr/bin/kryptik-chrome --menu" 2>&1 | grep '^Power:' | tail -1; }

# --- with no battery, as a VM has none ------------------------------------------------------
if pgrep -f /usr/libexec/kryptik/power.sh > /dev/null && wait_for 10 more "on mains" 0 \
   && [[ "$(state charge)" == none ]]; then
    pass "power-service" "running, and on mains with no battery: $(tr '\n' ' ' < /run/kryptik-power/state)"
else
    fail "power-service" "$(uncaught | grep -a 'power' | tail -3 | tr '\n' ' ')"
fi

# --- a battery ---------------------------------------------------------------------------
if modprobe test_power && wait_for 10 test -d /sys/class/power_supply/test_battery; then
    # test_usb counts as a charger: it stays off, so the mains adapter alone decides.
    echo off > "$TP/usb_online"; echo on > "$TP/ac_online"
    echo charging > "$TP/battery_status"; echo 50 > "$TP/battery_capacity"
else
    fail "test-power" "modprobe test_power: $(dmesg | tail -2 | tr '\n' ' ')"
fi
wait_for 45 looked mains 50
line="$(power_line)"
if [[ "$line" == "Power: on mains, the battery at 50%" ]]; then
    pass "chrome-power-mains" "$line"
else
    fail "chrome-power-mains" "${line:-no Power line}; state: $(tr '\n' ' ' < /run/kryptik-power/state)"
fi

batt="$(said 'on battery, the battery at 40%')"
echo off > "$TP/ac_online"; echo discharging > "$TP/battery_status"; echo 40 > "$TP/battery_capacity"
if wait_for 45 more 'on battery, the battery at 40%' "$batt"; then
    pass "power-on-battery" "the service saw the adapter go within its 30 s look"
else
    fail "power-on-battery" "$(uncaught | grep -a 'power:' | tail -2 | tr '\n' ' ')"
fi
line="$(power_line)"
if [[ "$line" == "Power: on battery, at 40%; at 3% the zones stop and the machine powers off" ]]; then
    pass "chrome-power-battery" "$line"
else
    fail "chrome-power-battery" "${line:-no Power line}"
fi

# --- the warnings: at 10% and at 5%, in a window of the chrome's, as its status loop opens one
echo 9 > "$TP/battery_capacity"
warned_10="no"; wait_for 45 warned_at 10 && warned_10="yes"
su -s /bin/sh "$USER_NAME" -c "/usr/bin/kryptik-chrome --battery" > "$LOG/battery.out" 2>&1 &
bp=$!
echo 4 > "$TP/battery_capacity"
warned_5="no"; wait_for 45 warned_at 5 && warned_5="yes"
told() { grep -qx "$1" "$LOG/battery.out"; }
wait_for 15 told 'at 4%'
mains="$(said 'on mains')"
echo on > "$TP/ac_online"; echo charging > "$TP/battery_status"
closed() { ! kill -0 "$bp" 2>/dev/null; }
if [[ "$warned_10/$warned_5" == yes/yes ]] && wait_for 50 closed && told 'at 9%' && told 'at 4%' \
   && told 'On mains now.' && warned_at ""; then
    pass "battery-warnings" "a warning at 10% and at 5%, a window that followed the charge and closed on mains: $(grep -v '^=' "$LOG/battery.out" | tr '\n' '|')"
else
    kill "$bp" 2>/dev/null
    fail "battery-warnings" "warned at 10%: ${warned_10}, at 5%: ${warned_5}; window: $(tr '\n' '|' < "$LOG/battery.out"); state: $(tr '\n' ' ' < /run/kryptik-power/state)"
fi
if wait_for 45 more 'on mains' "$mains"; then
    pass "power-on-mains-again" "and saw it come back"
else
    fail "power-on-mains-again" "$(uncaught | grep -a 'power:' | tail -2 | tr '\n' ' ')"
fi

# --- a critical battery --------------------------------------------------------------------
# An encrypted zone runs, so the host can find, on the state partition, that its volume was
# closed before the power went: the launcher's own words, kept in $LOG/work.out.
printf 'work-pass\n' > /root/pt/work.pass; chmod 600 /root/pt/work.pass
"$KD" volume init work --size 64M --passphrase-file /root/pt/work.pass > "$LOG/vol-work.out" 2>&1 \
    || fail "volume-init" "work: $(tail -2 "$LOG/vol-work.out" | tr '\n' ' ')"
setsid "$KD" run work --zones /usr/lib/kryptik/zones --rootfs /var/lib/kryptik/zones \
    --passphrase-file /root/pt/work.pass -- sh -c 'echo WORK-UP; sleep 600' > "$LOG/work.out" 2>&1 &
up() { grep -q WORK-UP "$LOG/work.out"; }
if wait_for 60 up; then
    pass "zone-running" "work runs on its encrypted volume"
else
    fail "zone-running" "$(tail -3 "$LOG/work.out" | tr '\n' ' ')"
fi
# What the service says from here goes to the state partition, which outlives the power-off.
(tail -n0 -F /run/uncaught-logs/current 2>/dev/null | grep --line-buffered -a 'power:' >> "$LOG/power.log") &

echo "GT SUMMARY passed=${PASS} failed=${FAIL}"
echo "GT END"
echo "GT CRITICAL"
echo off > "$TP/ac_online"; echo discharging > "$TP/battery_status"; echo 2 > "$TP/battery_capacity"
sleep 600
