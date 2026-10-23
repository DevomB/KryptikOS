#!/bin/bash
# Only feed the watchdogs: rebooting over a crashed service is worse than a hang.
# With NOWAYOUT a closed device keeps counting, so a hung shutdown resets the machine.
set -u
# AMD's TCO timer counts on through a sleep to idle (s2idle): its driver does not stop it for
# one, as Intel's does, and the ticks that would feed it stop. Fed, it would reset a machine
# that sleeps that way a minute into each sleep, so there it is left unopened, and stopped as
# its driver leaves it. In ACPI's own sleep states the firmware stops it.
sleeps_to_idle() { grep -q '\[s2idle\]' /sys/power/mem_sleep 2>/dev/null; }
fds=()
for dev in /dev/watchdog[0-9]*; do
    [ -c "$dev" ] || continue
    name="${dev##*/}"
    id="$(cat "/sys/class/watchdog/${name}/identity" 2>/dev/null || echo unknown)"
    if [ "$id" = "SP5100 TCO timer" ] && sleeps_to_idle; then
        echo "watchdog: not feeding ${dev} (${id}): it would count through this machine's sleep to idle"
        continue
    fi
    if exec {fd}>"$dev"; then
        fds+=("$fd")
        echo "watchdog: feeding ${dev} (${id}, timeout $(cat "/sys/class/watchdog/${name}/timeout" 2>/dev/null || echo '?')s)"
    else
        echo "watchdog: could not open ${dev}" >&2
    fi
done
if [ "${#fds[@]}" -eq 0 ]; then
    echo "watchdog: no watchdog device on this machine; nothing to feed"
    exec sleep infinity
fi
# The rounds wait in bash's own sleep, loaded once here: sleep(1) would be a program started
# every round, and while the state partition is suspended a program's loader can wait on /etc,
# whose upper layer is there, so the feeder would starve and reset the machine at the passphrase
# prompt.
enable -f /usr/lib/bash/sleep sleep || echo "watchdog: bash's sleep did not load; each round starts sleep(1)" >&2
while :; do
    for fd in "${fds[@]}"; do
        printf . >&"$fd" || echo "watchdog: a write to descriptor ${fd} failed" >&2
    done
    sleep 10
done
