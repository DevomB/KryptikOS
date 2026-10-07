#!/bin/bash
# Only feed the watchdogs: rebooting over a crashed service is worse than a hang.
# With NOWAYOUT a closed device keeps counting, so a hung shutdown resets the machine.
set -u
fds=()
for dev in /dev/watchdog[0-9]*; do
    [ -c "$dev" ] || continue
    name="${dev##*/}"
    if exec {fd}>"$dev"; then
        fds+=("$fd")
        echo "watchdog: feeding ${dev} ($(cat "/sys/class/watchdog/${name}/identity" 2>/dev/null || echo unknown), timeout $(cat "/sys/class/watchdog/${name}/timeout" 2>/dev/null || echo '?')s)"
    else
        echo "watchdog: could not open ${dev}" >&2
    fi
done
if [ "${#fds[@]}" -eq 0 ]; then
    echo "watchdog: no watchdog device on this machine; nothing to feed"
    exec sleep infinity
fi
while :; do
    for fd in "${fds[@]}"; do
        printf . >&"$fd" || echo "watchdog: a write to descriptor ${fd} failed" >&2
    done
    sleep 10
done
