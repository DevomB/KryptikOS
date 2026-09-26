#!/bin/bash
# Feed every registered watchdog while this process gets scheduled, and check
# nothing else: rebooting over a crashed service is worse than a hang.
# WATCHDOG_NOWAYOUT: closing a device does not stop it, so the supervisor must
# restart this within the timeout, and a shutdown that hangs gets reset.
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
