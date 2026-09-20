#!/bin/bash
# Feed every watchdog the kernel registered, for as long as this process is
# scheduled. That is the whole health check, on purpose: a feeder that also
# asked "is the desktop up, is the daemon answering" would reboot a machine
# over a crashed service, and a false reboot is worse than the hang it was
# meant to catch. What this does catch is what nothing else can: a userspace
# that has stopped running at all after boot-success judged the boot healthy,
# and, where there is a hardware timer (Intel's TCO, AMD's SP5100), a kernel
# that has stopped too. The software watchdog is always there as well, so a
# virtual machine and a board without a usable timer are still covered for
# the userspace case.
#
# The kernel is built with WATCHDOG_NOWAYOUT: once a device is opened, closing
# it does not stop the timer. So this script being killed and restarted is
# safe only because the supervisor restarts it inside the timeout, and at
# shutdown the machine has one timeout's worth of time to finish; a shutdown
# that hangs is reset, which is the right answer there too.
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
