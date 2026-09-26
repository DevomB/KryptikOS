#!/bin/sh
# Clock floor (docs/design/time.md): a clock earlier than the image's build
# date (a dead RTC battery) is raised to it before the network is asked.
# Always exits 0, so the net zone that depends on this oneshot still starts.
log=/var/log/kryptik/time.log
mkdir -p /var/log/kryptik
out="$(/usr/bin/kryptikd time floor 2>&1)"; rc=$?
echo "=== time floor $(date -Iseconds 2>/dev/null) rc=${rc} === ${out}" >> "$log" 2>/dev/null
# On the console too, so a serial log shows it.
echo "time-floor: ${out}"
exit 0
