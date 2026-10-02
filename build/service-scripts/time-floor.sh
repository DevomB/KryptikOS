#!/bin/sh
# Clock floor (docs/design/time.md): a clock behind the build date (a dead RTC) is raised to it.
log=/var/log/kryptik/time.log
mkdir -p /var/log/kryptik
out="$(/usr/bin/kryptikd time floor 2>&1)"; rc=$?
echo "=== time floor $(date -Iseconds 2>/dev/null) rc=${rc} === ${out}" >> "$log" 2>/dev/null
# On the console too, so a serial log shows it.
echo "time-floor: ${out}"
# Always 0: the net zone depends on this oneshot.
exit 0
