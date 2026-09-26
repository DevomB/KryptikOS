#!/bin/sh
# Log whether kryptikd can read the zones and the kernel supports them. Not -e:
# a machine that cannot start zones must still boot far enough to debug.
log=/var/log/kryptik/kryptikd-check.log
mkdir -p /var/log/kryptik
{
    echo "=== kryptikd check $(date -Iseconds 2>/dev/null) ==="
    /usr/bin/kryptikd list --zones /usr/lib/kryptik/zones \
        || echo "kryptikd-check: FAILED to read /usr/lib/kryptik/zones"
    if /usr/bin/kryptikd check --zones /usr/lib/kryptik/zones; then
        echo "kryptikd-check: kernel support OK"
    else
        echo "kryptikd-check: kernel support MISSING - zones will not start"
    fi
} >> "$log" 2>&1
# The verdict on the console too, for the serial log.
tail -3 "$log"
echo "kryptikd-check: complete (full output in $log)"
