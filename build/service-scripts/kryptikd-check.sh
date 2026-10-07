#!/bin/sh
# Log kryptikd's zone and kernel checks; no -e, so a machine without zones still boots to debug.
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
