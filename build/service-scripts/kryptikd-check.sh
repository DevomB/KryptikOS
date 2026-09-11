#!/bin/sh
# Deliberately not `-e`. A failure here must be reported, not abort the rest
# of the boot: a machine that cannot start zones should still come up far
# enough to be logged into and debugged.
log=/var/log/kryptik/kryptikd-check.log
mkdir -p /var/log/kryptik
{
    echo "=== kryptikd check $(date -Iseconds 2>/dev/null) ==="
    /usr/bin/kryptikd list --zones /etc/kryptik/zones \
        || echo "kryptikd-check: FAILED to read /etc/kryptik/zones"
    if /usr/bin/kryptikd check --zones /etc/kryptik/zones; then
        echo "kryptikd-check: kernel support OK"
    else
        echo "kryptikd-check: kernel support MISSING - zones will not start"
    fi
} >> "$log" 2>&1
# Echo the verdict to the console too, so a serial log shows it without
# anyone having to go looking in the filesystem.
tail -3 "$log"
echo "kryptikd-check: complete (full output in $log)"
