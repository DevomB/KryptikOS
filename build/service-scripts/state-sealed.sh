#!/bin/sh
# Exit 0 when a sleep has sealed the state partition, its mapping suspended, which any read or
# write there would wait on until the passphrase: seen from sysfs alone, which never waits.
#   KRYPTIK_SYSFS names another /sys, for the tests
sys="${KRYPTIK_SYSFS:-/sys}"
for m in "$sys"/class/block/dm-*; do
    n="" s=""
    read -r n 2> /dev/null < "$m/dm/name"
    [ "$n" = kryptik-state ] || continue
    read -r s 2> /dev/null < "$m/dm/suspended"
    [ "$s" = 1 ]
    exit
done
exit 1
