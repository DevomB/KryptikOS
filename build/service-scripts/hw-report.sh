#!/bin/sh
# A hardware report onto the USB medium, for a stick whose first partition
# carries a kryptik-report directory: whoever prepared it asked, and a machine
# with no working screen or keyboard can still be reported on. No other stick
# is written, nor a CD, nor an installed system. Never fails: the boot goes on.
set -u
. /usr/libexec/kryptik/devices.sh
. /usr/libexec/kryptik/ask.sh

grep -qs '^media=usb$' /run/kryptik/boot-identity || exit 0
esp="$(kryptik_part kryptik-esp)" || exit 0
[ -b "$esp" ] || exit 0

look=/run/kryptik/hwreport-look
mkdir -p "$look"
mount -o ro,nosuid,nodev,noexec "$esp" "$look" 2>/dev/null || exit 0
asked=no
[ -d "$look/kryptik-report" ] && asked=yes
umount "$look"
rmdir "$look" 2>/dev/null
[ "$asked" = yes ] || exit 0

echo "hw-report: this stick asks for a hardware report: one is written once the drivers have settled"
# Drivers load at coldplug and ask for their firmware as they start; the ten
# seconds are for the slow ones, so the log the report quotes has their words.
/usr/sbin/udevadm settle --timeout=30 || true
sleep 10
if out="$(/usr/sbin/kryptik-hwreport --save 2>&1)"; then
    tell "" "$out" "The report is on the stick: switch the machine off, or pull the stick." ""
else
    tell "" "$out" "No hardware report was written." ""
fi
exit 0
