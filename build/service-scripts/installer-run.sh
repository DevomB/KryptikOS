#!/bin/sh
# Run the installer, but only when the kernel command line asks for it.
#
# Armed the same way boot-smoke is: an ordinary boot must not partition a disk
# because one happens to be attached. The device is named explicitly on the
# command line, so "which disk" is never inferred.
set -u

say() { echo "KRYPTIK_INSTALL: $*"; }

target=""
for word in $(cat /proc/cmdline 2>/dev/null); do
    case "$word" in
        kryptik.install=*) target="${word#kryptik.install=}" ;;
    esac
done

if [ -z "$target" ]; then
    echo "installer: not requested on the kernel command line; nothing to do"
    exit 0
fi

echo
say "BEGIN target=${target}"

if [ ! -x /usr/sbin/kryptik-install ]; then
    say "FAILED no /usr/sbin/kryptik-install in this image"
    # Reported as a failing rc on purpose, even though this oneshot exits 0.
    # Exiting non-zero would fail the s6-rc bundle and cut the boot short, and
    # the transcript IS the test result - losing it would tell us less than this
    # line does. The host assertions key on rc=, not on the service exit status.
    say "rc=127"
    say "END"
    exit 0
fi

# --yes because there is nobody to type ERASE at a serial console in a test.
# The device still had to be named on the kernel command line to get here.
# Capture the status of the INSTALLER, not of the thing prefixing its output.
#
# This was `kryptik-install ... | sed ...` followed by `rc=$?`, which reads
# SED's status. sed succeeds at prefixing whatever it is handed, including
# nothing, so rc was 0 on every run. The first real failure - "sgdisk: command
# not found" - was duly reported as rc=0, and the only reason anyone noticed is
# that the separate result checks failed afterwards.
#
# /bin/sh here has no pipefail to lean on, so the output goes to a file and the
# pipeline is removed entirely.
logf=/run/kryptik-install.log
/usr/sbin/kryptik-install --target "$target" --yes > "$logf" 2>&1
rc=$?
sed 's/^/KRYPTIK_INSTALL: /' "$logf"
say "rc=${rc}"

if [ "$rc" -eq 0 ]; then
    # Say what is actually on the disk now, from outside the installer, so the
    # claim does not rest on the installer's own report.
    # sfdisk, because sgdisk is not in this image - which is why the previous
    # version of this line reported "0 partitions named kryptik-root" about a
    # disk it had never managed to look at.
    case "$target" in
        *[0-9]) part="${target}p2" ;;
        *)      part="${target}2"  ;;
    esac
    say "verify: partition 2 label=$(sfdisk --part-label "$target" 2 2>/dev/null || echo none)"
    say "verify: partition 2 node=${part} $([ -b "$part" ] && echo present || echo ABSENT)"
    say "verify: uuid=$(blkid -s UUID -o value "$part" 2>/dev/null || echo none)"
    say "verify: type=$(blkid -s TYPE -o value "$part" 2>/dev/null || echo none)"
    mkdir -p /run/verify
    if mount -o ro "$part" /run/verify 2>/dev/null; then
        say "verify: os_id=$(. /run/verify/etc/os-release 2>/dev/null && echo "${ID:-none}")"
        say "verify: has_init=$([ -x /run/verify/sbin/init ] && echo yes || echo no)"
        say "verify: has_kernel=$(ls /run/verify/boot/kryptik-* 2>/dev/null | wc -l)"
        say "verify: has_installjson=$([ -r /run/verify/etc/kryptik-install.json ] && echo yes || echo no)"
        say "verify: fstab_root=$(awk '$2=="/"{print $1; exit}' /run/verify/etc/fstab 2>/dev/null)"
        umount /run/verify
    else
        say "verify: could not mount ${part} read-only"
    fi
fi

say "END"
