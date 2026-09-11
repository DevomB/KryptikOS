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
    say "END"
    exit 0
fi

# --yes because there is nobody to type ERASE at a serial console in a test.
# The device still had to be named on the kernel command line to get here.
/usr/sbin/kryptik-install --target "$target" --yes 2>&1 | sed 's/^/KRYPTIK_INSTALL: /'
rc=$?
say "rc=${rc}"

if [ "$rc" -eq 0 ]; then
    # Say what is actually on the disk now, from outside the installer, so the
    # claim does not rest on the installer's own report.
    say "verify: $(sgdisk --print "$target" 2>/dev/null | grep -c 'kryptik-root') partition(s) named kryptik-root"
    part="${target}2"
    [ -b "$part" ] || part="${target}p2"
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
