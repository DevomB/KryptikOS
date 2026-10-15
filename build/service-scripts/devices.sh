#!/bin/sh
# Partitions by GPT label on the root's own disk only: another disk may carry the same labels.
# A label is the partition's name as the kernel read it from the table (PARTNAME), so finding
# one opens no disk and reads no filesystem, a USB stick's included.
# POSIX sh, sourced by services and tools; KRYPTIK_SYSFS names another /sys, for the tests.
#   kryptik_root_disk         the disk under the root, via dm and loop devices
#   kryptik_part LABEL        the one partition with LABEL there; fails on none or several
#   kryptik_part_count LABEL  how many carry LABEL there
#   kryptik_others LABEL      partitions with LABEL on other disks
#   kryptik_named LABEL       partitions with LABEL on any disk

_kd_sys="${KRYPTIK_SYSFS:-/sys}"

_kd_disk_of() {   # a partition (or disk) -> its whole disk
    n="$(basename "$1")"
    if [ -e "$_kd_sys/class/block/$n/partition" ]; then
        printf '/dev/%s' "$(basename "$(readlink -f "$_kd_sys/class/block/$n/..")")"
    else
        printf '/dev/%s' "$n"
    fi
}

# Follow device-mapper and loop stacks down to physical disks; one per line.
_kd_disks_under() {
    n="$(basename "$1")"
    if [ -d "$_kd_sys/class/block/$n/slaves" ] && [ -n "$(ls "$_kd_sys/class/block/$n/slaves" 2>/dev/null)" ]; then
        for s in "$_kd_sys"/class/block/"$n"/slaves/*; do _kd_disks_under "/dev/$(basename "$s")"; done
    elif [ -r "$_kd_sys/class/block/$n/loop/backing_file" ]; then
        bf="$(cat "$_kd_sys/class/block/$n/loop/backing_file")"
        src="$(awk -v f="$bf" 'BEGIN{best=""} {if (index(f, $2)==1 && length($2)>length(best)) {best=$2; dev=$1}} END{print dev}' /proc/mounts)"
        [ -n "$src" ] && _kd_disks_under "$src"
    else
        _kd_disk_of "/dev/$n"
        echo
    fi
}

kryptik_root_disk() {
    root_src="$(awk '$2 == "/" { print $1; exit }' /proc/mounts)"
    case "$root_src" in
        /dev/root)
            # No initramfs: root is /dev/root, and dm-0 the verity device.
            [ -e "$_kd_sys/block/dm-0" ] && root_src=/dev/dm-0 ;;
    esac
    [ -n "$root_src" ] || return 1
    _kd_disks_under "$root_src" | grep -v '^$' | sort -u | head -1
}

# Every partition named LABEL, on any disk, as "DISK PARTITION" device paths. A disk's directory
# in sysfs holds its partitions' own.
_kd_named() {   # LABEL
    [ -n "$1" ] || return 0
    for f in "$_kd_sys"/class/block/*/*/partition; do
        [ -e "$f" ] || continue
        p="${f%/partition}"
        [ "$(sed -n 's/^PARTNAME=//p' "$p/uevent" 2>/dev/null)" = "$1" ] || continue
        d="${p%/*}"
        printf '/dev/%s /dev/%s\n' "${d##*/}" "${p##*/}"
    done
}

kryptik_part_count() {   # LABEL
    disk="$(kryptik_root_disk)" || return 1
    _kd_named "$1" | awk -v d="$disk" '$1 == d { n++ } END { print n + 0 }'
}

kryptik_part() {   # LABEL -> the one partition on the root disk, or failure
    disk="$(kryptik_root_disk)" || { echo "" ; return 1; }
    found="$(_kd_named "$1" | awk -v d="$disk" '$1 == d { n++; p = $2 } END { if (n == 1) print p }')"
    if [ -n "$found" ]; then printf '%s\n' "$found"; return 0; fi
    echo ""
    return 1
}

kryptik_others() {   # LABEL -> partitions with LABEL that are NOT on the root disk
    disk="$(kryptik_root_disk)" || return 0
    _kd_named "$1" | awk -v d="$disk" '$1 != d { print $2 }'
}

kryptik_named() {   # LABEL -> partitions with LABEL on any disk
    _kd_named "$1" | awk '{ print $2 }'
}

# As a command, for kryptik-efiboot.
case "${0##*/}" in
    devices.sh)
        case "${1:-}" in
            disk)   kryptik_root_disk ;;
            part)   kryptik_part "${2:?label}" ;;
            count)  kryptik_part_count "${2:?label}" ;;
            others) kryptik_others "${2:?label}" ;;
            named)  kryptik_named "${2:?label}" ;;
            *) echo "usage: devices.sh disk | part LABEL | count LABEL | others LABEL | named LABEL" >&2; exit 2 ;;
        esac
        ;;
esac
