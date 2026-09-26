#!/bin/sh
# Which partitions belong to this installation: those with the right GPT label
# on the disk the running root came from, since another disk (a clone, an old
# install) can carry the same labels. POSIX sh, sourced by services and tools.
#   kryptik_root_disk         the disk under the root, via dm and loop devices
#   kryptik_part LABEL        the one partition with LABEL there; fails on none
#                             or several, never picks one
#   kryptik_part_count LABEL  how many carry LABEL there
#   kryptik_others LABEL      partitions with LABEL on other disks

_kd_disk_of() {   # a partition (or disk) -> its whole disk
    n="$(basename "$1")"
    if [ -e "/sys/class/block/$n/partition" ]; then
        printf '/dev/%s' "$(basename "$(readlink -f "/sys/class/block/$n/..")")"
    else
        printf '/dev/%s' "$n"
    fi
}

# Follow device-mapper and loop stacks down to physical disks; one per line.
_kd_disks_under() {
    n="$(basename "$1")"
    if [ -d "/sys/class/block/$n/slaves" ] && [ -n "$(ls "/sys/class/block/$n/slaves" 2>/dev/null)" ]; then
        for s in /sys/class/block/"$n"/slaves/*; do _kd_disks_under "/dev/$(basename "$s")"; done
    elif [ -r "/sys/class/block/$n/loop/backing_file" ]; then
        bf="$(cat "/sys/class/block/$n/loop/backing_file")"
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
            [ -e /sys/block/dm-0 ] && root_src=/dev/dm-0 ;;
    esac
    [ -n "$root_src" ] || return 1
    _kd_disks_under "$root_src" | grep -v '^$' | sort -u | head -1
}

kryptik_part_count() {   # LABEL
    disk="$(kryptik_root_disk)" || return 1
    n=0
    for d in $(blkid -t PARTLABEL="$1" -o device 2>/dev/null); do
        [ "$(_kd_disk_of "$d")" = "$disk" ] && n=$((n + 1))
    done
    echo "$n"
}

kryptik_part() {   # LABEL -> the one partition on the root disk, or failure
    disk="$(kryptik_root_disk)" || { echo "" ; return 1; }
    found=""; n=0
    for d in $(blkid -t PARTLABEL="$1" -o device 2>/dev/null); do
        if [ "$(_kd_disk_of "$d")" = "$disk" ]; then
            found="$d"; n=$((n + 1))
        fi
    done
    if [ "$n" -eq 1 ]; then printf '%s\n' "$found"; return 0; fi
    echo ""
    return 1
}

kryptik_others() {   # LABEL -> partitions with LABEL that are NOT on the root disk
    disk="$(kryptik_root_disk)" || return 0
    for d in $(blkid -t PARTLABEL="$1" -o device 2>/dev/null); do
        [ "$(_kd_disk_of "$d")" = "$disk" ] || printf '%s\n' "$d"
    done
}

# Run as a command (by kryptik-efiboot):
#   devices.sh disk | part LABEL | count LABEL | others LABEL
case "${0##*/}" in
    devices.sh)
        case "${1:-}" in
            disk)   kryptik_root_disk ;;
            part)   kryptik_part "${2:?label}" ;;
            count)  kryptik_part_count "${2:?label}" ;;
            others) kryptik_others "${2:?label}" ;;
            *) echo "usage: devices.sh disk | part LABEL | count LABEL | others LABEL" >&2; exit 2 ;;
        esac
        ;;
esac
