#!/usr/bin/env bash
# build/service-scripts/devices.sh against stand-in /sys trees: partitions found by the names the
# kernel read from their tables, on the root's disk or on others, with no disk ever probed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/build/service-scripts/devices.sh"
PASS=0; FAIL=0
check() {
    if [[ "$2" == "$3" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1))
    else printf '  FAIL  %s (got %q, want %q)\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# A blkid that writes down that it was asked: finding a label must not run it.
mkdir -p "$T/bin"
printf '#!/bin/sh\necho "$*" >> "%s/blkid.calls"\n' "$T" > "$T/bin/blkid"
chmod +x "$T/bin/blkid"

fresh() { rm -rf "$T/sys"; mkdir -p "$T/sys/class/block"; }
disk() { mkdir -p "$T/sys/class/block/$1"; }
part() {   # part DISK PARTITION [NAME]: the kernel's PARTNAME only when the table names it
    local p="$T/sys/class/block/$1/$2"
    mkdir -p "$p"; echo 1 > "$p/partition"
    { echo "MAJOR=8"; echo "DEVNAME=$2"; echo "DEVTYPE=partition"; [[ -n "${3:-}" ]] && echo "PARTNAME=$3"; } > "$p/uevent"
}
# devices.sh sourced as the services do, with the root's disk given.
dev() {   # dev ROOTDISK FUNCTION ARGS...
    local root="$1"; shift
    PATH="$T/bin:$PATH" KRYPTIK_SYSFS="$T/sys" sh -c '. "$1"; r="$2"; kryptik_root_disk() { echo "$r"; }; shift 2; "$@"' \
        sh "$D" "$root" "$@" 2>/dev/null
}
sorted() { tr ' ' '\n' | grep . | sort | tr '\n' ' '; }

echo "-- an installed disk, and a stick that carries the same labels"
fresh
disk vda
part vda vda1 kryptik-esp; part vda vda2 kryptik-a; part vda vda3 kryptik-b; part vda vda4 kryptik-state
disk sda
part sda sda1 kryptik-state; part sda sda2
check "the root disk's state partition" "$(dev /dev/vda kryptik_part kryptik-state)" /dev/vda4
check "counted once on the root disk" "$(dev /dev/vda kryptik_part_count kryptik-state)" 1
check "the stick's is another disk's" "$(dev /dev/vda kryptik_others kryptik-state)" /dev/sda1
check "named on any disk" "$(dev /dev/vda kryptik_named kryptik-state | sorted)" "/dev/sda1 /dev/vda4 "
check "booted from the stick, its own is the root's" "$(dev /dev/sda kryptik_part kryptik-state)" /dev/sda1
check "and the installed disk's is the other" "$(dev /dev/sda kryptik_others kryptik-state)" /dev/vda4
check "a label only one disk has" "$(dev /dev/vda kryptik_part kryptik-esp)" /dev/vda1
check "a label the root disk lacks" "$(dev /dev/sda kryptik_part kryptik-esp; echo "rc=$?")" "
rc=1"

echo "-- names the table does not give"
check "an unnamed partition is no label's" "$(dev /dev/vda kryptik_named '' | sorted)" ""
part vda vda5 kryptik-state-old; part vda vda6 xkryptik-state
check "a longer name is another name" "$(dev /dev/vda kryptik_part_count kryptik-state)" 1

echo "-- two of one label on the root's disk"
part vda vda7 kryptik-state
check "counted twice" "$(dev /dev/vda kryptik_part_count kryptik-state)" 2
check "and then no one partition" "$(dev /dev/vda kryptik_part kryptik-state; echo "rc=$?")" "
rc=1"

echo "-- other disk names"
fresh
disk nvme0n1; part nvme0n1 nvme0n1p4 kryptik-state
disk mmcblk0; part mmcblk0 mmcblk0p1 kryptik-esp
check "an NVMe namespace's partition" "$(dev /dev/nvme0n1 kryptik_part kryptik-state)" /dev/nvme0n1p4
check "an eMMC's" "$(dev /dev/mmcblk0 kryptik_part kryptik-esp)" /dev/mmcblk0p1
check "a disk with no partitions holds none" "$(fresh; disk sdb; dev /dev/sdb kryptik_part_count kryptik-state)" 0

echo "-- as a command, for kryptik-efiboot"
fresh; disk vda; part vda vda1 kryptik-esp
check "named, without a root" "$(PATH="$T/bin:$PATH" KRYPTIK_SYSFS="$T/sys" sh "$D" named kryptik-esp)" /dev/vda1
PATH="$T/bin:$PATH" sh "$D" nothing > /dev/null 2>&1
check "another word is refused" "$?" 2

echo "-- nothing probed"
check "blkid never ran" "$(cat "$T/blkid.calls" 2>/dev/null)" ""

echo
if [[ "$FAIL" -eq 0 ]]; then echo "All ${PASS} checks passed."; exit 0; fi
echo "${FAIL} of $((PASS + FAIL)) checks failed."; exit 1
