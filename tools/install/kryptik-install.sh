#!/bin/sh
#
# Install Kryptik from a booted install medium onto a whole disk
# (docs/design/boot-and-updates.md).
#
# This runs INSIDE a booted Kryptik medium, with a blank disk attached. It
# never runs on the build host and it has no business doing so: the host's
# disks are not a thing this project writes to, ever.
#
# What it writes, in order, after every check has passed:
#   GPT  1 kryptik-esp    the medium's ESP, byte for byte, then BOOTX64.EFI
#                         made the slot A kernel
#        2 kryptik-a      the medium's verity root image, byte for byte,
#                         read back and hashed against the medium's record
#        3 kryptik-b      empty (the first update fills it)
#        4 kryptik-state  LUKS2 (docs/design/state-encryption.md), ext4 inside
#                         it, with install.json and the first-boot preseed
#
# It refuses to touch:
#   - the device the running root is on, through any dm/loop stack
#   - the medium itself, the test-control disk, anything with a mounted
#     partition or active swap, anything that is not a whole block device
#   - a disk too small for the layout
#
# Those are not politeness. This runs as root with dd and mkfs in hand.
#
set -eu

PROG="kryptik-install"
say()  { printf '%s: %s\n' "$PROG" "$*"; }
die()  { printf '%s: FAILED: %s\n' "$PROG" "$*" >&2; exit 1; }

TARGET=""
ASSUME_YES=0
DRY_RUN=0
PRESEED=""
MNT_BASE=/run/kryptik-install

while [ $# -gt 0 ]; do
    case "$1" in
        --target)  TARGET="${2:-}"; shift 2 ;;
        --yes)     ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --preseed) PRESEED="${2:-}"; shift 2 ;;
        -h|--help)
            printf 'usage: %s --target /dev/vdb [--yes] [--dry-run] [--preseed FILE]\n' "$PROG"
            printf '\nInstalls the running medium onto --target. Destroys everything on it.\n'
            printf '%s\n' '--dry-run checks everything and writes nothing.'
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$TARGET" ] || die "--target is required"
[ "$(id -u)" = "0" ] || die "must run as root"

# --- every external tool, checked before the first write -------------------
missing=""
for tool in sfdisk partx blockdev blkid cryptsetup stty mkfs.ext4 dd sha256sum mount umount sync awk sed \
            readlink lsblk head cmp cp mkdir stat tr; do
    command -v "$tool" >/dev/null 2>&1 || missing="${missing} ${tool}"
done
[ -z "$missing" ] || die "this system is missing:${missing}
Refusing to start. Every tool this installer needs has to exist before it
touches a disk, not at the moment it is first called."

# Partition device naming. A disk whose name ends in a digit takes a "p"
# separator (nvme0n1 -> nvme0n1p2, mmcblk0 -> mmcblk0p2); one that does not
# takes the number directly (vdb -> vdb2, sda -> sda2).
part_dev() {
    case "$1" in
        *[0-9]) printf "%sp%s" "$1" "$2" ;;
        *)      printf "%s%s"  "$1" "$2" ;;
    esac
}

# The whole disk a block device belongs to (a partition -> its disk).
disk_of() {
    n="$(basename "$1")"
    if [ -e "/sys/class/block/$n/partition" ]; then
        printf '/dev/%s' "$(basename "$(readlink -f "/sys/class/block/$n/..")")"
    else
        printf '/dev/%s' "$n"
    fi
}

# Every physical disk under a device, through dm and loop stacks.
# Prints one /dev/X per line.
disks_under() {
    n="$(basename "$1")"
    if [ -d "/sys/class/block/$n/slaves" ] && [ -n "$(ls "/sys/class/block/$n/slaves" 2>/dev/null)" ]; then
        for s in /sys/class/block/"$n"/slaves/*; do disks_under "/dev/$(basename "$s")"; done
    elif [ -r "/sys/class/block/$n/loop/backing_file" ]; then
        # a loop device: the disk holding its backing file
        bf="$(cat "/sys/class/block/$n/loop/backing_file")"
        src="$(awk -v f="$bf" 'BEGIN{best=""} {if (index(f, $2)==1 && length($2)>length(best)) {best=$2; dev=$1}} END{print dev}' /proc/mounts)"
        [ -n "$src" ] && disks_under "$src"
    else
        disk_of "/dev/$n"
    fi
}

# --- refuse anything that is not a disposable whole disk -------------------
[ -b "$TARGET" ] || die "${TARGET} is not a block device.
This installer writes to a whole disk. It does not write to files, and it does
not create devices."
TARGET_REAL="$(readlink -f "$TARGET")"
[ -b "$TARGET_REAL" ] || die "${TARGET} resolves to ${TARGET_REAL}, which is not a block device"
tname="$(basename "$TARGET_REAL")"
[ -e "/sys/class/block/$tname/partition" ] && die "${TARGET} is a partition, not a whole disk. Name the disk."
[ "$(lsblk -dno TYPE "$TARGET_REAL" 2>/dev/null)" = "disk" ] || die "${TARGET} is not a whole disk (lsblk type: $(lsblk -dno TYPE "$TARGET_REAL" 2>/dev/null || echo unknown))"
[ "$(cat "/sys/class/block/$tname/ro" 2>/dev/null || echo 0)" = "0" ] || die "${TARGET} is read-only"

# The device the running root lives on, through every layer. If the target
# IS that disk, refuse - installing over the system you are running from is
# not a supported outcome, it is a crash with extra steps.
root_src="$(awk '$2 == "/" { print $1; exit }' /proc/mounts)"
root_disks="$(disks_under "$root_src" 2>/dev/null | sort -u)"
for d in $root_disks; do
    [ "$(readlink -f "$d")" = "$TARGET_REAL" ] && die "${TARGET} is the disk this system is running from (root ${root_src} sits on ${d}).
Refusing."
done
# Likewise the state partition, the medium's ESP and the test-control disk.
for lbl in kryptik-state kryptik-testctl; do
    for dev in $(blkid -t PARTLABEL="$lbl" -o device 2>/dev/null); do
        [ "$(readlink -f "$(disk_of "$dev")")" = "$TARGET_REAL" ] && die "${TARGET} holds the ${lbl} partition in use by this system. Refusing."
    done
done
for dev in $(blkid -t PARTLABEL=kryptik-media -o device 2>/dev/null); do
    [ "$(readlink -f "$(disk_of "$dev")")" = "$TARGET_REAL" ] && die "${TARGET} is the install medium. Refusing."
done

# Anything mounted from the target, or any of its partitions, is a hard stop.
mounted="$(awk -v d="${TARGET_REAL}" '$1 ~ "^" d { print $1 " on " $2 }' /proc/mounts)"
if [ -n "$mounted" ]; then
    printf '%s\n' "$mounted" | sed 's/^/  /'
    die "the target has mounted filesystems. Unmount them first, or pick another disk."
fi
if awk -v d="${TARGET_REAL}" 'NR>1 && $1 ~ "^" d { found=1 } END { exit !found }' /proc/swaps 2>/dev/null; then
    die "${TARGET} has active swap on it. Refusing."
fi

# --- what we are installing, from the medium ---------------------------------
media="$(sed -n 's/^media=//p' /run/kryptik/boot-identity 2>/dev/null)"
[ -n "$media" ] || die "this is not an install medium (no kryptik.media= on the signed command line)"
mkdir -p "$MNT_BASE/media" "$MNT_BASE/esp" "$MNT_BASE/state" "$MNT_BASE/tesp"
MAPPING=kryptik-install-state
cleanup() {
    [ -t 0 ] && stty echo 2>/dev/null || true
    for m in "$MNT_BASE/tesp" "$MNT_BASE/state" "$MNT_BASE/esp" "$MNT_BASE/media"; do
        mountpoint -q "$m" 2>/dev/null && umount "$m" 2>/dev/null || true
        rmdir "$m" 2>/dev/null || true
    done
    [ -b "/dev/mapper/$MAPPING" ] && cryptsetup close "$MAPPING" 2>/dev/null || true
    rmdir "$MNT_BASE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ESP_SRC=""      # a block device or a regular file holding the ESP image
ROOT_SRC=""     # block device holding the root image at ROOT_OFF
ROOT_OFF=0
case "$media" in
    usb)
        ROOT_SRC="$(blkid -t PARTLABEL=kryptik-media -o device 2>/dev/null | head -1)"
        [ -b "$ROOT_SRC" ] || die "no partition labelled kryptik-media on this medium"
        mdisk="$(disk_of "$ROOT_SRC")"
        ESP_SRC="$(blkid -t PARTLABEL=kryptik-esp -o device 2>/dev/null | grep "^${mdisk}" | head -1)"
        [ -b "$ESP_SRC" ] || die "no kryptik-esp partition on the medium ${mdisk}"
        mount -o ro "$ESP_SRC" "$MNT_BASE/esp" || die "could not mount the medium's ESP"
        ROOT_JSON="$MNT_BASE/esp/kryptik/root.json"
        ;;
    iso)
        mount -t iso9660 -o ro /dev/sr0 "$MNT_BASE/media" || die "could not mount the medium (/dev/sr0)"
        ESP_SRC="$MNT_BASE/media/esp.img"
        [ -f "$ESP_SRC" ] || die "no esp.img on the medium"
        ROOT_JSON="$MNT_BASE/media/root.json"
        ROOT_SRC=/dev/sr0
        # The signed command line's linear table is "0 N linear /dev/sr0 START":
        # the root image starts at sector START of the medium.
        ROOT_OFF="$(sed -n 's/.*linear \/dev\/sr0 \([0-9]*\).*/\1/p' /proc/cmdline | head -1)"
        [ -n "$ROOT_OFF" ] || die "could not read the root image offset from the signed command line"
        ROOT_OFF=$(( ROOT_OFF * 512 ))
        ;;
    *) die "unknown medium type '${media}'" ;;
esac
[ -r "$ROOT_JSON" ] || die "no root.json on the medium"
jget() { sed -n "s/^  \"$1\": \"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}\$/\1/p" "$ROOT_JSON" | head -1; }
ROOT_BYTES="$(jget total_bytes)"; ROOT_SHA="$(jget sha256)"; VERSION="$(jget version)"
[ -n "$ROOT_BYTES" ] && [ -n "$ROOT_SHA" ] || die "root.json is incomplete"
ESP_BYTES="$(stat -c %s "$ESP_SRC" 2>/dev/null || blockdev --getsize64 "$ESP_SRC")"
[ -b "$ESP_SRC" ] && ESP_BYTES="$(blockdev --getsize64 "$ESP_SRC")"

size_bytes="$(blockdev --getsize64 "$TARGET_REAL" 2>/dev/null || echo 0)"
[ "$size_bytes" -gt 0 ] || die "could not read the size of ${TARGET}"
MIB=1048576
esp_mib=$(( (ESP_BYTES + MIB - 1) / MIB ))
# A slot holds a whole root image and every update is a whole new image, so
# a slot sized to the first image (it used to be the image plus 16 MiB)
# refuses every larger release: kryptik-update says "slot is N bytes; the
# root image needs M" and there is no way forward but repartitioning. Each
# slot gets the image plus half again, at least 512 MiB of room, rounded up
# to 64 MiB: a release can grow by half before an installed machine has to
# be reinstalled.
slot_mib=$(( (ROOT_BYTES + MIB - 1) / MIB ))
room_mib=$(( slot_mib / 2 ))
[ "$room_mib" -ge 512 ] || room_mib=512
slot_mib=$(( (slot_mib + room_mib + 63) / 64 * 64 ))
# The state partition gets whatever is left, and the least it may be left
# with is room for one update payload and a gigabyte of the person's own
# data. It was a flat 512 MiB, which admitted a disk on which the installed
# system could never be updated: a payload is the root image plus two
# kernels, and it has to sit on this partition while it is verified and
# written into the other slot. An installer that accepts a disk has accepted
# updating it.
image_mib=$(( (ROOT_BYTES + MIB - 1) / MIB ))
state_min_mib=$(( image_mib + 128 + 1024 ))
need_mib=$(( 1 + esp_mib + 2 * slot_mib + state_min_mib + 1 ))
have_mib=$(( size_bytes / MIB ))
[ "$have_mib" -ge "$need_mib" ] || die "${TARGET} is ${have_mib} MiB; this layout needs at least ${need_mib} MiB
(ESP ${esp_mib} + two root slots of ${slot_mib} + state ${state_min_mib})."

say "medium       ${media} (version ${VERSION})"
say "target       ${TARGET} -> ${TARGET_REAL}, ${have_mib} MiB"
say "running root ${root_src} on ${root_disks:-unknown}"
say "layout       esp ${esp_mib} MiB, kryptik-a ${slot_mib} MiB, kryptik-b ${slot_mib} MiB, kryptik-state $(( have_mib - need_mib + state_min_mib )) MiB"
say "root image   ${ROOT_BYTES} bytes, sha256 ${ROOT_SHA}"
echo

if [ "$DRY_RUN" -eq 1 ]; then
    say "dry run: every check passed; nothing was written"
    exit 0
fi
if [ "$ASSUME_YES" -ne 1 ]; then
    printf '%s: this DESTROYS everything on %s. Type ERASE to continue: ' "$PROG" "$TARGET"
    read -r answer
    [ "$answer" = "ERASE" ] || die "not confirmed; nothing was written"
fi

# The state passphrase, before the first write: from the terminal twice, or
# one line of standard input when that is not a terminal (the unattended
# path). It reaches cryptsetup on a descriptor (printf is a builtin), never
# on a command line and never in a file.
if [ -t 0 ]; then
    stty -echo
    printf '%s: a passphrase for the state partition, asked at every boot: ' "$PROG"
    IFS= read -r STATE_PASS || STATE_PASS=""
    printf '\n%s: again: ' "$PROG"
    IFS= read -r again || again=""
    stty echo; echo
    [ "$STATE_PASS" = "$again" ] || die "the two passphrases differ; nothing was written"
    again=""
else
    IFS= read -r STATE_PASS || STATE_PASS=""
fi
[ -n "$STATE_PASS" ] || die "no state passphrase given; nothing was written"

# --- partition -------------------------------------------------------------
say "partitioning (sfdisk, GPT: kryptik-esp, kryptik-a, kryptik-b, kryptik-state)"
P1="$(part_dev "$TARGET_REAL" 1)"; P2="$(part_dev "$TARGET_REAL" 2)"
P3="$(part_dev "$TARGET_REAL" 3)"; P4="$(part_dev "$TARGET_REAL" 4)"
GPT_ESP=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
GPT_LINUX_ROOT_X86_64=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709
GPT_LINUX_FS=0FC63DAF-8483-4772-8E79-3D69D8477DE4
sfdisk --quiet --wipe always --wipe-partitions always "$TARGET_REAL" <<SFDISK
label: gpt
unit: sectors
start=2048, size=$(( esp_mib * 2048 )), type=${GPT_ESP}, name="kryptik-esp"
size=$(( slot_mib * 2048 )), type=${GPT_LINUX_ROOT_X86_64}, name="kryptik-a"
size=$(( slot_mib * 2048 )), type=${GPT_LINUX_ROOT_X86_64}, name="kryptik-b"
type=${GPT_LINUX_FS}, name="kryptik-state"
SFDISK
partx -u "$TARGET_REAL" >/dev/null 2>&1 || blockdev --rereadpt "$TARGET_REAL" >/dev/null 2>&1 || true
n=0
while { [ ! -b "$P1" ] || [ ! -b "$P4" ]; } && [ "$n" -lt 100 ]; do n=$((n + 1)); sleep 0.1 2>/dev/null || sleep 1; done
for p in "$P1" "$P2" "$P3" "$P4"; do [ -b "$p" ] || die "partition ${p} did not appear"; done
[ "$(blkid -s PARTLABEL -o value "$P2")" = "kryptik-a" ] || die "partition 2 is not labelled kryptik-a"

# --- copy, and verify what landed ------------------------------------------
say "writing the ESP (${esp_mib} MiB)"
dd if="$ESP_SRC" of="$P1" bs=4M conv=fsync status=none || die "writing the ESP failed"
say "writing the root image to kryptik-a (${ROOT_BYTES} bytes)"
if [ "$ROOT_OFF" -gt 0 ]; then
    dd if="$ROOT_SRC" of="$P2" bs=4M iflag=skip_bytes,count_bytes skip="$ROOT_OFF" count="$ROOT_BYTES" conv=fsync status=none || die "writing the root image failed"
else
    dd if="$ROOT_SRC" of="$P2" bs=4M iflag=count_bytes count="$ROOT_BYTES" conv=fsync status=none || die "writing the root image failed"
fi
say "reading kryptik-a back"
got="$(dd if="$P2" bs=4M iflag=count_bytes count="$ROOT_BYTES" status=none | sha256sum | cut -c1-64)"
[ "$got" = "$ROOT_SHA" ] || die "kryptik-a does not verify: wrote ${got}, the medium says ${ROOT_SHA}"
say "kryptik-a verifies (${got})"
say "clearing kryptik-b"
dd if=/dev/zero of="$P3" bs=1M count=4 conv=fsync status=none || die "clearing kryptik-b failed"
say "creating kryptik-state (LUKS2, ext4 inside it)"
printf '%s' "$STATE_PASS" | cryptsetup -q luksFormat --type luks2 --cipher aes-xts-plain64 \
    --key-size 512 --pbkdf argon2id --key-file=- "$P4" || die "luksFormat on ${P4} failed"
printf '%s' "$STATE_PASS" | cryptsetup open --type luks2 --key-file=- "$P4" "$MAPPING" \
    || die "could not open the new state partition"
STATE_PASS=""
mkfs.ext4 -q -F -L kryptik-state "/dev/mapper/$MAPPING" || die "mkfs.ext4 inside ${P4} failed"

# --- the target ESP: slot A is the committed boot file ----------------------
mount -o rw "$P1" "$MNT_BASE/tesp" || die "could not mount the new ESP"
[ -f "$MNT_BASE/tesp/EFI/kryptik/kryptik-a.efi" ] || die "the copied ESP has no slot A kernel"
cp "$MNT_BASE/tesp/EFI/kryptik/kryptik-a.efi" "$MNT_BASE/tesp/EFI/BOOT/BOOTX64.EFI.new" || die "could not stage BOOTX64.EFI"
sync -f "$MNT_BASE/tesp/EFI/BOOT/BOOTX64.EFI.new"
mv -f "$MNT_BASE/tesp/EFI/BOOT/BOOTX64.EFI.new" "$MNT_BASE/tesp/EFI/BOOT/BOOTX64.EFI" || die "could not install BOOTX64.EFI"
cmp -s "$MNT_BASE/tesp/EFI/BOOT/BOOTX64.EFI" "$MNT_BASE/tesp/EFI/kryptik/kryptik-a.efi" || die "BOOTX64.EFI is not the slot A kernel"
printf 'a\n' > "$MNT_BASE/tesp/kryptik/committed-slot"
rm -f "$MNT_BASE/tesp/kryptik/media-kernel"
sync
umount "$MNT_BASE/tesp" || die "could not unmount the new ESP"

# --- the state partition: what installed this, and the first-boot preseed --
mount -o rw "/dev/mapper/$MAPPING" "$MNT_BASE/state" || die "could not mount kryptik-state"
mkdir -p "$MNT_BASE/state/lib/kryptik"
cat > "$MNT_BASE/state/lib/kryptik/install.json" <<EOF
{
  "installed_at": "$(date -Iseconds 2>/dev/null || echo unknown)",
  "installed_by": "kryptik-install",
  "medium": "${media}",
  "version": "${VERSION}",
  "target": "${TARGET_REAL}",
  "layout": "design-08",
  "root_image_sha256": "${ROOT_SHA}",
  "root_image_bytes": ${ROOT_BYTES},
  "committed_slot": "a"
}
EOF
if [ -n "$PRESEED" ] && [ -r "$PRESEED" ]; then
    umask 077
    cp "$PRESEED" "$MNT_BASE/state/lib/kryptik/firstboot.preseed"
    chmod 0600 "$MNT_BASE/state/lib/kryptik/firstboot.preseed"
    say "first-boot preseed installed"
fi
sync
umount "$MNT_BASE/state" || die "could not unmount kryptik-state"
cryptsetup close "$MAPPING" || die "could not close the new state partition"
blockdev --flushbufs "$TARGET_REAL" 2>/dev/null || true
sync

say "installed ${VERSION} to ${TARGET_REAL}: boot it from firmware with the medium removed."
say "  slot a: ${P2}   slot b: ${P3} (empty)   state: ${P4}   esp: ${P1}"
say "The state partition opens with that passphrase and nothing else: there is no"
say "escrow. Keep a copy of its header (kryptik-recover --backup-state-header)."
