#!/bin/sh
# Install Kryptik from the booted medium onto a whole disk: ESP, root slots A
# and B, and a LUKS2 state partition (docs/design/boot-and-updates.md,
# docs/design/state-encryption.md). Runs as root inside a booted medium, never
# on a build host; every check runs before the first write.
#
#   kryptik-install --target DISK [--yes] [--dry-run] [--preseed FILE]
#                   [--replace-kryptik] [--slot-size MIB]
set -eu

PROG="kryptik-install"
say()  { printf '%s: %s\n' "$PROG" "$*"; }
die()  { printf '%s: FAILED: %s\n' "$PROG" "$*" >&2; exit 1; }

# root.json is the medium's own record, not signed material: a rewritten
# record must be able to make the install fail and nothing else, so every
# field is checked for form before it is used, and what lands on the disk is
# verified against the root hash the signed kernel carries.
decimal_field() {   # decimal_field NAME VALUE: a bounded decimal, or die
    case "$2" in ''|*[!0-9]*) die "root.json: $1 is not a number" ;; esac
    [ "${#2}" -le 15 ] || die "root.json: $1 is too large"
}
hex_field() {   # hex_field NAME VALUE LENGTH: lowercase hex of that length, or die
    case "$2" in *[!0-9a-f]*) die "root.json: $1 is not a hash" ;; esac
    [ "${#2}" -eq "$3" ] || die "root.json: $1 is not a hash"
}
# The root's dm-verity table from the signed command line, as
# "data_blocks hash_start_block root_hash salt"; empty when there is none.
verity_of() {   # verity_of FILE
    sed -n 's/.* verity 1 [^ ]* [^ ]* 4096 4096 \([0-9][0-9]*\) \([0-9][0-9]*\) sha256 \([0-9a-f]\{64\}\) \([0-9a-f]*\) .*/\1 \2 \3 \4/p' "$1" | head -1
}
# A slot may be made larger than this image needs, never smaller.
slot_size_ok() {   # slot_size_ok ASKED NEEDED: both in MiB, or die
    case "$1" in ''|0*|*[!0-9]*) die "--slot-size takes a number of MiB" ;; esac
    [ "${#1}" -le 9 ] || die "--slot-size $1 is too large"
    [ "$1" -ge "$2" ] || die "--slot-size $1 is less than the $2 MiB a slot needs: the image, and room for a later, larger one"
}

TARGET=""
ASSUME_YES=0
REPLACE=0
DRY_RUN=0
PRESEED=""
SLOT_ASKED=""
MNT_BASE=/run/kryptik-install

while [ $# -gt 0 ]; do
    case "$1" in
        --target)  TARGET="${2:-}"; shift 2 ;;
        --yes)     ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --preseed) PRESEED="${2:-}"; shift 2 ;;
        --replace-kryptik) REPLACE=1; shift ;;
        --slot-size) SLOT_ASKED="${2:-}"; [ -n "$SLOT_ASKED" ] || die "--slot-size needs a number of MiB"; shift 2 ;;
        -h|--help)
            printf 'usage: %s --target /dev/vdb [--yes] [--dry-run] [--preseed FILE] [--replace-kryptik] [--slot-size MIB]\n' "$PROG"
            printf '\nInstalls the running medium onto --target. Destroys everything on it.\n'
            printf '%s\n' '--dry-run checks everything and writes nothing.'
            printf '%s\n' '--replace-kryptik allows a disk that holds an old Kryptik installation or medium.'
            printf '%s\n' '--slot-size MIB makes each root slot that large, for later releases with larger images.'
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

# part_dev DISK N: nvme0n1 -> nvme0n1p2, vdb -> vdb2.
part_dev() {
    case "$1" in
        *[0-9]) printf "%sp%s" "$1" "$2" ;;
        *)      printf "%s%s"  "$1" "$2" ;;
    esac
}

# The boot services' answers to which disk a device is on and which partitions
# are this system's own.
. /usr/libexec/kryptik/devices.sh

# --- refuse anything that is not a disposable whole disk -------------------
[ -b "$TARGET" ] || die "${TARGET} is not a block device.
This installer writes to a whole disk. It does not write to files, and it does
not create devices."
TARGET_REAL="$(readlink -f "$TARGET")"
[ -b "$TARGET_REAL" ] || die "${TARGET} resolves to ${TARGET_REAL}, which is not a block device"
tname="$(basename "$TARGET_REAL")"

# Never the disk the running root is on, through any dm/loop layer: booted
# from a medium, that is the medium. First, so no other refusal stands in
# for it, and no flag overrides it.
root_src="$(awk '$2 == "/" { print $1; exit }' /proc/mounts)"
# Not root_src: without an initramfs the root is /dev/root, which names no device.
root_disks="$(kryptik_root_disk 2>/dev/null || true)"
for d in $root_disks; do
    [ "$(readlink -f "$d")" = "$TARGET_REAL" ] && die "${TARGET} is the disk this system is running from (root ${root_src} sits on ${d}).
Refusing."
done

[ -e "/sys/class/block/$tname/partition" ] && die "${TARGET} is a partition, not a whole disk. Name the disk."
[ "$(lsblk -dno TYPE "$TARGET_REAL" 2>/dev/null)" = "disk" ] || die "${TARGET} is not a whole disk (lsblk type: $(lsblk -dno TYPE "$TARGET_REAL" 2>/dev/null || echo unknown))"
[ "$(cat "/sys/class/block/$tname/ro" 2>/dev/null || echo 0)" = "0" ] || die "${TARGET} is read-only"

# Nothing on the target may be mounted or used as swap.
mounted="$(awk -v d="${TARGET_REAL}" '$1 ~ "^" d { print $1 " on " $2 }' /proc/mounts)"
if [ -n "$mounted" ]; then
    printf '%s\n' "$mounted" | sed 's/^/  /'
    die "the target has mounted filesystems. Unmount them first, or pick another disk."
fi
if awk -v d="${TARGET_REAL}" 'NR>1 && $1 ~ "^" d { found=1 } END { exit !found }' /proc/swaps 2>/dev/null; then
    die "${TARGET} has active swap on it. Refusing."
fi
# Nor held open by device-mapper (an unlocked LUKS partition, LVM) or md.
held=""
for h in "/sys/class/block/$tname/holders/"* "/sys/class/block/$tname/$tname"*/holders/*; do
    [ -e "$h" ] && held="${held} ${h##*/}"
done
[ -z "$held" ] || die "${TARGET} is in use: held open by${held}. Close them first, or pick another disk."

# A disk that carries Kryptik (an old installation, a medium, a test-control
# disk) may hold the only copy of someone's state: it is replaced only when
# asked for by name.
labels=""
for p in "/sys/class/block/$tname/$tname"*; do
    [ -e "$p/partition" ] || continue
    l="$(blkid -s PARTLABEL -o value "/dev/${p##*/}" 2>/dev/null || true)"
    case "$l" in
        kryptik-*) case " $labels " in *" $l "*) ;; *) labels="${labels:+$labels }$l" ;; esac ;;
    esac
done
if [ -n "$labels" ]; then
    [ "$REPLACE" -eq 1 ] || die "${TARGET} holds a Kryptik installation or medium (${labels}).
Nothing on it is in use by this system. To replace it, run again with
--replace-kryptik: everything on it, including its encrypted state, is destroyed."
    say "replacing ${labels} on ${TARGET}"
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
        # From the medium this system booted from, not any disk with the label.
        ROOT_SRC="$(kryptik_part kryptik-media)" || true
        [ -b "$ROOT_SRC" ] || die "no single kryptik-media partition on the medium this system booted from"
        ESP_SRC="$(kryptik_part kryptik-esp)" || true
        [ -b "$ESP_SRC" ] || die "no single kryptik-esp partition on the medium this system booted from"
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
decimal_field total_bytes "$ROOT_BYTES"
hex_field sha256 "$ROOT_SHA" 64
case "$VERSION" in *[!A-Za-z0-9._-]*) die "root.json: version has characters a version cannot" ;; esac
# The record must name the root the signed kernel carries, and its size must
# hold that root and its hash tree without being absurd.
VERITY="$(verity_of /proc/cmdline)"
[ -n "$VERITY" ] || die "could not read the root's verity table from the signed command line"
read -r V_BLOCKS V_HASH_START V_HASH V_SALT <<EOF
$VERITY
EOF
[ "$(jget root_hash)" = "$V_HASH" ] || die "root.json names root hash $(jget root_hash); the signed kernel carries ${V_HASH}"
[ "$(jget data_blocks)" = "$V_BLOCKS" ] || die "root.json names $(jget data_blocks) data blocks; the signed kernel carries ${V_BLOCKS}"
[ "$ROOT_BYTES" -ge $(( (V_HASH_START + 1) * 4096 )) ] || die "root.json: total_bytes is smaller than the root and its hash tree"
[ "$ROOT_BYTES" -le $(( V_BLOCKS * 4096 + V_BLOCKS * 64 + 16777216 )) ] || die "root.json: total_bytes is larger than a root and its hash tree can be"
ESP_BYTES="$(stat -c %s "$ESP_SRC" 2>/dev/null || blockdev --getsize64 "$ESP_SRC")"
[ -b "$ESP_SRC" ] && ESP_BYTES="$(blockdev --getsize64 "$ESP_SRC")"

size_bytes="$(blockdev --getsize64 "$TARGET_REAL" 2>/dev/null || echo 0)"
[ "$size_bytes" -gt 0 ] || die "could not read the size of ${TARGET}"
MIB=1048576
esp_mib=$(( (ESP_BYTES + MIB - 1) / MIB ))
# A slot must also hold later, larger images: the image plus half again (at
# least 512 MiB of room), rounded up to 64 MiB. tools/image/test-disk-size.sh
# does the same arithmetic.
slot_mib=$(( (ROOT_BYTES + MIB - 1) / MIB ))
room_mib=$(( slot_mib / 2 ))
[ "$room_mib" -ge 512 ] || room_mib=512
slot_mib=$(( (slot_mib + room_mib + 63) / 64 * 64 ))
if [ -n "$SLOT_ASKED" ]; then
    slot_size_ok "$SLOT_ASKED" "$slot_mib"
    slot_mib="$SLOT_ASKED"
fi
# State gets the rest: at least one update payload (the image plus two
# kernels, staged there while it is verified) and 1 GiB of user data.
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

# The state passphrase, before the first write: twice on a terminal, else one
# line of stdin. It reaches cryptsetup through a pipe from the printf builtin,
# never in argv or a file.
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
blockdev --flushbufs "$P2"   # so the read-back is of the disk, not of the page cache
say "reading kryptik-a back"
got="$(dd if="$P2" bs=4M iflag=count_bytes count="$ROOT_BYTES" status=none | sha256sum | cut -c1-64)"
[ "$got" = "$ROOT_SHA" ] || die "kryptik-a does not verify: wrote ${got}, the medium says ${ROOT_SHA}"
say "kryptik-a verifies (${got})"
# The record can lie about itself; the kernel's root hash cannot.
veritysetup verify --no-superblock --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
    --data-blocks="$V_BLOCKS" --hash-offset=$(( V_HASH_START * 4096 )) --salt="$V_SALT" "$P2" "$P2" "$V_HASH" \
    || die "kryptik-a does not verify against the root hash the signed kernel carries"
say "kryptik-a verifies against the signed kernel's root hash"
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
