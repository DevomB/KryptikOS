#!/bin/sh
# Install Kryptik from the booted medium onto a whole disk: ESP, root slots A
# and B, and a LUKS2 state partition (docs/design/boot-and-updates.md,
# docs/design/state-encryption.md). Runs as root inside a booted medium, never
# on a build host; every check runs before the first write.
#
#   kryptik-install --target DISK [--yes] [--dry-run] [--preseed FILE]
#                   [--replace-kryptik] [--slot-size MIB] [--keyboard NAME]
set -eu

PROG="kryptik-install"
say()  { printf '%s: %s\n' "$PROG" "$*"; }
die()  { printf '%s: FAILED: %s\n' "$PROG" "$*" >&2; exit 1; }

# A slot may be made larger than this image needs, never smaller.
slot_size_ok() {   # slot_size_ok ASKED NEEDED: both in MiB, or die
    case "$1" in ''|0*|*[!0-9]*) die "--slot-size takes a number of MiB" ;; esac
    [ "${#1}" -le 9 ] || die "--slot-size $1 is too large"
    [ "$1" -ge "$2" ] || die "--slot-size $1 is less than the $2 MiB a slot needs: the image, and room for a later, larger one"
}

# First boot reads the preseed after the disk is written, so a preseed it
# could not use is refused here, with the other refusals, by first boot's own
# rules (firstboot.sh): the first user= is a name it would create, and each hash
# a crypt hash, which a CRLF line end is not.
preseed_ok() {   # preseed_ok FILE, or die
    [ -r "$1" ] || die "cannot read the preseed ${1}; nothing was written"
    _pu="$(sed -n 's/^user=//p' "$1" | head -1)"
    _ph="$(sed -n 's/^password_hash=//p' "$1" | head -1)"
    _pr="$(sed -n 's/^root_password_hash=//p' "$1" | head -1)"
    case "$_pu" in ''|*[!a-z0-9_-]*|-*) die "the preseed ${1} names no user first boot would create (lower-case letters, digits, _ and -); nothing was written" ;; esac
    case "$_ph" in '$'?*) ;; *) die "the preseed ${1} names no crypt password_hash=; nothing was written" ;; esac
    case "$_ph$_pr" in *[!A-Za-z0-9./=\$]*) die "the preseed ${1} has a hash with characters no crypt hash has; nothing was written" ;; esac
    case "$_pr" in ''|'$'?*) ;; *) die "the preseed ${1} names a root_password_hash= that is not a crypt hash; nothing was written" ;; esac
}

TARGET=""
ASSUME_YES=0
REPLACE=0
DRY_RUN=0
PRESEED=""
SLOT_ASKED=""
KEYBOARD=""
MNT_BASE=/run/kryptik-install

while [ $# -gt 0 ]; do
    case "$1" in
        --target)  TARGET="${2:-}"; shift 2 ;;
        --yes)     ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --preseed) PRESEED="${2:-}"; shift 2 ;;
        --replace-kryptik) REPLACE=1; shift ;;
        --slot-size) SLOT_ASKED="${2:-}"; [ -n "$SLOT_ASKED" ] || die "--slot-size needs a number of MiB"; shift 2 ;;
        --keyboard) KEYBOARD="${2:-}"; [ -n "$KEYBOARD" ] || die "--keyboard needs a layout's name"; shift 2 ;;
        -h|--help)
            printf 'usage: %s --target /dev/vdb [--yes] [--dry-run] [--preseed FILE] [--replace-kryptik] [--slot-size MIB] [--keyboard NAME]\n' "$PROG"
            printf '\nInstalls the running medium onto --target. Destroys everything on it.\n'
            printf '%s\n' '--dry-run checks everything and writes nothing.'
            printf '%s\n' '--replace-kryptik allows a disk that holds an old Kryptik installation or medium.'
            printf '%s\n' '--slot-size MIB makes each root slot that large, for later releases with larger images.'
            printf '%s\n' '--keyboard NAME installs with that keyboard layout; kryptik keyboard lists them.'
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$TARGET" ] || die "--target is required"
[ "$(id -u)" = "0" ] || die "must run as root"

# --- every external tool, checked before the first write -------------------
missing=""
for tool in sfdisk blockdev blkid cryptsetup veritysetup stty mkfs.ext4 dd sha256sum mount umount sync awk sed od \
            grep readlink lsblk head tail wc cmp cp mkdir stat tr cut basename mv mountpoint rmdir chmod rm cat sleep \
            loadkeys chattr kryptik-efiboot; do
    command -v "$tool" >/dev/null 2>&1 || missing="${missing} ${tool}"
done
[ -z "$missing" ] || die "this system is missing:${missing}
Refusing to start. Every tool this installer needs has to exist before it
touches a disk, not at the moment it is first called."

# part_dev DISK N: nvme0n1 -> nvme0n1p2, vdb -> vdb2.
# Only a table the kernel reads whole (BLKRRPART) gives each partition its name (PARTNAME),
# which kryptik_named looks up. Partitions added one at a time, as partx adds them and as sfdisk
# does when its own re-read finds the disk busy, carry none. udev's probe of the new table keeps
# the disk busy for a moment.
reread_table() {   # DISK
    n=0
    until blockdev --rereadpt "$1" 2>/dev/null; do
        n=$((n + 1))
        [ "$n" -lt 100 ] || return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
}

part_dev() {
    case "$1" in
        *[0-9]) printf "%sp%s" "$1" "$2" ;;
        *)      printf "%s%s"  "$1" "$2" ;;
    esac
}

# A mount or swap table's sources, each compared by its canonical path: a disk
# mounted by another name (by-id, by-uuid, a link of its own) is still that disk.
mounted_on() {   # mounted_on DEVS < TABLE: "SOURCE on WHERE" for each source that is one of DEVS, one path a line
    while read -r src where _; do
        case "$src" in /*) ;; *) continue ;; esac
        real="$(readlink -f "$src" 2>/dev/null)" || continue
        printf '%s\n' "$1" | grep -qxF -- "$real" && printf '%s on %s\n' "$src" "$where"
    done
    return 0
}

# kryptik_root_disk and kryptik_part, as the boot services resolve them.
. /usr/libexec/kryptik/devices.sh
. /usr/libexec/kryptik/keyboard.sh
# What the medium's root.json may be trusted for, shared with kryptik-recover.
. /usr/libexec/kryptik/medium-root.sh
# The ESP's kernels and records, written as every other tool writes them.
. /usr/libexec/kryptik/esp-records.sh
[ -z "$KEYBOARD" ] || kb_row "$KEYBOARD" > /dev/null || die "no keyboard layout named ${KEYBOARD}: kryptik keyboard lists them"
[ -z "$PRESEED" ] || preseed_ok "$PRESEED"

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

# Nothing on the target may be mounted or used as swap, by whatever name.
devs="$TARGET_REAL"
for p in "/sys/class/block/$tname/$tname"*; do
    [ -e "$p/partition" ] && devs="${devs}
/dev/${p##*/}"
done
mounted="$(mounted_on "$devs" < /proc/mounts)"
if [ -n "$mounted" ]; then
    printf '%s\n' "$mounted" | sed 's/^/  /'
    die "the target has mounted filesystems. Unmount them first, or pick another disk."
fi
if [ -n "$(tail -n +2 /proc/swaps 2>/dev/null | mounted_on "$devs")" ]; then
    die "${TARGET} has active swap on it. Refusing."
fi
# Nor held open by device-mapper (an unlocked LUKS partition, LVM) or md.
held=""
for h in "/sys/class/block/$tname/holders/"* "/sys/class/block/$tname/$tname"*/holders/*; do
    [ -e "$h" ] && held="${held} ${h##*/}"
done
[ -z "$held" ] || die "${TARGET} is in use: held open by${held}. Close them first, or pick another disk."

# A disk that carries Kryptik may hold the only copy of someone's state: replaced only on request.
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
        mount -t vfat -o ro "$ESP_SRC" "$MNT_BASE/esp" || die "could not mount the medium's ESP"
        ROOT_JSON="$MNT_BASE/esp/kryptik/root.json"
        ;;
    iso)
        mount -t iso9660 -o ro /dev/sr0 "$MNT_BASE/media" || die "could not mount the medium (/dev/sr0)"
        ESP_SRC="$MNT_BASE/media/esp.img"
        [ -f "$ESP_SRC" ] || die "no esp.img on the medium"
        # For its kernels, read before anything is written.
        mount -t vfat -o ro,loop "$ESP_SRC" "$MNT_BASE/esp" || die "could not mount the medium's ESP image"
        ROOT_JSON="$MNT_BASE/media/root.json"
        ROOT_SRC=/dev/sr0
        # The signed linear table "0 N linear /dev/sr0 START" puts the root image at sector START.
        ROOT_OFF="$(sed -n 's/.*linear \/dev\/sr0 \([0-9]*\).*/\1/p' /proc/cmdline | head -1)"
        [ -n "$ROOT_OFF" ] || die "could not read the root image offset from the signed command line"
        ROOT_OFF=$(( ROOT_OFF * 512 ))
        ;;
    *) die "unknown medium type '${media}'" ;;
esac
medium_root "$ROOT_JSON" /proc/cmdline
for s in a b; do
    kernel_names_root "$MNT_BASE/esp/EFI/kryptik/kryptik-$s.efi" \
        || die "the medium's kernel for slot $s does not carry the root hash its signed command line names; nothing was written"
done
ESP_BYTES="$(stat -c %s "$ESP_SRC" 2>/dev/null || blockdev --getsize64 "$ESP_SRC")"
[ -b "$ESP_SRC" ] && ESP_BYTES="$(blockdev --getsize64 "$ESP_SRC")"

size_bytes="$(blockdev --getsize64 "$TARGET_REAL" 2>/dev/null || echo 0)"
[ "$size_bytes" -gt 0 ] || die "could not read the size of ${TARGET}"
# The ESP is the medium's FAT, copied whole, and a FAT's sectors may not be smaller than the
# disk's: on a disk with 4096-byte logical sectors (4Kn) Linux does not mount it, so neither the
# install nor any update could write it, and firmware may not read it either.
esp_ss="$(od -An -tu2 -j11 -N2 "$ESP_SRC" 2>/dev/null | tr -d ' ')"
disk_ss="$(blockdev --getss "$TARGET_REAL" 2>/dev/null || echo 512)"
[ "$disk_ss" -le "${esp_ss:-512}" ] || die "${TARGET} has ${disk_ss}-byte logical sectors, and the boot partition this medium copies is a FAT of ${esp_ss:-512}-byte sectors, which Linux does not mount there (and firmware may not read); give the disk a 512-byte sector format (an NVMe drive's LBA format), or pick another disk; nothing was written"
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

# The disk by its model and what it holds, read before ERASE is typed: on a medium nothing is
# mounted, so a backup disk passes every refusal above. Each partition is probed afresh, and
# what a device or a filesystem calls itself reaches the terminal as printable bytes only.
shown() { printf '%s' "$1" | LC_ALL=C tr -c '[:print:]' '?'; }
model="$(shown "$(lsblk -dno MODEL "$TARGET_REAL" 2>/dev/null | sed 's/ *$//')")"
holds=""
for p in "/sys/class/block/$tname/$tname"*; do
    [ -e "$p/partition" ] || continue
    pn="${p##*/}"
    fs="$(shown "$(blkid -p -o value -s TYPE "/dev/$pn" 2>/dev/null)")"
    lb="$(shown "$(blkid -p -o value -s LABEL "/dev/$pn" 2>/dev/null)")"
    sz="$(lsblk -dnro SIZE "/dev/$pn" 2>/dev/null || true)"   # raw: a column's padding left out
    holds="${holds:+$holds; }${pn} ${fs:-unformatted}${lb:+ \"$lb\"} ${sz}"
done
pt="$(blkid -p -o value -s PTTYPE "$TARGET_REAL" 2>/dev/null || true)"

say "medium       ${media} (version ${VERSION})"
say "target       ${TARGET} -> ${TARGET_REAL}, ${have_mib} MiB${model:+, ${model}}"
say "holds        ${pt:+${pt}: }${holds:-no partition}"
say "running root ${root_src} on ${root_disks:-unknown}"
say "layout       esp ${esp_mib} MiB, kryptik-a ${slot_mib} MiB, kryptik-b ${slot_mib} MiB, kryptik-state $(( have_mib - need_mib + state_min_mib )) MiB"
say "root image   ${ROOT_BYTES} bytes, sha256 ${ROOT_SHA}"
echo

if [ "$DRY_RUN" -eq 1 ]; then
    say "dry run: every check passed; nothing was written"
    exit 0
fi
# Before the first thing typed: ERASE and the passphrase are typed under the
# layout the installed system will ask the passphrase under.
if [ -n "$KEYBOARD" ]; then
    kb_load "$KEYBOARD" || die "could not load the keyboard layout ${KEYBOARD}; nothing was written"
fi
LAYOUT="$(kb_current)"
say "keyboard     ${LAYOUT}: the state passphrase is asked under it at every boot"
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
# A stolen disk is guessed at offline, slowed only by argon2id: a short passphrase is no lock.
# Counted in characters, as the medium's shell runs in the C locale, where ${#} counts bytes.
plen="$(LC_ALL=C.UTF-8; echo "${#STATE_PASS}")"
[ "$plen" -ge 8 ] || die "the state passphrase is ${plen} characters; it needs at least 8, as a stolen disk can be guessed at offline; nothing was written"
# Named in the firmware once nothing is left to refuse, and before anything
# is written to the disk: an install refused above has changed nothing.
kb_store "$LAYOUT" || die "the firmware did not take the keyboard layout ${LAYOUT}; nothing was written"

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
reread_table "$TARGET_REAL" || die "the kernel would not read the new partition table of ${TARGET_REAL}: the disk stayed busy"
n=0
while { [ ! -b "$P1" ] || [ ! -b "$P4" ]; } && [ "$n" -lt 100 ]; do n=$((n + 1)); sleep 0.1 2>/dev/null || sleep 1; done
for p in "$P1" "$P2" "$P3" "$P4"; do [ -b "$p" ] || die "partition ${p} did not appear"; done
kryptik_named kryptik-a | grep -qx "$P2" || die "the kernel does not name ${P2} kryptik-a, so the system could not find it"

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
root_verifies "$P2" || die "kryptik-a does not verify against the root hash the signed kernel carries"
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
mount -t vfat -o rw "$P1" "$MNT_BASE/tesp" || die "could not mount the new ESP"
[ -f "$MNT_BASE/tesp/EFI/kryptik/kryptik-a.efi" ] || die "the copied ESP has no slot A kernel"
esp_place "$MNT_BASE/tesp/EFI/kryptik/kryptik-a.efi" "$MNT_BASE/tesp/EFI/BOOT/BOOTX64.EFI" \
    || die "BOOTX64.EFI could not be made the slot A kernel"
esp_put "$MNT_BASE/tesp/kryptik/committed-slot" a || die "slot A could not be recorded as committed"
rm -f "$MNT_BASE/tesp/kryptik/media-kernel"
# Slot b was cleared above: the medium's kernel and version for it would name a release it does not hold.
rm -f "$MNT_BASE/tesp/EFI/kryptik/kryptik-b.efi" "$MNT_BASE/tesp/kryptik/version-b"
sync
umount "$MNT_BASE/tesp" || die "could not unmount the new ESP"
# A firmware entry for slot a as well, last in BootOrder, as kryptik-recover and boot-success
# leave one: some firmware boots an internal disk only from an entry, not by BOOTX64.EFI.
# Entries of an earlier Kryptik go first, as they name a partition this install replaced.
kryptik-efiboot forget > /dev/null 2>&1 || true
if entry="$(kryptik-efiboot ensure a "$P1" 2>&1)"; then
    say "firmware     $(printf '%s\n' "$entry" | tail -1)"
else
    say "firmware     no entry for slot a ($(printf '%s\n' "$entry" | tail -1)): the disk boots by BOOTX64.EFI alone"
fi

# --- the state partition: what installed this, and the first-boot preseed --
mount -t ext4 -o rw "/dev/mapper/$MAPPING" "$MNT_BASE/state" || die "could not mount kryptik-state"
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
if [ -n "$PRESEED" ]; then
    umask 077
    cp "$PRESEED" "$MNT_BASE/state/lib/kryptik/firstboot.preseed" || die "could not install the preseed"
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
