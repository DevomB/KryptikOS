#!/bin/sh
#
# Install Kryptik from a running Kryptik system onto a second disk.
#
# This runs INSIDE a booted Kryptik guest, with a blank virtual disk attached.
# It never runs on the build host and it has no business doing so: the host's
# disks are not a thing this project writes to, ever.
#
# It refuses to touch:
#   - the device the running root is on
#   - any device with a mounted partition
#   - anything that is not a block device
#
# Those are not politeness. This runs as root with dd and mkfs in hand.
#
set -eu

PROG="kryptik-install"
say()  { printf '%s: %s\n' "$PROG" "$*"; }
die()  { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

TARGET=""
ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="${2:-}"; shift 2 ;;
        --yes)    ASSUME_YES=1; shift ;;
        -h|--help)
            printf 'usage: %s --target /dev/vdb [--yes]\n' "$PROG"
            printf '\nInstalls the running system onto --target. Destroys everything on it.\n'
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$TARGET" ] || die "--target is required"
[ "$(id -u)" = "0" ] || die "must run as root"

# --- every external tool, checked before the first write -------------------
#
# The first run of this installer died with "sgdisk: command not found" AFTER it
# had announced it was partitioning. It had not written anything yet, by luck
# rather than design: a partitioner that dies part-way through leaves a disk
# that is neither the old system nor the new one.
#
# So the whole tool list is checked up front, and the message names everything
# that is missing at once rather than one per run.
missing=""
for tool in sfdisk partx blockdev blkid mkfs.ext4 tar mount umount sync awk sed; do
    command -v "$tool" >/dev/null 2>&1 || missing="${missing} ${tool}"
done
[ -z "$missing" ] || die "this system is missing:${missing}
Refusing to start. Every tool this installer needs has to exist before it
touches a disk, not at the moment it is first called."

# Partition device naming. A disk whose name ends in a digit takes a "p"
# separator (nvme0n1 -> nvme0n1p2, mmcblk0 -> mmcblk0p2); one that does not
# takes the number directly (vdb -> vdb2, sda -> sda2). Getting this wrong is
# how the first run came to be looking for /dev/vdbp2.
part_dev() {
    case "$1" in
        *[0-9]) printf "%sp%s" "$1" "$2" ;;
        *)      printf "%s%s"  "$1" "$2" ;;
    esac
}

# --- refuse anything that is not a disposable second disk ------------------

[ -b "$TARGET" ] || die "${TARGET} is not a block device.
This installer writes to a whole disk. It does not write to files, and it does
not create devices."

# The device the running root lives on. If the target IS that device, or a
# partition of it, refuse - installing over the system you are running from is
# not a supported outcome, it is a crash with extra steps.
root_src="$(awk '$2 == "/" { print $1; exit }' /proc/mounts)"
root_disk=""
case "$root_src" in
    /dev/*)
        root_disk="$(basename "$root_src")"
        # strip a trailing partition number: vda2 -> vda, sda1 -> sda
        root_disk="$(printf '%s' "$root_disk" | sed 's/p\{0,1\}[0-9]\{1,\}$//')"
        ;;
esac
target_disk="$(basename "$TARGET")"

if [ -n "$root_disk" ] && [ "$target_disk" = "$root_disk" ]; then
    die "${TARGET} is the disk this system is running from (root is ${root_src}).
Refusing."
fi

# Anything mounted from the target, or any of its partitions, is a hard stop.
mounted="$(awk -v d="/dev/${target_disk}" '$1 ~ "^" d { print $1 " on " $2 }' /proc/mounts)"
if [ -n "$mounted" ]; then
    printf '%s\n' "$mounted" | sed 's/^/  /'
    die "the target has mounted filesystems. Unmount them first, or pick another disk."
fi

# The root filesystem's own device must not be a partition of the target.
case "$root_src" in
    "/dev/${target_disk}"*) die "root (${root_src}) is on ${TARGET}. Refusing." ;;
esac

size_bytes="$(blockdev --getsize64 "$TARGET" 2>/dev/null || echo 0)"
[ "$size_bytes" -gt 0 ] || die "could not read the size of ${TARGET}"

say "target      ${TARGET}"
say "size        ${size_bytes} bytes"
say "running root ${root_src} (disk ${root_disk:-unknown})"
echo

if [ "$ASSUME_YES" -ne 1 ]; then
    printf '%s: this DESTROYS everything on %s. Type ERASE to continue: ' "$PROG" "$TARGET"
    read -r answer
    [ "$answer" = "ERASE" ] || die "not confirmed; nothing was written"
fi

# --- partition -------------------------------------------------------------
# Same layout as the developer image: partition 1 reserved for an ESP that does
# not exist yet, root on partition 2, so adding a bootloader later renumbers
# nothing.
# sfdisk, not sgdisk. gptfdisk is not in the base system, and pulling in a new
# pinned source just to partition a disk is a poor trade when util-linux - which
# is already here - does GPT perfectly well. The named-field script format takes
# the partition DEVICE on the left and derives the number from it, which is what
# lets this create partition 2 and leave slot 1 absent, matching the developer
# image exactly.
#
# Type 4F68BCE3-... is "Linux root (x86-64)": the GUID behind sgdisk's 8304.
ROOTPART="$(part_dev "$TARGET" 2)"
GPT_LINUX_ROOT_X86_64=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709

say "partitioning (sfdisk, GPT, root on partition 2)"
sfdisk --wipe always --wipe-partitions always "$TARGET" >/dev/null <<SFDISK
label: gpt
${ROOTPART} : start=2048, type=${GPT_LINUX_ROOT_X86_64}, name="kryptik-root"
SFDISK

# partprobe belongs to parted, which is also not in the base system. partx and
# blockdev are util-linux and are. Either may fail harmlessly when the kernel
# has already picked the table up, so the check that matters is the one below.
partx -u "$TARGET" >/dev/null 2>&1 || blockdev --rereadpt "$TARGET" >/dev/null 2>&1 || true

# Wait for the node instead of sleeping and hoping. eudev may take a moment, and
# a fixed sleep is either too short on a loaded machine or wasted on a fast one.
n=0
while [ ! -b "$ROOTPART" ] && [ "$n" -lt 50 ]; do
    n=$((n + 1))
    sleep 0.1 2>/dev/null || sleep 1
done
[ -b "$ROOTPART" ] || die "no partition 2 appeared on ${TARGET} as ${ROOTPART}.
sfdisk wrote the table; the kernel or eudev did not present the node."

# --- filesystem ------------------------------------------------------------
# -O encrypt: the filesystem half of CONFIG_FS_ENCRYPTION, so a zone on this
# installation can hold an encrypted directory. Same as the image builder.
say "creating the root filesystem on ${ROOTPART}"
mkfs.ext4 -q -F -L kryptik-root -O encrypt "$ROOTPART"

MNT=/run/kryptik-install
mkdir -p "$MNT"
mount "$ROOTPART" "$MNT"
cleanup() { umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# --- copy ------------------------------------------------------------------
# Everything except the virtual filesystems, the installer's own mountpoint,
# and the build-time bind mounts that only exist inside a chroot.
say "copying the system"
tar -C / -cf - \
    --exclude=./proc --exclude=./sys --exclude=./dev --exclude=./run \
    --exclude=./tmp --exclude=./kryptik --exclude=./kryptik-sources \
    --exclude=./kryptik-work --exclude=./kryptik-kryptikd \
    --exclude=./lost+found \
    . | tar -C "$MNT" -xf -

mkdir -p "$MNT/proc" "$MNT/sys" "$MNT/dev" "$MNT/run" "$MNT/tmp"
chmod 1777 "$MNT/tmp"

# --- identity --------------------------------------------------------------
ROOT_UUID="$(blkid -s UUID -o value "$ROOTPART")"

cat > "$MNT/etc/fstab" <<EOF
# Written by kryptik-install.
UUID=${ROOT_UUID}  /      ext4   defaults,noatime  0 1
proc               /proc  proc   nosuid,noexec,nodev  0 0
sysfs              /sys   sysfs  nosuid,noexec,nodev  0 0
tmpfs              /run   tmpfs  nosuid,nodev         0 0
devpts             /dev/pts devpts gid=5,mode=620,nosuid,noexec 0 0
EOF

# What this installation is, and what produced it. An installed system that
# cannot say where it came from is not auditable.
cat > "$MNT/etc/kryptik-install.json" <<EOF
{
  "installed_at": "$(date -Iseconds 2>/dev/null || echo unknown)",
  "installed_by": "kryptik-install",
  "target": "${TARGET}",
  "root_partition": "${ROOTPART}",
  "root_uuid": "${ROOT_UUID}",
  "source_root": "${root_src}",
  "source_image": $( [ -r /etc/kryptik-image.json ] && cat /etc/kryptik-image.json || echo null ),
  "note": "Installed from a running Kryptik system. No bootloader: boot it with qemu -kernel, same as the developer image."
}
EOF

sync
say "installed to ${ROOTPART} (UUID ${ROOT_UUID})"
say "there is no bootloader; boot it the same way as the developer image:"
say "  -drive file=<disk>,format=raw,if=virtio -kernel <kernel> -append 'root=UUID=${ROOT_UUID} rootwait rw console=ttyS0,115200'"
