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
say "partitioning"
sgdisk --zap-all "$TARGET" >/dev/null
sgdisk --new=2:2048:0 --typecode=2:8304 --change-name=2:kryptik-root "$TARGET" >/dev/null
partprobe "$TARGET" 2>/dev/null || true
sleep 1

ROOTPART="${TARGET}2"
[ -b "$ROOTPART" ] || ROOTPART="${TARGET}p2"
[ -b "$ROOTPART" ] || die "no partition 2 appeared on ${TARGET}"

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
