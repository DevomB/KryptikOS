#!/usr/bin/env bash
# Build a bootable Kryptik disk image from a sysroot and a kernel.
#
#   tools/image/mkdisk.sh --sysroot DIR --kernel FILE --out IMG [--size 6G]
#
# Produces a GPT disk with one ext4 root partition, and prints the exact QEMU
# command to boot it on a serial console.
#
# NO ROOT, NO LOOP MOUNTS. mkfs.ext4 -d populates a filesystem image from a
# directory directly, and the partition table is written to a sparse file and
# the filesystem dd'd into it at the right offset. Anything that needs
# losetup(8) needs privilege and leaves a device behind when it fails; this
# needs neither and cannot.
#
# WHAT IS NOT HERE YET, so nobody mistakes this for a shippable installer:
#
#   * No ESP and no bootloader. mkfs.vfat is not on this host and GRUB is not
#     built by stage 04, so the image boots with QEMU's -kernel rather than
#     from itself. Everything else about the layout is real, and the ESP slot
#     is left in the partition table for when it is.
#   * No dm-verity, no signing. See docs/roadmap.md Phase 7.
set -Eeuo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"

SYSROOT=""
KERNEL=""
OUT=""
SIZE="6G"
LABEL="kryptik-root"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --sysroot) SYSROOT="${2:?}"; shift 2 ;;
        --kernel)  KERNEL="${2:?}";  shift 2 ;;
        --out)     OUT="${2:?}";     shift 2 ;;
        --size)    SIZE="${2:?}";    shift 2 ;;
        --label)   LABEL="${2:?}";   shift 2 ;;
        -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$SYSROOT" ]] || die "--sysroot is required"
[[ -n "$OUT" ]]     || die "--out is required"
[[ -d "$SYSROOT" ]] || die "no such sysroot: ${SYSROOT}"

for t in mkfs.ext4 sgdisk truncate dd blkid; do
    have "$t" || die "required tool not found: ${t}"
done

# A sysroot with the build chroot still mounted inside it would be copied
# complete with the host's /dev and 15GB of kernel build tree.
mounted="$(LC_ALL=C awk -v r="${SYSROOT%/}/" '{t=$5; gsub(/\\040/," ",t); if (index(t,r)==1) print t}' \
           /proc/self/mountinfo 2>/dev/null || true)"
if [[ -n "$mounted" ]]; then
    err "filesystems are mounted inside ${SYSROOT}:"
    printf '  %s\n' $mounted >&2
    die "Refusing to image a tree that is in use. Unmount first:
  sudo build/stages/03-chroot-prep.sh umount"
fi

WORKDIR="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$WORKDIR'" EXIT
STAGE="${WORKDIR}/root"
ROOTFS="${WORKDIR}/rootfs.ext4"

log "staging the root filesystem"
mkdir -p "$STAGE"

# What does NOT go into a shipped image.
#
#   tools/        the stage 01 cross toolchain. It exists to build the system,
#                 is deliberately unhardened (see 01-toolchain.sh), and would
#                 add ~700MB of compilers nobody should find on a running
#                 machine.
#   kryptik*      bind-mount points for the repository, sources and work tree.
#                 Empty here, and meaningless on a booted system.
#   usr/src       kernel headers left from the toolchain build.
EXCLUDES=(--exclude=/tools --exclude=/kryptik --exclude=/kryptik-sources
          --exclude=/kryptik-work --exclude=/kryptik-kryptikd
          --exclude=/usr/src --exclude=/lost+found)

if have rsync; then
    rsync -aHAX --numeric-ids "${EXCLUDES[@]}" "${SYSROOT}/" "${STAGE}/"
else
    ( cd "$SYSROOT" && tar --numeric-owner \
        --exclude=./tools --exclude=./kryptik --exclude=./kryptik-sources \
        --exclude=./kryptik-work --exclude=./kryptik-kryptikd \
        --exclude=./usr/src --exclude=./lost+found -cf - . ) \
      | ( cd "$STAGE" && tar --numeric-owner -xf - )
fi

# The kernel, if one was given. An image with no /boot still boots under
# QEMU's -kernel, but it cannot tell you what it was built from.
if [[ -n "$KERNEL" ]]; then
    [[ -f "$KERNEL" ]] || die "no such kernel: ${KERNEL}"
    install -d -m 0755 "${STAGE}/boot"
    install -m 0644 "$KERNEL" "${STAGE}/boot/$(basename "$KERNEL")"
    for extra in "${KERNEL%/*}/System.map-"* "${KERNEL%/*}/config-"*; do
        [[ -e "$extra" ]] && install -m 0644 "$extra" "${STAGE}/boot/"
    done
fi

# --- identity -------------------------------------------------------------
#
# The image says what it is, in the image. Integration's boot smoke test had
# to keep a marker file beside the builder to tell whether a VM was running
# Kryptik's userspace or the host's; a system that carries its own provenance
# does not need one.
KERNEL_SHA=""
[[ -n "$KERNEL" ]] && KERNEL_SHA="$(sha256_of "$KERNEL")"
MANIFEST_DIGEST=""
[[ -f "${KRYPTIK_WORK}/artifact-manifest.txt" ]] && \
    MANIFEST_DIGEST="$(sed -n 's/^# digest: //p' "${KRYPTIK_WORK}/artifact-manifest.txt" | head -1)"
COMMIT="$(git -c safe.directory='*' -C "$KRYPTIK_ROOT" describe --always --dirty --abbrev=40 2>/dev/null || echo unknown)"

cat > "${STAGE}/etc/kryptik-image.json" <<EOF
{
  "built_at": "$(date -Iseconds)",
  "built_from_commit": "${COMMIT}",
  "sysroot": "${SYSROOT}",
  "sysroot_manifest_digest": "${MANIFEST_DIGEST}",
  "kernel": "$([[ -n "$KERNEL" ]] && basename "$KERNEL" || echo none)",
  "kernel_sha256": "${KERNEL_SHA}",
  "image_kind": "developer",
  "signed": false,
  "verity": false,
  "note": "Developer image. No ESP, no bootloader, no dm-verity, no signature. Boots via qemu -kernel."
}
EOF
chmod 0644 "${STAGE}/etc/kryptik-image.json"

# fstab for a real root device rather than the build-time placeholder.
cat > "${STAGE}/etc/fstab" <<EOF
# file system    mount point  type     options              dump  fsck
LABEL=${LABEL}   /            ext4     defaults,noatime     0     1
proc             /proc        proc     nosuid,noexec,nodev  0     0
sysfs            /sys         sysfs    nosuid,noexec,nodev  0     0
devpts           /dev/pts     devpts   gid=5,mode=620       0     0
tmpfs            /run         tmpfs    defaults             0     0
devtmpfs         /dev         devtmpfs mode=0755,nosuid     0     0
tmpfs            /dev/shm     tmpfs    nosuid,nodev         0     0
EOF

STAGE_BYTES="$(du -sb "$STAGE" | cut -f1)"
log "staged $(numfmt --to=iec "$STAGE_BYTES" 2>/dev/null || echo "$STAGE_BYTES") of root filesystem"

# --- filesystem -----------------------------------------------------------
#
# mkfs.ext4 -d populates from a directory with no mount and no privilege.
# ^metadata_csum_seed keeps the image readable by older e2fsprogs.
log "building the ext4 filesystem"
FS_SIZE="$SIZE"
truncate -s "$FS_SIZE" "$ROOTFS"
mkfs.ext4 -q -F -L "$LABEL" -d "$STAGE" -O '^has_journal' -E root_owner=0:0 "$ROOTFS" \
    || die "mkfs.ext4 failed - is ${FS_SIZE} large enough for ${STAGE_BYTES} bytes?"

# Journal on afterwards: mkfs -d with a journal is slower and the journal is
# rebuilt here anyway.
tune2fs -O has_journal "$ROOTFS" > /dev/null
ROOT_UUID="$(blkid -s UUID -o value "$ROOTFS")"
ok "filesystem built, UUID ${ROOT_UUID}"

# --- disk -----------------------------------------------------------------
#
# GPT with the root filesystem at 1MiB. Partition 1 is deliberately left free
# for the ESP a signed image will need; the root is partition 2 so adding one
# later does not renumber anything.
log "building the GPT disk image"
FS_BYTES="$(stat -c %s "$ROOTFS")"
DISK_BYTES=$(( FS_BYTES + 2 * 1024 * 1024 ))
rm -f "$OUT"
truncate -s "$DISK_BYTES" "$OUT"

ROOT_START=2048                       # 1MiB, in 512-byte sectors
ROOT_END=$(( ROOT_START + FS_BYTES / 512 - 1 ))
sgdisk --clear \
       --new=2:${ROOT_START}:${ROOT_END} \
       --typecode=2:4f68bce3-e8cd-4db1-96e7-fbcaf984b709 \
       --change-name=2:"kryptik-root" \
       "$OUT" > /dev/null

dd if="$ROOTFS" of="$OUT" bs=1M seek=1 conv=notrunc status=none
ok "wrote ${OUT} ($(numfmt --to=iec "$DISK_BYTES" 2>/dev/null || echo "$DISK_BYTES"))"

echo
sgdisk --print "$OUT" | sed 's/^/  /'
echo
ok "image identity"
sed 's/^/  /' "${STAGE}/etc/kryptik-image.json"

cat <<EOF

--- boot it ---

  tools/image/run-qemu-disk.sh --image ${OUT} \\
$([[ -n "$KERNEL" ]] && printf '      --kernel %s \\\n' "$KERNEL")      --mode console

The root device is partition 2: root=/dev/vda2 (LABEL=${LABEL}, UUID=${ROOT_UUID}).
Partition 1 is intentionally absent - that slot is the ESP a signed image
will need, and leaving it empty now means adding one later renumbers nothing.
EOF
