#!/usr/bin/env bash
# Stage 06 — install media: a verified root image, signed boot kernels, a
# USB disk image and an ISO. docs/design/boot-and-updates.md is the layout;
# this is its builder.
#
#   make iso            (runs this; KRYPTIK_VERSION=... names the release)
#   ./06-iso.sh --redo rootfs
#
# Runs OUTSIDE the chroot, as root: the sysroot has root-only directories
# that the root image must carry, and the kernel relink goes through
# 03-chroot-prep.sh. Everything it writes lands under ${KRYPTIK_WORK}/images
# and, at the end, ${KRYPTIK_OUT}.
#
# Steps, each stamped and resumable like a stage 04 package:
#   sb-keys        developer Secure Boot key pair (once; never in Git)
#   rootfs         staged tree -> ext4 -> dm-verity hash tree appended
#   cmdlines       the compiled-in command line for each boot variant
#   bind-kernels   kernel relinked per variant, inside the chroot
#   sign-kernels   sbsign, then sbverify
#   esp            the ESP FAT image used by the USB medium and the installer
#   usb            GPT: kryptik-esp + kryptik-media
#   iso            ISO9660 with the ESP as El Torito image and the root image
#                  as an appended partition; the ISO kernel names its offset
#   export         copies, checksums, MANIFEST
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config
require_outside_chroot "stage 06"
[[ "$EUID" -eq 0 ]] || die "stage 06 must run as root: the sysroot has root-only paths and the kernel relink needs the chroot.
  sudo -E make iso     (or SUDO= as root)"

stage_contract "${BASH_SOURCE[0]}" "img-" gcc
STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
mkdir -p "$STAMPS" "$LOGS"
# REDO is read by step() in common.sh.
# shellcheck disable=SC2034
REDO=""
# shellcheck disable=SC2034
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

SYSROOT="${KRYPTIK_WORK}/sysroot"
IMG="${KRYPTIK_WORK}/images"
KEYS="${KRYPTIK_WORK}/keys/sb"
CHROOTD="${KRYPTIK_ROOT}/build/stages/03-chroot-prep.sh"
KRYPTIK_VERSION="${KRYPTIK_VERSION:-0.1.$(date +%Y%m%d).$(git -c safe.directory='*' -C "$KRYPTIK_ROOT" rev-parse --short=8 HEAD 2>/dev/null || echo unknown)}"
COMMIT="$(git -c safe.directory='*' -C "$KRYPTIK_ROOT" describe --always --dirty --abbrev=40 2>/dev/null || echo unknown)"
ESP_MIB=512
export KRYPTIK_VERSION

# --- preflight ----------------------------------------------------------------
log "Kryptik stage 06 — install media ${KRYPTIK_VERSION}"
for t in mkfs.ext4 tune2fs dumpe2fs veritysetup sbsign sbverify mkfs.vfat mmd mcopy \
         xorriso sfdisk openssl rsync truncate dd sha256sum blkid; do
    have "$t" || die "required tool not found: ${t}"
done
[[ -d "$SYSROOT" ]] || die "no sysroot at ${SYSROOT}"
[[ -f "${SYSROOT}/boot/kryptik-${V_LINUX}" ]] || die "no kernel at ${SYSROOT}/boot/kryptik-${V_LINUX}; run make kernel"
[[ -d "${SYSROOT}/lib/modules/${V_LINUX_HARDENED}" ]] || warn "no modules under lib/modules/${V_LINUX_HARDENED}"
"$CHROOTD" guard-unmounted 2>/dev/null || die "the chroot is mounted inside ${SYSROOT}; unmount it first"
mkdir -p "$IMG" "$IMG/cmdlines" "$IMG/kernels" "$KRYPTIK_OUT"
chmod 0700 "$IMG"

# The whole of stage 05 is what this stage builds on.
stage_depends_on "kernel-" verify-install

# --- steps ------------------------------------------------------------------

s_sb_keys() {
    mkdir -p "$KEYS"; chmod 0700 "$KEYS"
    if [[ ! -f "$KEYS/kryptik-sb.key" ]]; then
        openssl req -new -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 \
            -subj "/CN=Kryptik developer Secure Boot key/" \
            -keyout "$KEYS/kryptik-sb.key" -out "$KEYS/kryptik-sb.crt"
        chmod 0600 "$KEYS/kryptik-sb.key"
        openssl x509 -in "$KEYS/kryptik-sb.crt" -outform DER -out "$KEYS/kryptik-sb.der"
        cat > "$KEYS/README" <<'EOF'
DEVELOPER Secure Boot key. Generated on the build host, not escrowed, not
rotated, enrolled only into disposable OVMF variable stores. It proves the
boot chain enforces a key and that Kryptik's kernels are bound to one. It is
not a production certificate and must never be enrolled in real firmware.
EOF
        echo "generated a new developer Secure Boot key"
    else
        echo "using the existing developer Secure Boot key"
    fi
    openssl x509 -in "$KEYS/kryptik-sb.crt" -noout -subject -fingerprint -sha256
}

s_rootfs() {
    local version="$1"
    local work; work="$(mktemp -d "${IMG}/stage.XXXXXX")"
    trap 'rm -rf "$work"' RETURN
    local stage="$work/root"
    mkdir -p "$stage"
    echo "--- staging the root tree ---"
    # Out: the stage 01 cross toolchain, the chroot bind mounts, kernel
    # source headers, the boot directory (kernels live on the ESP, signed),
    # cmake (a build tool that has no place in a running system), and the
    # chroot marker.
    rsync -aHAX --numeric-ids \
        --exclude=/tools --exclude=/kryptik --exclude=/kryptik-sources \
        --exclude=/kryptik-work --exclude=/kryptik-kryptikd --exclude=/usr/src \
        --exclude=/lost+found --exclude=/boot/'*' --exclude=/etc/kryptik/inside-chroot \
        --exclude=/usr/bin/cmake --exclude=/usr/bin/ccmake --exclude=/usr/bin/cpack --exclude=/usr/bin/ctest \
        --exclude=/usr/share/cmake* --exclude=/tmp/'*' --exclude=/run/'*' \
        "${SYSROOT}/" "${stage}/"
    mkdir -p "$stage/boot" "$stage/proc" "$stage/sys" "$stage/dev" "$stage/run" "$stage/tmp" \
             "$stage/var" "$stage/home" "$stage/root" "$stage/etc/kryptik"
    chmod 1777 "$stage/tmp"

    # Identity, in the image. The root image's own hash cannot be in it; that
    # goes on the ESP and into MANIFEST.
    sed -i "/^VERSION_ID=/d;/^VERSION=/d" "$stage/etc/os-release"
    printf 'VERSION_ID=%s\nVERSION="%s"\n' "$version" "$version" >> "$stage/etc/os-release"
    local kernel_sha; kernel_sha="$(sha256_of "${SYSROOT}/boot/kryptik-${V_LINUX}")"
    local manifest_digest=""
    [[ -f "${KRYPTIK_WORK}/artifact-manifest.txt" ]] && \
        manifest_digest="$(sed -n 's/^# digest: //p' "${KRYPTIK_WORK}/artifact-manifest.txt" | head -1)"
    # Size the filesystem before writing the identity that records it.
    local bytes; bytes="$(du -sb "$stage" | cut -f1)"
    local fs_bytes=$(( bytes + bytes / 8 + 96 * 1024 * 1024 ))
    fs_bytes=$(( (fs_bytes + 4095) / 4096 * 4096 ))
    printf '%s\n' "$fs_bytes" > "$stage/etc/kryptik/root-image-bytes"
    cat > "$stage/etc/kryptik-image.json" <<EOF
{
  "built_at": "$(date -Iseconds)",
  "version": "${version}",
  "built_from_commit": "${COMMIT}",
  "sysroot_manifest_digest": "${manifest_digest}",
  "kernel": "kryptik-${V_LINUX}",
  "kernel_release": "${V_LINUX_HARDENED}",
  "kernel_unbound_sha256": "${kernel_sha}",
  "root_image_bytes": ${fs_bytes},
  "image_kind": "verified",
  "verity": true,
  "signed_boot": "developer",
  "layout": "design-08",
  "note": "dm-verity root; the root hash is compiled into each signed kernel. Mutable state on PARTLABEL=kryptik-state."
}
EOF
    chmod 0644 "$stage/etc/kryptik-image.json"
    # No fstab entries for what sysinit mounts by label; the kernel finds
    # root from its own command line.
    cat > "$stage/etc/fstab" <<'EOF'
# Kryptik: root is dm-verity from the signed kernel's command line; /var, /etc
# (overlay), /home, /tmp are mounted by /usr/libexec/kryptik/sysinit.sh from
# the partition labelled kryptik-state. Nothing here needs a device name.
proc     /proc     proc     nosuid,noexec,nodev  0 0
sysfs    /sys      sysfs    nosuid,noexec,nodev  0 0
devpts   /dev/pts  devpts   gid=5,mode=620,nosuid,noexec 0 0
tmpfs    /dev/shm  tmpfs    nosuid,nodev         0 0
EOF

    echo "--- ext4 (${fs_bytes} bytes, no journal, read-only by design) ---"
    local img="${IMG}/kryptik-root.img"
    rm -f "$img"
    truncate -s "$fs_bytes" "$img"
    mkfs.ext4 -q -F -L kryptik-root -d "$stage" -O '^has_journal' -E root_owner=0:0 "$img"
    dumpe2fs -h "$img" 2>/dev/null | grep -E 'Filesystem features|Block count|Free blocks'

    echo "--- dm-verity hash tree, appended ---"
    local data_blocks=$(( fs_bytes / 4096 ))
    local salt; salt="$(openssl rand -hex 32)"
    # Room for the tree: about data/128 plus a superblock's worth, generous -
    # and a whole number of 4096-byte blocks. The ISO maps this image as a
    # linear target over the CD, whose logical block is 2048 bytes, and
    # device-mapper refuses a table whose length is not a multiple of that:
    #
    #     device-mapper: table: 252:0: len=5373942 not aligned to h/w
    #     logical block size 2048 of sr0
    #
    # which is how release bae1de53 never booted from its ISO (its image
    # ended 6 sectors past a multiple of 8) while the release before it, by
    # the luck of its size, did. The USB medium never noticed: its partition
    # is sized in MiB and its disk has 512-byte blocks.
    local total_bytes=$(( fs_bytes + fs_bytes / 64 + 4 * 1024 * 1024 ))
    total_bytes=$(( (total_bytes + 4095) / 4096 * 4096 ))
    truncate -s "$total_bytes" "$img"
    veritysetup format --no-superblock --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
        --data-blocks="$data_blocks" --hash-offset="$fs_bytes" --salt="$salt" \
        --root-hash-file="${IMG}/root.hash" "$img" "$img" > "${IMG}/veritysetup-format.txt"
    local root_hash; root_hash="$(tr -d '\n' < "${IMG}/root.hash")"
    [[ ${#root_hash} -eq 64 ]] || { echo "bad root hash: ${root_hash}"; return 1; }
    echo "--- verify the tree we just wrote (positive control) ---"
    veritysetup verify --no-superblock --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
        --data-blocks="$data_blocks" --hash-offset="$fs_bytes" --salt="$salt" "$img" "$img" "$root_hash"
    echo "--- and prove a flipped byte is detected (negative control) ---"
    local probe="$work/probe.img"
    cp --sparse=always "$img" "$probe"
    printf '\xff' | dd of="$probe" bs=1 seek=$(( 4096 * 100 + 7 )) conv=notrunc status=none
    if veritysetup verify --no-superblock --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
        --data-blocks="$data_blocks" --hash-offset="$fs_bytes" --salt="$salt" "$probe" "$probe" "$root_hash" 2>/dev/null; then
        echo "FAIL: a corrupted data block verified"; return 1
    fi
    echo "ok: corruption is detected"
    rm -f "$probe"

    local total; total="$(stat -c %s "$img")"
    local sha; sha="$(sha256_of "$img")"
    cat > "${IMG}/root.json" <<EOF
{
  "version": "${version}",
  "root_hash": "${root_hash}",
  "salt": "${salt}",
  "data_bytes": ${fs_bytes},
  "data_blocks": ${data_blocks},
  "data_sectors": $(( data_blocks * 8 )),
  "hash_start_block": ${data_blocks},
  "total_bytes": ${total},
  "sha256": "${sha}"
}
EOF
    printf '%s  kryptik-root.img\n' "$sha" > "${IMG}/kryptik-root.img.sha256"
    echo "--- root image ---"
    cat "${IMG}/root.json"
}

root_json() { sed -n "s/^  \"$1\": \"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}\$/\1/p" "${IMG}/root.json"; }

verity_table() {   # verity_table <dev> -> "0 <sectors> verity 1 dev dev 4096 4096 blocks start sha256 hash salt 1 panic_on_corruption"
    printf '0 %s verity 1 %s %s 4096 4096 %s %s sha256 %s %s 1 panic_on_corruption' \
        "$(root_json data_sectors)" "$1" "$1" "$(root_json data_blocks)" \
        "$(root_json hash_start_block)" "$(root_json root_hash)" "$(root_json salt)"
}
COMMON_ARGS="ro rootwait console=tty0 console=ttyS0,115200 panic=10 loglevel=4"

s_cmdlines() {
    local h="$1"; echo "root.json sha256: ${h}"
    # dm-mod.waitfor: dm-init builds the verity table at late init, before
    # a USB stick (or a disk behind an asynchronously probed controller)
    # has been enumerated, and it does not retry: the first USB boot ended
    # with "verity: Data device lookup failed (-ENODEV)" and then rootwait
    # waiting forever for a device that would never be created. waitfor
    # makes dm-init wait for the named partition before it creates
    # anything. The same for the installed slots: real disks are
    # asynchronous too.
    printf 'dm-mod.waitfor=PARTLABEL=kryptik-a dm-mod.create="kroot,,0,ro,%s" root=/dev/dm-0 %s kryptik.slot=a\n' \
        "$(verity_table PARTLABEL=kryptik-a)" "$COMMON_ARGS" > "${IMG}/cmdlines/slot-a.txt"
    printf 'dm-mod.waitfor=PARTLABEL=kryptik-b dm-mod.create="kroot,,0,ro,%s" root=/dev/dm-0 %s kryptik.slot=b\n' \
        "$(verity_table PARTLABEL=kryptik-b)" "$COMMON_ARGS" > "${IMG}/cmdlines/slot-b.txt"
    printf 'dm-mod.waitfor=PARTLABEL=kryptik-media dm-mod.create="kroot,,0,ro,%s" root=/dev/dm-0 %s kryptik.media=usb\n' \
        "$(verity_table PARTLABEL=kryptik-media)" "$COMMON_ARGS" > "${IMG}/cmdlines/media-usb.txt"
    for f in "${IMG}"/cmdlines/{slot-a,slot-b,media-usb}.txt; do
        echo "--- $(basename "$f") ($(wc -c < "$f") bytes) ---"; cat "$f"
    done
}

bind_in_chroot() {   # bind_in_chroot VARIANT...
    env KRYPTIK_ROOT="$KRYPTIK_ROOT" KRYPTIK_WORK="$KRYPTIK_WORK" KRYPTIK_SOURCES="$KRYPTIK_SOURCES" \
        KRYPTIK_JOBS="${KRYPTIK_JOBS:-}" KRYPTIK_STALE="${KRYPTIK_STALE:-refuse}" NO_COLOR=1 \
        "$CHROOTD" run /kryptik/build/stages/06-kernel-bind.sh "$@"
}

s_bind_kernels() {
    echo "cmdline digest: $1"
    bind_in_chroot slot-a slot-b media-usb
    ls -la "${IMG}/kernels/"
}

sign_one() {   # sign_one VARIANT
    local in="${IMG}/kernels/$1.efi" out="${IMG}/kernels/$1.signed.efi"
    sbsign --key "$KEYS/kryptik-sb.key" --cert "$KEYS/kryptik-sb.crt" --output "$out" "$in" >/dev/null
    sbverify --cert "$KEYS/kryptik-sb.crt" "$out"
    echo "$1: signed, $(stat -c %s "$out") bytes, sha256 $(sha256_of "$out")"
}

s_sign_kernels() {
    echo "kernels digest: $1"
    local v
    for v in slot-a slot-b media-usb; do sign_one "$v"; done
    # A signature by a different key must not verify (control).
    local tmpk; tmpk="$(mktemp -d)"
    openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=not kryptik/" \
        -keyout "$tmpk/k" -out "$tmpk/c" >/dev/null 2>&1
    if sbverify --cert "$tmpk/c" "${IMG}/kernels/slot-a.signed.efi" >/dev/null 2>&1; then
        echo "FAIL: a foreign certificate verified our kernel"; rm -rf "$tmpk"; return 1
    fi
    rm -rf "$tmpk"
    echo "ok: a foreign certificate does not verify the signature"
}

make_esp() {   # make_esp OUT BOOTX64-VARIANT
    local out="$1" boot="$2"
    rm -f "$out"
    truncate -s $(( ESP_MIB * 1024 * 1024 )) "$out"
    mkfs.vfat -F 32 -n KRYPTIKESP "$out" >/dev/null
    mmd -i "$out" ::/EFI ::/EFI/BOOT ::/EFI/kryptik ::/kryptik
    mcopy -i "$out" "${IMG}/kernels/${boot}.signed.efi" ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i "$out" "${IMG}/kernels/slot-a.signed.efi" ::/EFI/kryptik/kryptik-a.efi
    mcopy -i "$out" "${IMG}/kernels/slot-b.signed.efi" ::/EFI/kryptik/kryptik-b.efi
    local t; t="$(mktemp -d)"
    printf '%s\n' "$KRYPTIK_VERSION" > "$t/version-a"
    printf '%s\n' "$KRYPTIK_VERSION" > "$t/version-b"
    printf 'a\n' > "$t/committed-slot"
    cp "${IMG}/kryptik-root.img.sha256" "$t/root-image.sha256"
    cp "${IMG}/root.json" "$t/root.json"
    cp "$KEYS/kryptik-sb.crt" "$t/kryptik-sb.crt"
    printf '%s\n' "$boot" > "$t/media-kernel"
    mcopy -i "$out" "$t"/* ::/kryptik/
    rm -rf "$t"
}

s_esp() {
    echo "inputs digest: $1"
    make_esp "${IMG}/esp-usb.img" media-usb
    echo "--- ESP (usb) ---"; mdir -i "${IMG}/esp-usb.img" -/ :: | grep -vE '^\s*$'
}

make_gpt_image() {   # make_gpt_image OUT ESP-IMG ROOT-IMG ROOT-LABEL
    local out="$1" esp="$2" root="$3" label="$4"
    local esp_bytes root_bytes
    esp_bytes="$(stat -c %s "$esp")"; root_bytes="$(stat -c %s "$root")"
    local esp_sectors=$(( esp_bytes / 512 ))
    local root_sectors=$(( (root_bytes + 1048575) / 1048576 * 2048 ))
    local esp_start=2048
    local root_start=$(( esp_start + esp_sectors ))
    local total=$(( root_start + root_sectors + 2048 + 34 ))
    rm -f "$out"
    truncate -s $(( total * 512 )) "$out"
    sfdisk --quiet --wipe always "$out" <<EOF
label: gpt
unit: sectors
start=${esp_start}, size=${esp_sectors}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="kryptik-esp"
start=${root_start}, size=${root_sectors}, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, name="${label}"
EOF
    dd if="$esp" of="$out" bs=512 seek="$esp_start" conv=notrunc,sparse status=none
    dd if="$root" of="$out" bs=512 seek="$root_start" conv=notrunc,sparse status=none
    sfdisk -l "$out" | sed 's/^/  /'
}

s_usb() {
    echo "inputs digest: $1"
    local out="${IMG}/kryptik-${KRYPTIK_VERSION}-usb.img"
    make_gpt_image "$out" "${IMG}/esp-usb.img" "${IMG}/kryptik-root.img" kryptik-media
    sha256sum "$out" | sed "s| .*/| |" > "${out}.sha256"
    echo "usb image: $(stat -c %s "$out") bytes ($(du -h "$out" | cut -f1) on disk)"
    cat "${out}.sha256"
}

make_iso() {   # make_iso OUT ESP-IMG
    local out="$1" esp="$2"
    local t; t="$(mktemp -d)"
    cp "$KEYS/kryptik-sb.crt" "$t/"
    cp "${IMG}/root.json" "$t/"
    cat > "$t/README.txt" <<EOF
Kryptik ${KRYPTIK_VERSION} install medium (ISO).
Boot it as a CD/DVD on a UEFI machine. The verified root filesystem is an
appended partition (see root.json); the ISO kernel names its offset. To boot
from a USB stick use the USB image instead: this ISO's kernel looks for
/dev/sr0.
EOF
    rm -f "$out"
    # The appended partition's type is a GPT GUID (Linux filesystem data):
    # xorriso takes a one-byte MBR type or a GUID, and sfdisk's 0x8300
    # shorthand is neither ("Partition type '0x8300' is out of range").
    local rc
    xorriso -as mkisofs -quiet -o "$out" -iso-level 3 -V KRYPTIK -J -R \
        -e esp.img -no-emul-boot -isohybrid-gpt-basdat \
        -append_partition 2 0FC63DAF-8483-4772-8E79-3D69D8477DE4 "${IMG}/kryptik-root.img" -appended_part_as_gpt \
        -graft-points esp.img="$esp" kryptik-sb.crt="$t/kryptik-sb.crt" root.json="$t/root.json" README.txt="$t/README.txt" \
        2>&1 | grep -vE '^\s*$'
    rc="${PIPESTATUS[0]}"
    rm -rf "$t"
    [[ "$rc" -eq 0 ]] || { echo "xorriso exited ${rc}"; return 1; }
    [[ -s "$out" ]] || return 1
}

part2_start() { sfdisk -d "$1" 2>/dev/null | awk -F'[ ,]+' '/^\/.*2 :/ || /-2 :/ {for(i=1;i<=NF;i++) if($i=="start=") print $(i+1)}' | head -1; }

s_iso() {
    echo "inputs digest: $1"
    local iso="${IMG}/kryptik-${KRYPTIK_VERSION}.iso"
    echo "--- pass 1: layout (a placeholder ESP of the final size) ---"
    make_esp "${IMG}/esp-iso.img" slot-a
    make_iso "${IMG}/layout.iso" "${IMG}/esp-iso.img"
    local start; start="$(part2_start "${IMG}/layout.iso")"
    [[ -n "$start" ]] || { echo "could not read the appended partition's start"; sfdisk -d "${IMG}/layout.iso"; return 1; }
    echo "appended root partition starts at sector ${start}"
    local total_sectors=$(( $(root_json total_bytes) / 512 ))
    # The linear map's length must be whole 2048-byte CD blocks, or the
    # kernel refuses the table at boot (see the sizing of the image); a
    # build that would produce such an ISO stops here instead.
    if (( total_sectors % 4 != 0 )); then
        echo "the root image is ${total_sectors} sectors, not a whole number of 2048-byte CD blocks; the ISO would not boot"
        return 1
    fi
    printf 'dm-mod.create="kmedia,,0,ro,0 %s linear /dev/sr0 %s;kroot,,1,ro,%s" root=/dev/dm-1 %s kryptik.media=iso\n' \
        "$total_sectors" "$start" "$(verity_table /dev/dm-0)" "$COMMON_ARGS" > "${IMG}/cmdlines/media-iso.txt"
    cat "${IMG}/cmdlines/media-iso.txt"
    echo "--- bind and sign the ISO kernel ---"
    bind_in_chroot media-iso
    sign_one media-iso
    echo "--- pass 2: the real ESP and ISO ---"
    make_esp "${IMG}/esp-iso.img" media-iso
    make_iso "$iso" "${IMG}/esp-iso.img"
    local start2; start2="$(part2_start "$iso")"
    [[ "$start2" == "$start" ]] || { echo "FAIL: the root partition moved between passes (${start} -> ${start2})"; return 1; }
    echo "ok: root partition start unchanged at ${start2}"
    # The bytes at that offset must be the root image.
    local off=$(( start2 * 512 ))
    local got; got="$(dd if="$iso" bs=1M iflag=skip_bytes,count_bytes skip="$off" count="$(root_json total_bytes)" status=none | sha256sum | cut -c1-64)"
    [[ "$got" == "$(root_json sha256)" ]] || { echo "FAIL: appended partition is not the root image (${got})"; return 1; }
    echo "ok: appended partition is the root image byte for byte"
    rm -f "${IMG}/layout.iso"
    sha256sum "$iso" | sed "s| .*/| |" > "${iso}.sha256"
    xorriso -indev "$iso" -toc 2>/dev/null | grep -E 'ISO session|Media summary|El Torito' | sed 's/^/  /' || true
    sfdisk -l "$iso" | sed 's/^/  /'
    cat "${iso}.sha256"
}

# The update payload for this release: the root image, both slot kernels and
# root.json under a manifest signed with the release key the image trusts
# (stage 04's release-trust step wrote the matching allowed-signers line).
s_payload() {
    echo "inputs digest: $1"
    local keydir="${KRYPTIK_WORK}/keys/release"
    [[ -f "$keydir/kryptik-release" ]] || { echo "no release key at ${keydir}; stage 04 (release-trust) makes it"; return 1; }
    local out="${IMG}/payload-${KRYPTIK_VERSION}"
    rm -rf "$out"; mkdir -p "$out"
    cp --sparse=always "${IMG}/kryptik-root.img" "$out/"
    cp "${IMG}/kernels/slot-a.signed.efi" "$out/kryptik-a.efi"
    cp "${IMG}/kernels/slot-b.signed.efi" "$out/kryptik-b.efi"
    cp "${IMG}/root.json" "$out/"
    "${KRYPTIK_ROOT}/tools/release-manifest.sh" create --out "$out/manifest" --name kryptik \
        --version "$KRYPTIK_VERSION" --role development --root "$out" \
        kryptik-root.img kryptik-a.efi kryptik-b.efi root.json
    "${KRYPTIK_ROOT}/tools/release-manifest.sh" sign --key "$keydir/kryptik-release" "$out/manifest"
    # Verify it the way the guest will: through the allowed-signers line the
    # image carries, with --exact.
    local signers="${SYSROOT}/usr/share/kryptik/trust/release-signers"
    [[ -f "$signers" ]] || { echo "the sysroot has no ${signers}"; return 1; }
    "${KRYPTIK_ROOT}/tools/release-manifest.sh" verify --signers "$signers" --principal kryptik-release \
        --root "$out" --exact --strict "$out/manifest"
    ls -la "$out"
}

# The release record under ${KRYPTIK_OUT}: the small things (hashes, root
# record, signed kernels, certificate, manifest) and the PATHS of the
# images, which stay under ${IMG}. This used to copy the USB image, the ISO,
# the root image and the payload - some 9 GB per release, a byte-for-byte
# duplicate of what ${IMG} holds - and on a WSL host four releases of that
# grew the virtual disk file by 40 GB that never came back by itself.
# `make acceptance EXPORT=DIR` is what delivers tested images, from ${IMG}.
s_export() {
    echo "inputs digest: $1"
    local out="${KRYPTIK_OUT}/kryptik-${KRYPTIK_VERSION}"
    rm -rf "$out"; mkdir -p "$out/kernels"
    cp "${IMG}/kryptik-${KRYPTIK_VERSION}-usb.img.sha256" "$out/"
    cp "${IMG}/kryptik-${KRYPTIK_VERSION}.iso.sha256" "$out/"
    cp "${IMG}/kryptik-root.img.sha256" "${IMG}/root.json" "$out/"
    cp "${IMG}/payload-${KRYPTIK_VERSION}/manifest" "${IMG}/payload-${KRYPTIK_VERSION}/manifest.sig" "$out/"
    cp "${IMG}"/kernels/*.signed.efi "$out/kernels/"
    cp "$KEYS/kryptik-sb.crt" "$KEYS/kryptik-sb.der" "$out/"
    {
        echo "Kryptik ${KRYPTIK_VERSION}"
        echo "commit: ${COMMIT}"
        echo "built:  $(date -Iseconds)"
        echo "kernel: ${V_LINUX_HARDENED} (unbound bzImage sha256 $(sha256_of "${SYSROOT}/boot/kryptik-${V_LINUX}"))"
        echo "root hash: $(root_json root_hash)"
        echo
        echo "images (not copied here; make acceptance EXPORT=DIR delivers the tested ones):"
        echo "  ${IMG}/kryptik-${KRYPTIK_VERSION}-usb.img"
        echo "  ${IMG}/kryptik-${KRYPTIK_VERSION}.iso"
        echo "  ${IMG}/payload-${KRYPTIK_VERSION}/"
        echo
        cat "${IMG}/kryptik-${KRYPTIK_VERSION}-usb.img.sha256" "${IMG}/kryptik-${KRYPTIK_VERSION}.iso.sha256"
        ( cd "$out" && sha256sum ./kernels/*.efi ./*.crt ./*.der ./root.json ./manifest )
    } > "$out/MANIFEST.txt"
    cat "$out/MANIFEST.txt"
    ln -sfn "kryptik-${KRYPTIK_VERSION}" "${KRYPTIK_OUT}/latest"
}

# --- run --------------------------------------------------------------------
step sb-keys        s_sb_keys
step rootfs         s_rootfs "$KRYPTIK_VERSION"
step cmdlines       s_cmdlines "$(_hash_file "${IMG}/root.json")"
step bind-kernels   s_bind_kernels "$(cat "${IMG}"/cmdlines/{slot-a,slot-b,media-usb}.txt | sha256_of_stdin)"
step sign-kernels   s_sign_kernels "$(cat "${IMG}"/kernels/{slot-a,slot-b,media-usb}.efi | sha256_of_stdin)$(_hash_file "$KEYS/kryptik-sb.crt")"
step esp            s_esp "$(cat "${IMG}"/kernels/{slot-a,slot-b,media-usb}.signed.efi "${IMG}/root.json" | sha256_of_stdin)"
step usb            s_usb "$(cat "${IMG}/esp-usb.img" | sha256_of_stdin)$(root_json sha256)"
step iso            s_iso "$(cat "${IMG}"/kernels/{slot-a,slot-b}.signed.efi "${IMG}/root.json" | sha256_of_stdin)"
step payload        s_payload "$(cat "${IMG}"/kernels/{slot-a,slot-b}.signed.efi "${IMG}/root.json" | sha256_of_stdin)"
step export         s_export "$(cat "${IMG}"/kryptik-*.sha256 "${IMG}/payload-${KRYPTIK_VERSION}/manifest" | sha256_of_stdin)"
echo
ok "Stage 06 finished: ${KRYPTIK_OUT}/kryptik-${KRYPTIK_VERSION}"
