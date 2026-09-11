#!/usr/bin/env bash
# Launch the Kryptik developer VM under QEMU.
#
# SAFETY, because this is the script that could damage a developer's machine:
#   * no -drive, no disk image, no block device is ever opened. The VM is
#     kernel + initramfs only, so there is nothing to format and nothing that
#     can reach a host disk.
#   * no host networking. -nic none, so the guest cannot touch the host's
#     network, and none of the routed-zone machinery can be accidentally
#     exercised against a real interface.
#   * -no-reboot, so a guest panic or reboot ENDS the process rather than
#     looping forever eating a core.
#   * a hard timeout, enforced here rather than trusted to the guest.
#
# It never needs root: KVM is used when /dev/kvm is readable and the run falls
# back to TCG software emulation otherwise, which is slower but proves the same
# things.

set -euo pipefail

die() { printf 'run-qemu: %s\n' "$*" >&2; exit 1; }

KERNEL=""
INITRD=""
LOG=""
MODE="smoke"
TIMEOUT=300
# 3G is sized for the INITRAMFS path, where the entire image is unpacked into
# RAM and then copied onto a tmpfs root - so the guest needs room for two
# copies of its own userspace. A disk-rooted guest needs none of that: its root
# filesystem is on virtio-blk and stays there. Asking for 3G anyway is not
# harmless on a developer machine, where this VM shares a 7G WSL budget with a
# distribution build; it pushed that budget to its cap and WSL stopped
# accepting new sessions. --mem still overrides both.
MEM=3072
MEM_SET_BY_USER=0
ROOT_DISK_MEM=1536
CPUS=2
QEMU="${QEMU:-qemu-system-x86_64}"
EXTRA_APPEND=""
NIC="none"
# A raw image attached as virtio-blk. Always a file this harness made, never a
# host device: the guest gets write access to whatever this names, and the one
# mistake that cannot be undone is naming something real.
DISK=""
# Boot the disk AS the root filesystem rather than attaching it alongside an
# initramfs. Only possible because this kernel has virtio_blk and ext4 built in
# rather than as modules in an initrd - measured, not assumed: the guest
# reports KRYPTIK_VM_BLOCKDEV and mounts /dev/vda in the smoke payload.
ROOT_DISK=0

usage() {
    cat <<'EOF'
usage: run-qemu.sh --kernel FILE --initrd FILE --log FILE [options]

  --kernel FILE   bzImage to boot
  --initrd FILE   initramfs produced by mkinitramfs.sh
  --log FILE      where the guest serial console is written
  --mode MODE     smoke (default, runs the tests and powers off) | console
  --timeout SEC   hard wall-clock limit (default 300)
  --mem MB        guest memory (default 3072; the tmpfs root needs room)
  --cpus N        guest cpus (default 2)
  --append STR    extra kernel command line arguments
  --nic MODE      none (default) | user
                  "user" gives the guest a virtio NIC on QEMU's built-in
                  user-mode network: a NAT implemented inside the QEMU process,
                  outbound only, with no inbound path and no bridge, tap device
                  or capability required. It does NOT touch the host's NIC, ask
                  for root, or create anything that outlives the process.
                  It exists so the guest has a non-loopback interface for a
                  zone's isolation to be measured AGAINST - without one, "the
                  zone sees only lo" is not evidence, because the host sees
                  only lo as well.

  QEMU=/path/to/qemu-system-x86_64 selects a specific binary.
  QEMU_DATADIR=/path/to/share/qemu points a relocated QEMU at its own BIOS,
  VGA ROMs and firmware blobs. A QEMU unpacked somewhere other than / cannot
  find them on its own and fails with "could not load PC BIOS", which reads
  like a broken image rather than a search-path problem.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel) KERNEL="$2"; shift 2 ;;
        --initrd) INITRD="$2"; shift 2 ;;
        --log) LOG="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --mem) MEM="$2"; MEM_SET_BY_USER=1; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --append) EXTRA_APPEND="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        --root-disk) ROOT_DISK=1; shift ;;
        --nic) NIC="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$KERNEL" ]] || { usage; die "--kernel is required"; }
if (( ROOT_DISK )); then
    [[ -n "$DISK" ]] || { usage; die "--root-disk needs --disk"; }
    [[ -z "$INITRD" ]] || die "--root-disk and --initrd are alternatives: the
 disk IS the root filesystem, and an initramfs would take over as / instead."
else
    [[ -n "$INITRD" ]] || { usage; die "--initrd is required (or --root-disk with --disk)"; }
fi
[[ -n "$LOG" ]]    || { usage; die "--log is required"; }
[[ -r "$KERNEL" ]] || die "kernel not readable: $KERNEL"
if [[ -n "$INITRD" ]]; then
    [[ -r "$INITRD" ]] || die "initramfs not readable: $INITRD"
fi
command -v "$QEMU" >/dev/null 2>&1 || [[ -x "$QEMU" ]] || die "qemu not found: $QEMU"

mkdir -p "$(dirname "$LOG")"
: > "$LOG"

# Acceleration. KVM needs only group membership on /dev/kvm, never root.
ACCEL=()
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL=(-accel kvm -cpu host)
    ACCEL_NAME="kvm"
else
    # TCG is 10-40x slower. It proves the same isolation properties, so the
    # run is not skipped - the timeout is raised instead, and the harness
    # reports which one was used so a slow result is not read as a hang.
    ACCEL=(-accel tcg -cpu max)
    ACCEL_NAME="tcg (software emulation; no /dev/kvm)"
    TIMEOUT=$(( TIMEOUT * 3 ))
fi

# Networking. The default remains NONE: a test VM that cannot reach anything is
# the right default, and every check that matters runs without a NIC.
# -no-reboot is right for every mode but one: a panic should end the run rather
# than loop forever. The restart mode is the exception, because the thing it is
# measuring IS the reboot - the guest resets, the firmware runs again, and the
# second boot has to come back on its own. The payload powers off on that second
# boot, so the run still terminates; the harness timeout is the backstop if it
# does not.
REBOOT_ARGS=(-no-reboot)
if [[ "$MODE" == "restart" ]]; then
    REBOOT_ARGS=()
    printf 'run-qemu: reboot  allowed once - restart mode measures the second boot\n' >&2
fi

INITRD_ARGS=()
[[ -n "$INITRD" ]] && INITRD_ARGS=(-initrd "$INITRD")

DISK_ARGS=()
if [[ -n "$DISK" ]]; then
    [[ -f "$DISK" ]] || die "--disk $DISK is not a file. This harness only ever
 attaches images it made; it will not open a device node."
    case "$(readlink -f "$DISK")" in
        /dev/*) die "--disk $DISK resolves to a device node. Refusing: the guest
 gets write access to whatever this names." ;;
    esac
    # -snapshot: the guest's writes go to a temporary file QEMU makes and
    # deletes, never to the image. Two reasons, and both matter. The image is
    # an artifact whose sha256 is recorded as evidence, and a boot that edited
    # it would invalidate the record it was measured against. And a smoke check
    # that mutates its own input is not repeatable: the second run would be
    # testing something the first run wrote.
    # cache=writeback rather than unsafe: with -snapshot every write is
    # discarded at exit regardless, so "unsafe" bought no durability trade and
    # only kept more dirty pages in the host's page cache - which is the
    # resource that ran out.
    DISK_ARGS=(-drive "file=$DISK,format=raw,if=virtio,cache=writeback" -snapshot)
    printf 'run-qemu: disk    %s (raw, virtio, disposable)\n' "$DISK" >&2
fi

case "$NIC" in
    none)
        NIC_ARGS=(-nic none)
        ;;
    user)
        # QEMU user-mode networking. The NAT runs inside the QEMU process; there
        # is no tap device, no bridge, no capability and no root, and nothing
        # survives the process exiting. The host's own NIC is untouched.
        # -netdev plus -device, not -nic, because romfile= is a DEVICE
        # property and -nic rejects it outright ("Invalid parameter 'romfile'").
        #
        # romfile= disables the NIC's option ROM. Without it QEMU insists on
        # efi-virtio.rom - an iPXE image that ships in a separate package - and
        # refuses to start at all if it is absent. That is a hard failure over a
        # boot path this VM never uses: it boots from -kernel and has no reason
        # to PXE.
        # shellcheck disable=SC2054  # commas belong to QEMU's option syntax,
        # they are not array separators: each element here is one argv entry.
        NIC_ARGS=(-netdev user,id=kn0 -device virtio-net-pci,netdev=kn0,romfile=)
        printf 'run-qemu: nic     user-mode NAT (guest gets a virtio NIC; host NIC untouched)\n' >&2
        ;;
    *)
        die "--nic must be 'none' or 'user', not '$NIC'"
        ;;
esac

APPEND="console=ttyS0,115200 panic=-1 loglevel=6 kryptik.mode=$MODE $EXTRA_APPEND"
if (( ROOT_DISK && ! MEM_SET_BY_USER )); then
    MEM="$ROOT_DISK_MEM"
    printf 'run-qemu: mem     %sM (disk-rooted: no RAM needed for the root filesystem)\n' "$MEM" >&2
fi

if (( ROOT_DISK )); then
    # init=/init because the image's stage-1 init is at the root, where an
    # initramfs would have found it; rw because the zone tests write.
    APPEND="root=/dev/vda rw init=/init $APPEND"
fi

printf 'run-qemu: accel   %s\n' "$ACCEL_NAME" >&2
printf 'run-qemu: kernel  %s\n' "$KERNEL" >&2
if [[ -n "$INITRD" ]]; then
    printf 'run-qemu: initrd  %s (%s bytes)\n' "$INITRD" "$(stat -c %s "$INITRD")" >&2
else
    printf 'run-qemu: initrd  none - the disk is the root filesystem\n' >&2
fi
printf 'run-qemu: mode    %s, timeout %ss\n' "$MODE" "$TIMEOUT" >&2
printf 'run-qemu: log     %s\n' "$LOG" >&2

QEMU_ARGS=()
# A QEMU installed outside / (unpacked from a package into a prefix, for
# instance) cannot find bios-256k.bin and friends. -L points it at them.
if [[ -n "${QEMU_DATADIR:-}" ]]; then
    [[ -d "$QEMU_DATADIR" ]] || die "QEMU_DATADIR is not a directory: $QEMU_DATADIR"
    QEMU_ARGS+=(-L "$QEMU_DATADIR")
    printf 'run-qemu: datadir %s\n' "$QEMU_DATADIR" >&2
fi

QEMU_ARGS+=(
    -m "$MEM"
    "${DISK_ARGS[@]}"
    -smp "$CPUS"
    "${ACCEL[@]}"
    -kernel "$KERNEL"
    "${INITRD_ARGS[@]}"
    -append "$APPEND"
    "${NIC_ARGS[@]}"
    "${REBOOT_ARGS[@]}"
    -display none
)

if [[ "$MODE" == "console" ]]; then
    # Interactive: serial on this terminal, and a copy to the log.
    QEMU_ARGS+=(-serial mon:stdio)
    set +e
    "$QEMU" "${QEMU_ARGS[@]}" 2>&1 | tee "$LOG"
    rc=${PIPESTATUS[0]}
    set -e
else
    QEMU_ARGS+=(-serial "file:$LOG")
    set +e
    timeout --foreground "$TIMEOUT" "$QEMU" "${QEMU_ARGS[@]}"
    rc=$?
    set -e
    if (( rc == 124 )); then
        printf 'run-qemu: TIMED OUT after %ss\n' "$TIMEOUT" >&2
    fi
fi

# What the harness booted, appended to its own log so that boot-smoke stays a
# pure log reader. These are HOST facts and are named as such: the guest cannot
# know which file was handed to qemu, and the host cannot know what the guest
# did with it. boot-smoke compares the two.
#
# `file` prints the version string that is compiled into the bzImage, which is
# the same string the running kernel reports in /proc/version.
{
    printf 'KRYPTIK_HOST_KERNEL_FILE=%s\n' "$KERNEL"
    printf 'KRYPTIK_HOST_KERNEL_SHA256=%s\n' "$(sha256sum "$KERNEL" 2>/dev/null | cut -d" " -f1)"
    kfv="$(file -b "$KERNEL" 2>/dev/null | sed -n 's/.*version \([^ ]*\) .*/\1/p')"
    printf 'KRYPTIK_HOST_KERNEL_VERSION=%s\n' "$kfv"
} >> "$LOG" 2>/dev/null || true

printf 'run-qemu: qemu exited %s, serial log %s bytes\n' "$rc" "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" >&2
exit "$rc"
