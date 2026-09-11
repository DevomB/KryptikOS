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
MEM=3072
CPUS=2
QEMU="${QEMU:-qemu-system-x86_64}"
EXTRA_APPEND=""

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
        --mem) MEM="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --append) EXTRA_APPEND="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$KERNEL" ]] || { usage; die "--kernel is required"; }
[[ -n "$INITRD" ]] || { usage; die "--initrd is required"; }
[[ -n "$LOG" ]]    || { usage; die "--log is required"; }
[[ -r "$KERNEL" ]] || die "kernel not readable: $KERNEL"
[[ -r "$INITRD" ]] || die "initramfs not readable: $INITRD"
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

APPEND="console=ttyS0,115200 panic=-1 loglevel=6 kryptik.mode=$MODE $EXTRA_APPEND"

printf 'run-qemu: accel   %s\n' "$ACCEL_NAME" >&2
printf 'run-qemu: kernel  %s\n' "$KERNEL" >&2
printf 'run-qemu: initrd  %s (%s bytes)\n' "$INITRD" "$(stat -c %s "$INITRD")" >&2
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
    -smp "$CPUS"
    "${ACCEL[@]}"
    -kernel "$KERNEL"
    -initrd "$INITRD"
    -append "$APPEND"
    -nic none                 # no host networking, deliberately
    -no-reboot                # a panic ends the run instead of looping
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

printf 'run-qemu: qemu exited %s, serial log %s bytes\n' "$rc" "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" >&2
exit "$rc"
