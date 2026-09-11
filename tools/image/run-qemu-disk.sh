#!/usr/bin/env bash
# Boot a Kryptik disk image under QEMU on a serial console.
#
#   tools/image/run-qemu-disk.sh --image IMG [--kernel FILE] [--mode console|smoke]
#
# --mode console  interactive serial console, no timeout
# --mode smoke    boot, capture the serial log, power off, and report
#
# Uses -kernel because the image has no bootloader yet; see tools/image/mkdisk.sh.
# Nothing here touches the host's disks, boot configuration or networking:
# QEMU gets one file and, unless --net is given, no NIC at all.
set -Eeuo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"

IMAGE=""
KERNEL=""
MODE="console"
MEM="2048"
CPUS="2"
TIMEOUT="180"
NET="none"
EXTRA_APPEND=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --image)   IMAGE="${2:?}";  shift 2 ;;
        --kernel)  KERNEL="${2:?}"; shift 2 ;;
        --mode)    MODE="${2:?}";   shift 2 ;;
        --mem)     MEM="${2:?}";    shift 2 ;;
        --cpus)    CPUS="${2:?}";   shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --net)     NET="user";      shift ;;
        --append)  EXTRA_APPEND="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$IMAGE" ]] || die "--image is required"
[[ -f "$IMAGE" ]] || die "no such image: ${IMAGE}"

# QEMU: the host's if it has one, otherwise the copy integration unpacked.
QEMU="$(command -v qemu-system-x86_64 2>/dev/null || true)"
for cand in "${KRYPTIK_QEMU:-}" \
            "$HOME/kryptik-overnight-2026-09-11/tooling/qemu/usr/bin/qemu-system-x86_64"; do
    [[ -n "$QEMU" ]] && break
    [[ -n "$cand" && -x "$cand" ]] && QEMU="$cand"
done
[[ -n "$QEMU" ]] || die "no qemu-system-x86_64 found. Set KRYPTIK_QEMU to one."

# The unpacked QEMU is a relocated Debian package, not an installed one: its
# libraries sit beside it rather than on the system search path, and its BIOS
# and option ROMs live under usr/share/qemu. Without the first it dies with
# "libfdt.so.1: cannot open shared object file"; without the second it starts
# and then cannot find a BIOS. A QEMU found on the host PATH needs neither.
QEMU_ENV=(env)
case "$QEMU" in
    */tooling/qemu/usr/bin/qemu-system-x86_64)
        QEMU_PREFIX="${QEMU%/usr/bin/qemu-system-x86_64}"
        QEMU_LIB="${QEMU_PREFIX}/usr/lib/x86_64-linux-gnu"
        QEMU_DATA="${QEMU_PREFIX}/usr/share/qemu"
        if [[ -d "$QEMU_LIB" ]]; then
            QEMU_ENV=(env "LD_LIBRARY_PATH=${QEMU_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}")
        fi
        ;;
esac

# Prove it can start before a boot depends on it. A missing shared library here
# is a two-second failure with a readable message; discovered during the boot
# it is an empty serial log and a timeout.
if ! "${QEMU_ENV[@]}" "$QEMU" --version >/dev/null 2>&1; then
    die "found ${QEMU} but it will not run:
$("${QEMU_ENV[@]}" "$QEMU" --version 2>&1 | head -3)"
fi

# A kernel is required while the image has no bootloader. Fall back to one
# inside the image's own /boot if the caller did not name one.
if [[ -z "$KERNEL" ]]; then
    die "--kernel is required: this image has no bootloader yet.
Use the kernel stage 05 installed, e.g.
  --kernel \${KRYPTIK_WORK}/sysroot/boot/kryptik-<version>"
fi
[[ -f "$KERNEL" ]] || die "no such kernel: ${KERNEL}"

# console=ttyS0 so everything lands on the serial line we capture.
# root=/dev/vda2: partition 1 is reserved for the ESP; see mkdisk.sh.
APPEND="root=/dev/vda2 rootwait rw console=ttyS0,115200 panic=10 ${EXTRA_APPEND}"

# shellcheck disable=SC2054  # the commas are QEMU option syntax
#   (q35,accel=tcg / file=...,format=raw), not array separators.
# A full boot under TCG takes minutes; with KVM it takes seconds. Fall back
# to TCG rather than failing when /dev/kvm is not usable.
ACCEL=tcg
CPUMODEL=max
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL=kvm
    CPUMODEL=host
fi

QEMU_ARGS=(
    -machine "q35,accel=${ACCEL}"
    -cpu "$CPUMODEL"
    -smp "$CPUS"
    -m "$MEM"
    -kernel "$KERNEL"
    -append "$APPEND"
    -drive "file=${IMAGE},format=raw,if=virtio,cache=unsafe"
    -nographic
    -no-reboot
)
[[ "$NET" == "none" ]] && QEMU_ARGS+=( -nic none )
[[ -n "${QEMU_DATA:-}" && -d "${QEMU_DATA}" ]] && QEMU_ARGS+=( -L "$QEMU_DATA" )

log "booting ${IMAGE##*/}"
dim "  qemu   : ${QEMU} (accel=${ACCEL})"
dim "  kernel : ${KERNEL}"
dim "  append : ${APPEND}"
dim "  mode   : ${MODE}"
echo

case "$MODE" in
console)
    dim "  interactive. Ctrl-A X to quit QEMU."
    echo
    exec "${QEMU_ENV[@]}" "$QEMU" "${QEMU_ARGS[@]}"
    ;;
smoke)
    LOGDIR="${KRYPTIK_WORK}/logs"
    mkdir -p "$LOGDIR"
    SERIAL="${LOGDIR}/vm-serial.$(date +%Y%m%dT%H%M%S).log"
    ln -sfn "$SERIAL" "${LOGDIR}/vm-serial.latest.log"

    # `timeout` rather than trusting the guest to power itself off: a kernel
    # panic with panic=10 reboots, and -no-reboot turns that into an exit, but
    # a hang in userspace would otherwise wait forever.
    set +e
    trap - ERR
    timeout --foreground "$TIMEOUT" "${QEMU_ENV[@]}" "$QEMU" "${QEMU_ARGS[@]}" \
        < /dev/null > "$SERIAL" 2>&1
    rc=$?
    trap _kryptik_trap ERR
    set -e

    echo "serial log: ${SERIAL}"
    [[ "$rc" -eq 124 ]] && warn "QEMU hit the ${TIMEOUT}s timeout"
    exit "$rc"
    ;;
*)
    die "unknown --mode ${MODE} (expected console or smoke)"
    ;;
esac
