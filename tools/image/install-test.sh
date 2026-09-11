#!/usr/bin/env bash
#
# Prove the installer works, by installing and then BOOTING what it produced.
#
# Two VMs:
#   1. boot the developer image with a blank second disk attached, and let the
#      installer write to it
#   2. boot that second disk as the root disk, and run the full boot smoke
#      against it
#
# Phase 2 is the point. "The installer exited 0" and "the system it produced
# boots" are different claims, and only the second is worth anything.
#
set -Eeuo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROG="${0##*/}"
die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }

IMAGE="" KERNEL="" DISK="" SIZE="6G" TIMEOUT="300"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)   IMAGE="${2:?}";   shift 2 ;;
        --kernel)  KERNEL="${2:?}";  shift 2 ;;
        --disk)    DISK="${2:?}";    shift 2 ;;
        --size)    SIZE="${2:?}";    shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help)
            printf 'usage: %s --image <dev.img> --kernel <f> [--disk <f>] [--size 6G]\n' "$PROG"
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$IMAGE"  ]] || die "--image is required"
[[ -f "$IMAGE"  ]] || die "no such image: ${IMAGE}"
[[ -n "$KERNEL" ]] || die "--kernel is required"
[[ -f "$KERNEL" ]] || die "no such kernel: ${KERNEL}"
DISK="${DISK:-${KRYPTIK_WORK:?KRYPTIK_WORK is not set}/images/kryptik-installed.img}"

# Same refusal as everywhere else that hands a path to something which will
# partition it: files only, never a device.
if [[ -e "$DISK" && ! -f "$DISK" ]]; then
    die "refusing to use ${DISK} as a target disk: it is a $(stat -c %F "$DISK"), not a file."
fi
case "$DISK" in
    /dev/*|/sys/*|/proc/*|/boot/*) die "refusing to use ${DISK} as a target disk." ;;
esac

PASS=0; FAIL=0
green() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
[[ -n "${NO_COLOR:-}" ]] && { green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
                              red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }; }

want() { if grep -qE "$2" "$1"; then green "$3"; else red "$3"; fi; }

# ---------------------------------------------------------------- phase 1 --
log "phase 1: a blank disk, and an installer pointed at it"
rm -f "$DISK"
mkdir -p "$(dirname "$DISK")"
truncate -s "$SIZE" "$DISK"
printf '  blank disk: %s (%s)\n' "$DISK" "$SIZE"

P1LOG="$(mktemp)"
trap 'rm -f "$P1LOG" "${P1LOG}.txt"' EXIT INT TERM

"${SELF}/run-qemu-disk.sh" --image "$IMAGE" --kernel "$KERNEL" \
    --extra-disk "$DISK" --mode smoke --timeout "$TIMEOUT" \
    --append "kryptik.install=/dev/vdb kryptik.smoke=1" > "$P1LOG" 2>&1 || true

SERIAL1="$(grep -oE '/[^ ]*vm-serial\.[0-9T]+\.log' "$P1LOG" | head -1 || true)"
[[ -n "$SERIAL1" && -f "$SERIAL1" ]] || {
    sed 's/^/  /' "$P1LOG" | tail -20
    die "phase 1 produced no serial log"
}
# Serial consoles emit CR LF; strip it before matching anything anchored.
tr -d '\r' < "$SERIAL1" > "${P1LOG}.txt"
printf '  transcript: %s (%s lines)\n\n' "$SERIAL1" "$(grep -c '' < "${P1LOG}.txt")"

want "${P1LOG}.txt" 'KRYPTIK_INSTALL: BEGIN target=/dev/vdb' "the installer was armed and ran"
want "${P1LOG}.txt" 'KRYPTIK_INSTALL: rc=0'                  "the installer exited 0"
want "${P1LOG}.txt" 'KRYPTIK_INSTALL: verify: 1 partition'   "a kryptik-root partition exists"
want "${P1LOG}.txt" 'KRYPTIK_INSTALL: verify: type=ext4'     "partition 2 is ext4"
want "${P1LOG}.txt" 'KRYPTIK_INSTALL: verify: os_id=kryptik' "the copied tree says it is kryptik"
want "${P1LOG}.txt" 'KRYPTIK_INSTALL: verify: has_init=yes'  "it has an init"
want "${P1LOG}.txt" 'KRYPTIK_INSTALL: verify: has_installjson=yes' \
                                                             "it records what installed it"
want "${P1LOG}.txt" 'KRYPTIK_INSTALL: verify: fstab_root=UUID=' \
                                                             "fstab names the root by UUID"
if grep -q 'KRYPTIK_INSTALL: FAILED' "${P1LOG}.txt"; then
    red "the installer reported a failure"
    grep 'KRYPTIK_INSTALL:' "${P1LOG}.txt" | sed 's/^/       /' | tail -20
fi

if [[ "$FAIL" -ne 0 ]]; then
    printf '\nphase 1 failed; not booting the result.\n'
    printf '%d passed, %d failed\n' "$PASS" "$FAIL"
    exit 1
fi

# ---------------------------------------------------------------- phase 2 --
log "phase 2: boot the disk the installer produced"
printf '  this is the claim that matters: not that the installer exited 0,\n'
printf '  but that what it wrote is a system that comes up.\n\n'

if "${SELF}/boot-smoke.sh" --image "$DISK" --kernel "$KERNEL" --timeout "$TIMEOUT"; then
    green "the installed system booted and passed the boot smoke"
else
    red "the installed system did not pass the boot smoke"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
