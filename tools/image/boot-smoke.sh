#!/usr/bin/env bash
# Boot a Kryptik disk image and assert on what the serial console said.
#
#   tools/image/boot-smoke.sh --image IMG --kernel FILE [--timeout 240]
#
# Boots with kryptik.smoke=1, which is the only thing that arms the in-guest
# boot-smoke service. The guest reports what it is, then powers itself off;
# this reads the transcript and decides.
#
# A launch failure is not a pass. Every assertion below is positive - something
# had to appear in the log - and the absence of the whole transcript fails
# rather than silently satisfying "no errors found".
set -uo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR
set +e

IMAGE=""; KERNEL=""; TIMEOUT="240"
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --image)   IMAGE="${2:?}";   shift 2 ;;
        --kernel)  KERNEL="${2:?}";  shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$IMAGE"  ]] || die "--image is required"
[[ -n "$KERNEL" ]] || die "--kernel is required"

PASS=0; FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
want()  { # want <description> <regex>
    if grep -qE "$2" "$SERIAL"; then green "$1"; else red "$1"; fi
}
deny()  { # deny <description> <regex that must NOT appear>
    if grep -qE "$2" "$SERIAL"; then red "$1"; else green "$1"; fi
}

log "booting for smoke"
"${SELF}/run-qemu-disk.sh" --image "$IMAGE" --kernel "$KERNEL" \
    --mode smoke --timeout "$TIMEOUT" --append "kryptik.smoke=1"
qrc=$?
SERIAL="${KRYPTIK_WORK}/logs/vm-serial.latest.log"
[[ -f "$SERIAL" ]] || die "no serial log at ${SERIAL}"
echo "serial log: ${SERIAL} ($(grep -c '' < "$SERIAL") lines)"
echo

# The transcript has to exist at all. Without this every check below could
# pass vacuously on an empty file.
echo "-- the guest got far enough to speak"
want "kernel produced output"            'Linux version'
want "boot-smoke ran"                    'KRYPTIK_SMOKE: BEGIN'
want "boot-smoke finished"               'KRYPTIK_SMOKE: END'

echo
echo "-- it is Kryptik, measured inside the guest"
want "pid 1 is s6-svscan"                'KRYPTIK_SMOKE: pid1=s6-svscan'
want "os-release says kryptik"           'KRYPTIK_SMOKE: os_id=kryptik'
want "the image carries its provenance"  'KRYPTIK_SMOKE: image_json_present=yes'
want "compiler targets kryptik"          'KRYPTIK_SMOKE: compiler=x86_64-kryptik-linux-gnu'
want "root came from a virtio disk"      'KRYPTIK_SMOKE: root_source=/dev/vda2'

echo
echo "-- the mounts sysinit is responsible for"
for m in /proc /sys /dev/pts /dev/shm /run; do
    want "mounted ${m}" "KRYPTIK_SMOKE: mount_ok=${m}$"
done
deny "no mount reported missing"         'KRYPTIK_SMOKE: mount_MISSING='

echo
echo "-- services the database brought up"
want "eudev is supervised"               'KRYPTIK_SMOKE: svc_eudev=up'
want "getty-tty1 is supervised"          'KRYPTIK_SMOKE: svc_getty-tty1=up'

echo
echo "-- the hardening tunables reached the kernel"
want "kptr_restrict=2"                   'sysctl kernel.kptr_restrict=2'
want "dmesg_restrict=1"                  'sysctl kernel.dmesg_restrict=1'
want "yama.ptrace_scope=3"               'sysctl kernel.yama.ptrace_scope=3'
want "unprivileged_bpf_disabled=1"       'sysctl kernel.unprivileged_bpf_disabled=1'
want "kexec_load_disabled=1"             'sysctl kernel.kexec_load_disabled=1'

echo
echo "-- the zone model on this kernel"
want "kryptikd checked the kernel"       'KRYPTIK_SMOKE: kryptikd_check_begin'
want "landlock is an active LSM"         'KRYPTIK_SMOKE: lsm=.*landlock'
want "cgroup v2 is mounted"              'KRYPTIK_SMOKE: cgroup2=/'

echo
echo "-- it shut down, rather than being killed"
want "poweroff was requested"            'KRYPTIK_SMOKE: POWEROFF'
want "the machine powered down"          'reboot: Power down|Power down'
deny "no kernel panic"                   'Kernel panic'
deny "no oops"                           'Oops:|BUG:'
[[ "$qrc" -ne 124 ]] && green "qemu exited without hitting the timeout" \
                     || red "qemu hit the ${TIMEOUT}s timeout"

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed."
    echo "Transcript: ${SERIAL}"
    exit 1
fi
echo "All ${PASS} checks passed."
