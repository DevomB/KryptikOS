#!/usr/bin/env bash
# Boot an install medium under OVMF and check what the guest printed.
#
#   tools/image/media-smoke.sh (--usb IMG | --iso ISO) [--vars clean|enrolled|ms]
#                              [--expect-refused] [--timeout N]
#
# Boots by firmware discovery alone (run-ovmf.sh); a kryptik-testctl disk arms
# the poweroff. Every check needs something to appear, so an empty run fails.
#
# --expect-refused: the store's keys did not sign our kernel (--vars ms), and
# the firmware must refuse it: the negative control for the enforced chain.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; ISO=""; VARS="clean"; REFUSED=0; TIMEOUT=420
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --iso) ISO="${2:?}"; shift 2 ;;
        --vars) VARS="${2:?}"; shift 2 ;;
        --expect-refused) REFUSED=1; shift ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$USB" || -n "$ISO" ]] || die "--usb or --iso is required"
MEDIUM="${USB:-$ISO}"; KIND="$([[ -n "$USB" ]] && echo usb || echo iso)"
[[ -f "$MEDIUM" ]] || die "no such medium: ${MEDIUM}"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
want()  { if grep -qE "$2" "$TXT"; then green "$1"; else red "$1"; fi; }
deny()  { if grep -qE "$2" "$TXT"; then red "$1"; else green "$1"; fi; }

VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
TESTCTL="${VMDIR}/testctl-smoke.img"
"${SELF}/mk-testctl.sh" --out "$TESTCTL" smoke_poweroff=1 > /dev/null || die "could not make the control disk"

log "media smoke: ${KIND} ${MEDIUM##*/} (variables: ${VARS})"
[[ "$REFUSED" -eq 1 ]] && [[ "$TIMEOUT" -gt 120 ]] && TIMEOUT=120
# A refused boot never powers off: it is stopped once the firmware says so.
UNTIL=()
[[ "$REFUSED" -eq 1 ]] && UNTIL=(--until 'Access Denied|Security Violation')
# This run's own log, never the shared "latest" symlink (maybe another run's).
SERIAL="${KRYPTIK_WORK}/logs/ovmf-serial.smoke-${KIND}-${VARS}$([[ "$REFUSED" -eq 1 ]] && echo -refused).$(date +%Y%m%dT%H%M%S).$$.log"
"${SELF}/run-ovmf.sh" "--${KIND}" "$MEDIUM" --testctl "$TESTCTL" --vars "$VARS" --mode smoke --timeout "$TIMEOUT" --name "smoke-${KIND}" --log "$SERIAL" "${UNTIL[@]}"
qrc=$?
[[ -f "$SERIAL" ]] || die "no serial log at ${SERIAL}"
TXT="$(mktemp)"; trap 'rm -f "$TXT"' EXIT
tr -d '\r' < "$SERIAL" > "$TXT"
echo "serial log: ${SERIAL} ($(grep -c '' < "$TXT") lines, qemu exit ${qrc})"
echo

if [[ "$REFUSED" -eq 1 ]]; then
    # No kernel or userspace ran, and the firmware itself refused the image:
    # an empty, hung or crashed boot is not a refusal. OVMF reports a Secure
    # Boot rejection as "Access Denied" (LoadImage's EFI_ACCESS_DENIED) or
    # "Security Violation" (DXE core), after naming the option it tried.
    echo "-- the firmware must refuse a kernel its keys did not sign (variables: ${VARS})"
    [[ "$VARS" == "ms" || "$VARS" == "enrolled" ]] || red "--expect-refused needs a store with Secure Boot on (ms or enrolled); '${VARS}' proves nothing"
    deny "no kernel banner appeared"                 'Linux version'
    deny "no Kryptik userspace ran"                  'KRYPTIK_SMOKE: BEGIN'
    want "the firmware tried the medium's boot file"  'BdsDxe: failed to load|BdsDxe: loading Boot'
    want "and refused it for its signature"          'Access Denied|Security Violation'
    deny "no firmware assertion or crash"            'ASSERT|Exception Type|!!!! X64'
    [[ "$qrc" -ne 0 ]] && green "the guest never powered itself off (nothing ran that could)" || red "qemu exited 0: something in the guest powered it off, which means something ran"
    echo
    if [[ "$FAIL" -gt 0 ]]; then
        echo "${FAIL} check(s) failed, ${PASS} passed. Transcript: ${SERIAL}"
        echo "A refusal is only proven by the firmware's own refusal message; a silent or broken boot is a failure of this test."
        exit 1
    fi
    echo "All ${PASS} checks passed: the ${KIND} medium was refused under foreign keys (${SERIAL})."
    exit 0
fi

echo "-- the firmware loaded our kernel from the medium's own boot file"
want "kernel produced output"              'Linux version'
want "the command line is the signed one"  'KRYPTIK_SMOKE: cmdline=.*kryptik\.media='"${KIND}"
want "booted as an install medium"         "KRYPTIK_SMOKE: boot_identity=slot= media=${KIND}"
want "UEFI boot"                           'KRYPTIK_SMOKE: efi=yes'
if [[ "$VARS" == "enrolled" ]]; then
    want "Secure Boot is enforced"         'KRYPTIK_SMOKE: secureboot=1'
else
    want "Secure Boot is off with a clean store" 'KRYPTIK_SMOKE: secureboot=(0|unreadable)'
fi

echo
echo "-- the root is the verified image"
if [[ "$KIND" == "iso" ]]; then
    want "root is the verity device over the CD"  'KRYPTIK_SMOKE: root_source=/dev/dm-1 ext4 ro'
else
    want "root is the verity device"       'KRYPTIK_SMOKE: root_source=/dev/dm-0 ext4 ro'
fi
want "dm-verity reports the root valid"   'KRYPTIK_SMOKE: verity_root=0 [0-9]+ verity V'
want "the root cannot be written"          'KRYPTIK_SMOKE: root_writable=no'
want "state is a tmpfs on this medium"     'KRYPTIK_SMOKE: var_source=tmpfs tmpfs'
want "/etc is an overlay"                  'KRYPTIK_SMOKE: etc_source=overlay'
for m in /var /etc /home /tmp /run /dev/pts /dev/shm; do
    want "mounted ${m}" "KRYPTIK_SMOKE: mount_ok=${m}$"
done
deny "no mount reported missing"           'KRYPTIK_SMOKE: mount_MISSING='

echo
echo "-- it is Kryptik, measured inside the guest"
want "boot-smoke ran"                      'KRYPTIK_SMOKE: BEGIN'
want "boot-smoke finished"                 'KRYPTIK_SMOKE: END'
want "pid 1 is s6-svscan"                  'KRYPTIK_SMOKE: pid1=s6-svscan'
want "os-release says kryptik"             'KRYPTIK_SMOKE: os_id=kryptik'
want "the image carries its provenance"    'KRYPTIK_SMOKE: image_json_present=yes'
want "kernel is the hardened build"        'KRYPTIK_SMOKE: kernel=.*hardened'
want "eudev is supervised"                 'KRYPTIK_SMOKE: svc_eudev=up'
want "seatd is supervised"                 'KRYPTIK_SMOKE: svc_seatd=up'
want "the watchdog feeder is supervised"   'KRYPTIK_SMOKE: svc_watchdog=up'
want "a watchdog is armed, no way out"     'KRYPTIK_SMOKE: watchdog watchdog[0-9]+: .* state=active .* nowayout=1'
want "landlock is an active LSM"           'KRYPTIK_SMOKE: lsm=.*landlock'
want "cgroup v2 is mounted"                'KRYPTIK_SMOKE: cgroup2=/'
want "kryptikd checked the kernel"         'KRYPTIK_SMOKE: kryptikd_check_rc=0'
want "processes run on hardened_malloc"    'KRYPTIK_SMOKE: allocator=hardened_malloc'
want "with room for its guard mappings"    'KRYPTIK_SMOKE: sysctl vm.max_map_count=1048576'
want "the installer was not armed"         'installer: no kryptik-testctl control disk|control disk names no install_target'

echo
echo "-- it shut down, rather than being killed"
want "poweroff was requested"              'KRYPTIK_SMOKE: POWEROFF'
want "the machine powered down"            'reboot: Power down|Power down'
deny "shutdown fell back to sysrq"         'POWEROFF_DID_NOT_TAKE_EFFECT'
deny "no kernel panic"                     'Kernel panic'
deny "no oops"                             'Oops:|BUG:'
[[ "$qrc" -ne 124 ]] && green "qemu exited without hitting the timeout" || red "qemu hit the ${TIMEOUT}s timeout"

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed. Transcript: ${SERIAL}"
    exit 1
fi
echo "All ${PASS} checks passed."
