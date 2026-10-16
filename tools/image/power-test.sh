#!/usr/bin/env bash
#
# The power source on the INSTALLED system (the power suite): install from the medium, boot the
# disk alone, and run the guest-side checks (build/guest-tests/power-check.sh) as root over the
# serial login, the kernel's test_power standing in for a battery and a mains adapter.
#
#   tools/image/power-test.sh --usb IMG [--disk FILE] [--timeout N]
#
# The power service follows the adapter, the chrome's menu names the source and the charge, and
# the chrome warns in a window at 10% and again at 5%.
# Then the battery is set to 2% unplugged: the service stops the zones and powers the machine
# off, and the host opens the state partition to find that it said so and that the running
# zone's volume was closed first.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; DISK=""; TIMEOUT=600
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate cryptsetup losetup; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/power.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/power-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"

# ----------------------------------------------------------------- step 1 --
step "step 1: install"
fresh_disk "$USB"
install_disk power-install "$USB" --vars clean && green "installed" || { red "install failed"; exit 1; }

# ----------------------------------------------------------------- step 2 --
step "step 2: the power source, from the guest, to a critical battery"
start_vm power-p2 --net user
DRIVE_TIMEOUT=900 drive --qmp "$QMP" \
    "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "send:su - root -c 'bash /usr/lib/kryptik/guest-tests/power-check.sh ${TUSER} 2>&1'" \
    "expect:Password: ?" "send:${RPASS}" \
    "expect:GT END" "expect:GT CRITICAL" "expect:Power down" "wait-exit"
drc=$?
stop_vm
T="$(tr -d '\r' < "$LOG")"
[[ "$drc" -eq 0 ]] && green "the guest ran its checks, and powered off at the critical battery" || red "the drive failed (see above)"
summary="$(grep -o 'GT SUMMARY passed=[0-9]* failed=[0-9]*' <<<"$T" | tail -1)"
echo "  guest summary: ${summary:-none}"
gp="$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<<"$summary")"; gf="$(sed -n 's/.*failed=\([0-9]*\).*/\1/p' <<<"$summary")"
if [[ -n "$summary" && "${gf:-1}" -eq 0 && "${gp:-0}" -ge 8 ]]; then green "every guest check passed (${gp})"; else red "guest checks: ${gp:-0} passed, ${gf:-?} failed"; fi
grep 'GT FAIL' <<<"$T" | sed 's/^/        /'
for name in power-service sleep-drivers power-key-drivers chrome-power-mains power-on-battery chrome-power-battery battery-warnings power-on-mains-again zone-running; do
    grep -q "GT PASS ${name}" <<<"$T" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ----------------------------------------------------------------- step 3 --
step "step 3: the state partition, after the power-off"
MNT="$(mktemp -d)"
if open_state "$DISK" "$MNT"; then
    d="$MNT/log/kryptik/power-check"
    said="$(grep -a 'power: the battery is at 2%' "$d/power.log" 2>/dev/null | tail -1)"
    [[ -n "$said" ]] && green "the service said why it powered off: ${said}" \
        || red "no word from the service about the critical battery: $(tail -2 "$d/power.log" 2>/dev/null | tr '\n' ' ')"
    closed="$(grep -a 'volume closed' "$d/work.out" 2>/dev/null | tail -1)"
    [[ -n "$closed" ]] && green "the running zone's volume was closed before the power went: ${closed}" \
        || red "work's launcher never closed its volume: $(tail -3 "$d/work.out" 2>/dev/null | tr '\n' ' ')"
    close_state "$MNT"
else
    red "the state partition did not open on the host"
fi
rmdir "$MNT" 2>/dev/null

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Serial transcript ${LOG}"
[[ "$FAIL" -eq 0 ]] || exit 1
