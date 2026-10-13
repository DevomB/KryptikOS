#!/usr/bin/env bash
#
# Sound on the INSTALLED system (the sound suite): install from the medium, boot the disk alone
# with an HD Audio controller whose codec plays into a WAV file on the host, and run the
# guest-side checks (build/guest-tests/sound-check.sh) as root over the serial login.
#
#   tools/image/sound-test.sh --usb IMG [--disk FILE] [--timeout N]
#
# The guest finds the card with its codec bound. The kernel loads no module by itself, so
# that rests on modprobe loading every codec driver before snd-hda-intel probes
# (build/config/modprobe.d/sound.conf).
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
        -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/sound.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/sound-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
WAV="${VMDIR}/sound-out.wav"

# ----------------------------------------------------------------- step 1 --
step "step 1: install"
fresh_disk "$USB"
install_disk sound-install "$USB" --vars clean && green "installed" || { red "install failed"; exit 1; }

# ----------------------------------------------------------------- step 2 --
step "step 2: the card, from the guest"
rm -f "$WAV"
start_vm sound-p2 --net user --sound "$WAV"
DRIVE_TIMEOUT=300 drive --qmp "$QMP" \
    "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "send:su - root -c 'bash /usr/lib/kryptik/guest-tests/sound-check.sh 2>&1; echo SNDCHECK-DONE'" \
    "expect:Password: ?" "send:${RPASS}" \
    "expect:GT END" "expect:SNDCHECK-DONE" \
    "send:su - root -c 'poweroff'" "expect:Password: ?" "send:${RPASS}" \
    "expect:Power down" "wait-exit"
drc=$?
stop_vm
T="$(tr -d '\r' < "$LOG")"
[[ "$drc" -eq 0 ]] && green "the guest checks ran to their end" || red "the drive failed (see above)"
summary="$(grep -o 'GT SUMMARY passed=[0-9]* failed=[0-9]*' <<<"$T" | tail -1)"
echo "  guest summary: ${summary:-none}"
gp="$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<<"$summary")"; gf="$(sed -n 's/.*failed=\([0-9]*\).*/\1/p' <<<"$summary")"
if [[ -n "$summary" && "${gf:-1}" -eq 0 && "${gp:-0}" -ge 4 ]]; then green "every guest check passed (${gp})"; else red "guest checks: ${gp:-0} passed, ${gf:-?} failed"; fi
grep 'GT FAIL' <<<"$T" | sed 's/^/        /'
for name in sound-card codec-bound codec-drivers-ahead pcm-nodes; do
    grep -q "GT PASS ${name}" <<<"$T" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done
rm -f "$WAV"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Serial transcript ${LOG}"
[[ "$FAIL" -eq 0 ]] || exit 1
