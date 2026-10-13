#!/usr/bin/env bash
#
# Sound on the INSTALLED system (the sound suite): install from the medium, boot the disk alone
# with two HD Audio cards, the first playing into a WAV file on the host and the second
# recording silence, and run the guest-side checks (build/guest-tests/sound-check.sh) as root
# over the serial login.
#
#   tools/image/sound-test.sh --usb IMG [--disk FILE] [--timeout N]
#
# The guest finds both cards with their codecs bound. The kernel loads no module by itself, so
# that rests on modprobe loading every codec driver before snd-hda-intel probes
# (build/config/modprobe.d/sound.conf). Then zones play and record through zone 0's mixer:
# the host finds a zone's tone in what the first card played, and two zones' tones together.
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
step "step 2: the cards and the mixer, from the guest"
rm -f "$WAV"
start_vm sound-p2 --net user --sound "$WAV"
DRIVE_TIMEOUT=600 drive --qmp "$QMP" \
    "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "send:su - root -c 'bash /usr/lib/kryptik/guest-tests/sound-check.sh ${TUSER} 2>&1; echo SNDCHECK-DONE'" \
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
if [[ -n "$summary" && "${gf:-1}" -eq 0 && "${gp:-0}" -ge 21 ]]; then green "every guest check passed (${gp})"; else red "guest checks: ${gp:-0} passed, ${gf:-?} failed"; fi
grep 'GT FAIL' <<<"$T" | sed 's/^/        /'
for name in sound-card codec-bound codec-drivers-ahead pcm-nodes zone-proc-asound-empty mixer-running mixer-zones mixer-own-user \
            zone-socket-no-card zone-plays zones-play-together record-refused-ungranted status-shows-recording \
            holder-recorded record-granted grant-ends-with-zone holder-cleared foreign-uid-refused chrome-grants-microphone \
            chrome-takes-microphone-back chrome-sets-volume microphone-window volume-steps; do
    grep -q "GT PASS ${name}" <<<"$T" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ----------------------------------------------------------------- step 3 --
step "step 3: what the first card played"
# Quarter seconds with sound in them, each read for 440 Hz and 660 Hz (Goertzel): one tone's
# share of the power is near a half alone and a quarter beside another, and near none when it
# is not playing.
heard="$(python3 - "$WAV" <<'PY'
import array, math, struct, sys
raw = open(sys.argv[1], "rb").read()
if raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
    sys.exit("not a WAV file")
pos, rate, ch, data = 12, 0, 0, b""
while pos + 8 <= len(raw):
    cid, size = raw[pos:pos + 4], struct.unpack("<I", raw[pos + 4:pos + 8])[0]
    if cid == b"fmt ":
        _, ch, rate = struct.unpack("<HHI", raw[pos + 8:pos + 16])
    if cid == b"data":
        # QEMU writes the size when it exits; a file it did not close holds what it wrote.
        end = pos + 8 + size if 0 < size <= len(raw) - pos - 8 else len(raw)
        data = raw[pos + 8:end]
        break
    pos += 8 + size + (size & 1)
if not rate or not ch:
    sys.exit("no format chunk")
frames = array.array("h", data[:len(data) // (2 * ch) * 2 * ch])[::ch]
win = rate // 4
def share(x, f, energy):
    k = 2 * math.cos(2 * math.pi * f / rate)
    s1 = s2 = 0.0
    for v in x:
        s1, s2 = v + k * s1 - s2, s1
    return (s1 * s1 + s2 * s2 - k * s1 * s2) / (len(x) * energy)
alone = together = loud = 0
for i in range(0, len(frames) - win + 1, win):
    x = frames[i:i + win]
    energy = sum(v * v for v in x)
    if energy < win * 300 ** 2:
        continue
    loud += 1
    a, b = share(x, 440, energy) > 0.1, share(x, 660, energy) > 0.1
    alone += a and not b
    together += a and b
print(f"{rate} Hz, {len(frames) / rate:.1f} s, {loud} quarter seconds with sound: "
      f"{alone} of 440 Hz alone, {together} of 440 Hz and 660 Hz together")
PY
)"
echo "  ${heard:-no reading}"
alone="$(sed -n 's/.*sound: \([0-9]*\) of 440 Hz alone.*/\1/p' <<<"$heard")"
together="$(sed -n 's/.*alone, \([0-9]*\) of 440 Hz and 660 Hz together.*/\1/p' <<<"$heard")"
[[ "${alone:-0}" -ge 8 ]] && green "a zone's tone reached the card: ${alone} quarter seconds of 440 Hz alone" \
    || red "the zone's tone is not in what the card played (${alone:-0} quarter seconds of 440 Hz alone)"
[[ "${together:-0}" -ge 4 ]] && green "two zones were mixed: ${together} quarter seconds of 440 Hz and 660 Hz together" \
    || red "two zones' tones were not mixed (${together:-0} quarter seconds of both)"
rm -f "$WAV"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Serial transcript ${LOG}"
[[ "$FAIL" -eq 0 ]] || exit 1
