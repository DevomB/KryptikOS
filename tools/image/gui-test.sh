#!/usr/bin/env bash
#
# The zoned desktop on the INSTALLED system (gate G8): install from the
# medium, boot the disk alone with a virtual GPU, keyboard and mouse, start
# the desktop session for an ordinary user and run the guest-side checks
# (build/guest-tests/gui-check.sh) as root over the serial login, pressing
# keys and taking screenshots through QMP where the guest asks for them.
#
#   tools/image/gui-test.sh --usb IMG [--disk FILE] [--timeout N]
#
# What the host adds to the guest's verdicts: a screenshot while a zone
# window is focused, in which the zone's focused border colour (from
# build/desktop/zone-colours.h, the same table dwl was built with) must
# actually be on screen; the fullscreen toggle (Alt+e) and the yes/no to
# the transfer questions, delivered as keystrokes on the guest's keyboard
# so the trusted windows are exercised by input, not by writing their
# answer files for them.
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
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/gui.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
phase() { printf '\n==> %s\n' "$*"; }
TUSER=tester; TPASS=tester-pw; RPASS=root-pw
TUSER_HASH="$(openssl passwd -6 "$TPASS")"; ROOT_HASH="$(openssl passwd -6 "$RPASS")"
DRV="${SELF}/vm-drive.py"
VARSF="${VMDIR}/gui-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
LATEST="${KRYPTIK_WORK}/logs/ovmf-serial.latest.log"
SHOT="${VMDIR}/gui-untrusted.ppm"
SHOT_FS="${VMDIR}/gui-untrusted-fullscreen.ppm"

# ---------------------------------------------------------------- phase 1 --
phase "phase 1: install"
rm -f "$DISK"; truncate -s 12G "$DISK"
CTL="${VMDIR}/testctl-gui.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars clean --mode smoke --timeout "$TIMEOUT" --name gui-install > /dev/null
tr -d '\r' < "$LATEST" | grep -q 'KRYPTIK_INSTALL: rc=0' && green "installed" || { red "install failed"; exit 1; }

# ---------------------------------------------------------------- phase 2 --
phase "phase 2: the desktop, driven"
rm -f "$SHOT" "$SHOT_FS"
out="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --net user --gpu --mem 3072 --name gui-p2)"
SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"; QMP="$(sed -n 's/^qmp=//p' <<<"$out")"
[[ -S "$SER" ]] || die "no serial socket: ${out}"
python3 "$DRV" --serial "$SER" --qmp "$QMP" --timeout 600 \
    "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "send:su - root -c 'bash /usr/lib/kryptik/guest-tests/gui-check.sh ${TUSER} 2>&1 | tee /var/log/kryptik/gui-check.log; echo GCHECK-DONE'" \
    "expect:Password: ?" "send:${RPASS}" \
    "expect:GT SCREENSHOT-READY" "sleep:2" "screendump:${SHOT}" \
    "expect:GT KEY-FULLSCREEN\r?\n" "key:alt+e" \
    "expect:GT SCREENSHOT-FULLSCREEN" "sleep:2" "screendump:${SHOT_FS}" \
    "expect:GT KEY-FULLSCREEN-AGAIN" "key:alt+e" \
    "expect:GT CONSENT-WAIT 1" "sleep:6" "key:y" "key:ret" \
    "expect:GT CONSENT-WAIT 2" "sleep:6" "key:n" "key:ret" \
    "expect:GT END" "expect:GCHECK-DONE" \
    "send:su - root -c 'poweroff'" "expect:Password: ?" "send:${RPASS}" \
    "expect:Power down" "wait-exit"
drc=$?
sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
T="$(tr -d '\r' < "$LOG")"
[[ "$drc" -eq 0 ]] && green "the guest checks ran to their end with the keystrokes delivered" || red "the drive failed (see above)"
summary="$(grep -o 'GT SUMMARY passed=[0-9]* failed=[0-9]*' <<<"$T" | tail -1)"
echo "  guest summary: ${summary:-none}"
gp="$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<<"$summary")"; gf="$(sed -n 's/.*failed=\([0-9]*\).*/\1/p' <<<"$summary")"
if [[ -n "$summary" && "${gf:-1}" -eq 0 && "${gp:-0}" -ge 25 ]]; then green "every guest check passed (${gp})"; else red "guest checks: ${gp:-0} passed, ${gf:-?} failed"; fi
grep 'GT FAIL' <<<"$T" | sed 's/^/        /'
for name in session-socket compositor-running chrome-focus-record chrome-window-is-zone0 zone0-sees-capture zone-proxy-path zone-sees-needed zone-hidden-globals zone-bind-refused proxy-logged-refusal \
            focus-shows-zone focus-shows-label title-prefixed fullscreen-identity-recorded second-zone-window no-virtual-input clipboard-isolated clipboard-move-gesture clipboard-moved \
            transfer-policy no-question-for-policy-refusal transfer-approved transfer-landed transfer-denied denied-file-absent; do
    grep -q "GT PASS ${name}" <<<"$T" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ---------------------------------------------------------------- phase 3 --
phase "phase 3: the screenshots show the zone's border, windowed and fullscreen"
check_shot() {   # check_shot FILE WHAT
local shot="$1" what="$2" verdict
if [[ -s "$shot" ]]; then
    # The colours dwl was built with: the header is the single source.
    verdict="$(python3 - "$shot" "${SELF}/../../build/desktop/zone-colours.h" <<'PY'
import re, sys
shot, header = sys.argv[1], sys.argv[2]
h = open(header).read()
m = re.search(r'X\("untrusted",\s*0x([0-9a-f]{6})ff,\s*0x([0-9a-f]{6})ff\)', h)
border, focus = m.group(1), m.group(2)
def rgb(x): return tuple(int(x[i:i+2], 16) for i in (0, 2, 4))
data = open(shot, "rb").read()
# P6: magic, width, height, maxval (comments allowed), one whitespace, then pixels
tokens = []; pos = 0
while len(tokens) < 4:
    while data[pos:pos+1].isspace(): pos += 1
    if data[pos:pos+1] == b"#":
        while data[pos:pos+1] not in (b"\n", b""): pos += 1
        continue
    start = pos
    while not data[pos:pos+1].isspace(): pos += 1
    tokens.append(data[start:pos])
pos += 1
w, hgt = int(tokens[1]), int(tokens[2])
px = data[pos:pos + w * hgt * 3]
counts = {}
for name, col in (("focused", rgb(focus)), ("unfocused", rgb(border)), ("white", (255, 255, 255))):
    counts[name] = sum(1 for i in range(0, len(px), 3) if px[i] == col[0] and px[i+1] == col[1] and px[i+2] == col[2])
print(f"  screenshot {w}x{hgt}: untrusted focused #{focus}: {counts['focused']} px, unfocused #{border}: {counts['unfocused']} px, unzoned white: {counts['white']} px")
# a 4 px border around even a small window is thousands of pixels; require hundreds
print("SHOT-OK" if counts["focused"] + counts["unfocused"] >= 400 else "SHOT-NO-BORDER")
PY
)"
    printf '%s\n' "$verdict" | grep -v 'SHOT-'
    [[ "$verdict" == *SHOT-OK* ]] && green "${what}: the zone window's border is on screen in the zone's colour (${shot})" || red "${what}: the zone's border colour was not found in the screenshot (${shot})"
else
    red "${what}: no screenshot was taken"
fi
}
check_shot "$SHOT" "windowed"
# dwl keeps the zone border in fullscreen (dwl-zone-borders.py edit 6), so a
# window cannot hide which zone it belongs to by going fullscreen.
check_shot "$SHOT_FS" "fullscreen"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Guest log: /var/log/kryptik/gui-check.log on ${DISK}; serial transcript ${LOG}; screenshots ${SHOT} ${SHOT_FS}"
[[ "$FAIL" -eq 0 ]] || exit 1
