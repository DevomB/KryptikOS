#!/usr/bin/env bash
#
# The zoned desktop on the INSTALLED system (the desktop suite): install from the
# medium, boot the disk alone with a virtual GPU, keyboard and mouse, start
# the desktop session for an ordinary user and run the guest-side checks
# (build/guest-tests/gui-check.sh) as root over the serial login, pressing
# keys and taking screenshots through QMP where the guest asks for them.
#
#   tools/image/gui-test.sh --usb IMG [--disk FILE] [--timeout N]
#
# What the host adds to the guest's verdicts: screenshots in which each
# window's frame is measured on all four sides, in its zone's colour from
# build/desktop/zone-colours.h (full width focused, narrower by the band
# unfocused), windowed, fullscreen and around a buffer larger than its
# window; the fullscreen toggle (Alt+e) and the yes/no to the transfer
# questions, delivered as keystrokes on the guest's keyboard, so the
# trusted windows are exercised by input, not by writing answer files.
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
        -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/gui.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/gui-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
SHOT="${VMDIR}/gui-untrusted.ppm"
SHOT_FS="${VMDIR}/gui-untrusted-fullscreen.ppm"
SHOT_OVER="${VMDIR}/gui-untrusted-oversize.ppm"

# ----------------------------------------------------------------- step 1 --
step "step 1: install"
# Sized from the medium, not a constant: see test-disk-size.sh.
DISK_SIZE="$("${SELF}/test-disk-size.sh" --medium "$USB")" || die "could not size the test disk from the medium"
rm -f "$DISK"; truncate -s "$DISK_SIZE" "$DISK"
CTL="${VMDIR}/testctl-gui.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "${PRESEED[@]}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars clean --mode smoke --timeout "$TIMEOUT" --name gui-install > /dev/null
tr -d '\r' < "$LATEST" | grep -q 'KRYPTIK_INSTALL: rc=0' && green "installed" || { red "install failed"; exit 1; }

# ----------------------------------------------------------------- step 2 --
step "step 2: the desktop, driven"
rm -f "$SHOT" "$SHOT_FS" "$SHOT_OVER"
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
    "expect:GT SCREENSHOT-OVERSIZE" "sleep:2" "screendump:${SHOT_OVER}" \
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
            focus-shows-zone focus-shows-label title-prefixed fullscreen-identity-recorded oversize-window second-zone-window no-virtual-input clipboard-isolated clipboard-move-gesture clipboard-moved \
            transfer-policy no-question-for-policy-refusal transfer-approved transfer-landed transfer-denied denied-file-absent; do
    grep -q "GT PASS ${name}" <<<"$T" && green "guest: ${name}" || red "guest: ${name} (not passed)"
done

# ----------------------------------------------------------------- step 3 --
step "step 3: the screenshots show every window framed on all four sides"
check_shot() {   # check_shot FILE WHAT ZONE:focused|unfocused...
local shot="$1" what="$2" verdict
shift 2
if [[ -s "$shot" ]]; then
    # The colours and widths dwl was built with: the headers are the single source.
    verdict="$(python3 - "$shot" "${SELF}/../../build/desktop/zone-colours.h" "${SELF}/../../build/desktop/dwl-config.h" "$@" <<'PY'
import re, sys
shot, colours_h, config_h, *want = sys.argv[1:]
h = open(colours_h).read()
c = open(config_h).read()
named = {z: bytes.fromhex(v) for z, v in re.findall(r'X\("(\w+)",\s*0x([0-9a-f]{6})ff\)', h)}
named["unzoned"] = bytes.fromhex(re.search(r'KRYPTIK_UNZONED_BORDER\s+0x([0-9a-f]{6})ff', h).group(1))
root = bytes.fromhex(re.search(r'rootcolor\[\]\s*=\s*COLOR\(0x([0-9a-f]{6})ff\)', c).group(1))
bw = int(re.search(r'\bborderpx\s*=\s*(\d+)', c).group(1))
band = int(re.search(r'\bbandpx\s*=\s*(\d+)', c).group(1))
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

def at(x, y):
    i = (y * w + x) * 3
    return px[i:i + 3]

def run(x, y, dx, dy, col):
    """Pixels of `col` from (x, y) on, one step (dx, dy) at a time."""
    n = 0
    while 0 <= x < w and 0 <= y < hgt and at(x, y) == col:
        n += 1; x += dx; y += dy
    return n

def frame(col):
    """The window framed in `col`, found by its top border (the first run of
    50 or more) and its left border (down from that run's start). A surface
    starts at (bw, bw), so neither can be covered; the right and bottom are
    then measured where they must be."""
    for y in range(hgt):
        x = 0
        while x < w:
            if at(x, y) != col:
                x += 1
                continue
            n = run(x, y, 1, 0, col)
            if n < 50:
                x += n
                continue
            x1, y1 = x + n - 1, y + run(x, y, 0, 1, col) - 1
            xm, ym = (x + x1) // 2, (y + y1) // 2
            return (x, y, x1, y1), {"top": run(xm, y, 0, 1, col), "bottom": run(xm, y1, 0, -1, col),
                                    "left": run(x, ym, 1, 0, col), "right": run(x1, ym, -1, 0, col)}
    return None, None

ok = True
for spec in want:
    zone, state = spec.split(":")
    col = named[zone]
    box, sides = frame(col)
    if box is None:
        print(f"  {zone} ({state}): no frame in #{col.hex()} on screen")
        ok = False
        continue
    expect = bw if state == "focused" else bw - band
    good = all(v == expect for v in sides.values())
    if state == "unfocused" and good:
        # The band, in the root colour, lies just inside each side.
        x0, y0, x1, y1 = box
        xm, ym = (x0 + x1) // 2, (y0 + y1) // 2
        good = min(run(xm, y0 + expect, 0, 1, root), run(xm, y1 - expect, 0, -1, root),
                   run(x0 + expect, ym, 1, 0, root), run(x1 - expect, ym, -1, 0, root)) >= band
    extra = f" + {band} band" if state == "unfocused" else ""
    print(f"  {zone} ({state}): frame {box[0]},{box[1]}-{box[2]},{box[3]}: top {sides['top']} bottom {sides['bottom']}"
          f" left {sides['left']} right {sides['right']} px, want {expect}{extra}{'' if good else '  <- WRONG'}")
    ok = ok and good
print("FRAME-OK" if ok else "FRAME-BAD")
PY
)"
    printf '%s\n' "$verdict" | grep -v 'FRAME-'
    [[ "$verdict" == *FRAME-OK* ]] && green "${what}: every window is framed in its zone's colour, at its width, on all four sides (${shot})" || red "${what}: a window's frame is missing or the wrong width (${shot})"
else
    red "${what}: no screenshot was taken"
fi
}
check_shot "$SHOT" "windowed" untrusted:focused unzoned:unfocused
# dwl keeps the zone border in fullscreen (dwl-zone-borders.py edit 8), so a
# window cannot hide which zone it belongs to by going fullscreen.
check_shot "$SHOT_FS" "fullscreen" untrusted:focused
# wlprobe oversize commits a buffer 40 px larger than its configure: the
# borders must stay above the surface, or its excess covers them.
check_shot "$SHOT_OVER" "oversized buffer" untrusted:focused unzoned:unfocused

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Guest log: /var/log/kryptik/gui-check.log on ${DISK}; serial transcript ${LOG}; screenshots ${SHOT} ${SHOT_FS} ${SHOT_OVER}"
[[ "$FAIL" -eq 0 ]] || exit 1
