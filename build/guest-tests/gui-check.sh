#!/usr/bin/env bash
# The zoned desktop, measured on the installed system (gate G8). Runs as root
# inside the guest; tools/image/gui-test.sh boots the disk with a virtual GPU
# and keyboard, drives this over the serial login, takes screenshots and
# presses keys where this script says "GT ..." lines ask it to.
#
# Verdict lines start with "GT ": PASS/FAIL/INFO, a name, what was seen.
# Coordination lines the host reacts to:
#   GT SCREENSHOT-READY      a zone window is focused: take a screenshot
#   GT KEY-FULLSCREEN        press Alt+e (dwl: toggle fullscreen)
#   GT CONSENT-WAIT n        a transfer question is on screen: answer it
#                            (the host presses y or n, then Enter)
#   GT END
#
# What is measured, and how:
#   the session starts for an ordinary user (dwl on the virtual GPU through
#   seatd, the chrome as its startup command); zone 0's own client is
#   offered the capture and clipboard globals (positive control); a zone's
#   client, through its proxy, is offered neither and is disconnected for
#   asking; a zone window is recorded by the chrome with its zone and label
#   and its title carries the zone prefix; fullscreen keeps that record;
#   clipboards are per zone until the zone 0 gesture moves one payload; a
#   transfer waits for the person and lands only after yes, is refused
#   after no, and is refused without a question when policy forbids it.
set -u
Z=/usr/lib/kryptik/zones
R=/var/lib/kryptik/zones
KD=/usr/bin/kryptikd
USER_NAME="${1:-tester}"
UID_="$(id -u "$USER_NAME")"
RT="/run/user/$UID_"
LOG=/var/log/kryptik/gui-check
mkdir -p "$LOG" /root/gt
PASS=0; FAIL=0
pass() { echo "GT PASS $1${2:+ - $2}"; PASS=$((PASS + 1)); }
fail() { echo "GT FAIL $1${2:+ - $2}"; FAIL=$((FAIL + 1)); }
info() { echo "GT INFO $*"; }
as_user() { su -s /bin/bash "$USER_NAME" -c "XDG_RUNTIME_DIR=$RT WAYLAND_DISPLAY=wayland-0 $*"; }
wait_for() {   # wait_for SECONDS CMD...
    local n="$1"; shift
    while [[ "$n" -gt 0 ]]; do "$@" >/dev/null 2>&1 && return 0; n=$((n - 1)); sleep 1; done
    return 1
}
zone_log() { cat "/var/log/kryptik/zone-$1.log" 2>/dev/null; }
mark() { echo "--- $1 ---" >> "/var/log/kryptik/zone-$2.log" 2>/dev/null; }
since_mark() {   # since_mark MARK ZONE: the zone's log after the marker line
    awk -v m="--- $1 ---" '$0==m {p=1; next} p' "/var/log/kryptik/zone-$2.log" 2>/dev/null
}
PP=/root/gt/pass; printf 'zone-pass\n' > "$PP"; chmod 600 "$PP"
UPP="/home/$USER_NAME/.zone-pass"; cp "$PP" "$UPP"; chown "$USER_NAME" "$UPP"; chmod 600 "$UPP"
launch() {   # launch ZONE CMD...: as the user, with the passphrase on fd 3 for encrypted zones
    local zone="$1"; shift
    as_user "kryptik-launch --passphrase-fd 3 $zone -- $* 3<$UPP"
}
launch_plain() { local zone="$1"; shift; as_user "kryptik-launch $zone -- $*"; }

echo "GT BEGIN $(date -Iseconds 2>/dev/null)"
[[ "$(id -u)" = 0 ]] || { fail "root" "this must run as root"; echo "GT END"; exit 1; }
for z in work dev personal; do
    "$KD" volume init "$z" --size 64M --passphrase-file "$PP" > "$LOG/vol-$z.out" 2>&1 || fail "volume-$z" "$(tail -1 "$LOG/vol-$z.out")"
done
[[ -c /dev/dri/card0 ]] && pass "gpu-device" "/dev/dri/card0 present" || fail "gpu-device" "no /dev/dri/card0 (virtio-gpu?)"
[[ "$(s6-svstat -o up /run/service/seatd 2>/dev/null)" = true ]] && pass "seatd-up" || fail "seatd-up"
[[ "$(s6-svstat -o up /run/service/kryptikd-serve 2>/dev/null)" = true ]] && pass "launch-daemon-up" || fail "launch-daemon-up"

# --- the session --------------------------------------------------------------
su -s /bin/bash "$USER_NAME" -c 'setsid /usr/bin/kryptik-session </dev/null >/dev/null 2>&1 &'
if wait_for 30 test -S "$RT/wayland-0"; then pass "session-socket" "dwl listening at $RT/wayland-0"; else fail "session-socket" "$(cat "$RT/kryptik/session.log" 2>/dev/null | tail -3 | tr '\n' ' ')"; fi
pgrep -u "$USER_NAME" -x dwl >/dev/null && pass "compositor-running" || fail "compositor-running" "$(tail -3 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"
wait_for 20 test -f "$RT/kryptik/focus" && pass "chrome-focus-record" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "chrome-focus-record" "no $RT/kryptik/focus after 20 s"
grep -q '^zone=0' "$RT/kryptik/focus" 2>/dev/null && pass "chrome-window-is-zone0" "the launcher window is recorded as zone 0 (trusted)" || fail "chrome-window-is-zone0" "$(cat "$RT/kryptik/focus" 2>/dev/null | tr '\n' ' '); terminals: $(pgrep -u "$USER_NAME" -a havoc 2>/dev/null | tr '\n' ';'); session.log: $(tail -4 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"

# --- what zone 0 sees, and what a zone sees ---------------------------------------
as_user "/usr/libexec/kryptik/wlprobe list" > "$LOG/probe-zone0.out" 2>&1
grep -q 'zwlr_screencopy_manager_v1' "$LOG/probe-zone0.out" && grep -q 'wl_data_device_manager' "$LOG/probe-zone0.out" \
    && pass "zone0-sees-capture" "the compositor offers screencopy and the data device to zone 0's own client (positive control)" \
    || fail "zone0-sees-capture" "$(grep -c '^global' "$LOG/probe-zone0.out") globals; $(tail -1 "$LOG/probe-zone0.out")"
mark probe untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe list" > "$LOG/launch-probe.out" 2>&1
sleep 3
out="$(since_mark probe untrusted)"
[[ "$out" == *"connected /run/kryptik/wayland-0"* ]] && pass "zone-proxy-path" "the zone's client connected to /run/kryptik/wayland-0 (the proxy)" || fail "zone-proxy-path" "$(echo "$out" | head -3 | tr '\n' ' ') [$(cat "$LOG/launch-probe.out" | tr '\n' ' ')]"
for g in wl_compositor wl_shm wl_seat xdg_wm_base; do
    [[ "$out" == *"global "*" $g "* ]] || fail "zone-sees-$g" "not offered"
done
[[ "$out" == *"global "*" xdg_wm_base "* ]] && pass "zone-sees-needed" "wl_compositor, wl_shm, wl_seat, xdg_wm_base offered"
hidden_seen=""
for g in zwlr_screencopy_manager_v1 wl_data_device_manager zwlr_data_control_manager_v1 zwlr_layer_shell_v1 zwp_virtual_keyboard_manager_v1 zwlr_virtual_pointer_manager_v1 zwlr_export_dmabuf_manager_v1 zwlr_gamma_control_manager_v1 zwlr_output_manager_v1 ext_session_lock_manager_v1 zwlr_foreign_toplevel_manager_v1; do
    [[ "$out" == *" $g "* ]] && hidden_seen="$hidden_seen $g"
done
[[ -z "$hidden_seen" ]] && pass "zone-hidden-globals" "no capture, clipboard, layer-shell, virtual-input, dmabuf-export, gamma, output-management or session-lock global reaches the zone" || fail "zone-hidden-globals" "reached the zone:$hidden_seen"
mark bind untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe bind zwlr_screencopy_manager_v1" > "$LOG/launch-bind.out" 2>&1
sleep 3
out="$(since_mark bind untrusted)"
[[ "$out" == *"bind refused"* ]] && pass "zone-bind-refused" "a bind of the screencopy manager got wl_display.error and a closed connection" || fail "zone-bind-refused" "$(echo "$out" | tail -3 | tr '\n' ' ')"
grep -q 'not advertised' "$RT/kryptik/untrusted/proxy.log" 2>/dev/null && pass "proxy-logged-refusal" "$(grep 'not advertised' "$RT/kryptik/untrusted/proxy.log" | tail -1 | cut -c1-120)" || fail "proxy-logged-refusal" "no refusal in the proxy log"

# --- a real window: identity in the chrome's record, on screen, in fullscreen --
launch_plain untrusted "havoc" > "$LOG/launch-havoc-untrusted.out" 2>&1
if wait_for 20 grep -q '^zone=untrusted' "$RT/kryptik/focus"; then
    pass "focus-shows-zone" "$(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    fail "focus-shows-zone" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); launch: $(cat "$LOG/launch-havoc-untrusted.out" | tr '\n' ' ')"
fi
grep -q '^label=UNTRUSTED' "$RT/kryptik/focus" 2>/dev/null && pass "focus-shows-label" "the text identity is the zone file's label" || fail "focus-shows-label"
grep -q '^title=\[untrusted\]' "$RT/kryptik/focus" 2>/dev/null && pass "title-prefixed" "$(grep '^title=' "$RT/kryptik/focus")" || fail "title-prefixed" "$(grep '^title=' "$RT/kryptik/focus" 2>/dev/null)"
sleep 2
echo "GT SCREENSHOT-READY"
sleep 6
echo "GT KEY-FULLSCREEN"
if wait_for 20 grep -q '^fullscreen=1' "$RT/kryptik/focus"; then
    pass "fullscreen-identity-recorded" "$(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    fail "fullscreen-identity-recorded" "focus after Alt+e: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
# the window is fullscreen now: the host takes a screenshot in which the
# zone's border colour must still be on screen (dwl keeps the frame)
sleep 2
echo "GT SCREENSHOT-FULLSCREEN"
sleep 6
echo "GT KEY-FULLSCREEN-AGAIN"
wait_for 20 grep -q '^fullscreen=0' "$RT/kryptik/focus" && pass "fullscreen-off-again" || fail "fullscreen-off-again"

# --- a second zone with a window; no virtual input for either --------------------
launch personal "havoc" > "$LOG/launch-havoc-personal.out" 2>&1
wait_for 20 grep -q '^zone=personal' "$RT/kryptik/focus" && pass "second-zone-window" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "second-zone-window" "$(cat "$LOG/launch-havoc-personal.out" | tr '\n' ' ')"
mark probe personal
launch personal "/usr/libexec/kryptik/wlprobe list" > /dev/null 2>&1; sleep 3
out="$(since_mark probe personal)"
if [[ "$out" == *"global "* && "$out" != *"virtual_keyboard"* && "$out" != *"virtual_pointer"* && "$out" != *"input_method"* ]]; then pass "no-virtual-input" "no virtual keyboard/pointer or input-method global in personal either"; else fail "no-virtual-input" "$(echo "$out" | grep -c global) globals; virtual input: $(echo "$out" | grep -o 'virtual_[a-z]*' | tr '\n' ' ')"; fi

# --- clipboards: per zone, until the zone 0 gesture ----------------------------------
BRK='import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect("/run/kryptik/broker"); s.sendall(sys.argv[1].encode()); s.shutdown(socket.SHUT_WR)
d=b""
while True:
    b=s.recv(4096)
    if not b: break
    d+=b
sys.stdout.write(d.decode(errors="replace"))'
mark clip untrusted
launch_plain untrusted "python3 -c '$BRK' 'clipboard-set text/plain 14
from-untrusted'" > /dev/null 2>&1; sleep 2
[[ "$(since_mark clip untrusted)" == *ok* ]] && pass "clipboard-set" "untrusted set its clipboard through its broker" || fail "clipboard-set" "$(since_mark clip untrusted | tail -2 | tr '\n' ' ')"
mark clip1 personal
launch personal "python3 -c '$BRK' 'clipboard-get
'" > /dev/null 2>&1; sleep 2
[[ "$(since_mark clip1 personal)" == *empty* ]] && pass "clipboard-isolated" "personal's clipboard is empty: nothing crosses by itself" || fail "clipboard-isolated" "$(since_mark clip1 personal | tail -2 | tr '\n' ' ')"
as_user "kryptik-launch --clipboard-move untrusted personal" > "$LOG/clip-move.out" 2>&1 && pass "clipboard-move-gesture" "$(tr '\n' ' ' < "$LOG/clip-move.out")" || fail "clipboard-move-gesture" "$(tr '\n' ' ' < "$LOG/clip-move.out")"
mark clip2 personal
launch personal "python3 -c '$BRK' 'clipboard-get
'" > /dev/null 2>&1; sleep 2
[[ "$(since_mark clip2 personal)" == *from-untrusted* ]] && pass "clipboard-moved" "personal now holds the one payload the gesture moved" || fail "clipboard-moved" "$(since_mark clip2 personal | tail -2 | tr '\n' ' ')"

# --- transfers: the person decides ------------------------------------------------------
TRF='import socket,sys,os,array
s=socket.socket(socket.AF_UNIX); s.connect("/run/kryptik/broker")
fd=os.open(sys.argv[3],os.O_RDONLY)
s.sendmsg([("transfer %s %s\n"%(sys.argv[1],sys.argv[2])).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])
s.shutdown(socket.SHUT_WR)
d=b""
while True:
    b=s.recv(4096)
    if not b: break
    d+=b
sys.stdout.write(d.decode(errors="replace"))'
launch work "havoc" > /dev/null 2>&1   # work must be running to receive
wait_for 20 grep -q '^zone=work' "$RT/kryptik/focus" || info "work window not focused yet: $(tr '\n' ' ' < "$RT/kryptik/focus")"
# policy first: untrusted names no destination
mark trf0 untrusted
launch_plain untrusted "sh -c 'echo nope > \$HOME/x.txt; python3 -c \"$TRF\" work x.txt \$HOME/x.txt'" > /dev/null 2>&1; sleep 3
[[ "$(since_mark trf0 untrusted)" == *"does not name"* ]] && pass "transfer-policy" "untrusted -> work refused by policy, with no question asked" || fail "transfer-policy" "$(since_mark trf0 untrusted | tail -2 | tr '\n' ' ')"
# The chrome's watcher holds watcher.lock in the channel for as long as the
# session runs (kryptikd consent.rs); it is not a question, so it is not
# counted. Everything else there is.
questions() { ls /run/kryptik-consent/ 2>/dev/null | grep -v "^watcher.lock$"; }
[[ -z "$(questions)" ]] && pass "no-question-for-policy-refusal" || fail "no-question-for-policy-refusal" "$(questions | tr '
' ' ')"
# dev -> work: allowed by policy, asked of the person
mark trf1 dev
echo "GT CONSENT-WAIT 1"
launch dev "sh -c 'echo report-body > \$HOME/report.txt; python3 -c \"$TRF\" work report.txt \$HOME/report.txt'" > "$LOG/trf1.out" 2>&1
n=40; while [[ "$n" -gt 0 ]] && [[ "$(since_mark trf1 dev)" != *ok* && "$(since_mark trf1 dev)" != *error* ]]; do n=$((n - 1)); sleep 1; done
out="$(since_mark trf1 dev)"
[[ "$out" == *"ok report.txt"* ]] && pass "transfer-approved" "after the person said yes: $(echo "$out" | grep -o 'ok .*' | head -1)" || fail "transfer-approved" "$(echo "$out" | tail -2 | tr '\n' ' ')"
if [[ -f "$R/work/incoming/report.txt" ]] && [[ "$(cat "$R/work/incoming/report.txt")" = report-body ]]; then pass "transfer-landed" "the file is in work's incoming/, byte-identical"; else fail "transfer-landed" "$(ls -la "$R/work/incoming" 2>&1 | tail -2 | tr '\n' ' ')"; fi
mark trf2 dev
echo "GT CONSENT-WAIT 2"
launch dev "sh -c 'echo secret2 > \$HOME/report2.txt; python3 -c \"$TRF\" work report2.txt \$HOME/report2.txt'" > "$LOG/trf2.out" 2>&1
n=40; while [[ "$n" -gt 0 ]] && [[ "$(since_mark trf2 dev)" != *ok* && "$(since_mark trf2 dev)" != *error* ]]; do n=$((n - 1)); sleep 1; done
out="$(since_mark trf2 dev)"
[[ "$out" == *"refused by the user"* ]] && pass "transfer-denied" "after the person said no: refused" || fail "transfer-denied" "$(echo "$out" | tail -2 | tr '\n' ' ')"
[[ -e "$R/work/incoming/report2.txt" ]] && fail "denied-file-absent" "the refused file landed anyway" || pass "denied-file-absent" "nothing landed"
[[ -z "$(questions)" ]] && pass "consent-cleaned" "no question left behind" || fail "consent-cleaned" "$(questions | tr '
' ' ')"

# --- teardown ------------------------------------------------------------------------------
# The session's own log and the last focus record live on the runtime tmpfs
# and vanish with the power; keep copies on the state partition, where a
# post-mortem (loop-mount p4, log/kryptik/) can read what the compositor
# and the chrome said. Without this the "(no window)" run left nothing to
# read but the verdict.
cp -f "$RT/kryptik/session.log" /var/log/kryptik/session.log 2>/dev/null
cp -f "$RT/kryptik/focus" /var/log/kryptik/focus.last 2>/dev/null
for z in untrusted personal dev work; do "$KD" stop "$z" >/dev/null 2>&1; done
pkill -u "$USER_NAME" -x dwl 2>/dev/null
sleep 2
pgrep -u "$USER_NAME" -x dwl >/dev/null && info "dwl still running after the session was ended" || pass "session-ends" "the compositor exited cleanly"
echo "GT SUMMARY passed=$PASS failed=$FAIL"
echo "GT END"
[[ "$FAIL" -eq 0 ]]
