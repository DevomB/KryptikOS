#!/usr/bin/env bash
# The zoned desktop, measured on the installed system (the desktop suite). Runs as root
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
zone_why() {   # zone_why ZONE: the registry's view, the zone's and its proxy's logs, what runs
    echo "entries: $(ls /run/kryptik/zones 2>&1 | tr '\n' ' ')| $1: $(ls -la --time-style=full-iso /run/kryptik/zones/"$1" 2>&1 | tr '\n' ' ')| running: $("$KD" list --running 2>&1 | tr '\n' ' ')| log: $(zone_log "$1" | tail -10 | tr '\n' ' ')| proxy: $(tail -4 "$RT/kryptik/$1/proxy.log" 2>&1 | tr '\n' ' ')| procs: $(pgrep -af "havoc|kryptikd run $1" 2>/dev/null | cut -c1-90 | tr '\n' ';')"
}
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
# One DRM device, and it is the native driver's. The firmware framebuffer
# (simpledrm) is built in and the GPU driver is a module (boot.fragment), so
# the module must have replaced it at coldplug: two cards put wlroots on its
# multi-GPU path, which the pixman renderer cannot serve, and the compositor
# died at start without a screen to fail on. The card left is not card0:
# simpledrm held that number when the driver's card was registered.
# virtio-gpu hangs its card on the PCI function, whose driver is the
# transport (virtio-pci); the GPU driver is the virtio device's under it.
cards=()
for c in /sys/class/drm/card[0-9]*; do
    [[ -e "$c" && "${c##*/}" != *-* ]] || continue
    d="$(readlink -f "$c/device")"
    drv="$(readlink -f "$d"/virtio*/driver 2>/dev/null | head -1)"
    cards+=("${c##*/}=$(basename "${drv:-$(readlink -f "$d/driver")}" 2>/dev/null)")
done
[[ "${#cards[@]}" -eq 1 && "${cards[0]}" == *=virtio_gpu ]] && pass "gpu-device" "${cards[0]}" || fail "gpu-device" "${#cards[@]} DRM device(s): ${cards[*]:-none} (the firmware framebuffer not replaced?)"
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
    fail "focus-shows-zone" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); launch: $(cat "$LOG/launch-havoc-untrusted.out" | tr '\n' ' '); $(zone_why untrusted)"
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

# --- a second zone with a window; no virtual input for either -------------
# A zone runs ONE supervised command at a time (kryptikd: "One instance per
# zone"), so the probe goes into personal before its window does, and the
# untrusted window from above is stopped before anything else is asked of
# that zone. The first run on installed media handed a second command to a
# running zone at every step from here on, and each was refused as
# "already running (launcher pid N)".
stop_zone() { as_user "kryptik-launch --stop $1" > /dev/null 2>&1; wait_for 15 test ! -e "/run/kryptik/zones/$1/init.pid"; sleep 1; }
stop_zone untrusted
mark probe personal
launch personal "/usr/libexec/kryptik/wlprobe list" > "$LOG/launch-probe-personal.out" 2>&1
# The probe has answered once its launcher exits; an encrypted zone's volume
# closes after that, and only then may personal be launched again (one
# instance per zone). Three seconds was not enough on installed media.
wait_for 30 test ! -e /run/kryptik/zones/personal/init.pid; sleep 1
out="$(since_mark probe personal)"
if [[ "$out" == *"global "* && "$out" != *"virtual_keyboard"* && "$out" != *"virtual_pointer"* && "$out" != *"input_method"* ]]; then pass "no-virtual-input" "no virtual keyboard/pointer or input-method global in personal either"; else fail "no-virtual-input" "$(echo "$out" | grep -c global) globals; virtual input: $(echo "$out" | grep -o 'virtual_[a-z]*' | tr '\n' ' '); $(tr '\n' ' ' < "$LOG/launch-probe-personal.out")"; fi
launch personal "havoc" > "$LOG/launch-havoc-personal.out" 2>&1
wait_for 20 grep -q '^zone=personal' "$RT/kryptik/focus" && pass "second-zone-window" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "second-zone-window" "$(cat "$LOG/launch-havoc-personal.out" | tr '\n' ' '); $(zone_why personal)"
stop_zone personal

# --- clipboards: per zone, until the zone 0 gesture -----------------------
# A zone's clipboard lives in its launcher, so both zones stay up across the
# gesture: each runs one resident command that speaks to its broker through
# broker-client.py - one line per call, because the launch protocol refuses
# an argument with a newline in it, which is how the first run's multi-line
# `python3 -c` probes never reached a zone - and prints the broker's answer
# into the zone's log.
BC=/usr/lib/kryptik/guest-tests/broker-client.py
mark clip untrusted
launch_plain untrusted "sh -c 'python3 $BC clipboard-set text/plain from-untrusted; echo SET-DONE; sleep 90'" > "$LOG/clip-set.out" 2>&1
wait_for 15 grep -q SET-DONE /var/log/kryptik/zone-untrusted.log
[[ "$(since_mark clip untrusted)" == *ok* ]] && pass "clipboard-set" "untrusted set its clipboard through its broker" || fail "clipboard-set" "$(since_mark clip untrusted | tail -2 | tr '\n' ' '); $(tr '\n' ' ' < "$LOG/clip-set.out")"
mark clip1 personal
launch personal "sh -c 'python3 $BC clipboard-get; echo GET1-DONE; sleep 25; python3 $BC clipboard-get; echo GET2-DONE'" > "$LOG/clip-get.out" 2>&1
wait_for 15 grep -q GET1-DONE /var/log/kryptik/zone-personal.log
first="$(since_mark clip1 personal | sed '/GET1-DONE/q')"
[[ "$first" == *empty* ]] && pass "clipboard-isolated" "personal's clipboard is empty: nothing crosses by itself" || fail "clipboard-isolated" "$(echo "$first" | tail -2 | tr '\n' ' '); $(tr '\n' ' ' < "$LOG/clip-get.out")"
as_user "kryptik-launch --clipboard-move untrusted personal" > "$LOG/clip-move.out" 2>&1 && pass "clipboard-move-gesture" "$(tr '\n' ' ' < "$LOG/clip-move.out")" || fail "clipboard-move-gesture" "$(tr '\n' ' ' < "$LOG/clip-move.out")"
wait_for 45 grep -q GET2-DONE /var/log/kryptik/zone-personal.log
second="$(since_mark clip1 personal | sed -n '/GET1-DONE/,$p')"
[[ "$second" == *from-untrusted* ]] && pass "clipboard-moved" "personal now holds the one payload the gesture moved" || fail "clipboard-moved" "$(echo "$second" | tail -2 | tr '\n' ' ')"
stop_zone untrusted; stop_zone personal

# --- transfers: the person decides ------------------------------------------------------
launch work "havoc" > /dev/null 2>&1   # work must be running to receive
wait_for 20 grep -q '^zone=work' "$RT/kryptik/focus" || info "work window not focused yet: $(tr '\n' ' ' < "$RT/kryptik/focus"); $(zone_why work)"
# policy first: untrusted names no destination
mark trf0 untrusted
launch_plain untrusted "sh -c 'echo nope > \$HOME/x.txt; python3 $BC transfer work x.txt \$HOME/x.txt'" > /dev/null 2>&1; sleep 3
[[ "$(since_mark trf0 untrusted)" == *"does not name"* ]] && pass "transfer-policy" "untrusted -> work refused by policy, with no question asked" || fail "transfer-policy" "$(since_mark trf0 untrusted | tail -2 | tr '\n' ' ')"
# The chrome's watcher holds watcher.lock in the channel for as long as the
# session runs (kryptikd consent.rs); it is not a question, so it is not
# counted. Everything else there is.
questions() {   # every entry in the consent directory except the watcher lock
    local f
    for f in /run/kryptik-consent/* /run/kryptik-consent/.[!.]*; do
        [[ -e "$f" ]] || continue
        [[ "${f##*/}" = watcher.lock ]] && continue
        echo "${f##*/}"
    done
}
[[ -z "$(questions)" ]] && pass "no-question-for-policy-refusal" || fail "no-question-for-policy-refusal" "$(questions | tr '
' ' ')"
# dev -> work: allowed by policy, asked of the person
mark trf1 dev
echo "GT CONSENT-WAIT 1"
launch dev "sh -c 'echo report-body > \$HOME/report.txt; python3 $BC transfer work report.txt \$HOME/report.txt'" > "$LOG/trf1.out" 2>&1
n=40; while [[ "$n" -gt 0 ]] && [[ "$(since_mark trf1 dev)" != *ok* && "$(since_mark trf1 dev)" != *error* ]]; do n=$((n - 1)); sleep 1; done
out="$(since_mark trf1 dev)"
[[ "$out" == *"ok report.txt"* ]] && pass "transfer-approved" "after the person said yes: $(echo "$out" | grep -o 'ok .*' | head -1)" || fail "transfer-approved" "$(echo "$out" | tail -2 | tr '\n' ' '); $(zone_why work)"
if [[ -f "$R/work/incoming/report.txt" ]] && [[ "$(cat "$R/work/incoming/report.txt")" = report-body ]]; then pass "transfer-landed" "the file is in work's incoming/, byte-identical"; else fail "transfer-landed" "$(ls -la "$R/work/incoming" 2>&1 | tail -2 | tr '\n' ' ')"; fi
# dev's launcher returns once the transfer command has run, and an encrypted
# zone then closes its volume; a second launch into dev before that meets
# "already running (launcher pid N)" (one instance per zone). Wait for the
# registry to drop it, as for personal above.
wait_for 30 test ! -e /run/kryptik/zones/dev/init.pid; sleep 1
mark trf2 dev
echo "GT CONSENT-WAIT 2"
launch dev "sh -c 'echo secret2 > \$HOME/report2.txt; python3 $BC transfer work report2.txt \$HOME/report2.txt'" > "$LOG/trf2.out" 2>&1
n=40; while [[ "$n" -gt 0 ]] && [[ "$(since_mark trf2 dev)" != *ok* && "$(since_mark trf2 dev)" != *error* ]]; do n=$((n - 1)); sleep 1; done
out="$(since_mark trf2 dev)"
[[ "$out" == *"refused by the user"* ]] && pass "transfer-denied" "after the person said no: refused" || fail "transfer-denied" "$(echo "$out" | tail -2 | tr '\n' ' ')"
[[ -e "$R/work/incoming/report2.txt" ]] && fail "denied-file-absent" "the refused file landed anyway" || pass "denied-file-absent" "nothing landed"
# The broker withdraws its .ask and .answer as soon as the person answers;
# the chrome's watcher then removes its own .dialog bookkeeping on its next
# one-second pass. Give it that moment before asserting the channel is clean,
# or the just-answered dialog is still there when we look.
n=20; while [[ "$n" -gt 0 && -n "$(questions)" ]]; do n=$((n - 1)); sleep 1; done
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
