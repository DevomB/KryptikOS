#!/usr/bin/env bash
# Desktop suite, run as root in the installed guest by tools/image/gui-test.sh.
# The host boots it with a virtual GPU and keyboard and acts on these lines:
#   GT SCREENSHOT-READY, GT SCREENSHOT-FULLSCREEN,
#   GT SCREENSHOT-OVERSIZE                          take a screenshot
#   GT KEY-FOCUS-ZONE, GT KEY-FOCUS-OVERSIZE,
#   GT KEY-FOCUS-FORGED, GT KEY-FOCUS-PERSONAL      press Alt+j (explicit focus)
#   GT KEY-FULLSCREEN, GT KEY-FULLSCREEN-AGAIN      press Alt+e (fullscreen, then back)
#   GT KEY-FOCUS-AWAY, GT KEY-FOCUS-CHILD, GT KEY-FOCUS-PARENT,
#   GT KEY-FOCUS-BELOW, GT KEY-FOCUS-LATE            press Alt+j
#   GT KEY-ZOOM-BELOW, GT KEY-ZOOM-AGAIN            press Alt+Return (zoom)
#   GT KEY-PARENT-FULLSCREEN, GT KEY-LATE-FULLSCREEN press Alt+e
#   GT KEY-MENU                                     press Alt+p (the chrome menu)
#   GT CONSENT-CODE 1 NN                            type NN and Enter (the question's code)
#   GT CONSENT-WAIT 2                               type y and Enter (not the code: refused)
#   GT POINTER-ZONE0, GT POINTER-UNTRUSTED          move the pointer onto the newest window
#   GT HEAD-ON, GT HEAD-OFF                         plug a second monitor in, pull it out
#   GT KEY-FOCUS-HEAD                               press Alt+period (the next monitor)
#   GT KEY-FOCUS-HEAD-WINDOW                        press Alt+j
#   GT SCREENSHOT-HEAD                              take a screenshot of the second monitor
#   GT END
# Verdicts: "GT PASS|FAIL|INFO name - detail".
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
# A filter kill below the zone's pid 1 shows only in the kernel's audit line (type=1326).
zone_why() {   # zone_why ZONE: the registry, both logs, what runs and the filter's last kills
    echo "entries: $(ls /run/kryptik/zones 2>&1 | tr '\n' ' ')| $1: $(ls -la --time-style=full-iso /run/kryptik/zones/"$1" 2>&1 | tr '\n' ' ')| running: $("$KD" list --running 2>&1 | tr '\n' ' ')| log: $(zone_log "$1" | tail -10 | tr '\n' ' ')| proxy: $(tail -4 "$RT/kryptik/$1/proxy.log" 2>&1 | tr '\n' ' ')| procs: $(pgrep -af "havoc|kryptikd run $1" 2>/dev/null | cut -c1-90 | tr '\n' ';')| seccomp: $(dmesg 2>/dev/null | grep -a 'type=1326' | tail -3 | tr '\n' ' ')"
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
# One DRM device, the GPU's: beside simpledrm, wlroots takes a multi-GPU path pixman cannot serve.
cards=()
for c in /sys/class/drm/card[0-9]*; do
    [[ -e "$c" && "${c##*/}" != *-* ]] || continue
    d="$(readlink -f "$c/device")"
    # The PCI function's driver is virtio-pci; the GPU driver is on the virtio device under it.
    drv="$(readlink -f "$d"/virtio*/driver 2>/dev/null | head -1)"
    cards+=("${c##*/}=$(basename "${drv:-$(readlink -f "$d/driver")}" 2>/dev/null)")
done
[[ "${#cards[@]}" -eq 1 && "${cards[0]}" == *=virtio_gpu ]] && pass "gpu-device" "${cards[0]}" || fail "gpu-device" "${#cards[@]} DRM device(s): ${cards[*]:-none} (the firmware framebuffer not replaced?)"
[[ "$(s6-svstat -o up /run/service/seatd 2>/dev/null)" = true ]] && pass "seatd-up" || fail "seatd-up"
[[ "$(s6-svstat -o up /run/service/kryptikd-serve 2>/dev/null)" = true ]] && pass "launch-daemon-up" || fail "launch-daemon-up"

# --- the session ------------------------------------------------------------
su -s /bin/bash "$USER_NAME" -c 'setsid /usr/bin/kryptik-session </dev/null >/dev/null 2>&1 &'
if wait_for 30 test -S "$RT/wayland-0"; then pass "session-socket" "dwl listening at $RT/wayland-0"; else fail "session-socket" "$(cat "$RT/kryptik/session.log" 2>/dev/null | tail -3 | tr '\n' ' ')"; fi
pgrep -u "$USER_NAME" -x dwl >/dev/null && pass "compositor-running" || fail "compositor-running" "$(tail -3 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"
wait_for 20 test -f "$RT/kryptik/focus" && pass "chrome-focus-record" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "chrome-focus-record" "no $RT/kryptik/focus after 20 s"
# The record exists before the chrome's own window has mapped: wait for the window.
wait_for 20 grep -q '^zone=0' "$RT/kryptik/focus" && pass "chrome-window-is-zone0" "the launcher window is recorded as zone 0 (trusted)" || fail "chrome-window-is-zone0" "$(cat "$RT/kryptik/focus" 2>/dev/null | tr '\n' ' '); terminals: $(pgrep -u "$USER_NAME" -a havoc 2>/dev/null | tr '\n' ';'); session.log: $(tail -4 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"

# --- what zone 0 sees, and what a zone sees ---------------------------------
as_user "/usr/libexec/kryptik/wlprobe list" > "$LOG/probe-zone0.out" 2>&1
grep -q 'zwlr_screencopy_manager_v1' "$LOG/probe-zone0.out" && grep -q 'wl_data_device_manager' "$LOG/probe-zone0.out" \
    && pass "zone0-sees-capture" "the compositor offers screencopy and the data device to zone 0's own client (positive control)" \
    || fail "zone0-sees-capture" "$(grep -c '^global' "$LOG/probe-zone0.out") globals; $(tail -1 "$LOG/probe-zone0.out")"
mark probe untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe list" > "$LOG/launch-probe.out" 2>&1
sleep 3
out="$(since_mark probe untrusted)"
[[ "$out" == *"connected /run/kryptik/wayland-0"* ]] && pass "zone-proxy-path" "the zone's client connected to /run/kryptik/wayland-0 (the proxy)" || fail "zone-proxy-path" "$(echo "$out" | head -3 | tr '\n' ' ') [$(cat "$LOG/launch-probe.out" | tr '\n' ' ')]"
needed_missing=""
for g in wl_compositor wl_shm wl_seat xdg_wm_base; do
    [[ "$out" == *"global "*" $g "* ]] || needed_missing="$needed_missing $g"
done
[[ -z "$needed_missing" ]] && pass "zone-sees-needed" "wl_compositor, wl_shm, wl_seat, xdg_wm_base offered" || fail "zone-sees-needed" "not offered:$needed_missing"
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

# --- a zone window goes fullscreen only by the user's key ----------------
# wlprobe asks for it once drawn and says which configures were fullscreen;
# zone 0's request is granted, which shows the probe would see a grant.
as_user "/usr/libexec/kryptik/wlprobe fullscreen 4" > "$LOG/fullscreen-zone0.out" 2>&1
grep -q 'configure (fullscreen)' "$LOG/fullscreen-zone0.out" && pass "zone0-fullscreen-granted" || fail "zone0-fullscreen-granted" "$(tr '\n' ' ' < "$LOG/fullscreen-zone0.out")"
# Granted only while that window has the focus: the probe asks once the
# keyboard has left it, after Alt+j moved the focus to the launcher, and the
# request gets no fullscreen configure.
as_user "/usr/libexec/kryptik/wlprobe fullscreen 7 late" > "$LOG/fullscreen-zone0-late.out" 2>&1 &
late0_pid=$!
wait_for 10 grep -q 'keyboard entered the window' "$LOG/fullscreen-zone0-late.out"
echo "GT KEY-FOCUS-AWAY"
wait "$late0_pid" 2>/dev/null
if grep -q 'asked for fullscreen' "$LOG/fullscreen-zone0-late.out" && ! grep -q 'configure (fullscreen)' "$LOG/fullscreen-zone0-late.out"; then
    pass "zone0-fullscreen-needs-focus" "an unfocused zone 0 window asked and was not made fullscreen"
else
    fail "zone0-fullscreen-needs-focus" "$(grep -E 'asked|committed|keyboard' "$LOG/fullscreen-zone0-late.out" | tail -4 | tr '\n' ' ')"
fi
mark fs untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe fullscreen 6" > "$LOG/launch-fullscreen.out" 2>&1
fs_answered() { since_mark fs untrusted | sed -n '/asked for fullscreen/,$p' | grep -q committed; }
wait_for 20 fs_answered; answered=$?
wait_for 20 test ! -e /run/kryptik/zones/untrusted/init.pid; sleep 1
out="$(since_mark fs untrusted)"
if [[ "$answered" = 0 && "$out" != *"(fullscreen)"* ]]; then
    pass "zone-fullscreen-refused" "the zone's own request was answered with a configure that is not fullscreen"
else
    fail "zone-fullscreen-refused" "$(echo "$out" | tail -4 | tr '\n' ' '); $(tr '\n' ' ' < "$LOG/launch-fullscreen.out")"
fi

# --- a fullscreen zone window keeps the focus from what it hides -------------
# wlprobe child maps a window and a child of it, both tiled: a zone's child
# is never drawn above its parent. The zone starts for the probe, so its
# windows take no focus from zone 0, and Alt+j walks there, newest window
# first. From the fullscreen parent, Alt+j must then find nothing: every
# other window is hidden below it, zone 0's and other zones' alike.
focus_is() { grep -q "^title=\[untrusted\] $1\$" "$RT/kryptik/focus" 2>/dev/null && grep -q "^fullscreen=$2" "$RT/kryptik/focus"; }
zone_gone() { test ! -e /run/kryptik/zones/untrusted/init.pid; }
child_ready() { since_mark child untrusted | grep -q 'child committed'; }
mark child untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe child 45" > "$LOG/launch-child.out" 2>&1
if wait_for 20 child_ready; then
    pass "zone-child-mapped" "$(since_mark child untrusted | grep -c committed) commits"
else
    fail "zone-child-mapped" "$(since_mark child untrusted | tail -3 | tr '\n' ' '); $(tr '\n' ' ' < "$LOG/launch-child.out")"
fi
sleep 1
echo "GT KEY-FOCUS-CHILD"
wait_for 10 focus_is child 0 && pass "child-focused" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "child-focused" "focus after Alt+j: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
echo "GT KEY-FOCUS-PARENT"
wait_for 10 focus_is child-parent 0 && pass "parent-focused" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "parent-focused" "focus after Alt+j: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
echo "GT KEY-PARENT-FULLSCREEN"
wait_for 10 focus_is child-parent 1 && pass "parent-fullscreen" || fail "parent-fullscreen" "focus after Alt+e: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
echo "GT KEY-FOCUS-BELOW"
sleep 3
if focus_is child-parent 1; then
    pass "fullscreen-keeps-focus" "Alt+j left the record on the fullscreen window"
else
    fail "fullscreen-keeps-focus" "Alt+j moved the record to a hidden window: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
# The record names the window the compositor believes on top, which is never
# a covered one; the probe's wl_keyboard events say where the keys go.
child_entries() { since_mark child untrusted | grep -c 'keyboard entered the child'; }
[[ "$(child_entries)" -eq 1 ]] && pass "keyboard-stays-on-fullscreen" "the child saw the keyboard once, before its parent went fullscreen" || fail "keyboard-stays-on-fullscreen" "the hidden child got the keyboard: $(since_mark child untrusted | grep keyboard | tr '\n' ' ')"
echo "GT KEY-ZOOM-BELOW"
sleep 3
[[ "$(child_entries)" -eq 1 ]] && focus_is child-parent 1 && pass "zoom-keeps-keyboard" "Alt+Return left the keyboard on the fullscreen window" || fail "zoom-keeps-keyboard" "$(since_mark child untrusted | grep keyboard | tail -2 | tr '\n' ' '); focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
# Twice: dwl's zoom moves the window it finds to the front of its list, and
# only from the front does the old search pass the fullscreen window and
# land on the hidden child.
echo "GT KEY-ZOOM-AGAIN"
sleep 3
[[ "$(child_entries)" -eq 1 ]] && focus_is child-parent 1 && pass "zoom-twice-keeps-keyboard" "a second Alt+Return left it there too" || fail "zoom-twice-keeps-keyboard" "$(since_mark child untrusted | grep keyboard | tail -2 | tr '\n' ' '); focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
# A zone 0 window opened over the fullscreen zone window ends that fullscreen
# and takes the keyboard, as a passphrase prompt must.
as_user "/usr/libexec/kryptik/wlprobe oversize 0 8 over-fullscreen" > "$LOG/zone0-over.out" 2>&1 &
over_pid=$!
if wait_for 15 grep -q 'keyboard entered the window' "$LOG/zone0-over.out" && wait_for 10 grep -q '^title=over-fullscreen' "$RT/kryptik/focus"; then
    pass "zone0-over-fullscreen-gets-keyboard" "$(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    fail "zone0-over-fullscreen-gets-keyboard" "zone 0's window: $(grep -E 'keyboard|committed' "$LOG/zone0-over.out" | tail -3 | tr '\n' ' '); focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
parent_windowed() { since_mark child untrusted | sed -n '/configure (fullscreen)/,$p' | grep committed | grep -v child | grep -qv '(fullscreen)'; }
wait_for 10 parent_windowed && pass "zone0-window-ends-fullscreen" "the parent's next configure was not fullscreen" || fail "zone0-window-ends-fullscreen" "$(since_mark child untrusted | grep committed | tail -3 | tr '\n' ' ')"
wait "$over_pid" 2>/dev/null
wait_for 60 zone_gone
# A child that maps under its fullscreen parent ends the fullscreen: the
# zone cannot have it drawn above the bar, so both are shown tiled instead.
late_drawn() { since_mark late untrusted | grep -q committed; }
late_done() { since_mark late untrusted | sed -n '/asked for a child/,$p' | grep committed | grep -v child | grep -qv '(fullscreen)'; }
mark late untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe child 25 late" > "$LOG/launch-late.out" 2>&1
wait_for 20 late_drawn
sleep 1
echo "GT KEY-FOCUS-LATE"
wait_for 10 focus_is child-parent 0
echo "GT KEY-LATE-FULLSCREEN"
if wait_for 20 late_done && wait_for 10 grep -q '^fullscreen=0' "$RT/kryptik/focus"; then
    pass "child-ends-fullscreen" "$(since_mark late untrusted | grep -E 'asked for a child|committed' | tail -3 | tr '\n' ' ')"
else
    fail "child-ends-fullscreen" "$(since_mark late untrusted | tail -4 | tr '\n' ' '); focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
wait_for 40 zone_gone

# --- a mapped zone window cannot take the chrome's focus ----------------------
mark map untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe oversize 0 8 map-focus" > "$LOG/map-focus.out" 2>&1
probe_committed() { since_mark "$1" untrusted | grep -q 'committed '; }
probe_configured() { since_mark "$1" untrusted | grep -Eq 'committed .* for a [1-9][0-9]*x[1-9][0-9]* configure'; }
if wait_for 20 probe_committed map && test -e /run/kryptik/zones/untrusted/init.pid && grep -q '^zone=0' "$RT/kryptik/focus"; then
    pass "map-keeps-zone0-focus"
else
    fail "map-keeps-zone0-focus" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus"); probe: $(since_mark map untrusted | tail -3 | tr '\n' ' ')"
fi
wait_for 20 test ! -e /run/kryptik/zones/untrusted/init.pid; sleep 1

# A terminal, focused by an explicit user key.
launch_plain untrusted "havoc" > "$LOG/launch-havoc-untrusted.out" 2>&1
echo "GT KEY-FOCUS-ZONE"
if wait_for 20 grep -q '^zone=untrusted' "$RT/kryptik/focus"; then
    pass "focus-shows-zone" "$(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    fail "focus-shows-zone" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); launch: $(cat "$LOG/launch-havoc-untrusted.out" | tr '\n' ' '); $(zone_why untrusted)"
fi
grep -q '^label=UNTRUSTED' "$RT/kryptik/focus" 2>/dev/null && pass "focus-shows-label" "the text identity is the zone file's label" || fail "focus-shows-label"
grep -q '^title=\[untrusted\]' "$RT/kryptik/focus" 2>/dev/null && pass "title-prefixed" "$(grep '^title=' "$RT/kryptik/focus")" || fail "title-prefixed" "$(grep '^title=' "$RT/kryptik/focus" 2>/dev/null)"
grep -q '^zone=untrusted' "$RT/kryptik/focus.zone" 2>/dev/null && pass "last-zone-recorded" "$(tr '\n' ' ' < "$RT/kryptik/focus.zone")" || fail "last-zone-recorded" "$(tr '\n' ' ' < "$RT/kryptik/focus.zone" 2>/dev/null)"
sleep 2
echo "GT SCREENSHOT-READY"
sleep 6
echo "GT KEY-FULLSCREEN"
if wait_for 20 grep -q '^fullscreen=1' "$RT/kryptik/focus" && grep -q '^zone=untrusted' "$RT/kryptik/focus"; then
    pass "fullscreen-by-key" "$(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    fail "fullscreen-by-key" "focus after Alt+e: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
# The host's screenshot must show the bar naming the zone above the window.
sleep 2
echo "GT SCREENSHOT-FULLSCREEN"
sleep 6
echo "GT KEY-FULLSCREEN-AGAIN"
wait_for 20 grep -q '^fullscreen=0' "$RT/kryptik/focus" && pass "fullscreen-off-again" || fail "fullscreen-off-again"
# Alt+p opens another menu window (the chrome's text menu in a zone 0 terminal), closed once seen.
menu_windows() { pgrep -u "$USER_NAME" -f 'havoc /usr/bin/kryptik-chrome --menu' | wc -l; }
menus_before="$(menu_windows)"
more_menus() { [[ "$(menu_windows)" -gt "$menus_before" ]]; }
echo "GT KEY-MENU"
if wait_for 20 more_menus; then
    pass "menu-opens-on-key" "$(menu_windows) menu windows after Alt+p, ${menus_before} before"
    pkill -n -u "$USER_NAME" -f 'havoc /usr/bin/kryptik-chrome --menu' 2>/dev/null
else
    fail "menu-opens-on-key" "no new menu window after Alt+p: $(pgrep -u "$USER_NAME" -af 'kryptik-chrome --menu' | cut -c1-80 | tr '\n' ';')"
fi
# A zone 0 window taking focus keeps the last zone window's record, which the menu's f shows.
as_user "/usr/libexec/kryptik/wlprobe oversize 0 15 zone-0" > "$LOG/zone0-window.out" 2>&1 &
if wait_for 20 grep -q '^zone=0' "$RT/kryptik/focus"; then
    grep -q '^zone=untrusted' "$RT/kryptik/focus.zone" 2>/dev/null \
        && pass "menu-keeps-last-zone" "focus is zone 0; the last zone window: $(tr '\n' ' ' < "$RT/kryptik/focus.zone")" \
        || fail "menu-keeps-last-zone" "$(tr '\n' ' ' < "$RT/kryptik/focus.zone" 2>/dev/null)"
else
    fail "menu-keeps-last-zone" "no zone 0 window took focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); $(tr '\n' ' ' < "$LOG/zone0-window.out")"
fi
pkill -u "$USER_NAME" -f 'wlprobe oversize 0 15 zone-0' 2>/dev/null

# A zone runs one command at a time, so its window is stopped before the next.
stop_zone() { as_user "kryptik-launch --stop $1" > /dev/null 2>&1; wait_for 15 test ! -e "/run/kryptik/zones/$1/init.pid"; sleep 1; }
stop_zone untrusted
# A closing window must not kill the compositor: every later window would find no display.
if pgrep -u "$USER_NAME" -x dwl > /dev/null; then
    pass "compositor-survives-close" "dwl still runs after the untrusted window closed"
else
    fail "compositor-survives-close" "dwl is gone after the untrusted window closed; session.log: $(tail -4 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"
fi

# --- a window cannot cover its own frame ------------------------------------
# wlprobe answers every configure with a buffer 40 px larger than asked. dwl
# clips a surface only to (w - bw) x (h - bw), so the excess lies under the
# right and bottom borders; the host measures all four in its screenshot.
mark oversize untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe oversize 40 30" > "$LOG/launch-oversize.out" 2>&1
wait_for 20 probe_configured oversize || fail "oversize-mapped" "probe did not draw its configured window"
echo "GT KEY-FOCUS-OVERSIZE"
if wait_for 20 grep -q '^title=\[untrusted\] oversize' "$RT/kryptik/focus"; then
    pass "oversize-window" "$(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    fail "oversize-window" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); launch: $(tr '\n' ' ' < "$LOG/launch-oversize.out"); $(zone_why untrusted)"
fi
sleep 2
echo "GT SCREENSHOT-OVERSIZE"
sleep 6
stop_zone untrusted
# A window titled as another zone's is named by the app_id the proxy stamps, never its title.
mark forged untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe oversize 0 20 '[vault] forged'" > "$LOG/launch-forged.out" 2>&1
wait_for 20 probe_configured forged || fail "forged-mapped" "probe did not draw its configured window"
echo "GT KEY-FOCUS-FORGED"
if wait_for 20 grep -q '^title=\[untrusted\] \[vault\] forged' "$RT/kryptik/focus"; then
    grep -q '^zone=untrusted' "$RT/kryptik/focus.zone" && grep -q '^label=UNTRUSTED' "$RT/kryptik/focus.zone" \
        && pass "forged-title-named-by-zone" "$(tr '\n' ' ' < "$RT/kryptik/focus.zone")" \
        || fail "forged-title-named-by-zone" "$(tr '\n' ' ' < "$RT/kryptik/focus.zone" 2>/dev/null)"
else
    fail "forged-title-named-by-zone" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); launch: $(tr '\n' ' ' < "$LOG/launch-forged.out"); $(zone_why untrusted)"
fi
stop_zone untrusted

# --- a second zone with a window; no virtual input for either ---------------
mark probe personal
launch personal "/usr/libexec/kryptik/wlprobe list" > "$LOG/launch-probe-personal.out" 2>&1
# An encrypted zone relaunches only once its volume has closed, after its launcher exits.
wait_for 30 test ! -e /run/kryptik/zones/personal/init.pid; sleep 1
out="$(since_mark probe personal)"
if [[ "$out" == *"global "* && "$out" != *"virtual_keyboard"* && "$out" != *"virtual_pointer"* && "$out" != *"input_method"* ]]; then pass "no-virtual-input" "no virtual keyboard/pointer or input-method global in personal either"; else fail "no-virtual-input" "$(echo "$out" | grep -c global) globals; virtual input: $(echo "$out" | grep -o 'virtual_[a-z]*' | tr '\n' ' '); $(tr '\n' ' ' < "$LOG/launch-probe-personal.out")"; fi
launch personal "havoc" > "$LOG/launch-havoc-personal.out" 2>&1
echo "GT KEY-FOCUS-PERSONAL"
wait_for 20 grep -q '^zone=personal' "$RT/kryptik/focus" && pass "second-zone-window" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "second-zone-window" "$(cat "$LOG/launch-havoc-personal.out" | tr '\n' ' '); $(zone_why personal)"
# --- zone 0 runs no user application (ADR-003) ------------------------------
ppid_of() { awk '/^PPid:/ { print $2 }' "/proc/$1/status" 2>/dev/null; }
lineage=" $$ "; p="$(ppid_of "$$")"
while [[ -n "$p" && "$p" -gt 1 ]]; do lineage="${lineage}${p} "; p="$(ppid_of "$p")"; done
in_test_tree() {   # in_test_tree PID: this shell, an ancestor of it, or below one of them
    local p="$1"
    while [[ -n "$p" && "$p" -gt 1 ]]; do [[ "$lineage" == *" $p "* ]] && return 0; p="$(ppid_of "$p")"; done
    return 1
}
# With personal's terminal up: outside the zones' cgroups only zone 0's own
# programs and this test's shell tree may run.
foreign=(); zoned=""
for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    exe="$(readlink "$d/exe" 2>/dev/null)" && [[ -n "$exe" ]] || continue   # kernel threads, zombies
    if [[ "$(cat "$d/cgroup" 2>/dev/null)" == *:/kryptik/* ]]; then
        [[ "$exe" == /usr/bin/havoc ]] && zoned="$zoned $p:$(sed -n 's|^0::||p' "$d/cgroup")"
        continue
    fi
    in_test_tree "$p" && continue
    cmd="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)"
    read -r _ script _ <<<"$cmd"
    # An interpreter only as one of Kryptik's scripts; havoc only around the chrome's menu or a launch.
    case "$exe" in
        /usr/bin/s6-*|/usr/sbin/s6-*|/usr/libexec/s6-*|/usr/sbin/udevd|/usr/sbin/agetty|/usr/bin/seatd|/usr/bin/kryptikd|/usr/bin/kryptik-wlproxy|/usr/bin/kryptik-launch|/usr/bin/dwl|/usr/bin/sleep) ;;
        /usr/bin/bash|/usr/bin/python3)
            case "$script" in /usr/libexec/kryptik/*|/usr/bin/kryptik-session|/usr/bin/kryptik-chrome) ;; *) foreign+=("$p ${cmd:0:60}") ;; esac ;;
        /usr/bin/havoc)
            case "$script" in /usr/bin/kryptik-chrome|/usr/bin/kryptik-launch) ;; *) foreign+=("$p ${cmd:0:60}") ;; esac ;;
        *) foreign+=("$p ${cmd:0:60}") ;;
    esac
done
[[ "${#foreign[@]}" -eq 0 ]] && pass "zone0-own-programs-only" "every process outside the zones' cgroups is one of zone 0's own" || fail "zone0-own-programs-only" "$(printf '%s; ' "${foreign[@]}")"
[[ -n "$zoned" ]] && pass "zone-app-in-cgroup" "the zone's terminal runs in its cgroup:$zoned" || fail "zone-app-in-cgroup" "no havoc in a /kryptik cgroup; processes in one: $(grep -ls kryptik /proc/[0-9]*/cgroup 2>/dev/null | wc -l)"

stop_zone personal

# --- clipboards: per zone, until the zone 0 gesture -------------------------
BC=/usr/lib/kryptik/guest-tests/broker-client.py
# A zone's clipboard lives in its launcher, so both zones stay up across the gesture.
mark clip untrusted
launch_plain untrusted "sh -c 'python3 $BC clipboard-set text/plain from-untrusted; echo SET-DONE; python3 $BC clipboard-wait-empty 90; echo WAIT-DONE'" > "$LOG/clip-set.out" 2>&1
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
wait_for 30 grep -q 'clipboard-empty' /var/log/kryptik/zone-untrusted.log; emptied=$?
if [[ "$second" == *from-untrusted* && "$emptied" = 0 ]]; then pass "clipboard-moved" "personal holds the one payload the gesture moved, and untrusted's own broker answers empty: moved, not copied"; else fail "clipboard-moved" "personal: $(echo "$second" | tail -2 | tr '\n' ' '); untrusted: $(since_mark clip untrusted | tail -3 | tr '\n' ' ')"; fi
stop_zone untrusted; stop_zone personal

# --- transfers: the user decides --------------------------------------------
launch work "havoc" > /dev/null 2>&1   # work must be running to receive
# policy first: untrusted names no destination
mark trf0 untrusted
launch_plain untrusted "sh -c 'echo nope > \$HOME/x.txt; python3 $BC transfer work x.txt \$HOME/x.txt'" > /dev/null 2>&1; sleep 3
[[ "$(since_mark trf0 untrusted)" == *"does not name"* ]] && pass "transfer-policy" "untrusted -> work refused by policy, with no question asked" || fail "transfer-policy" "$(since_mark trf0 untrusted | tail -2 | tr '\n' ' ')"
questions() {   # every consent entry except the chrome's watcher.lock (consent.rs)
    local f
    for f in /run/kryptik-consent/* /run/kryptik-consent/.[!.]*; do
        [[ -e "$f" ]] || continue
        [[ "${f##*/}" = watcher.lock ]] && continue
        echo "${f##*/}"
    done
}
[[ -z "$(questions)" ]] && pass "no-question-for-policy-refusal" || fail "no-question-for-policy-refusal" "$(questions | tr '
' ' ')"
# dev -> work: allowed by policy, so the user is asked and types the code the question shows.
consent_code() {   # consent_code FROM TO: that question's code, from the file beside it, which no zone can read
    local a n=30
    while [[ "$n" -gt 0 ]]; do
        for a in /run/kryptik-consent/*.ask; do
            if grep -qx "from=$1" "$a" 2>/dev/null && grep -qx "to=$2" "$a" && [[ -s "${a%.ask}.code" ]]; then
                cat "${a%.ask}.code"; return 0
            fi
        done
        n=$((n - 1)); sleep 1
    done
    return 1
}
mark trf1 dev
launch dev "sh -c 'echo report-body > \$HOME/report.txt; python3 $BC transfer work report.txt \$HOME/report.txt'" > "$LOG/trf1.out" 2>&1
code="$(consent_code dev work)"
[[ "$code" =~ ^[1-9][0-9]$ ]] && pass "consent-code-shown" "the question's window asks for code $code" || fail "consent-code-shown" "no code beside the question: $(questions | tr '\n' ' ')"
echo "GT CONSENT-CODE 1 ${code:-00}"
n=40; while [[ "$n" -gt 0 ]] && [[ "$(since_mark trf1 dev)" != *ok* && "$(since_mark trf1 dev)" != *error* ]]; do n=$((n - 1)); sleep 1; done
out="$(since_mark trf1 dev)"
[[ "$out" == *"ok report.txt"* ]] && pass "transfer-approved" "after the person typed the code: $(echo "$out" | grep -o 'ok .*' | head -1)" || fail "transfer-approved" "$(echo "$out" | tail -2 | tr '\n' ' '); $(zone_why work)"
if [[ -f "$R/work/incoming/report.txt" ]] && [[ "$(cat "$R/work/incoming/report.txt")" = report-body ]]; then pass "transfer-landed" "the file is in work's incoming/, byte-identical"; else fail "transfer-landed" "$(ls -la "$R/work/incoming" 2>&1 | tail -2 | tr '\n' ' ')"; fi
# Delivered as the destination's own: left to root or to the sender, it is a
# file work cannot open, or one it does not hold alone.
work_uid="$(sed -n 's/^uid_base *= *\([0-9]*\).*/\1/p' /usr/lib/kryptik/zones/work.toml)"
landed_uid="$(stat -c %u "$R/work/incoming/report.txt" 2>/dev/null)"
[[ -n "$work_uid" && "$landed_uid" == "$work_uid" ]] && pass "transfer-owned-by-destination" "report.txt belongs to work's identity (uid $landed_uid)" || fail "transfer-owned-by-destination" "owner uid ${landed_uid:-unreadable}; work's identity is ${work_uid:-unknown}"
# As for personal above: wait for dev's volume to close before the next launch.
wait_for 30 test ! -e /run/kryptik/zones/dev/init.pid; sleep 1
mark trf2 dev
launch dev "sh -c 'echo secret2 > \$HOME/report2.txt; python3 $BC transfer work report2.txt \$HOME/report2.txt'" > "$LOG/trf2.out" 2>&1
consent_code dev work > /dev/null || info "the second question's window asked for no code"
echo "GT CONSENT-WAIT 2"
n=40; while [[ "$n" -gt 0 ]] && [[ "$(since_mark trf2 dev)" != *ok* && "$(since_mark trf2 dev)" != *error* ]]; do n=$((n - 1)); sleep 1; done
out="$(since_mark trf2 dev)"
[[ "$out" == *"refused by the user"* ]] && pass "plain-y-refused" "y without the code is a refusal" || fail "plain-y-refused" "$(echo "$out" | tail -2 | tr '\n' ' ')"
[[ -e "$R/work/incoming/report2.txt" ]] && fail "denied-file-absent" "the refused file landed anyway" || pass "denied-file-absent" "nothing landed"
# The chrome's watcher removes its .dialog on its next one-second pass: wait for it.
n=20; while [[ "$n" -gt 0 && -n "$(questions)" ]]; do n=$((n - 1)); sleep 1; done
[[ -z "$(questions)" ]] && pass "consent-cleaned" "no question left behind" || fail "consent-cleaned" "$(questions | tr '
' ' ')"

# --- a zone's cursor image is never drawn ---------------------------------------------
# wlprobe cursor, once the pointer enters its window, asks for an image that,
# drawn, covers the screen. The compositor tells a client which output each
# of its surfaces is shown on, a cursor image among them once it is in use:
# zone 0's image is told, so the same word missing for a zone's means the
# compositor never took it. (A screenshot from the host holds no cursor.)
as_user "/usr/libexec/kryptik/wlprobe cursor 12" > "$LOG/cursor-zone0.out" 2>&1 &
probe0=$!
wait_for 20 grep -q committed "$LOG/cursor-zone0.out"
echo "GT POINTER-ZONE0"
wait_for 20 grep -q 'set a ' "$LOG/cursor-zone0.out" && pass "zone0-cursor-set" "$(grep 'set a ' "$LOG/cursor-zone0.out")" || fail "zone0-cursor-set" "$(tr '\n' ' ' < "$LOG/cursor-zone0.out")"
wait_for 10 grep -q 'the cursor image entered an output' "$LOG/cursor-zone0.out" && pass "zone0-cursor-shown" "the compositor took zone 0's image: it entered an output" || fail "zone0-cursor-shown" "zone 0's cursor image entered no output, so a zone's proves nothing: $(tr '\n' ' ' < "$LOG/cursor-zone0.out")"
wait "$probe0" 2>/dev/null
stop_zone untrusted
mark cursor untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe cursor 20" > "$LOG/launch-cursor.out" 2>&1
cursor_asked() { since_mark cursor untrusted | grep -q 'set a '; }
wait_for 20 probe_committed cursor || fail "cursor-mapped" "the probe did not draw its window: $(tr '\n' ' ' < "$LOG/launch-cursor.out")"
echo "GT POINTER-UNTRUSTED"
wait_for 20 cursor_asked && pass "zone-cursor-asked" "$(since_mark cursor untrusted | grep 'set a ')" || fail "zone-cursor-asked" "$(since_mark cursor untrusted | tail -3 | tr '\n' ' '); $(zone_why untrusted)"
sleep 6
# The zone's client hears of its window through its proxy, so it would hear of its image.
since_mark cursor untrusted | grep -q 'the window entered an output' && pass "zone-hears-of-outputs" "the zone's client was told its window entered an output" || fail "zone-hears-of-outputs" "$(since_mark cursor untrusted | tail -3 | tr '\n' ' ')"
if since_mark cursor untrusted | grep -q 'the cursor image entered an output'; then
    fail "zone-cursor-not-shown" "the compositor took the zone's cursor image: it entered an output"
else
    pass "zone-cursor-not-shown" "six seconds after the zone asked, its cursor image has entered no output"
fi
# --- a second monitor, plugged in and pulled out -------------------------------------------
# A zone's window on the new monitor is framed and named as on the first, the
# chrome's record follows the monitor in use, and pulling the monitor out
# takes down neither the compositor nor the zone.
for z in untrusted personal dev work; do stop_zone "$z"; done
outputs() { as_user "/usr/libexec/kryptik/wlprobe list" 2>/dev/null | grep -c ' wl_output '; }
heads() { [[ "$(outputs)" -eq "$1" ]]; }
focus_output() { sed -n 's/^output=//p' "$RT/kryptik/focus" 2>/dev/null; }
first_head="$(focus_output)"
echo "GT HEAD-ON"
if wait_for 30 heads 2; then
    pass "second-head-appears" "the compositor offers two outputs once the second is plugged in"
else
    fail "second-head-appears" "$(outputs) output(s); connectors: $(for s in /sys/class/drm/card*-*/status; do printf '%s=%s ' "${s%/status}" "$(cat "$s" 2>/dev/null)"; done)"
fi
echo "GT KEY-FOCUS-HEAD"
on_second_head() { local o; o="$(focus_output)"; [[ -n "$o" && "$o" != "$first_head" ]]; }
if wait_for 20 on_second_head; then
    pass "chrome-follows-head" "the record names $(focus_output) after Alt+period; the first monitor is ${first_head}"
else
    fail "chrome-follows-head" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
second_head="$(focus_output)"
launch_plain untrusted "havoc" > "$LOG/launch-havoc-head2.out" 2>&1
sleep 3
echo "GT KEY-FOCUS-HEAD-WINDOW"
zone_on_second_head() { grep -q '^zone=untrusted' "$RT/kryptik/focus" && [[ "$(focus_output)" == "$second_head" ]]; }
if wait_for 20 zone_on_second_head; then
    pass "second-head-zone-window" "$(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    fail "second-head-zone-window" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); launch: $(tr '\n' ' ' < "$LOG/launch-havoc-head2.out"); $(zone_why untrusted)"
fi
if grep -q '^title=\[untrusted\]' "$RT/kryptik/focus" 2>/dev/null && grep -q '^label=UNTRUSTED' "$RT/kryptik/focus"; then
    pass "second-head-names-zone" "$(grep -E '^(title|label)=' "$RT/kryptik/focus" | tr '\n' ' ')"
else
    fail "second-head-names-zone" "$(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
sleep 2
echo "GT SCREENSHOT-HEAD"
sleep 6
echo "GT HEAD-OFF"
if wait_for 30 heads 1; then pass "second-head-gone" "one output again"; else fail "second-head-gone" "$(outputs) output(s) after the monitor was pulled"; fi
pgrep -u "$USER_NAME" -x dwl > /dev/null && pass "compositor-survives-unplug" "dwl still runs" \
    || fail "compositor-survives-unplug" "session.log: $(tail -4 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"
test -e /run/kryptik/zones/untrusted/init.pid && pass "zone-survives-unplug" "untrusted still runs" || fail "zone-survives-unplug" "$(zone_why untrusted)"
back_on_first_head() { [[ "$(focus_output)" == "$first_head" ]]; }
wait_for 20 back_on_first_head && pass "chrome-back-on-first-head" "$(tr '\n' ' ' < "$RT/kryptik/focus")" \
    || fail "chrome-back-on-first-head" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
stop_zone untrusted

# --- teardown ------------------------------------------------------------------------------
# The runtime tmpfs does not survive power-off: copy the session log and the
# last focus record to the state partition (p4, log/kryptik/) for a post-mortem.
cp -f "$RT/kryptik/session.log" /var/log/kryptik/session.log 2>/dev/null
cp -f "$RT/kryptik/focus" /var/log/kryptik/focus.last 2>/dev/null
for z in untrusted personal dev work; do "$KD" stop "$z" >/dev/null 2>&1; done
pkill -u "$USER_NAME" -x dwl 2>/dev/null
sleep 2
pgrep -u "$USER_NAME" -x dwl >/dev/null && info "dwl still running after the session was ended" || pass "session-ends" "the compositor exited cleanly"
echo "GT SUMMARY passed=$PASS failed=$FAIL"
echo "GT END"
[[ "$FAIL" -eq 0 ]]
