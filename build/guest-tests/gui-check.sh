#!/usr/bin/env bash
# Desktop suite, run as root in the installed guest by tools/image/gui-test.sh.
# The host boots it with a virtual GPU and keyboard and acts on these lines:
#   GT SCREENSHOT-READY, GT SCREENSHOT-FULLSCREEN,
#   GT SCREENSHOT-OVERSIZE                          take a screenshot
#   GT KEY-FOCUS-ZONE, GT KEY-FOCUS-OVERSIZE,
#   GT KEY-FOCUS-FORGED, GT KEY-FOCUS-PERSONAL      press Alt+j (explicit focus)
#   GT KEY-FULLSCREEN, GT KEY-FULLSCREEN-AGAIN      press Alt+e (fullscreen, then back)
#   GT KEY-MARKS-FULLSCREEN                         press Alt+e (fullscreen again)
#   GT SCREENSHOT-MARKS, GT SCREENSHOT-NO-MARKS     take a screenshot
#   GT KEY-FOCUS-AWAY, GT KEY-FOCUS-CHILD, GT KEY-FOCUS-PARENT,
#   GT KEY-FOCUS-BELOW, GT KEY-FOCUS-LATE            press Alt+j
#   GT KEY-ZOOM-BELOW, GT KEY-ZOOM-AGAIN            press Alt+Return (zoom)
#   GT KEY-PARENT-FULLSCREEN, GT KEY-LATE-FULLSCREEN press Alt+e
#   GT KEY-MENU                                     press Alt+p (the chrome menu)
#   GT KEY-FOCUS-NAMED 1..3, back-1..back-3         press Alt+j, then Alt+k
#   GT KEY-VIEW-VAULT, GT KEY-FOCUS-VAULT,
#   GT KEY-VAULT-BACK                               press Alt+9, Alt+j, Alt+1
#   GT KEY-FOCUS-CLIP 1..4, GT KEY-FOCUS-CLIP-PERSONAL  press Alt+j
#   GT KEY-FOCUS-MOVE 1..4, GT KEY-FOCUS-MOVED 1..4     press Alt+j
#   GT CONSENT-CODE 1 NN                            type NN and Enter (the question's code)
#   GT CONSENT-WAIT 2                               type y and Enter (not the code: refused)
#   GT POINTER-ZONE0, GT POINTER-UNTRUSTED          move the pointer onto the newest window
#   GT SCREENSHOT-POPUP                             take a screenshot
#   GT KEY-MENU-POPUP                               press Alt+p (the chrome menu)
#   GT KEY-FOCUS-POPUP                              press Alt+j
#   GT KEY-LOCK                                     press Alt+Shift+l (the screen lock)
#   GT SCREENSHOT-LOCKED                            take a screenshot
#   GT LOCK-TYPE-WRONG                              type a wrong password and Enter
#   GT LOCK-TYPE-RIGHT                              type the user's password and Enter
#   GT LOCK-TYPE-IDLE, GT LOCK-TYPE-IDLE-AGAIN      type the user's password and Enter
#   GT KEY-FOCUS-HOLD                               press Alt+j
#   GT LOCK-TYPE-HOLD                               type the user's password and Enter
#   GT LOCK-TYPE-SUSPEND                            type the user's password and Enter
#   GT KEY-VOLUME-DOWN                              press the volume-down key
#   GT KEY-LOCK-LAYOUT                              press Alt+Shift+l
#   GT KEY-LOCKED-VOLUME-UP                         press the volume-up key
#   GT KEY-LOCKED-MUTE, GT KEY-LOCKED-MUTE-AGAIN    press the mute key
#   GT KEY-LOCKED-MENU                              press Alt+p, then Escape
#   GT KEY-LAYOUT-NEXT, GT KEY-LAYOUT-BACK          press Super+Space (the next layout)
#   GT LOCK-TYPE-OTHER-LAYOUT, GT LOCK-TYPE-FIRST-LAYOUT
#                                                   type the user's password and Enter
#   GT HEAD-ON, GT HEAD-OFF                         plug a second monitor in, pull it out
#   GT KEY-FOCUS-HEAD                               press Alt+period (the next monitor)
#   GT KEY-FOCUS-HEAD-WINDOW                        press Alt+j
#   GT SCREENSHOT-HEAD                              take a screenshot of the second monitor
#   GT KEY-MENU-WIFI                                press Alt+p (a menu window for Wi-Fi)
#   GT WIFI-TYPE N TEXT                             type TEXT and Enter (letters and digits)
#   GT KEY-MENU-OPEN                                press Alt+p (a menu window for an open network)
#   GT OPEN-TYPE N TEXT                             type TEXT and Enter (letters and digits)
#   GT KEY-VIEW-BROWSER                             press Alt+3 (a tag nothing is on)
#   GT KEY-BROWSER-AWAY, GT KEY-BROWSER-AGAIN       press Alt+1, then the browser key (Alt+Shift+u)
#   GT KEY-BROWSER-ASIDE                            press Alt+1
#   GT KEY-BROWSER-LAUNCH, GT KEY-BROWSER-BACK      press the browser key, then Alt+1
#   GT KEY-VT-ADMIN, GT KEY-VT-DESKTOP              press Ctrl+Alt+F2, then Ctrl+Alt+F1
#   GT KEY-MENU-AFTER-VT                            press Alt+p
#   GT END
# Verdicts: "GT PASS|FAIL|INFO name - detail".
set -u
R=/var/lib/kryptik/zones
KD=/usr/bin/kryptikd
USER_NAME="${1:-tester}"
# The user's login password, which the screen lock's checks send to the launch daemon.
USER_PW="${2:-}"
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
    echo "entries: $(ls /run/kryptik/zones 2>&1 | tr '\n' ' ')| $1: $(ls -la --time-style=full-iso /run/kryptik/zones/"$1" 2>&1 | tr '\n' ' ')| running: $("$KD" list --running 2>&1 | tr '\n' ' ')| log: $(zone_log "$1" | tail -10 | tr '\n' ' ')| proxy: $(tail -4 "/run/kryptik-proxy/$UID_/$1.log" 2>&1 | tr '\n' ' ')| procs: $(pgrep -af "havoc|kryptikd run $1" 2>/dev/null | cut -c1-90 | tr '\n' ';')| seccomp: $(dmesg 2>/dev/null | grep -a 'type=1326' | grep -av 'comm="dwl"' | tail -3 | tr '\n' ' ')"
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
# The user's two layouts, us then de, for the lock's round with both; us is in force first, so
# every other round types as it would with one.
su -s /bin/sh "$USER_NAME" -c 'mkdir -p "$HOME/.config/kryptik" && printf "us de\n" > "$HOME/.config/kryptik/keyboard"'
su -s /bin/bash "$USER_NAME" -c 'setsid /usr/bin/kryptik-session </dev/null >/dev/null 2>&1 &'
if wait_for 30 test -S "$RT/wayland-0"; then pass "session-socket" "dwl listening at $RT/wayland-0"; else fail "session-socket" "$(cat "$RT/kryptik/session.log" 2>/dev/null | tail -3 | tr '\n' ' ')"; fi
pgrep -u "$USER_NAME" -x dwl >/dev/null && pass "compositor-running" || fail "compositor-running" "$(tail -3 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"
# The desktop's own cgroup bounds what a zone can make the compositor hold: a quarter of the
# memory, 1 GiB at least (cgroup.rs's desktop_memory_max).
dwl_pid="$(pgrep -u "$USER_NAME" -xo dwl)"
want_max=$(( $(sed -n 's/^MemTotal: *\([0-9]*\) kB$/\1/p' /proc/meminfo) * 1024 / 4 ))
(( want_max < (1 << 30) )) && want_max=$(( 1 << 30 ))
dcg=/sys/fs/cgroup/kryptik-desktop
if [[ "$(cat "/proc/${dwl_pid:-0}/cgroup" 2>/dev/null)" == "0::/kryptik-desktop" && "$(cat "$dcg/memory.max" 2>/dev/null)" == "$want_max" ]]; then
    pass "desktop-memory-bound" "dwl runs in $dcg under memory.max $want_max"
else
    fail "desktop-memory-bound" "dwl ${dwl_pid:-gone}: $(cat "/proc/${dwl_pid:-0}/cgroup" 2>&1); memory.max $(cat "$dcg/memory.max" 2>&1), want $want_max; session.log: $(grep -a 'kryptik-launch' "$RT/kryptik/session.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
fi
# dwl runs without group kryptik, which reaches the launch daemon and the mixer's control socket;
# the session's spawner keeps it for the keys' commands (compositor-separation design).
kgid="$(awk -F: '$1 == "kryptik" { print $3 }' /etc/group)"
spawner_pid="$(pgrep -u "$USER_NAME" -xo dwl-spawner)"
dgroups="$(sed -n 's/^Groups:[[:space:]]*//p' "/proc/${dwl_pid:-0}/status" 2>/dev/null)"
sgroups="$(sed -n 's/^Groups:[[:space:]]*//p' "/proc/${spawner_pid:-0}/status" 2>/dev/null)"
if [[ -n "$kgid" && -r "/proc/${dwl_pid:-0}/status" ]] && ! grep -qw "$kgid" <<<"$dgroups" && grep -qw "$kgid" <<<"$sgroups"; then
    pass "dwl-without-group" "dwl ${dwl_pid} runs with groups ${dgroups:-none}, without kryptik (${kgid}); its spawner ${spawner_pid} keeps it"
else
    fail "dwl-without-group" "dwl ${dwl_pid:-gone}: groups ${dgroups:-none}; spawner ${spawner_pid:-none}: groups ${sgroups:-none}; kryptik is ${kgid:-missing}; session.log: $(grep -a 'kryptik-launch' "$RT/kryptik/session.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
fi
# The seat is dwl's alone: seatd answers group seat, which the launch daemon gives dwl and the
# login lacks, so nothing else of the session can switch the console or take the screens and keys.
seatgid="$(awk -F: '$1 == "seat" { print $3 }' /etc/group)"
lgroups="$(id -G "$USER_NAME" 2>/dev/null)"
if [[ -n "$seatgid" ]] && grep -qw "$seatgid" <<<"$dgroups" && ! grep -qw "$seatgid" <<<"$sgroups" \
   && ! grep -qw "$seatgid" <<<"$lgroups"; then
    pass "seat-is-dwls" "dwl ${dwl_pid} holds seat (${seatgid}); its spawner ${spawner_pid} and ${USER_NAME} do not"
else
    fail "seat-is-dwls" "seat is ${seatgid:-missing}; dwl: ${dgroups:-none}; spawner: ${sgroups:-none}; ${USER_NAME}: ${lgroups:-none}"
fi
dwl_env="$(tr '\0' '\n' < "/proc/$(pgrep -u "$USER_NAME" -xo dwl)/environ" 2>/dev/null \
           | grep -E '^(XKB_DEFAULT_LAYOUT|XKB_DEFAULT_VARIANT|XKB_DEFAULT_OPTIONS|KRYPTIK_LAYOUTS)=' | sort | tr '\n' ' ')"
if [[ "$dwl_env" == "KRYPTIK_LAYOUTS=us de XKB_DEFAULT_LAYOUT=us,de XKB_DEFAULT_OPTIONS=grp:win_space_toggle XKB_DEFAULT_VARIANT=, " ]]; then
    pass "desktop-layouts" "the user's list became dwl's keymap: ${dwl_env}"
else
    fail "desktop-layouts" "dwl's environment: ${dwl_env:-none}"
fi
wait_for 20 test -f "$RT/kryptik/focus" && pass "chrome-focus-record" "$(tr '\n' ' ' < "$RT/kryptik/focus")" || fail "chrome-focus-record" "no $RT/kryptik/focus after 20 s"
# The record exists before the chrome's own window has mapped: wait for the window.
wait_for 20 grep -q '^zone=0' "$RT/kryptik/focus" && pass "chrome-window-is-zone0" "the launcher window is recorded as zone 0 (trusted)" || fail "chrome-window-is-zone0" "$(cat "$RT/kryptik/focus" 2>/dev/null | tr '\n' ' '); terminals: $(pgrep -u "$USER_NAME" -a havoc 2>/dev/null | tr '\n' ';'); session.log: $(tail -4 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"
# The chrome arms the idle lock, ten minutes by default. The suite stops it, as its own quiet
# stretches would lock the session under it; the lock section runs one of 8 s.
if wait_for 20 pgrep -u "$USER_NAME" -fx '/usr/bin/kryptik-lock --idle 600'; then
    pass "idle-lock-armed" "the chrome started kryptik-lock --idle 600"
else
    fail "idle-lock-armed" "kryptik-lock processes: $(pgrep -u "$USER_NAME" -af kryptik-lock | tr '\n' ';')"
fi
pkill -u "$USER_NAME" -fx '/usr/bin/kryptik-lock --idle 600' 2>/dev/null

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
for g in zwlr_screencopy_manager_v1 zwlr_data_control_manager_v1 zwp_primary_selection_device_manager_v1 zwlr_layer_shell_v1 zwp_virtual_keyboard_manager_v1 zwlr_virtual_pointer_manager_v1 zwlr_export_dmabuf_manager_v1 zwlr_gamma_control_manager_v1 zwlr_output_manager_v1 ext_session_lock_manager_v1 zwlr_foreign_toplevel_manager_v1; do
    [[ "$out" == *" $g "* ]] && hidden_seen="$hidden_seen $g"
done
[[ -z "$hidden_seen" ]] && pass "zone-hidden-globals" "no capture, data-control, primary-selection, layer-shell, virtual-input, dmabuf-export, gamma, output-management or session-lock global reaches the zone" || fail "zone-hidden-globals" "reached the zone:$hidden_seen"
# Where a zone's unwritten pool is charged (resource-limits design, Tests). dwl reads it first, so
# its pages are the desktop's, inside the desktop's bound and outside the zone's. The probe then
# drops the pool and keeps its descriptor, as a zone may: the pages stay the desktop's until the
# proxy punches the range.
desk_mem() { cat /sys/fs/cgroup/kryptik-desktop/memory.current 2>/dev/null || echo 0; }
# Its shmem alone, which the zone's pool is and dwl's own allocations are not.
desk_shmem() { awk '$1 == "shmem" { print $2; f = 1 } END { if (!f) print 0 }' /sys/fs/cgroup/kryptik-desktop/memory.stat 2>/dev/null; }
charge_said() { since_mark charge untrusted | grep -q "$1"; }
mark charge untrusted
before="$(desk_mem)"; sbefore="$(desk_shmem)"
launch_plain untrusted "/usr/libexec/kryptik/wlprobe charge keep" > "$LOG/launch-charge.out" 2>&1 &
charge_job=$!
if wait_for 30 charge_said 'sample memory.current now'; then
    sleep 1
    held="$(desk_mem)"; kept="$held"; sheld="$(desk_shmem)"; skept="$sheld"
    wait_for 15 charge_said 'pool gone' && { sleep 1; kept="$(desk_mem)"; skept="$(desk_shmem)"; }
    unfreed="$(grep -h 'pages were not freed' "/run/kryptik-proxy/$UID_/untrusted.log" 2>/dev/null | tail -1)"
    info "desktop-charge: a zone's unwritten 4 MiB pool raised the desktop's memory.current by $(( (held - before) / 1024 )) KiB and its shmem by $(( (sheld - sbefore) / 1024 )) KiB while dwl showed it; once the pool was gone and the zone kept its descriptor, by $(( (kept - before) / 1024 )) KiB and $(( (skept - sbefore) / 1024 )) KiB; the proxy: ${unfreed:-no unfreed pages logged}"
else
    info "desktop-charge: the probe drew nothing: $(since_mark charge untrusted | tail -3 | tr '\n' ' ')"
fi
wait "$charge_job" 2>/dev/null
# The launch returns once the zone runs; the probe keeps its window 10 s, and the next checks
# start untrusted themselves.
wait_for 20 test ! -e /run/kryptik/zones/untrusted/init.pid; sleep 1
# No zone reaches dwl's sockets: of every socket untrusted's user can find, none
# is dwl's own or one of its zones' sockets, and its own is the proxy's. Each file is
# stat'ed, which sees through a socket bound in over a file. The launcher marks
# each line of a zone's output in its log ("zone untrusted| "), so the lines
# are found unanchored.
mapfile -t comps < <(stat -c '%d:%i' "$RT/wayland-0" /run/kryptik-compositor/"$UID_"/* 2>/dev/null)
mark socks untrusted
launch_plain untrusted "sh -c 'find / -path /proc -prune -o -path /sys -prune -o -exec stat -c \"T-%F %d:%i %n\" {} + 2>/dev/null | grep \"^T-socket \" | sed \"s/^T-socket /SOCK /\"; echo SOCKS-DONE'" > "$LOG/launch-socks.out" 2>&1
socks_done() { since_mark socks untrusted | grep -q SOCKS-DONE; }
wait_for 120 socks_done
socks="$(since_mark socks untrusted | grep -o 'SOCK [0-9][0-9]*:[0-9][0-9]* .*')"
reached="$(for id in "${comps[@]}"; do grep "^SOCK ${id} " <<<"$socks"; done)"
if [[ "${#comps[@]}" -lt 2 ]] || ! socks_done; then
    fail "compositor-socket-unreached" "dwl's sockets (${comps[*]:-not found}) or the zone's list ($(since_mark socks untrusted | tail -2 | tr '\n' ' ')) could not be read"
elif [[ "$socks" != *" /run/kryptik/wayland-0"* ]]; then
    fail "compositor-socket-unreached" "the zone found no proxy socket, so its list proves nothing: $(tr '\n' ';' <<<"$socks")"
elif [[ -n "$reached" ]]; then
    fail "compositor-socket-unreached" "the zone reaches a socket of dwl's: $(tr '\n' ';' <<<"$reached")"
else
    pass "compositor-socket-unreached" "none of the zone's $(grep -c . <<<"$socks") sockets is one of dwl's ${#comps[@]} (${comps[*]}); it reaches the proxy's"
fi
# The move gesture's socket, beside the proxy's directory, is none of them either.
door="$(stat -c '%d:%i' "/run/kryptik-proxy/$UID_/untrusted.control" 2>/dev/null)"
if [[ -n "$door" ]] && socks_done && ! grep -q "^SOCK ${door} " <<<"$socks"; then
    pass "move-door-unreached" "none of the zone's sockets is the move gesture's (${door})"
else
    fail "move-door-unreached" "the gesture's socket: ${door:-not found}; the zone's reaching it: $(grep "^SOCK ${door:-none} " <<<"$socks" | tr '\n' ';')"
fi
wait_for 20 test ! -e /run/kryptik/zones/untrusted/init.pid; sleep 1
mark bind untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe bind zwlr_screencopy_manager_v1" > "$LOG/launch-bind.out" 2>&1
sleep 3
out="$(since_mark bind untrusted)"
[[ "$out" == *"bind refused"* ]] && pass "zone-bind-refused" "a bind of the screencopy manager got wl_display.error and a closed connection" || fail "zone-bind-refused" "$(echo "$out" | tail -3 | tr '\n' ' ')"
plog="/run/kryptik-proxy/$UID_/untrusted.log"
grep -q 'not advertised' "$plog" 2>/dev/null && pass "proxy-logged-refusal" "$(grep 'not advertised' "$plog" | tail -1 | cut -c1-120)" || fail "proxy-logged-refusal" "no refusal in the proxy log $plog"

# --- dwl's socket for each zone -----------------------------------------------
# The proxy reaches dwl through untrusted's own socket, never dwl's. Through it a
# client is told only of the globals the proxy lets through, and binding a hidden
# one by the number zone 0's list gives it ends the connection; zone 0's own
# client binds that number (the control).
zsock="/run/kryptik-compositor/$UID_/untrusted"
# The daemon passes dwl's socket as descriptor 4, checked as the session's, and the proxy
# connects through /proc/self/fd/4.
ppid0="$(pgrep -f '^kryptik-wlproxy --zone untrusted ' | head -1)"
proxy_cmd="$(tr '\0' ' ' < "/proc/${ppid0:-none}/cmdline" 2>/dev/null)"
proxy_up="$(readlink "/proc/${ppid0:-none}/fd/4" 2>/dev/null)"
[[ "$proxy_cmd" == *"--upstream /proc/self/fd/4 "* && "$proxy_up" == "$zsock" ]] && pass "proxy-upstream-zone-socket" "untrusted's proxy reaches dwl at $zsock, by descriptor" \
    || fail "proxy-upstream-zone-socket" "the proxy's command line: ${proxy_cmd:-none}; its descriptor 4: ${proxy_up:-none}"
as_user "WAYLAND_DISPLAY=$zsock /usr/libexec/kryptik/wlprobe list" > "$LOG/probe-zone-socket.out" 2>&1
offered="$(awk '$1 == "global" { print $3 }' "$LOG/probe-zone-socket.out" | sort -u | tr '\n' ' ')"
beyond="$(awk '$1 == "global" { print $3 }' "$LOG/probe-zone-socket.out" \
    | grep -vxE 'wl_compositor|wl_subcompositor|wl_shm|wl_seat|wl_output|xdg_wm_base|zxdg_decoration_manager_v1|wp_viewporter|wp_cursor_shape_manager_v1|wp_fractional_scale_manager_v1' | tr '\n' ' ')"
if grep -qxF "connected $zsock" "$LOG/probe-zone-socket.out" && [[ -z "$beyond" && "$offered" == *xdg_wm_base* && "$offered" == *wl_seat* ]]; then
    pass "zone-socket-allowlist" "dwl tells untrusted's socket of ${offered% } alone"
else
    fail "zone-socket-allowlist" "beyond the proxy's list: ${beyond:-none}; offered: ${offered:-none}; $(tail -2 "$LOG/probe-zone-socket.out" | tr '\n' ' ')"
fi
number_of() { awk -v g="$1" '$1 == "global" && $3 == g { print $2; exit }' "$LOG/probe-zone0.out"; }
as_user "/usr/libexec/kryptik/wlprobe bind zwlr_screencopy_manager_v1 $(number_of zwlr_screencopy_manager_v1)" > "$LOG/bind-zone0-screencopy.out" 2>&1
refused=""; taken=""
for g in zwlr_screencopy_manager_v1 zwp_virtual_keyboard_manager_v1 ext_session_lock_manager_v1; do
    num="$(number_of "$g")"
    as_user "WAYLAND_DISPLAY=$zsock /usr/libexec/kryptik/wlprobe bind $g ${num:-0}" > "$LOG/bind-zone-socket-$g.out" 2>&1
    # libwayland calls a global it hides invalid or, in newer releases, unavailable.
    if [[ -n "$num" ]] && grep -qE "message=(invalid global $g \($num\)|global $g \($num\) is unavailable)" "$LOG/bind-zone-socket-$g.out" \
       && grep -q '^bind refused' "$LOG/bind-zone-socket-$g.out"; then
        refused+=" $g ($num)"
    else
        taken+=" $g (${num:-not listed for zone 0}): $(tail -2 "$LOG/bind-zone-socket-$g.out" | tr '\n' ' ')"
    fi
done
if grep -q '^bind accepted' "$LOG/bind-zone0-screencopy.out" && [[ -z "$taken" ]]; then
    pass "zone-socket-bind-refused" "each bound by its number on untrusted's socket ended the connection:${refused}; zone 0's client bound screencopy"
else
    fail "zone-socket-bind-refused" "zone 0's control: $(tail -1 "$LOG/bind-zone0-screencopy.out");${taken:- none taken}"
fi

# --- the proxy as a user of its own -------------------------------------------
# untrusted's proxy, which the launch daemon started, runs as the top uid of the
# zone's block, which no zone maps, with no group, under no_new_privs and seccomp,
# in a network namespace and a cgroup of its own. That uid lists neither the
# user's home nor the consent directory and reaches neither the launch daemon's
# socket, dwl's own nor any proxy's from outside a zone; and dwl refuses
# personal's proxy uid on untrusted's socket.
puid() { echo $(( $(sed -n 's/^uid_base[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "/etc/kryptik/zones/$1.toml") + 65535 )); }
P_UNTRUSTED="$(puid untrusted)"; P_PERSONAL="$(puid personal)"
ppid_="$(pgrep -f '^kryptik-wlproxy --zone untrusted ' | head -1)"
st="/proc/${ppid_:-none}/status"
ids="${P_UNTRUSTED}[[:space:]]*${P_UNTRUSTED}[[:space:]]*${P_UNTRUSTED}[[:space:]]*${P_UNTRUSTED}"
if [[ -n "$ppid_" ]] && grep -qx "Uid:[[:space:]]*$ids" "$st" && grep -qx "Gid:[[:space:]]*$ids" "$st" \
   && grep -qx 'Groups:[[:space:]]*' "$st" && grep -qx 'NoNewPrivs:[[:space:]]*1' "$st" && grep -qx 'Seccomp:[[:space:]]*2' "$st" \
   && grep -qx 'CapPrm:[[:space:]]*0000000000000000' "$st" && grep -qx 'CapEff:[[:space:]]*0000000000000000' "$st" \
   && [[ "$(readlink "/proc/$ppid_/ns/ipc")" != "$(readlink /proc/1/ns/ipc)" ]] \
   && [[ "$(readlink "/proc/$ppid_/ns/net")" != "$(readlink /proc/1/ns/net)" ]]; then
    pass "proxy-own-user" "untrusted's proxy (pid $ppid_) is uid $P_UNTRUSTED with no group and no capability, NoNewPrivs 1, Seccomp 2, in network and IPC namespaces of its own"
else
    fail "proxy-own-user" "pid ${ppid_:-none}: $(grep -E '^(Uid|Gid|Groups|CapPrm|CapEff|NoNewPrivs|Seccomp):' "$st" 2>/dev/null | tr '\n' ' ')net $(readlink "/proc/$ppid_/ns/net" 2>/dev/null) against $(readlink /proc/1/ns/net)"
fi
pcg="$(sed -n 's/^0:://p' "/proc/${ppid_:-none}/cgroup" 2>/dev/null)"
if [[ "$pcg" == */proxy.untrusted.* && "$(cat "/sys/fs/cgroup$pcg/memory.max" 2>/dev/null)" == 134217728 && "$(cat "/sys/fs/cgroup$pcg/pids.max" 2>/dev/null)" == 1 ]]; then
    pass "proxy-cgroup" "$pcg: memory.max 128 MiB, pids.max 1"
else
    fail "proxy-cgroup" "cgroup ${pcg:-none}: memory.max $(cat "/sys/fs/cgroup$pcg/memory.max" 2>&1), pids.max $(cat "/sys/fs/cgroup$pcg/pids.max" 2>&1)"
fi
reach="$(python3 - "$P_UNTRUSTED" "$(getent passwd "$USER_NAME" | cut -d: -f6)" "$RT/wayland-0" "/run/kryptik-proxy/$UID_/untrusted/wayland-0" "/run/kryptik-proxy/$UID_/untrusted.control" <<'PY'
import errno, os, socket, sys
uid, home, own, proxy, door = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
os.setgroups([]); os.setgid(uid); os.setuid(uid)
for kind, path in (("dir", home), ("dir", "/run/kryptik-consent"), ("sock", "/run/kryptik-launch/launch.sock"), ("sock", own), ("sock", proxy), ("sock", door)):
    try:
        if kind == "dir":
            os.listdir(path)
        else:
            s = socket.socket(socket.AF_UNIX)
            s.connect(path)
            s.close()
        print(f"REACHED {path}")
    except OSError as e:
        print(f"refused {path} {errno.errorcode.get(e.errno, e.errno)}")
PY
)"
if [[ "$(grep -c '^refused .* EACCES$' <<<"$reach")" -eq 6 ]]; then
    pass "proxy-uid-reaches-nothing" "as uid $P_UNTRUSTED: $(tr '\n' ';' <<<"$reach")"
else
    fail "proxy-uid-reaches-nothing" "as uid $P_UNTRUSTED: $(tr '\n' ';' <<<"$reach")"
fi
slog="$RT/kryptik/session.log"
refused_before="$(grep -c "^dwl: zone untrusted refused a client of uid $P_PERSONAL " "$slog" 2>/dev/null)"
other="$(python3 - "$P_PERSONAL" "$zsock" <<'PY'
import os, sys
uid = int(sys.argv[1])
os.setgroups([]); os.setgid(uid); os.setuid(uid)
os.execve("/usr/libexec/kryptik/wlprobe", ["wlprobe", "list"], {"WAYLAND_DISPLAY": sys.argv[2]})
PY
)"
dwl_refused() { [[ "$(grep -c "^dwl: zone untrusted refused a client of uid $P_PERSONAL " "$slog" 2>/dev/null)" -gt "${refused_before:-0}" ]]; }
if [[ "$other" == *"closed before the registry was listed"* ]] && wait_for 5 dwl_refused; then
    pass "zone-socket-refuses-other-proxy" "personal's proxy uid $P_PERSONAL was closed on untrusted's socket, and dwl said so"
else
    fail "zone-socket-refuses-other-proxy" "the probe as uid $P_PERSONAL: $(tr '\n' ' ' <<<"$other"); dwl: $(grep 'refused a client' "$slog" 2>/dev/null | tail -2 | tr '\n' ' ')"
fi
# Every socket that uid can reach, found under / (not /proc or /sys), as it would
# connect to one: only dwl's sockets for the session's zones may serve it. A server whose
# rules refuse the uid (an s6-ipcserver's, dwl's for another zone) may take the connection
# and end it at once, unread: that is closed, not served.
swept="$(python3 - "$P_UNTRUSTED" "$zsock" <<'PY'
import os, socket, stat, sys
uid, own = int(sys.argv[1]), sys.argv[2]
os.setgroups([]); os.setgid(uid); os.setuid(uid)
def reaches(path):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(2)
    try:
        s.connect(path)
    except OSError:
        s.close()
        return None
    # Served: the far end waits for this uid to speak, or speaks; closed: it hung up unasked.
    try:
        s.settimeout(1)
        return "closed" if s.recv(1) == b"" else "served"
    except socket.timeout:
        return "served"
    except OSError:
        return "closed"
    finally:
        s.close()
for top, dirs, files in os.walk("/"):
    if top == "/":
        dirs[:] = [d for d in dirs if d not in ("proc", "sys")]
    for name in files:
        path = os.path.join(top, name)
        try:
            if stat.S_ISSOCK(os.lstat(path).st_mode):
                r = reaches(path)
                if r:
                    print(f"{'REACHED' if r == 'served' else 'CLOSED'} {path}")
        except OSError:
            pass
# The control: its own zone's socket, by the name it is given (it cannot list the directory).
print("SWEPT" + (" CONTROL" if reaches(own) == "served" else ""))
PY
)"
beyond="$(grep '^REACHED ' <<<"$swept" | grep -v "^REACHED /run/kryptik-compositor/$UID_/" | tr '\n' ';')"
closed="$(grep '^CLOSED ' <<<"$swept" | cut -d' ' -f2- | tr '\n' ' ')"
if [[ "$swept" == *"SWEPT CONTROL"* && -z "$beyond" ]]; then
    pass "proxy-uid-socket-sweep" "as uid $P_UNTRUSTED no socket under / serves it but its zone's own, by its name; closed on it unread: ${closed:-none}"
else
    fail "proxy-uid-socket-sweep" "as uid $P_UNTRUSTED, served beyond dwl's zone sockets: ${beyond:-none}; closed: ${closed:-none}; $(grep '^SWEPT' <<<"$swept")"
fi
# s6-rc's oneshot runner serves root alone (s6-rc-init's rules): the proxy's uid, and the
# session's user with its groups, are closed on at once, before any request is read.
runner_to() {   # runner_to UID [USER]: served, closed or unreached
    python3 - "$1" "${2:-}" /run/s6-rc/servicedirs/s6rc-oneshot-runner/s <<'PY'
import os, pwd, socket, sys
uid, user, path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
if user:
    os.initgroups(user, pwd.getpwnam(user).pw_gid); os.setgid(pwd.getpwnam(user).pw_gid)
else:
    os.setgroups([]); os.setgid(uid)
os.setuid(uid)
s = socket.socket(socket.AF_UNIX)
s.settimeout(2)
try:
    s.connect(path)
except OSError as e:
    print(f"unreached ({e.strerror})"); sys.exit()
s.settimeout(1)
try:
    print("closed" if s.recv(1) == b"" else "served")
except socket.timeout:
    print("served")
except OSError:
    print("closed")
PY
}
r_proxy="$(runner_to "$P_UNTRUSTED")"; r_user="$(runner_to "$UID_" "$USER_NAME")"
if [[ -S /run/s6-rc/servicedirs/s6rc-oneshot-runner/s && "$r_proxy" != served && "$r_user" != served ]]; then
    pass "oneshot-runner-serves-root-alone" "s6-rc's oneshot runner, to the proxy's uid: ${r_proxy}; to the session's user: ${r_user}"
else
    fail "oneshot-runner-serves-root-alone" "the runner's socket: $(ls -l /run/s6-rc/servicedirs/s6rc-oneshot-runner/s 2>&1); proxy uid: ${r_proxy:-none}; session user: ${r_user:-none}"
fi

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
# Nor the keyboard when the zone 0 window it mapped behind closes, as a
# question does once answered: the keyboard goes back to the window before.
as_user "/usr/libexec/kryptik/wlprobe oversize 0 90 holder" > "$LOG/holder.out" 2>&1 &
holder_pid=$!
wait_for 15 grep -q 'keyboard entered the window' "$LOG/holder.out"
as_user "/usr/libexec/kryptik/wlprobe oversize 0 90 closer" > "$LOG/closer.out" 2>&1 &
closer_pid=$!
wait_for 15 grep -q 'keyboard entered the window' "$LOG/closer.out"
mark behind untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe oversize 0 30 behind" > "$LOG/launch-behind.out" 2>&1
wait_for 20 probe_committed behind; sleep 1
pkill -u "$USER_NAME" -f 'wlprobe oversize 0 90 closer' 2>/dev/null; wait "$closer_pid" 2>/dev/null
sleep 3
back="$(grep -c 'keyboard entered the window' "$LOG/holder.out")"
if ! probe_committed behind; then
    fail "close-keeps-zone0-focus" "the zone's window never drew: $(since_mark behind untrusted | tail -3 | tr '\n' ' ')"
elif since_mark behind untrusted | grep -q 'keyboard entered'; then
    fail "close-keeps-zone0-focus" "the zone's window took the keyboard when the zone 0 window in front of it closed; focus: $(tr '\n' ' ' < "$RT/kryptik/focus")"
elif [[ "$back" -lt 2 ]]; then
    fail "close-keeps-zone0-focus" "the earlier zone 0 window had the keyboard ${back} time(s), not back again; focus: $(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    pass "close-keeps-zone0-focus" "the keyboard went back to the earlier zone 0 window, not to the zone's window mapped behind the one that closed"
fi
pkill -u "$USER_NAME" -f 'wlprobe oversize 0 90 holder' 2>/dev/null; wait "$holder_pid" 2>/dev/null
wait_for 40 test ! -e /run/kryptik/zones/untrusted/init.pid; sleep 1
# With no other window on its tag the keyboard goes nowhere, until the user's
# key takes it to the zone's window.
echo "GT KEY-EMPTY-TAG"
sleep 2
as_user "/usr/libexec/kryptik/wlprobe oversize 0 90 alone" > "$LOG/alone.out" 2>&1 &
alone_pid=$!
wait_for 15 grep -q 'keyboard entered the window' "$LOG/alone.out"
mark lone untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe oversize 0 30 lone" > "$LOG/launch-lone.out" 2>&1
wait_for 20 probe_committed lone; sleep 1
pkill -u "$USER_NAME" -f 'wlprobe oversize 0 90 alone' 2>/dev/null; wait "$alone_pid" 2>/dev/null
sleep 3
if ! probe_committed lone; then
    fail "alone-keeps-no-keyboard" "the zone's window never drew: $(since_mark lone untrusted | tail -3 | tr '\n' ' ')"
elif since_mark lone untrusted | grep -q 'keyboard entered'; then
    fail "alone-keeps-no-keyboard" "the zone's window, alone on its tag, took the keyboard when the zone 0 window closed; focus: $(tr '\n' ' ' < "$RT/kryptik/focus")"
else
    pass "alone-keeps-no-keyboard" "alone on its tag after the zone 0 window closed, the zone's window got no keyboard"
fi
echo "GT KEY-FOCUS-LONE"
lone_keyed() { since_mark lone untrusted | grep -q 'keyboard entered'; }
wait_for 10 lone_keyed && pass "alone-reached-by-key" "Alt+j gave the zone's window the keyboard" \
    || fail "alone-reached-by-key" "no keyboard for the zone's window after Alt+j: $(since_mark lone untrusted | tail -3 | tr '\n' ' ')"
wait_for 40 test ! -e /run/kryptik/zones/untrusted/init.pid; sleep 1
echo "GT KEY-TAG-BACK"
sleep 2

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
# The bar over a fullscreen window also names the zones that hold the microphone and the camera,
# as the window covers the chrome's own windows that say so: the microphone's holder as the
# mixer records it, and the camera granted with vivid standing in for one. The camera's window,
# opening on the grant, ends the fullscreen as any zone 0 window does; closed, Alt+e puts it back.
# The mixer's directory is first made anew, as a restart that made it again would: the compositor's
# watch stays with the old one, and the mark must come all the same.
micdir=/run/kryptik-sound/marks
micrec="$micdir/microphone"
mic_record() {   # mic_record OWNER ZONE: a record of who may record, as OWNER writes it
    printf '%s\n' "$2" > "$micrec.t" && chown "$1" "$micrec.t" && chmod 0644 "$micrec.t" && mv -f "$micrec.t" "$micrec"
}
mv "$micdir" "$micdir.before" && install -d -m 0755 -o 87 "$micdir"
mic_record 87 untrusted
modprobe vivid n_devs=1 node_types=0x1 2> "$LOG/vivid-marks.err"
marks_cam="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"
wait_for 15 pgrep -u "$USER_NAME" -f 'kryptik-chrome --camera untrusted'
# Its window must be up, zone 0's and with the keyboard, before it is closed: only then has it
# ended untrusted's fullscreen, which Alt+e is to give back.
wait_for 15 grep -qx 'zone=0' "$RT/kryptik/focus" \
    || info "marks: the camera's window has not taken the keyboard: $(tr '\n' ' ' < "$RT/kryptik/focus")"
pkill -u "$USER_NAME" -f 'kryptik-chrome --camera untrusted'
wait_for 15 grep -q '^zone=untrusted' "$RT/kryptik/focus"
echo "GT KEY-MARKS-FULLSCREEN"
if wait_for 20 grep -q '^fullscreen=1' "$RT/kryptik/focus" && grep -q '^zone=untrusted' "$RT/kryptik/focus"; then
    pass "marks-fullscreen" "untrusted fullscreen again, holding the camera (${marks_cam}) and the microphone"
else
    fail "marks-fullscreen" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); camera: ${marks_cam}; vivid: $(tr '\n' ' ' < "$LOG/vivid-marks.err")"
fi
sleep 2
echo "GT SCREENSHOT-MARKS"
sleep 6
# Taken back; and a record of the microphone's holder the mixer did not write counts for nothing.
as_user "kryptik-launch --camera-revoke" > /dev/null 2>&1
mic_record 0 untrusted
sleep 2
echo "GT SCREENSHOT-NO-MARKS"
sleep 6
# The mixer's own directory back, its control socket in it.
rm -rf "$micdir" && mv "$micdir.before" "$micdir"
modprobe -r vivid uvcvideo 2>/dev/null
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
# The menu's network line: what the daemon passes on of the net zone's own status, here a
# wired uplink with no radio.
net_line() { as_user "kryptik-launch --info net" 2>/dev/null | sed -n 's/^network //p'; }
net_ready() { [[ "$(net_line)" == "ready: "* ]]; }
if wait_for 60 net_ready && [[ "$(net_line)" =~ ^ready:\ uplink\ [0-9.]+/[0-9]+,\ DNS$ ]]; then
    pass "menu-network-line" "Network: $(net_line)"
else
    fail "menu-network-line" "kryptik-launch --info net: $(as_user "kryptik-launch --info net" 2>&1 | tr '\n' ' ')"
fi
# At the text login the user's `kryptik status net` asks the launch service for the same line.
status_user="$(as_user "kryptik status net" 2>&1)"
if [[ -n "$(net_line)" && "$status_user" == *$'\n'"    network  $(net_line)"* ]]; then
    pass "status-network-line-user" "kryptik status net, as the user: $(grep -m1 'network  ' <<<"$status_user" | sed 's/^ *//')"
else
    fail "status-network-line-user" "kryptik status net: $(tr '\n' ' ' <<<"$status_user" | cut -c1-300); the menu's: $(net_line)"
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
# A net zone that withholds statements shows only in their age, so the launcher
# names a stale one. The menu runs with a stored statement from today, then with
# one 45 days old (kryptikd verified what it stored and reads it as it is), and
# whatever was stored before is put back.
UPD=/var/lib/kryptik/update
menu_text() { printf 'q\n' | as_user "TERM=dumb /usr/bin/kryptik-chrome --menu" 2>&1; }
statement() {   # statement EPOCH: the stored statement, issued then, for a version below any real one
    printf 'KRYPTIK-LATEST-1\nrole: development\nversion: 0.0.1\nissued: %s\nmanifest-sha256: %064d\nbase: 0.0.1/\n' \
        "$(date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ)" 0 > "$UPD/pointer"
}
quiet_line() { grep -o 'Update: no statement from the release key for .*' <<<"$1"; }
[[ -d "$UPD" ]] || mkdir -m 700 "$UPD"; rm -f /root/gt/pointer.kept
[[ -e "$UPD/pointer" ]] && cp -p "$UPD/pointer" /root/gt/pointer.kept
statement "$(date +%s)"; fresh="$(menu_text)"
statement "$(( $(date +%s) - 45 * 86400 ))"; old="$(menu_text)"
if [[ -e /root/gt/pointer.kept ]]; then mv -f /root/gt/pointer.kept "$UPD/pointer"; else rm -f "$UPD/pointer"; fi
if [[ "$fresh" == *"trusted launcher"* && -z "$(quiet_line "$fresh")" && "$(quiet_line "$old")" == *" for 45 days "* ]]; then
    pass "menu-names-stale-statement" "45 days old: $(quiet_line "$old"); from today: no line"
else
    fail "menu-names-stale-statement" "from today: $(quiet_line "$fresh" || tr '\n' ' ' <<<"$fresh" | cut -c1-200) | 45 days old: $(quiet_line "$old" || tr '\n' ' ' <<<"$old" | cut -c1-300)"
fi
# With none ever accepted, the install's age counts where the image names a
# channel: the menu runs with no statement, a channel named and the install
# record dated 45 days back, and all three are put back.
CONF=/etc/kryptik/update.conf; REC=/var/lib/kryptik/install.json
installed="$(stat -c %Y "$REC" 2>/dev/null)"
rm -f /root/gt/conf.kept /root/gt/pointer.kept
[[ -e "$CONF" ]] && cp -p "$CONF" /root/gt/conf.kept
[[ -e "$UPD/pointer" ]] && mv -f "$UPD/pointer" /root/gt/pointer.kept
mkdir -p /etc/kryptik && printf 'channel = https://channel.invalid/\n' > "$CONF"
[[ -n "$installed" ]] && touch -d "@$(( $(date +%s) - 45 * 86400 ))" "$REC"
never="$(menu_text)"
[[ -n "$installed" ]] && touch -d "@$installed" "$REC"
if [[ -e /root/gt/conf.kept ]]; then mv -f /root/gt/conf.kept "$CONF"; else rm -f "$CONF"; fi
[[ -e /root/gt/pointer.kept ]] && mv -f /root/gt/pointer.kept "$UPD/pointer"
told="$(grep -o 'Update: no statement from the release key since .*' <<<"$never")"
if [[ -n "$installed" && "$told" == *"since this machine was installed, 45 days ago"* ]]; then
    pass "menu-names-install-age" "$told"
else
    fail "menu-names-install-age" "install record dated ${installed:-unread}; the menu said: $(tr '\n' ' ' <<<"$never" | cut -c1-300)"
fi
# The menu's u reaches the channel's verbs as the user: automatic fetching turned on
# there is on in kryptikd's record, and off again. A channel is named for it, and the
# setting and the configuration are put back.
rm -f /root/gt/conf.kept /root/gt/auto.kept
[[ -e "$CONF" ]] && cp -p "$CONF" /root/gt/conf.kept
[[ -e "$UPD/auto" ]] && cp -p "$UPD/auto" /root/gt/auto.kept
printf 'channel = https://channel.invalid/\n' > "$CONF"
printf 'u\na\n\nq\n' | as_user "TERM=dumb /usr/bin/kryptik-chrome --menu" > "$LOG/menu-update.out" 2>&1
auto_on="$(cat "$UPD/auto" 2>/dev/null)"
printf 'u\nm\n\nq\n' | as_user "TERM=dumb /usr/bin/kryptik-chrome --menu" >> "$LOG/menu-update.out" 2>&1
auto_off=gone; [[ -e "$UPD/auto" ]] && auto_off="still $(cat "$UPD/auto")"
if [[ -e /root/gt/conf.kept ]]; then mv -f /root/gt/conf.kept "$CONF"; else rm -f "$CONF"; fi
if [[ -e /root/gt/auto.kept ]]; then mv -f /root/gt/auto.kept "$UPD/auto"; else rm -f "$UPD/auto"; fi
if [[ "$auto_on" == on && "$auto_off" == gone ]]; then
    pass "menu-update-auto" "the menu's u, then a, turned automatic fetching on through the launch daemon, and u, then m, off"
else
    fail "menu-update-auto" "after a: ${auto_on:-no record}; after m: ${auto_off}; $(tail -4 "$LOG/menu-update.out" | tr '\n' ' ')"
fi
# A trial that failed reads as one, not as a release to install: the menu names it from
# kryptikd's status with boot-success's reason, and the record is put back as it was.
BOOTST=/var/lib/kryptik/boot
rm -f /root/gt/trial.failed.kept
[[ -e "$BOOTST/trial.failed" ]] && cp -p "$BOOTST/trial.failed" /root/gt/trial.failed.kept
printf 'b\narmed=1\nwhy=came up unhealthy: service net-zone is not up\n' > "$BOOTST/trial.failed"
failed_menu="$(menu_text)"
if [[ -e /root/gt/trial.failed.kept ]]; then mv -f /root/gt/trial.failed.kept "$BOOTST/trial.failed"; else rm -f "$BOOTST/trial.failed"; fi
told="$(grep -o 'Update: the trial of slot b .*' <<<"$failed_menu")"
if [[ "$told" == "Update: the trial of slot b came up unhealthy: service net-zone is not up; this machine runs the release before it (u for more)" ]]; then
    pass "menu-names-failed-trial" "$told"
else
    fail "menu-names-failed-trial" "the menu said: $(tr '\n' ' ' <<<"$failed_menu" | cut -c1-300)"
fi
# A trial armed for the next boot reads as armed, not as a release to install again.
rm -f /root/gt/trial.kept
[[ -e "$BOOTST/trial" ]] && cp -p "$BOOTST/trial" /root/gt/trial.kept
printf 'b\narmed=1\n' > "$BOOTST/trial"
armed_menu="$(menu_text)"
if [[ -e /root/gt/trial.kept ]]; then mv -f /root/gt/trial.kept "$BOOTST/trial"; else rm -f "$BOOTST/trial"; fi
told="$(grep -o 'Update: slot b is armed.*' <<<"$armed_menu")"
if [[ "$told" == "Update: slot b is armed: the next boot tries it (u for more)" ]]; then
    pass "menu-names-armed-trial" "$told"
else
    fail "menu-names-armed-trial" "the menu said: $(tr '\n' ' ' <<<"$armed_menu" | cut -c1-300)"
fi

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
# A window is the zone's whose socket its client came through, whatever app_id it
# claims: a client of personal's socket calling itself the vault's is personal's, stays
# on the tag in view rather than the vault's, and given the keyboard, the chrome names
# it personal.
as_user "WLPROBE_APP_ID=kryptik.vault.forged WAYLAND_DISPLAY=/run/kryptik-compositor/$UID_/personal /usr/libexec/kryptik/wlprobe oversize 0 40 socket-named" > "$LOG/socket-named.out" 2>&1 &
named_pid=$!
named_drawn() { grep -q 'committed ' "$LOG/socket-named.out"; }
wait_for 15 named_drawn
# Alt+j walks the keyboard round the tag's windows, so one press puts it on the probe
# whether or not the probe took it on map, and Alt+k as often walks it back.
named=""
for k in 1 2 3 back-1 back-2 back-3; do
    echo "GT KEY-FOCUS-NAMED $k"
    sleep 2
    if [[ -z "$named" ]] && grep -qx 'title=socket-named' "$RT/kryptik/focus"; then named="$(tr '\n' ' ' < "$RT/kryptik/focus")"; fi
done
if [[ "$named" == *"zone=personal "* ]] && grep -q 'keyboard entered the window' "$LOG/socket-named.out"; then
    pass "zone-socket-names-window" "$named"
else
    fail "zone-socket-names-window" "focus with the probe's title: ${named:-never}; now: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); the probe: $(tail -3 "$LOG/socket-named.out" | tr '\n' ' ')"
fi
wait "$named_pid" 2>/dev/null
# And the vault's socket keeps its windows on the vault's tag whatever they claim: a client
# of it calling itself personal's maps out of view; Alt+9 shows that tag, Alt+j gives the
# window the keyboard, named the vault's, and Alt+1 comes back.
as_user "WLPROBE_APP_ID=kryptik.personal.forged WAYLAND_DISPLAY=/run/kryptik-compositor/$UID_/vault /usr/libexec/kryptik/wlprobe oversize 0 25 vault-placed" > "$LOG/vault-placed.out" 2>&1 &
vault_pid=$!
vault_drawn() { grep -q 'committed ' "$LOG/vault-placed.out"; }
wait_for 15 vault_drawn
in_view="$(tr '\n' ' ' < "$RT/kryptik/focus")"
echo "GT KEY-VIEW-VAULT"
sleep 2
echo "GT KEY-FOCUS-VAULT"
sleep 2
placed="$(tr '\n' ' ' < "$RT/kryptik/focus")"
echo "GT KEY-VAULT-BACK"
sleep 2
if [[ "$in_view" != *"title=vault-placed "* && "$placed" == *"zone=vault "* && "$placed" == *"title=vault-placed "* ]]; then
    pass "vault-tag-by-socket" "on tag 9: $placed"
else
    fail "vault-tag-by-socket" "before Alt+9: $in_view; after Alt+9 and Alt+j: ${placed:-nothing}; the probe: $(tail -3 "$LOG/vault-placed.out" | tr '\n' ' ')"
fi
wait "$vault_pid" 2>/dev/null
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
        /usr/bin/s6-*|/usr/sbin/s6-*|/usr/libexec/s6-*|/usr/sbin/udevd|/usr/sbin/agetty|/usr/bin/seatd|/usr/bin/kryptikd|/usr/bin/kryptik-wlproxy|/usr/bin/kryptik-launch|/usr/bin/kryptik-lock|/usr/bin/dwl|/usr/bin/sleep) ;;
        # Zone 0's mixer, which the zones play and record through.
        /usr/libexec/kryptik/kryptik-sound) ;;
        # The chrome's watch on the monitors, which gives each new one the user's scale.
        /usr/bin/kryptik-display) ;;
        /usr/bin/bash|/usr/bin/python3)
            case "$script" in /usr/libexec/kryptik/*|/usr/bin/kryptik-session|/usr/bin/kryptik-chrome) ;; *) foreign+=("$p ${cmd:0:60}") ;; esac ;;
        /usr/bin/havoc)
            case "$script" in /usr/bin/kryptik-chrome|/usr/bin/kryptik-launch) ;; *) foreign+=("$p ${cmd:0:60}") ;; esac ;;
        *) foreign+=("$p ${cmd:0:60}") ;;
    esac
done
[[ "${#foreign[@]}" -eq 0 ]] && pass "zone0-own-programs-only" "every process outside the zones' cgroups is one of zone 0's own" || fail "zone0-own-programs-only" "$(printf '%s; ' "${foreign[@]}")"
# dwl starts no program itself: the session's spawner runs the keys' commands from a fixed table,
# and dwl's own filter refuses exec (compositor-separation design).
dwl_pid="$(pgrep -u "$USER_NAME" -xo dwl)"
spawner="$(pgrep -u "$USER_NAME" -xo dwl-spawner)"
# Every thread carries the filter, not the leader alone.
unfiltered="$(for s in /proc/"${dwl_pid:-0}"/task/*/status; do grep -qE '^Seccomp:[[:space:]]+2$' "$s" 2>/dev/null || echo "${s%/status}"; done)"
if [[ -z "$unfiltered" ]] && grep -qE '^Seccomp:[[:space:]]+2$' "/proc/${dwl_pid:-0}/status" 2>/dev/null \
   && grep -qE '^NoNewPrivs:[[:space:]]+1$' "/proc/${dwl_pid:-0}/status" 2>/dev/null && [[ -n "$spawner" ]]; then
    pass "dwl-execs-nothing" "dwl ${dwl_pid} runs under its no-exec filter, and its spawner is ${spawner}"
else
    fail "dwl-execs-nothing" "dwl ${dwl_pid:-gone}: $(grep -E '^(Seccomp|NoNewPrivs):' "/proc/${dwl_pid:-0}/status" 2>&1 | tr '\n' ' '); threads without the filter: ${unfiltered:-none}; spawner: ${spawner:-none}; $(pgrep -u "$USER_NAME" -a dwl | tr '\n' ';')"
fi
# And it reads only below its own list and writes no file (Landlock), as its session log says:
# every path of the list there, one thread to bind, and no signal outside its domain (ABI 6).
if grep -qE '^dwl: confined: reads only below ([0-9]+) of its \1 paths, .*, signals nothing outside it \(1 thread, ' "$RT/kryptik/session.log" 2>/dev/null; then
    pass "dwl-confined-to-its-files" "$(grep -m1 '^dwl: confined: ' "$RT/kryptik/session.log")"
else
    fail "dwl-confined-to-its-files" "session.log: $(grep -a '^dwl: \(confined\|not confined\|Landlock\)' "$RT/kryptik/session.log" 2>/dev/null | head -3 | tr '\n' ' ')"
fi
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

# --- copy and paste inside a zone -------------------------------------------
# The proxy serves the zone's selection to the zone's own clients (compositor/wlproxy/src/
# clipboard.rs): a copy in one of untrusted's windows pastes in another of untrusted's, and
# reaches neither personal's windows nor zone 0's, whose selection is the compositor's. A
# client is offered the selection as the keyboard enters it, so Alt+j walks the keyboard
# round the windows: four presses visit the copying window and then the pasting one, in
# either order they mapped.
mark copy untrusted
launch_plain untrusted "sh -c '/usr/libexec/kryptik/wlprobe copy 90 kryptik4471 & exec /usr/libexec/kryptik/wlprobe paste 90'" > "$LOG/launch-copy.out" 2>&1
two_drawn() { [[ "$(since_mark copy untrusted | grep -c 'committed ')" -ge 2 ]]; }
wait_for 20 two_drawn
for k in 1 2 3 4; do
    echo "GT KEY-FOCUS-CLIP $k"
    sleep 3
done
if since_mark copy untrusted | grep -q 'copied$' && since_mark copy untrusted | grep -q 'pasted: kryptik4471$'; then
    pass "zone-copy-pastes-in-zone" "one of untrusted's clients copied, and another pasted the text"
else
    fail "zone-copy-pastes-in-zone" "$(since_mark copy untrusted | grep -E 'copied|pasted|no selection|sent to|keyboard|copy cancelled' | tail -8 | tr '\n' ' '); launch: $(tr '\n' ' ' < "$LOG/launch-copy.out")"
fi
stop_zone untrusted
mark paste personal
launch personal "/usr/libexec/kryptik/wlprobe paste 30" > "$LOG/launch-paste.out" 2>&1
paste_drawn() { since_mark paste personal | grep -q 'committed '; }
wait_for 20 paste_drawn
echo "GT KEY-FOCUS-CLIP-PERSONAL"
pasted_personal() { since_mark paste personal | grep -qE 'no selection|pasted: |a selection'; }
if wait_for 15 pasted_personal && since_mark paste personal | grep -q 'no selection' && ! since_mark paste personal | grep -q 'pasted: '; then
    pass "zone-copy-stays-in-zone" "personal's client, given the keyboard, was offered no selection"
else
    fail "zone-copy-stays-in-zone" "$(since_mark paste personal | tail -5 | tr '\n' ' '); launch: $(tr '\n' ' ' < "$LOG/launch-paste.out")"
fi
stop_zone personal
as_user "/usr/libexec/kryptik/wlprobe paste 6" > "$LOG/paste-zone0.out" 2>&1
if grep -q '^no selection' "$LOG/paste-zone0.out" && ! grep -q '^pasted: ' "$LOG/paste-zone0.out"; then
    pass "zone-copy-not-in-zone0" "zone 0's client, on the compositor itself, was offered no selection"
else
    fail "zone-copy-not-in-zone0" "$(tr '\n' ' ' < "$LOG/paste-zone0.out")"
fi

# --- the move gesture carries a zone's copy to another zone's windows -------
# kryptik-launch --clipboard-move, the chrome's m<N><M>, takes what untrusted's windows copied
# from untrusted's proxy, gives it to personal's, and clears it in untrusted once personal holds
# it: personal's window pastes it, and untrusted's is no longer offered it. Four Alt+j presses
# before the move visit every window, the copying one among them, and four after it again.
mark move untrusted
launch_plain untrusted "sh -c '/usr/libexec/kryptik/wlprobe copy 120 moved4471 & exec /usr/libexec/kryptik/wlprobe paste 120'" > "$LOG/launch-move.out" 2>&1
mark move personal
launch personal "/usr/libexec/kryptik/wlprobe paste 120" > "$LOG/launch-move-paste.out" 2>&1
three_drawn() { [[ "$(since_mark move untrusted | grep -c 'committed ')" -ge 2 ]] && since_mark move personal | grep -q 'committed '; }
wait_for 30 three_drawn
for k in 1 2 3 4; do
    echo "GT KEY-FOCUS-MOVE $k"
    sleep 3
done
as_user "kryptik-launch --clipboard-move untrusted personal" > "$LOG/move.out" 2>&1; moved=$?
mark moved untrusted; mark moved personal
for k in 1 2 3 4; do
    echo "GT KEY-FOCUS-MOVED $k"
    sleep 3
done
if since_mark move untrusted | grep -q 'copied$' && [[ "$moved" = 0 ]] \
   && grep -qx "moved 9 bytes of text/plain;charset=utf-8 from untrusted's windows to personal's" "$LOG/move.out" \
   && since_mark moved personal | grep -q 'pasted: moved4471$'; then
    pass "move-crosses-zones" "$(cat "$LOG/move.out"); personal's window pasted it"
else
    fail "move-crosses-zones" "move: $(tr '\n' ' ' < "$LOG/move.out") (rc $moved); untrusted: $(since_mark move untrusted | grep -E 'copied|pasted|no selection|keyboard' | tail -4 | tr '\n' ' '); personal: $(since_mark moved personal | tail -3 | tr '\n' ' ')"
fi
if since_mark moved untrusted | grep -q 'no selection' && ! since_mark moved untrusted | grep -q 'pasted: '; then
    pass "move-leaves-nothing-behind" "untrusted's pasting window, given the keyboard after the move, was offered no selection"
else
    fail "move-leaves-nothing-behind" "$(since_mark moved untrusted | tail -4 | tr '\n' ' ')"
fi
# What moved is in no log of zone 0's: the proxies and the launcher name the type and length.
PROXIES="/run/kryptik-proxy/$UID_"
if grep -q 'move: took 9 bytes of text/plain;charset=utf-8' "$PROXIES/untrusted.log" 2>/dev/null \
   && ! grep -rqsF moved4471 "$RT/kryptik" "$PROXIES" /run/uncaught-logs; then
    pass "move-in-no-log" "$(grep -h 'move: ' "$PROXIES/untrusted.log" "$PROXIES/personal.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
else
    fail "move-in-no-log" "proxy lines: $(grep -h 'move' "$PROXIES/untrusted.log" 2>/dev/null | tail -2 | tr '\n' ' '); holding the text: $(grep -rlsF moved4471 "$RT/kryptik" "$PROXIES" /run/uncaught-logs | tr '\n' ' ')"
fi
# The gesture's socket answers the session's user alone: root, past the socket's 0600, is
# refused as any other uid would be. The proxy writes the refusal and closes without reading,
# so the request may meet a closed socket; the refusal is read all the same.
door="$PROXIES/untrusted.control"
refusal="$(python3 - "$door" 2>&1 <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(sys.argv[1])
try:
    s.sendall(b"take\n")
    s.shutdown(socket.SHUT_WR)
except (BrokenPipeError, ConnectionResetError):
    pass
print(s.recv(200).decode(errors="replace").strip())
PY
)"
[[ "$refusal" == "error: not the session's user" ]] && pass "move-door-refuses-others" "root, at $door, was told: $refusal" \
    || fail "move-door-refuses-others" "root got: ${refusal:-nothing}"
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
launch_plain untrusted "/usr/libexec/kryptik/wlprobe cursor 20 shape" > "$LOG/launch-cursor.out" 2>&1
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
# A cursor by name is the compositor's own drawing, from its theme: the zone may ask for one.
if since_mark cursor untrusted | grep -q 'asked for the text cursor by name' && ! since_mark cursor untrusted | grep -qE 'refused|connection closed'; then
    pass "zone-cursor-by-name" "the zone asked for the text cursor by name through its proxy, and its session stood"
else
    fail "zone-cursor-by-name" "$(since_mark cursor untrusted | tail -4 | tr '\n' ' ')"
fi
# --- a zone's window hears the scale it is shown at ------------------------------------------
# wp_fractional_scale_v1 through the proxy: the compositor tells each window its output's scale,
# in 120ths, so a browser draws text sharp at 1.5 instead of being scaled down from 2. This
# machine's output is at 1, which wlroots sends as 120 once the window is shown.
stop_zone untrusted
mark scale untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe scale 10" > "$LOG/launch-scale.out" 2>&1
scale_heard() { since_mark scale untrusted | grep -q 'preferred scale '; }
if wait_for 20 scale_heard && ! since_mark scale untrusted | grep -qE 'refused|connection closed'; then
    pass "zone-fractional-scale" "the zone's window heard its $(since_mark scale untrusted | grep -m1 'preferred scale ') through its proxy"
else
    fail "zone-fractional-scale" "$(since_mark scale untrusted | tail -4 | tr '\n' ' '); $(zone_why untrusted)"
fi
# --- a zone's window animates on a clock of its own ----------------------------------------
# A zone's monotonic clock starts at a random point (isolate::set_time_origin), so the
# compositor's frame times, read from zone 0's clock, share no base with the zone's.
# wlprobe animate commits on every frame callback and says how both clocks ran; in zone 0,
# where they are one clock, it shows the measure is sound.
anim_fields() {   # anim_fields < OUTPUT -> "FRAMES COMP OWN GAP", from wlprobe animate's line
    grep -o 'animated: .*' | tail -1 | sed -n 's/^animated: \([0-9]*\) frames; .* ran \([0-9]*\) ms and .* clock \(-\{0,1\}[0-9]*\) ms; .* is \(-\{0,1\}[0-9]*\) ms from.*/\1 \2 \3 \4/p'
}
# ran_alike FRAMES COMP OWN: 20 frames or more, and the two clocks ran within a fifth and 100 ms
ran_alike() { (( ${1:-0} >= 20 && ${2:-0} - ${3:-0} <= ${3:-0} / 5 + 100 && ${3:-0} - ${2:-0} <= ${3:-0} / 5 + 100 )); }
abs() { local v="${1:-0}"; echo "${v#-}"; }
stop_zone untrusted
as_user "/usr/libexec/kryptik/wlprobe animate 5" > "$LOG/animate-zone0.out" 2>&1
read -r f0 c0 o0 g0 < <(anim_fields < "$LOG/animate-zone0.out")
if ran_alike "$f0" "$c0" "$o0" && (( $(abs "$g0") < 2000 )); then
    pass "zone0-frame-clock" "zone 0: ${f0} frames; the compositor's frame times ran ${c0} ms and its clock ${o0} ms, ${g0} ms apart: one clock"
else
    fail "zone0-frame-clock" "the compositor's frame times are not zone 0's clock, so a zone's proves nothing: $(tr '\n' ' ' < "$LOG/animate-zone0.out" | tail -c 300)"
fi
mark animate untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe animate 5" > "$LOG/launch-animate.out" 2>&1
anim_said() { since_mark animate untrusted | grep -q 'animated: '; }
wait_for 30 anim_said
read -r f1 c1 o1 g1 < <(since_mark animate untrusted | anim_fields)
if ran_alike "$f1" "$c1" "$o1" && (( $(abs "$g1") >= 60000 )); then
    pass "zone-window-animates" "untrusted: ${f1} frames; the compositor's frame times ran ${c1} ms and the zone's clock ${o1} ms; the compositor's clock is ${g1} ms from the zone's"
else
    fail "zone-window-animates" "$(since_mark animate untrusted | tail -3 | tr '\n' ' '); $(zone_why untrusted)"
fi
stop_zone untrusted
# --- a zone's popup, inside its window and only while it has the keyboard ----------------
# wlprobe popup opens a popup from its window's centre, larger than the screen, that may be
# neither moved nor resized, draws it 200 px larger still in cyan, and grabs the keyboard for
# it with a serial no input gave, which wlroots does not check. The window maps behind zone
# 0's, so the grab is a window's that has no keyboard. The host's screenshot must show the
# window's frame whole and no cyan outside it; the menu Alt+p opens must take the keyboard,
# and the popup goes as it does.
mark popup untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe popup 40 grab" > "$LOG/launch-popup.out" 2>&1
popup_drawn() { since_mark popup untrusted | grep -q 'popup committed '; }
if wait_for 20 popup_drawn && grep -q '^zone=0' "$RT/kryptik/focus"; then
    pass "zone-popup-drawn" "$(since_mark popup untrusted | grep 'popup committed '), behind zone 0's window"
else
    fail "zone-popup-drawn" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); probe: $(since_mark popup untrusted | tail -4 | tr '\n' ' '); launch: $(tr '\n' ' ' < "$LOG/launch-popup.out"); $(zone_why untrusted)"
fi
sleep 2
echo "GT SCREENSHOT-POPUP"
sleep 6
menus_before="$(menu_windows)"
popup_done() { since_mark popup untrusted | grep -q 'popup done'; }
echo "GT KEY-MENU-POPUP"
if wait_for 20 more_menus && wait_for 10 popup_done && wait_for 10 grep -q '^zone=0' "$RT/kryptik/focus"; then
    pass "zone-popup-yields-keyboard" "the menu opened over the zone's grab, and the popup was closed as the keyboard moved"
else
    fail "zone-popup-yields-keyboard" "menu windows: $(menu_windows), ${menus_before} before; focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); probe: $(since_mark popup untrusted | tail -4 | tr '\n' ' ')"
fi
pkill -n -u "$USER_NAME" -f 'havoc /usr/bin/kryptik-chrome --menu' 2>/dev/null
stop_zone untrusted
# Alt+j to the popup's own window closes it as well: made while the window had no keyboard,
# its grab would swallow the window's enter, and the keys would go on to zone 0's window
# under a frame that names the zone's.
mark popup-own untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe popup 40 grab" > "$LOG/launch-popup-own.out" 2>&1
own_drawn() { since_mark popup-own untrusted | grep -q 'popup committed '; }
own_done() { since_mark popup-own untrusted | grep -q 'popup done'; }
own_keyed() { since_mark popup-own untrusted | grep -q 'keyboard entered the window'; }
wait_for 20 own_drawn
echo "GT KEY-FOCUS-POPUP"
if wait_for 10 own_done && wait_for 10 own_keyed && wait_for 10 grep -q '^zone=untrusted' "$RT/kryptik/focus"; then
    pass "zone-popup-ends-on-own-focus" "Alt+j gave the window the keyboard and closed the popup that had grabbed it unasked"
else
    fail "zone-popup-ends-on-own-focus" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); probe: $(since_mark popup-own untrusted | tail -4 | tr '\n' ' '); launch: $(tr '\n' ' ' < "$LOG/launch-popup-own.out")"
fi
stop_zone untrusted
# --- the screen lock -------------------------------------------------------------------------
# The launch daemon checks the login password against the user's own shadow entry. After a
# wrong one the next waits 2 s, the right one included, which the daemon does not check
# then; the right one after the pause is taken; and no log holds what was typed.
pw_try() { printf '%s\n' "$1" | as_user "kryptik-launch --check-password" 2>&1; echo "exit=$?"; }
in_logs() { grep -rlsF -e "$1" -e "$2" /run/uncaught-logs "$RT/kryptik" "/run/kryptik-proxy/$UID_" /var/log/kryptik/zone-*.log; }
guess=lock-guess-4471
t1="$(pw_try "$guess")"; t2="$(pw_try "$USER_PW")"; sleep 3; t3="$(pw_try "$USER_PW")"
if [[ -z "$USER_PW" ]]; then
    fail "password-check-pauses" "no password given: gui-check.sh USER PASSWORD"
elif [[ "$t1" == "error: wrong password"*"exit=1" && "$t2" == "error: wait "*"exit=1" && "$t3" == "exit=0" && -z "$(in_logs "$guess" "$USER_PW")" ]]; then
    pass "password-check-pauses" "a wrong password: ${t1%%$'\n'*}; the right one at once: ${t2%%$'\n'*}; the right one after the pause: taken; neither is in a log"
else
    fail "password-check-pauses" "wrong: $(tr '\n' ' ' <<<"$t1"); right at once: $(tr '\n' ' ' <<<"$t2"); right after the pause: $(tr '\n' ' ' <<<"$t3"); logs holding one: $(in_logs "$guess" "$USER_PW" | tr '\n' ' ')"
fi
# The lock, Alt+Shift+l, must take the keyboard from zone 0's window while a zone's popup
# holds a grab no input gave, and close that popup; show nothing but itself; refuse a wrong
# password; stay locked when its program is killed, and lock again; keep every key from a
# grab a zone makes while it is locked; and give zone 0's window the keyboard back for the
# login password.
slog="$RT/kryptik/session.log"
said() { grep -c "^kryptik-lock: $1" "$slog" 2>/dev/null; }
more() { [[ "$(said "$1")" -gt "$2" ]]; }
entered0() { grep -c 'keyboard entered the window' "$LOG/lock-zone0.out"; }
back0() { [[ "$(entered0)" -ge 2 ]]; }
# The lock takes the camera back too: vivid stands in for one, granted to untrusted before this
# round's windows open, so the chrome's camera window is up and under them by then.
modprobe vivid n_devs=1 node_types=0x1 2> "$LOG/vivid.err"
cam_given="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"
wait_for 15 pgrep -u "$USER_NAME" -f 'kryptik-chrome --camera untrusted'
# Mapped after lock-0's window, the camera's would take the keyboard from it: it must have it first.
wait_for 15 grep -qx 'zone=0' "$RT/kryptik/focus" \
    || info "lock: the camera's window has not taken the keyboard: $(tr '\n' ' ' < "$RT/kryptik/focus")"
sleep 1
as_user "/usr/libexec/kryptik/wlprobe oversize 0 300 lock-0" > "$LOG/lock-zone0.out" 2>&1 &
lock0_pid=$!
wait_for 15 grep -q 'keyboard entered the window' "$LOG/lock-zone0.out"
mark lock untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe popup 300 grab" > "$LOG/launch-lock.out" 2>&1
lock_grabbed() { since_mark lock untrusted | grep -q 'popup committed '; }
lock_popup_done() { since_mark lock untrusted | grep -q 'popup done'; }
wait_for 20 lock_grabbed
locked0="$(said locked)"; refused0="$(said refused)"; unlocked0="$(said unlocked)"
echo "GT KEY-LOCK"
if wait_for 20 more locked "$locked0" && wait_for 10 lock_popup_done && wait_for 10 grep -q 'keyboard left the window' "$LOG/lock-zone0.out"; then
    pass "lock-takes-keyboard" "Alt+Shift+l locked the session, closed the zone's grabbing popup and took the keyboard from zone 0's window"
else
    fail "lock-takes-keyboard" "lock: $(grep 'kryptik-lock' "$slog" | tail -3 | tr '\n' ' '); zone 0's window: $(tr '\n' ' ' < "$LOG/lock-zone0.out"); the zone's: $(since_mark lock untrusted | tail -3 | tr '\n' ' ')"
fi
if wait_for 10 grep -q '^kryptik-lock: the camera was taken back from zone untrusted' "$slog" \
    && [[ "$("$KD" camera status 2>&1)" == none* && ! -e /run/kryptik-camera/untrusted/video0 ]]; then
    pass "lock-takes-camera" "granted to untrusted (${cam_given}), the camera went back as the screen locked"
else
    fail "lock-takes-camera" "granted: ${cam_given}; $("$KD" camera status 2>&1); lock: $(grep 'kryptik-lock' "$slog" | tail -3 | tr '\n' ' '); vivid: $(tr '\n' ' ' < "$LOG/vivid.err")"
fi
modprobe -r vivid uvcvideo 2>/dev/null
sleep 2
echo "GT SCREENSHOT-LOCKED"
sleep 6
echo "GT LOCK-TYPE-WRONG"
if wait_for 20 more refused "$refused0" && grep '^kryptik-lock: refused' "$slog" | tail -1 | grep -q 'wrong password$'; then
    pass "lock-refuses-wrong-password" "$(grep '^kryptik-lock: refused' "$slog" | tail -1)"
else
    fail "lock-refuses-wrong-password" "$(grep 'kryptik-lock' "$slog" | tail -3 | tr '\n' ' ')"
fi
# Killed, the lock's program leaves the session locked with no window given the keyboard,
# and the lock locks again. The newest kryptik-lock is the one drawing: the process that
# starts it again came before it.
pkill -KILL -n -x -u "$USER_NAME" kryptik-lock 2>/dev/null
if wait_for 20 more locked "$((locked0 + 1))" && grep -q 'the lock died of signal 9; locking again' "$slog" \
   && [[ "$(entered0)" -eq 1 ]] && ! since_mark lock untrusted | grep -q 'keyboard entered'; then
    pass "lock-survives-its-death" "killed, the lock locked again, and no window got the keyboard meanwhile"
else
    fail "lock-survives-its-death" "lock: $(grep 'kryptik-lock' "$slog" | tail -3 | tr '\n' ' '); zone 0's window: $(tr '\n' ' ' < "$LOG/lock-zone0.out"); the zone's: $(since_mark lock untrusted | tail -3 | tr '\n' ' ')"
fi
# A zone's grab made while locked, from a window started then: the password typed next must
# still reach the lock, and the popup closes as the keyboard goes back.
stop_zone untrusted
mark lock2 untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe popup 120 grab" > "$LOG/launch-lock2.out" 2>&1
lock2_grabbed() { since_mark lock2 untrusted | grep -q 'popup committed '; }
lock2_done() { since_mark lock2 untrusted | grep -q 'popup done'; }
wait_for 20 lock2_grabbed; grabbed_locked=$?
# The wrong password's 2 s pause ended while the zone restarted.
echo "GT LOCK-TYPE-RIGHT"
if wait_for 30 more unlocked "$unlocked0" && wait_for 10 back0; then
    pass "lock-unlocks-with-password" "the login password unlocked the session and zone 0's window has the keyboard again"
else
    fail "lock-unlocks-with-password" "lock: $(grep 'kryptik-lock' "$slog" | tail -3 | tr '\n' ' '); zone 0's window: $(tr '\n' ' ' < "$LOG/lock-zone0.out")"
fi
if [[ "$grabbed_locked" -eq 0 ]] && more unlocked "$unlocked0" && wait_for 10 lock2_done && ! since_mark lock2 untrusted | grep -q 'keyboard entered'; then
    pass "lock-keeps-keys-from-zone-grab" "a zone's popup grabbed the keyboard while locked; the password still reached the lock, and the popup closed at the unlock"
else
    fail "lock-keeps-keys-from-zone-grab" "the zone's probe: $(since_mark lock2 untrusted | tail -4 | tr '\n' ' '); launch: $(tr '\n' ' ' < "$LOG/launch-lock2.out")"
fi
pkill -u "$USER_NAME" -f 'wlprobe oversize 0 300 lock-0' 2>/dev/null; wait "$lock0_pid" 2>/dev/null
stop_zone untrusted
# Idle, the session locks itself: kryptik-lock --idle, as the chrome starts it, locks after
# its seconds without input, turns the screens off --blank seconds later and on again at the
# first key, and locks again after the next quiet stretch once unlocked. The compositor tells
# the watcher each screen's power as it changes, so its log says what was done, not asked.
as_user "/usr/bin/kryptik-lock --idle 8 --blank 4" > "$LOG/idle-lock.out" 2>&1 &
idle_pid=$!
idle_said() { [[ "$(grep -c "^kryptik-lock: $1" "$LOG/idle-lock.out")" -ge "$2" ]]; }
# The compositor's word: a screen off, and one on again after that, however many there are.
power_off() { grep -qE '^kryptik-lock: screen [0-9]+ power off$' "$LOG/idle-lock.out"; }
power_back() { sed -n '/^kryptik-lock: screen [0-9]* power off$/,$p' "$LOG/idle-lock.out" | grep -qE '^kryptik-lock: screen [0-9]+ power on$'; }
if wait_for 30 idle_said locked 1 && grep -q '^kryptik-lock: no input for 8 s, locking' "$LOG/idle-lock.out"; then
    pass "idle-locks" "8 s without input locked the session"
else
    fail "idle-locks" "$(tr '\n' ' ' < "$LOG/idle-lock.out"); session.log: $(grep 'kryptik-lock' "$slog" | tail -2 | tr '\n' ' ')"
fi
if wait_for 15 idle_said 'screens off' 1 && wait_for 5 power_off; then
    pass "idle-blanks" "4 s after the lock the screens went off, and the compositor says the output's power is off"
else
    fail "idle-blanks" "the watcher: $(tr '\n' ' ' < "$LOG/idle-lock.out")"
fi
echo "GT LOCK-TYPE-IDLE"
if wait_for 30 idle_said unlocked 1 && wait_for 5 power_back && idle_said 'screens on' 1; then
    pass "key-wakes-screens" "the first key turned the screens on again, and the password unlocked"
else
    fail "key-wakes-screens" "the watcher: $(tr '\n' ' ' < "$LOG/idle-lock.out")"
fi
if wait_for 30 idle_said locked 2; then
    pass "idle-locks-again" "unlocked by the password, the session locked itself again after 8 s more without input"
else
    fail "idle-locks-again" "$(tr '\n' ' ' < "$LOG/idle-lock.out")"
fi
echo "GT LOCK-TYPE-IDLE-AGAIN"
wait_for 30 idle_said unlocked 2 || fail "idle-unlocks" "$(tr '\n' ' ' < "$LOG/idle-lock.out")"
# Its own quiet stretches below must not lock the session under the suite.
pkill -u "$USER_NAME" -fx '/usr/bin/kryptik-lock --idle 8 --blank 4' 2>/dev/null; wait "$idle_pid" 2>/dev/null

# --- holding the screen awake ------------------------------------------------------------------
# A window of a zone whose file says hold_awake keeps the session's idle timers off while it is
# shown and has the keyboard (docs/design/laptop.md). zone 0's probe of them counts inhibitors as
# the lock's timers do: it hears nothing while personal's window holds, and hears the session is
# idle within its 2 s once a zone 0 window takes the keyboard, and again once the lock comes.
# dwl offers the inhibitor only on the sockets of zones whose file allows it, and untrusted's
# file never does.
offers_hold() { as_user "WAYLAND_DISPLAY=/run/kryptik-compositor/$UID_/$1 /usr/libexec/kryptik/wlprobe list" 2>&1 | grep -c ' zwp_idle_inhibit_manager_v1 '; }
if [[ "$(offers_hold personal)" -eq 1 && "$(offers_hold untrusted)" -eq 0 ]]; then
    pass "zone-hold-socket" "dwl offers the idle inhibitor on personal's socket, whose file says hold_awake, and not on untrusted's"
else
    fail "zone-hold-socket" "offered on personal's socket: $(offers_hold personal); on untrusted's: $(offers_hold untrusted)"
fi
mark holdhid untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe inhibit 5" > "$LOG/launch-hold-hidden.out" 2>&1
hold_hidden() { since_mark holdhid untrusted | grep -q 'no zwp_idle_inhibit_manager_v1 offered'; }
if wait_for 20 hold_hidden; then
    pass "zone-hold-refused" "untrusted's window is offered no idle inhibitor"
else
    fail "zone-hold-refused" "$(since_mark holdhid untrusted | tail -3 | tr '\n' ' '); launch: $(tr '\n' ' ' < "$LOG/launch-hold-hidden.out")"
fi
stop_zone untrusted
mark hold personal
launch personal "/usr/libexec/kryptik/wlprobe inhibit 120" > "$LOG/launch-hold.out" 2>&1
hold_keys() { [[ "$(since_mark hold personal | grep -c 'keyboard entered the window')" -ge "$1" ]]; }
hold_asked() { since_mark hold personal | grep -q 'asked to keep the screen awake'; }
hold_drawn() { since_mark hold personal | grep -q 'committed '; }
# Mapped behind zone 0's window, it has the keyboard once the user's key takes it there.
wait_for 30 hold_drawn
echo "GT KEY-FOCUS-HOLD"
wait_for 15 hold_keys 1 && hold_asked; held=$?
sleep 1
as_user "/usr/libexec/kryptik/wlprobe idle 2000 6" > "$LOG/hold-idle.out" 2>&1
if [[ "$held" -eq 0 ]] && grep -q '^watching for 2000 ms' "$LOG/hold-idle.out" && ! grep -qx 'idled' "$LOG/hold-idle.out"; then
    pass "zone-holds-screen-awake" "personal's window, shown with the keyboard, kept zone 0's 2 s idle timer from running out in 6 s"
else
    fail "zone-holds-screen-awake" "personal's probe: $(since_mark hold personal | tail -3 | tr '\n' ' '); zone 0's idle probe: $(tr '\n' ' ' < "$LOG/hold-idle.out"); $(zone_why personal)"
fi
# The chrome names the zone holding the screen awake, from dwl's status, for its menu.
hold_named() { [[ "$(head -n 1 "$RT/kryptik/holdawake" 2>/dev/null)" == personal ]]; }
if wait_for 10 hold_named; then
    pass "chrome-names-hold" "the chrome's record names personal as holding the screen awake"
else
    fail "chrome-names-hold" "holdawake: $(tr '\n' ' ' < "$RT/kryptik/holdawake" 2>/dev/null)"
fi
# The idle lock heeds the hold: one of 2 s, started now, is still waiting 6 s later and never locked.
as_user "/usr/bin/kryptik-lock --idle 2 --blank 30" > "$LOG/hold-idle-lock.out" 2>&1 &
holdidle_pid=$!
sleep 6
pgrep -u "$USER_NAME" -fx '/usr/bin/kryptik-lock --idle 2 --blank 30' > /dev/null; waiting=$?
pkill -u "$USER_NAME" -fx '/usr/bin/kryptik-lock --idle 2 --blank 30' 2>/dev/null; wait "$holdidle_pid" 2>/dev/null
if [[ "$waiting" -eq 0 ]] && ! grep -q 'locking' "$LOG/hold-idle-lock.out"; then
    pass "idle-lock-heeds-hold" "a 2 s idle lock started while personal's window held the screen awake was still waiting 6 s later"
else
    fail "idle-lock-heeds-hold" "still waiting: $([[ "$waiting" -eq 0 ]] && echo yes || echo no); $(tr '\n' ' ' < "$LOG/hold-idle-lock.out")"
fi
# A zone 0 window maps in front and takes the keyboard: the hold ends at once.
as_user "/usr/libexec/kryptik/wlprobe oversize 0 30 hold-0" > "$LOG/hold-zone0.out" 2>&1 &
hold0_pid=$!
hold_left() { since_mark hold personal | grep -q 'keyboard left the window'; }
wait_for 15 grep -q 'keyboard entered the window' "$LOG/hold-zone0.out" && wait_for 5 hold_left; moved=$?
as_user "/usr/libexec/kryptik/wlprobe idle 2000 6" > "$LOG/hold-idle-away.out" 2>&1
if [[ "$moved" -eq 0 ]] && grep -qx 'idled' "$LOG/hold-idle-away.out"; then
    pass "hold-ends-off-keyboard" "a zone 0 window took the keyboard from personal's, and zone 0's 2 s idle timer ran out"
else
    fail "hold-ends-off-keyboard" "zone 0's window: $(tr '\n' ' ' < "$LOG/hold-zone0.out" | cut -c1-200); personal's probe: $(since_mark hold personal | tail -3 | tr '\n' ' '); idle probe: $(tr '\n' ' ' < "$LOG/hold-idle-away.out")"
fi
hold_unnamed() { [[ -z "$(head -n 1 "$RT/kryptik/holdawake" 2>/dev/null)" ]]; }
if wait_for 10 hold_unnamed; then
    pass "chrome-hold-cleared" "the chrome's record names no zone once the zone 0 window took the keyboard"
else
    fail "chrome-hold-cleared" "holdawake: $(tr '\n' ' ' < "$RT/kryptik/holdawake" 2>/dev/null)"
fi
# Closed, it gives personal's window the keyboard back; the lock takes it, and the hold ends.
pkill -u "$USER_NAME" -f 'wlprobe oversize 0 30 hold-0' 2>/dev/null; wait "$hold0_pid" 2>/dev/null
wait_for 10 hold_keys 2; back=$?
as_user "/usr/bin/kryptik-lock" > "$LOG/hold-lock.out" 2>&1 &
holdlock_pid=$!
wait_for 20 grep -q '^kryptik-lock: locked' "$LOG/hold-lock.out"; locked_now=$?
as_user "/usr/libexec/kryptik/wlprobe idle 2000 6" > "$LOG/hold-idle-locked.out" 2>&1
if [[ "$back" -eq 0 && "$locked_now" -eq 0 ]] && grep -qx 'idled' "$LOG/hold-idle-locked.out"; then
    pass "hold-ends-at-lock" "personal's window had the keyboard back; the lock took it, and zone 0's 2 s idle timer ran out"
else
    fail "hold-ends-at-lock" "keyboard back: $([[ "$back" -eq 0 ]] && echo yes || echo no); lock: $(tr '\n' ' ' < "$LOG/hold-lock.out"); idle probe: $(tr '\n' ' ' < "$LOG/hold-idle-locked.out")"
fi
echo "GT LOCK-TYPE-HOLD"
wait_for 30 grep -q '^kryptik-lock: unlocked' "$LOG/hold-lock.out" || fail "hold-lock-unlocks" "$(tr '\n' ' ' < "$LOG/hold-lock.out")"
wait "$holdlock_pid" 2>/dev/null
stop_zone personal

# --- no sleep where the display would not come back --------------------------------------------
# This VM shows through virtio-gpu, whose driver a sleep would leave waiting for good, so the
# daemon refuses before it freezes a zone or drops a key. `kryptik suspend` locks first and is
# told; the password opens the same session, on the same boot, and the compositor answers.
boot0="$(< /proc/sys/kernel/random/boot_id)"
entries0="$(dmesg 2>/dev/null | grep -c 'PM: suspend entry')"
as_user "kryptik suspend" > "$LOG/suspend.out" 2>&1 &
susp_pid=$!
told_awake() { grep -q "suspend: error: the display's driver, virtio-gpu, does not come back from a sleep" "$LOG/suspend.out"; }
if wait_for 30 told_awake; then
    pass "suspend-refused-virtio-gpu" "kryptik suspend locked, and the daemon refused the sleep: virtio-gpu"
else
    fail "suspend-refused-virtio-gpu" "$(tr '\n' ' ' < "$LOG/suspend.out" | cut -c1-300)"
fi
# Keys in the second after the lock's label changed, as it does with the refusal, go nowhere.
sleep 2
echo "GT LOCK-TYPE-SUSPEND"
susp_ended() { ! kill -0 "$susp_pid" 2>/dev/null; }
none_suspended() { ! grep -qx 1 /sys/block/dm-*/dm/suspended 2>/dev/null; }
still_answers() { timeout 10 su -s /bin/bash "$USER_NAME" -c "XDG_RUNTIME_DIR=$RT WAYLAND_DISPLAY=wayland-0 /usr/libexec/kryptik/wlprobe list" 2>&1 | grep -q 'sync done'; }
entries="$(dmesg 2>/dev/null | grep -c 'PM: suspend entry')"
if wait_for 30 susp_ended && grep -q '^kryptik-lock: unlocked' "$LOG/suspend.out" \
        && [[ "$(< /proc/sys/kernel/random/boot_id)" == "$boot0" && "$entries" == "$entries0" ]] && none_suspended && still_answers; then
    pass "suspend-refused-stays-awake" "the password unlocked the same boot, the kernel was never asked to sleep, no mapping is suspended, and the compositor answers"
else
    fail "suspend-refused-stays-awake" "boot $(< /proc/sys/kernel/random/boot_id) (was ${boot0}); suspend entries ${entries} (were ${entries0}); suspended mappings: $(grep -lx 1 /sys/block/dm-*/dm/suspended 2>/dev/null | tr '\n' ' '); $(tail -3 "$LOG/suspend.out" | tr '\n' ' ')"
fi
wait "$susp_pid" 2>/dev/null
# The volume keys are dwl's bindings to zone 0's mixer, which runs without a card here.
mixer() { /usr/libexec/kryptik/kryptik-sound --control status 2>&1 | sed -n 's/^master //p'; }
master_is() { [[ "$(mixer)" == "$1" ]]; }
m0="$(mixer)"; m0="${m0%% *}"
echo "GT KEY-VOLUME-DOWN"
if [[ "$m0" =~ ^[0-9]+$ ]] && wait_for 10 master_is "$(( m0 >= 5 ? m0 - 5 : 0 ))"; then
    pass "volume-key" "the volume-down key took the mixer from ${m0} to $(mixer)"
else
    fail "volume-key" "before: ${m0:-no answer}; after: $(mixer)"
fi
# With two layouts the lock names the one in force, as Super+Space switches: the password typed
# in de, where this keyboard's - key types another character, is refused, and typed again once
# Super+Space is back on us, it opens the lock.
layout_said() { grep -c "^kryptik-lock: layout $1\$" "$slog" 2>/dev/null; }
layout_more() { [[ "$(layout_said "$1")" -gt "$2" ]]; }
us0="$(layout_said US)"; de0="$(layout_said DE)"
locked2="$(said locked)"; refused2="$(said refused)"; unlocked2="$(said unlocked)"
echo "GT KEY-LOCK-LAYOUT"
wait_for 20 more locked "$locked2" && wait_for 10 layout_more US "$us0"; named_us=$?
# Under that lock the volume keys still act, and no other binding does: Alt+p opens no menu.
# Escape then clears the p the lock took as typed.
m1="$(mixer)"; m1="${m1%% *}"; up1="$(( ${m1:-0} + 5 > 100 ? 100 : ${m1:-0} + 5 ))"
menus_locked="$(menu_windows)"
echo "GT KEY-LOCKED-VOLUME-UP"
wait_for 10 master_is "$up1"; went_up=$?
echo "GT KEY-LOCKED-MUTE"
wait_for 10 master_is "$up1 muted"; went_mute=$?
echo "GT KEY-LOCKED-MUTE-AGAIN"
wait_for 10 master_is "$up1"; went_back=$?
if [[ "$m1" =~ ^[0-9]+$ && "$went_up/$went_mute/$went_back" == 0/0/0 ]]; then
    pass "lock-passes-volume-keys" "locked, the volume-up key took the mixer from ${m1} to ${up1}, and the mute key muted it and unmuted it"
else
    fail "lock-passes-volume-keys" "from ${m1:-no answer}: up ${went_up}, mute ${went_mute}, unmute ${went_back} (0 is done); now $(mixer)"
fi
echo "GT KEY-LOCKED-MENU"
sleep 4
if [[ "$(menu_windows)" -eq "$menus_locked" && "$(said unlocked)" -eq "$unlocked2" ]]; then
    pass "lock-holds-other-keys" "under the lock Alt+p opened no menu, and the session stayed locked"
else
    fail "lock-holds-other-keys" "menu windows: ${menus_locked} before Alt+p, $(menu_windows) after; $(grep 'kryptik-lock' "$slog" | tail -2 | tr '\n' ' ')"
fi
echo "GT KEY-LAYOUT-NEXT"
wait_for 10 layout_more DE "$de0"; named_de=$?
if [[ "$named_us/$named_de" == 0/0 ]]; then
    pass "lock-names-layout" "the lock named US, then DE after Super+Space"
else
    fail "lock-names-layout" "$(grep 'kryptik-lock' "$slog" | tail -4 | tr '\n' ' ')"
fi
echo "GT LOCK-TYPE-OTHER-LAYOUT"
if wait_for 15 more refused "$refused2"; then
    pass "lock-refuses-other-layout" "the password typed in de was refused: $(grep '^kryptik-lock: refused' "$slog" | tail -1)"
else
    fail "lock-refuses-other-layout" "$(grep 'kryptik-lock' "$slog" | tail -3 | tr '\n' ' ')"
fi
us1="$(layout_said US)"
echo "GT KEY-LAYOUT-BACK"
wait_for 10 layout_more US "$us1"
# The refusal's pause, which the next try waits out.
sleep 3
echo "GT LOCK-TYPE-FIRST-LAYOUT"
if wait_for 20 more unlocked "$unlocked2"; then
    pass "lock-opens-in-first-layout" "back on us, the same keys opened the lock"
else
    fail "lock-opens-in-first-layout" "$(grep 'kryptik-lock' "$slog" | tail -3 | tr '\n' ' ')"
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
# The user's choices for the monitors, which the watcher the chrome runs makes whenever one
# comes: the first as it is, and any other at scale 2.
displays() { as_user "/usr/bin/kryptik-display" 2>&1; }
first_name="$(displays | awk 'NR == 1 { print $1 }')"
as_user "mkdir -p \$HOME/.config/kryptik && printf '%s 1\n* 2\n' '$first_name' > \$HOME/.config/kryptik/display"
echo "GT HEAD-ON"
if wait_for 30 heads 2; then
    pass "second-head-appears" "the compositor offers two outputs once the second is plugged in"
else
    fail "second-head-appears" "$(outputs) output(s); connectors: $(for s in /sys/class/drm/card*-*/status; do printf '%s=%s ' "${s%/status}" "$(cat "$s" 2>/dev/null)"; done)"
fi
second_scaled() { displays | grep -v "^${first_name} " | grep -q '  scale 2  '; }
if [[ -n "$first_name" ]] && wait_for 15 second_scaled && displays | grep -q "^${first_name}  scale 1  "; then
    pass "second-head-scale-chosen" "the new monitor came at the scale the user's * line asks, the first as its own line asks: $(displays | tr '\n' '|')"
else
    fail "second-head-scale-chosen" "$(displays | tr '\n' '|'); session.log: $(grep 'kryptik-display' "$RT/kryptik/session.log" 2>/dev/null | tail -3 | tr '\n' ' ')"
fi
echo "GT KEY-FOCUS-HEAD"
on_second_head() { local o; o="$(focus_output)"; [[ -n "$o" && "$o" != "$first_head" ]]; }
if wait_for 20 on_second_head; then
    pass "chrome-follows-head" "the record names $(focus_output) after Alt+period; the first monitor is ${first_head}"
else
    fail "chrome-follows-head" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
fi
second_head="$(focus_output)"
# What a zone is told of the monitors: both, each named by its number with no make or model,
# as the zone's proxy rewrites them, and the second at the scale chosen for it.
mark outs untrusted
launch_plain untrusted "/usr/libexec/kryptik/wlprobe outputs" > "$LOG/launch-outputs.out" 2>&1
told_outputs() { since_mark outs untrusted | grep -q 'outputs [0-9]'; }
wait_for 20 told_outputs
zone_outs="$(since_mark outs untrusted)"
named="$(grep -c ' name "output-[0-9]*"' <<<"$zone_outs")"
described="$(grep -c ' description "output-[0-9]*"' <<<"$zone_outs")"
blank="$(grep -c ' geometry .* make "" model ""' <<<"$zone_outs")"
if [[ "$named" -eq 2 && "$described" -eq 2 && "$blank" -eq 2 ]] && grep -q ' scale 2$' <<<"$zone_outs" \
   && grep -q ' scale 1$' <<<"$zone_outs"; then
    pass "zone-sees-heads-unnamed" "two outputs named by number, with no make or model, one at scale 2"
else
    fail "zone-sees-heads-unnamed" "$(tr '\n' '|' <<<"$zone_outs" | cut -c1-400); launch: $(tr '\n' ' ' < "$LOG/launch-outputs.out")"
fi
# The probe's zone stops, so the window below starts untrusted afresh on the second head.
stop_zone untrusted
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
as_user "rm -f \$HOME/.config/kryptik/display"
back_on_first_head() { [[ "$(focus_output)" == "$first_head" ]]; }
wait_for 20 back_on_first_head && pass "chrome-back-on-first-head" "$(tr '\n' ' ' < "$RT/kryptik/focus")" \
    || fail "chrome-back-on-first-head" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null)"
stop_zone untrusted

# --- Wi-Fi from the menu ----------------------------------------------------------------
# A network saved from the chrome's own window, as `kryptik wifi add` saves one at the
# administration login: the host types each answer once it is asked for, and the passphrase,
# read unechoed by kryptik-launch in that window, reaches the net zone's file.
WCONF=/var/lib/kryptik/wifi/wpa_supplicant.conf
menus_before="$(menu_windows)"
echo "GT KEY-MENU-WIFI"
wifi_typed=no
if wait_for 20 more_menus; then
    sleep 2; echo "GT WIFI-TYPE 1 w"
    sleep 3; echo "GT WIFI-TYPE 2 a"
    sleep 2; echo "GT WIFI-TYPE 3 ztmenunet"
    sleep 2; echo "GT WIFI-TYPE 4 menupassphrase1"
    wifi_typed=yes
fi
if [[ "$wifi_typed" == yes ]] && wait_for 30 grep -qx $'\tssid="ztmenunet"' "$WCONF" \
   && grep -qx $'\tpsk="menupassphrase1"' "$WCONF"; then
    pass "chrome-wifi-add" "the menu's w, then a, saved ztmenunet, its passphrase typed in the chrome's own window"
else
    fail "chrome-wifi-add" "typed: ${wifi_typed}; networks in the file: $(grep -c '^network=' "$WCONF" 2>/dev/null); menu windows: $(menu_windows)"
fi
menus_open="$(menu_windows)"
pkill -n -u "$USER_NAME" -f 'havoc /usr/bin/kryptik-chrome --menu' 2>/dev/null
"$KD" wifi forget ztmenunet --wifi-dir /var/lib/kryptik/wifi > /dev/null 2>&1
# An open network from the same menu, with o: no passphrase is asked for or saved. The window
# just closed is gone first, or the new one would only bring the count back to where it was.
menus_fewer() { [[ "$(menu_windows)" -lt "$menus_open" ]]; }
wait_for 5 menus_fewer
menus_before="$(menu_windows)"
echo "GT KEY-MENU-OPEN"
open_typed=no
if wait_for 20 more_menus; then
    sleep 2; echo "GT OPEN-TYPE 1 w"
    sleep 3; echo "GT OPEN-TYPE 2 o"
    sleep 2; echo "GT OPEN-TYPE 3 ztmenuopen"
    open_typed=yes
fi
open_block() { sed -n '/^\tssid="ztmenuopen"$/,/^}$/p' "$WCONF" 2>/dev/null; }
if [[ "$open_typed" == yes ]] && wait_for 30 grep -qx $'\tssid="ztmenuopen"' "$WCONF" \
   && open_block | grep -qx $'\tkey_mgmt=NONE' && ! open_block | grep -q 'psk='; then
    pass "chrome-wifi-add-open" "the menu's w, then o, saved ztmenuopen as an open network without asking for a passphrase"
else
    fail "chrome-wifi-add-open" "typed: ${open_typed}; ztmenuopen's block: $(open_block | tr '\n\t' '  '); menu windows: $(menu_windows)"
fi
pkill -n -u "$USER_NAME" -f 'havoc /usr/bin/kryptik-chrome --menu' 2>/dev/null
"$KD" wifi forget ztmenuopen --wifi-dir /var/lib/kryptik/wifi > /dev/null 2>&1
# The menu's s, as the user's launcher asks it: the daemon's scan job signals the net zone,
# which has no radio here, and passes on its answer. The forget above restarts the net zone,
# for which the daemon answers that the zone is not running, so it is asked until it answers.
scan_answered() { scan_said="$(as_user "kryptik-launch --wifi-scan" 2>&1)"; [[ "$scan_said" == "the net zone has no Wi-Fi radio" ]]; }
if wait_for 60 scan_answered; then
    pass "chrome-wifi-scan" "kryptik-launch --wifi-scan: $scan_said"
else
    fail "chrome-wifi-scan" "kryptik-launch --wifi-scan: $(tr '\n' ' ' <<<"$scan_said" | cut -c1-200)"
fi

# --- the browser, in a zone that carries it ---------------------------------------------
# untrusted names the browser image, which the installer kept from the medium: Firefox opens a
# page of the zone's own, and its window is drawn as untrusted's. It starts on a tag nothing is
# on: mapped beside the launcher, which has the keyboard, the window would wait to be picked,
# and no key pressed at a set time can wait out a start that takes Firefox many seconds.
echo "GT KEY-VIEW-BROWSER"
wait_for 10 grep -qx 'zone=-' "$RT/kryptik/focus" || info "browser: a window still shows after Alt+3: $(tr '\n' ' ' < "$RT/kryptik/focus")"
mark firefox untrusted
launch_plain untrusted "sh -c 'printf \"<title>kryptik-page</title><p>kryptik</p>\" > /tmp/page.html && exec firefox --new-instance file:///tmp/page.html'" > "$LOG/launch-firefox.out" 2>&1 &
ff_page() { grep -q '^title=.*kryptik-page' "$RT/kryptik/focus" && grep -qx 'zone=untrusted' "$RT/kryptik/focus"; }
ff_broke=""
if wait_for 120 ff_page; then
    # With its app_id as the proxy stamped it, which the browser key matches (dwl-config.h).
    pass "browser-window" "Firefox from the browser image opened a page in untrusted: $(grep -E '^(title|appid)=' "$RT/kryptik/focus" | tr '\n' ' ')"
    # Its idle startup tasks and its startup cache's first write come later, the write at most
    # 60 s after the cache's last entry: a call the zone's filter kills there ends Firefox after
    # its window has shown.
    sleep 90
    if ff_page; then
        pass "browser-stays-up" "Firefox's window is still untrusted's 90 s after its page showed"
    else
        ff_broke="browser-stays-up"
        fail "browser-stays-up" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); $(since_mark firefox untrusted | tail -5 | tr '\n' ' '); kernel: $(dmesg 2>/dev/null | grep -E 'type=1326|seccomp' | grep -av 'comm="dwl"' | tail -2 | tr '\n' ' ')"
    fi
else
    # A start that shows nothing prints nothing in the zone either. The host prints FAIL lines
    # alone, so this one carries what the proxy refused, what the zone's filter killed, and
    # whether Firefox still runs and where it waits.
    ff_broke="browser-window"
    fail "browser-window" "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); zone: $(since_mark firefox untrusted | tail -5 | tr '\n' ' '); proxy: $(tail -4 "$plog" 2>/dev/null | tr '\n' ' '); kernel: $(dmesg 2>/dev/null | grep -E 'type=1326|seccomp|segfault|traps:' | grep -av 'comm="dwl"' | tail -4 | tr '\n' ' '); firefox: $(ps -eo pid=,stat=,wchan:24=,etime=,args= 2>/dev/null | grep '[f]irefox' | head -8 | cut -c1-120 | tr '\n' ';'); launch: $(tail -3 "$LOG/launch-firefox.out" 2>/dev/null | tr '\n' ' ')"
fi
# --- a second launch puts the open browser in front ----------------------------------------
# Alt+1 shows another tag; the browser key then views Firefox's tag, 3, on its monitor and
# gives it the keyboard, and starts no second Firefox, which would only say that the first is
# running. The menu's b asks dwl the same through a file in the session's runtime directory,
# which dwl takes from the user alone: one root wrote is removed unheard. With the zone stopped
# the key starts Firefox, on the tag left empty.
# Firefox's own processes: its content processes are started with -contentproc.
ff_count() {
    local n=0 p
    for p in $(pgrep -f '(^|/)firefox( |$)'); do
        tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- '-contentproc' || n=$((n + 1))
    done
    echo "$n"
}
ff_front() { ff_page && grep -qx 'tagset=4' "$RT/kryptik/focus"; }
ff_away() { ! grep -q '^title=.*kryptik-page' "$RT/kryptik/focus"; }
ff_record() { echo "focus: $(tr '\n' ' ' < "$RT/kryptik/focus" 2>/dev/null); browsers: $(tr '\n' ' ' < "$RT/kryptik/browsers" 2>/dev/null)"; }
front="$RT/kryptik/front/browser-front"
ff_before="$(ff_count)"
echo "GT KEY-BROWSER-AWAY"
wait_for 10 ff_away || info "browser: Alt+1 left the keyboard with Firefox: $(ff_record)"
echo "GT KEY-BROWSER-AGAIN"
if wait_for 15 ff_front; then
    sleep 5
    if [[ "$(ff_count)" -eq "$ff_before" ]]; then
        pass "browser-key-brings-forward" "the browser key viewed tag 3 and gave untrusted's Firefox the keyboard; ${ff_before} Firefox before and after"
    else
        fail "browser-key-brings-forward" "a second Firefox started: ${ff_before} before, $(ff_count) after"
    fi
else
    fail "browser-key-brings-forward" "$(ff_record)"
fi
echo "GT KEY-BROWSER-ASIDE"
wait_for 10 ff_away || info "browser: Alt+1 left the keyboard with Firefox: $(ff_record)"
printf 'untrusted\n' > "$front"
sleep 3
if ff_away && [[ ! -e "$front" ]]; then
    pass "browser-front-only-the-users" "a request root wrote was removed, and the keyboard stayed where it was"
else
    fail "browser-front-only-the-users" "$(ff_record); the request: $(ls -la "$front" 2>&1)"
fi
as_user "umask 077 && echo untrusted > $front.tmp && mv -f $front.tmp $front"
if wait_for 10 ff_front && [[ ! -e "$front" ]]; then
    pass "browser-front-request" "the user's request put untrusted's Firefox in front on tag 3, and was removed"
else
    fail "browser-front-request" "$(ff_record); the request: $(ls -la "$front" 2>&1)"
fi
stop_zone untrusted
echo "GT KEY-BROWSER-LAUNCH"
if wait_for 120 grep -qx 'zone=untrusted' "$RT/kryptik/focus"; then
    pass "browser-key-launches" "with untrusted stopped, the browser key started Firefox: $(grep '^title=' "$RT/kryptik/focus")"
else
    fail "browser-key-launches" "$(ff_record)"
fi
stop_zone untrusted
echo "GT KEY-BROWSER-BACK"

# --- the administration login, a console away ---------------------------------------------
# Ctrl+Alt+F2 puts tty2's login in front, and Ctrl+Alt+F1 brings the desktop back, which answers
# its clients and takes keys as before. Last, so a desktop that did not come back ends no round.
vt_is() { [[ "$(fgconsole 2>/dev/null)" == "$1" ]]; }
answers() { timeout 10 su -s /bin/bash "$USER_NAME" -c "XDG_RUNTIME_DIR=$RT WAYLAND_DISPLAY=wayland-0 /usr/libexec/kryptik/wlprobe list" 2>&1 | grep -q 'sync done'; }
menus_vt="$(menu_windows)"
echo "GT KEY-VT-ADMIN"
if wait_for 15 vt_is 2; then
    pass "vt-admin-login" "Ctrl+Alt+F2 put tty2's login in front"
else
    fail "vt-admin-login" "the console in front is $(fgconsole 2>&1)"
fi
echo "GT KEY-VT-DESKTOP"
if wait_for 15 vt_is 1 && wait_for 15 answers; then
    pass "vt-desktop-back" "Ctrl+Alt+F1 brought the desktop back, and the compositor answers a client"
else
    fail "vt-desktop-back" "console $(fgconsole 2>&1); dwl $(pgrep -u "$USER_NAME" -x dwl > /dev/null && echo running || echo gone); session.log: $(tail -3 "$RT/kryptik/session.log" 2>/dev/null | tr '\n' ' ')"
fi
echo "GT KEY-MENU-AFTER-VT"
more_menus() { [[ "$(menu_windows)" -gt "$menus_vt" ]]; }
if wait_for 15 more_menus; then
    pass "vt-desktop-takes-keys" "Alt+p opened the menu after the switch back"
else
    fail "vt-desktop-takes-keys" "menu windows: ${menus_vt} before Alt+p, $(menu_windows) after"
fi
pkill -n -u "$USER_NAME" -f 'havoc /usr/bin/kryptik-chrome --menu' 2>/dev/null

# --- what untrusted's filter refuses Firefox, after a browser check failed ------------------
# A kill's audit line names one call. Here the filter notifies instead: Firefox runs as the user
# in zone 0 under `kryptikd seccomp-trace --zone untrusted`, in a mount and pid namespace of its
# own with untrusted's /usr set bound over /usr and no render or sound node, so one round names
# every call the filter refuses. A soft refusal gets the errno a zone gets, a kill ENOSYS, and
# Firefox goes on. After the last key step: the window it maps could take a key meant for a check.
if [[ -n "$ff_broke" ]]; then
    ffset="$(awk '$1 == "kryptik-usr" && $2 ~ /browser-/ { print $2 }' /proc/self/mounts | tail -1)"
    ff_calls=""
    if [[ -n "$ffset" ]]; then
        ff_calls="$(FFSET="$ffset" FFUSER="$USER_NAME" FFRT="$RT" timeout -k 5 120 \
            unshare -m -p -f --mount-proc --kill-child sh -c '
                mount --bind "$FFSET" /usr || exit 1
                for d in /dev/dri /dev/snd; do [ -d "$d" ] && mount -t tmpfs -o mode=0755 none "$d"; done
                exec su -s /bin/bash "$FFUSER" -c "h=\$(mktemp -d) && cd \$h && printf \"<title>kryptik-page</title><p>kryptik</p>\" > page.html && HOME=\$h XDG_RUNTIME_DIR=$FFRT WAYLAND_DISPLAY=wayland-0 timeout -k 5 60 /usr/bin/kryptikd seccomp-trace --zones /usr/lib/kryptik/zones --zone untrusted -- firefox --new-instance file://\$h/page.html"' 2>&1 \
            | sed -n 's/^.*KRYPTIK_SECCOMP_DENIED //p' | sort | uniq -c | sort -rn \
            | awk '{ n = $1; $1 = ""; printf "%s x%d;", $0, n }')"
    fi
    fail "browser-window-trace" "${ff_broke} failed; untrusted's filter, notifying instead of killing, refused Firefox in zone 0 over ${ffset:-no browser /usr set}:${ff_calls:- nothing}"
fi

# What dwl called outside its filter's list over the whole suite, which the filter logs (audit
# type 1326) and lets through, by number and how often: the list's next entries, until none.
dwl_unlisted="$(dmesg 2>/dev/null | grep -a 'type=1326' | grep -a 'comm="dwl"' | grep -ao ' syscall=[0-9]*' \
    | sort | uniq -c | awk '{ printf "%s%s x%s", s, substr($2, 9), $1; s = ", " }')"
info "dwl's calls outside its list: ${dwl_unlisted:-none}"

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
