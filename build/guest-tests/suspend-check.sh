#!/usr/bin/env bash
# Suspend suite, run as root in the installed guest by tools/image/suspend-test.sh. The host boots
# it with S3 on, a virtual GPU and keyboard, and acts on these lines:
#   GT KEY-LOCK 1|2                  press Alt+Shift+l (the screen lock)
#   GT LOCK-TYPE-STATE-WRONG         type a wrong passphrase and Enter
#   GT LOCK-TYPE-STATE 1|2|3         type the second state passphrase and Enter
#   GT ZONE-PASS-TYPE 1              type the work zone's passphrase and Enter
#   GT ZONE-PASS-SKIP                press Enter alone, where the chrome asks for it again
#   GT SLEEPING 1                    wait for the guest to sleep, dump its memory, wait past
#                                    the watchdog's timeout, then wake it; or for
#                                    GT DID-NOT-SLEEP 1, the kernel's refusal
#   GT SLEEPING 2                    the same, the refusal expected (GT DID-NOT-SLEEP 2)
#   GT POWER-KEY 1|2|3               press the power button, then as GT SLEEPING (3, 4, 8)
#   GT POWER-KEY SOON                the same, a refusal expected (GT DID-NOT-SLEEP 7)
#   GT KEY-LOCK 3|4                  press Alt+Shift+l
#   GT SLEEPING 3|4                  as GT SLEEPING 1, a refusal told as GT DID-NOT-SLEEP 5, 6
#   GT LOCK-TYPE-STATE 4..7          type the second state passphrase and Enter
#   GT STATE-KEY HEX, GT ZONE-KEY HEX, GT CACHE-MARK HEX
#                                    what the dump must not hold
#   GT MARK HEX                      what it must, to show the search finds what is there
#   GT END
# Verdicts: "GT PASS|FAIL|INFO name - detail".
#
# While the state partition is suspended, whatever reaches /var, /home, /root or /etc's upper
# layer waits for it, this script included: in those stretches it reads only /run, /proc and
# /sys, and starts nothing that looks a user up (su, id) or reads the clock's zone (date).
set -u
# The root login's home is on the state partition.
cd / || exit 1
KD=/usr/bin/kryptikd
# Where work's volume is mounted, as zone 0 sees it.
R=/var/lib/kryptik/zones
USER_NAME="${1:-tester}"
STATE_PW="${2:-}"
# The host types the second passphrase, the seed reversed: only the seed crosses the serial line,
# so a copy of the passphrase in the guest's memory came from its way to the lock and back.
SEED="${3:-}"
UID_="$(id -u "$USER_NAME")"
RT="/run/user/$UID_"
OUT=/run/kryptik-suspend-check
mkdir -p "$OUT"; chmod 700 "$OUT"
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
slog="$RT/kryptik/session.log"
said() { grep -c "^kryptik-lock: $1" "$slog" 2>/dev/null; }
more() { [[ "$(said "$1")" -gt "$2" ]]; }
# A device-mapper device's flag, from sysfs alone: 1 suspended, 0 not, none when it is not there.
dm_flag() {
    local d
    for d in /sys/block/dm-*; do
        [[ "$(< "$d/dm/name")" == "$1" ]] && { echo "$(< "$d/dm/suspended")"; return; }
    done
    echo none
}
state_flag() { dm_flag kryptik-state; }
state_is() { [[ "$(state_flag)" == "$1" ]]; }
# Each running zone and whether its cgroup says it is frozen, from /run and cgroupfs.
zones_frozen() {
    local z cg out=""
    for z in /run/kryptik/zones/*/; do
        z="${z%/}"; cg="$(< "$z/cgroup")" 2>/dev/null || continue
        [[ -f "$cg/cgroup.events" ]] || continue
        out+="${z##*/}=$(grep -c '^frozen 1$' "$cg/cgroup.events") "
    done
    echo "${out% }"
}
all_frozen() { local f; f="$(zones_frozen)"; [[ -n "$f" && "$f" != *=0* ]]; }
# One zone's freezer: 1 frozen, 0 not, none when it does not run.
zone_frozen() {
    local cg
    cg="$(< "/run/kryptik/zones/$1/cgroup")" 2>/dev/null || { echo none; return; }
    if [[ -f "$cg/cgroup.events" ]]; then grep -c '^frozen 1$' "$cg/cgroup.events"; else echo none; fi
}
thawed() { [[ "$(zone_frozen "$1")" == 0 ]]; }
# A zone that waits for its volume's passphrase: frozen, its volume suspended.
waits() { [[ "$(zone_frozen "$1")" == 1 && "$(dm_flag "kryptik-zone-$1")" == 1 ]]; }
none_frozen() { local f; f="$(zones_frozen)"; [[ -n "$f" && "$f" != *=1* ]]; }
# Processes waiting on a disk (state D) in two looks 3 s apart, but the writer, which must, and
# kernel threads (PF_KTHREAD in stat's flags): ext4 setting up a fresh volume's inode tables
# writes through its loop device onto the partition, and this is about what userspace answers.
blocked() {
    local p s fl second="" first=()
    for p in /proc/[0-9]*; do s="$(< "$p/stat")" 2>/dev/null || continue; [[ "${s##*) }" == D* ]] && first+=("${p#/proc/}"); done
    sleep 3
    for p in "${first[@]}"; do
        [[ "$p" == "$writer" ]] && continue
        s="$(< "/proc/$p/stat")" 2>/dev/null || continue
        read -r _ _ _ _ _ _ fl _ <<<"${s##*) }"
        (( ${fl:-0} & 0x200000 )) && continue
        [[ "${s##*) }" == D* ]] && second+=" $p:$(< "/proc/$p/comm")"
    done
    echo "${second# }"
}
# What the session's programs wait on, for a round that found the lock or the compositor stuck:
# each one's state, kernel wait and stack, and the system call it is in with its arguments (a
# poll's timeout tells the lock's 15 s wait on the daemon from a wait on the compositor), and
# the session log's last lines, onto the serial line.
stuck_report() {
    local p c
    for p in $(pgrep -x 'dwl|kryptik-lock|kryptik-chrome|seatd'); do
        c="$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)"
        info "pid ${p} ${c:0:60}: state $(awk '{print $3}' "/proc/$p/stat" 2>/dev/null), waits in $(cat "/proc/$p/wchan" 2>/dev/null), syscall $(cat "/proc/$p/syscall" 2>/dev/null); $(tr '\n' '|' < "/proc/$p/stack" 2>/dev/null | cut -c1-300)"
    done
    tail -n 25 "$slog" 2>/dev/null | sed 's/^/GT INFO session.log: /'
}
boot_id="$(< /proc/sys/kernel/random/boot_id)"

echo "GT BEGIN"
[[ "$(id -u)" = 0 ]] || { fail "root" "this must run as root"; echo "GT END"; exit 1; }
state_dev="$(sed -n 's/^state_dev=//p' /run/kryptik/boot-identity 2>/dev/null)"
[[ -b "$state_dev" && -n "$STATE_PW" && "$SEED" =~ ^[0-9a-f]{12}$ ]] || { fail "setup" "state device '${state_dev}', a passphrase and a 12-digit seed are needed"; echo "GT END"; exit 1; }

# --- the second passphrase and the keys -------------------------------------------------------
# Files on /run, removed once read: tmpfs frees, and the kernel zeroes, the pages they held.
printf '%s' "$STATE_PW" > "$OUT/old"
printf '%s' "$(rev <<<"$SEED")" > "$OUT/new"
if cryptsetup luksAddKey --batch-mode --pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 65536 \
        --key-file "$OUT/old" "$state_dev" "$OUT/new" > "$OUT/addkey.out" 2>&1; then
    pass "second-passphrase" "a keyslot for the passphrase the host types"
else
    fail "second-passphrase" "$(tail -2 "$OUT/addkey.out" | tr '\n' ' ')"
fi
rm -f "$OUT/new"
# A volume key, as hex: the dump is searched for its bytes. The file holding it goes at once.
vkey() {   # vkey DEVICE PASSPHRASE-FILE
    cryptsetup luksDump --dump-volume-key --batch-mode --key-file "$2" --volume-key-file "$OUT/vk" "$1" > /dev/null 2>&1
    od -An -v -tx1 "$OUT/vk" 2>/dev/null | tr -dc '0-9a-f'
    rm -f "$OUT/vk"
}
skey="$(vkey "$state_dev" "$OUT/old")"
rm -f "$OUT/old"
[[ "${#skey}" -ge 64 ]] && echo "GT STATE-KEY $skey" || fail "state-key-read" "cryptsetup luksDump gave ${#skey} hex digits"

# --- the session, a zone with a volume, one without, and a writer on /var -----------------------
su -s /bin/bash "$USER_NAME" -c 'setsid /usr/bin/kryptik-session </dev/null >/dev/null 2>&1 &'
wait_for 30 test -S "$RT/wayland-0" && pass "session-up" || fail "session-up" "$(tail -3 "$slog" 2>/dev/null | tr '\n' ' ')"
# The chrome's idle lock would lock the session under the suite.
wait_for 20 pkill -u "$USER_NAME" -fx '/usr/bin/kryptik-lock --idle 600'
# No newline: cryptsetup's --key-file would take it as part of the passphrase, which kryptikd strips.
PP="$OUT/zone-pass"; printf zone-pass > "$PP"; chmod 600 "$PP"
UPP="$RT/zone-pass"; cp "$PP" "$UPP"; chown "$USER_NAME" "$UPP"; chmod 600 "$UPP"
"$KD" volume init work --size 64M --passphrase-file "$PP" > "$OUT/vol.out" 2>&1 || fail "volume-init" "$(tail -1 "$OUT/vol.out")"
# A tick a second into the zone's home, /home/ZONE inside it: on its volume for work, on its own
# tmpfs for untrusted, which no path here reaches, so both are read through the zone's pid 1.
tick() { echo "sh -c \"while :; do date +%s >> /home/$1/ticks; sleep 1; done\""; }
tickfile() { local pid _; read -r pid _ < "/run/kryptik/zones/$1/init.pid" 2>/dev/null; echo "/proc/${pid:-0}/root/home/$1/ticks"; }
ticking() { [[ -s "$(tickfile "$1")" ]]; }
as_user "kryptik-launch --no-display --passphrase-fd 3 work -- $(tick work) 3<$UPP" > "$OUT/launch-work.out" 2>&1 &
as_user "kryptik-launch --no-display untrusted -- $(tick untrusted)" > "$OUT/launch-untrusted.out" 2>&1 &
ticks() { wc -l < "$(tickfile "$1")" 2>/dev/null || echo 0; }
# Counted again at each look: wait_for runs its command anew, its arguments as they were.
lines_past() { [[ "$(wc -l < "$1" 2>/dev/null || echo 0)" -gt "$2" ]]; }
ticks_past() { [[ "$(ticks "$1")" -gt "$2" ]]; }
if wait_for 60 ticking work && wait_for 60 ticking untrusted; then
    pass "zones-ticking" "work (its own volume) and untrusted count a tick a second"
else
    fail "zones-ticking" "work: $(tail -1 "$OUT/launch-work.out" 2>/dev/null); untrusted: $(tail -1 "$OUT/launch-untrusted.out" 2>/dev/null)"
fi
zkey="$(vkey /var/lib/kryptik/volumes/work.luks "$PP")"
[[ "${#zkey}" -ge 64 ]] && echo "GT ZONE-KEY $zkey" || fail "zone-key-read" "cryptsetup luksDump gave ${#zkey} hex digits"
# Bytes kept in a file on /run, which is memory: the dump must hold them. Only their hex crosses
# the serial line.
head -c 4096 /dev/urandom > "$OUT/mark"
echo "GT MARK $(head -c 32 "$OUT/mark" | od -An -v -tx1 | tr -dc 0-9a-f)"
WLOG=/var/log/kryptik/suspend-writer
: > "$WLOG"
( n=0; while :; do n=$((n + 1)); echo "$n" >> "$WLOG" || exit; sleep 1; done ) &
writer=$!
wait_for 10 test -s "$WLOG"

# --- the way back, proven awake ---------------------------------------------------------------
# The key dropped and the zones frozen with the machine up, then every cache of dentries and
# inodes dropped: a lookup or a read that reaches the partition now waits for it.
if "$KD" suspend --awake > "$OUT/awake.out" 2>&1 && state_is 1; then
    pass "state-suspended" "$(tr '\n' ' ' < "$OUT/awake.out")"
else
    fail "state-suspended" "flag $(state_flag): $(tr '\n' ' ' < "$OUT/awake.out")"
fi
echo 2 > /proc/sys/vm/drop_caches
all_frozen && pass "zones-frozen" "$(zones_frozen)" || fail "zones-frozen" "$(zones_frozen)"
sleep 3
w="$(< "/proc/$writer/stat")"
[[ "${w##*) }" == D* ]] && pass "writer-waits" "the writer on /var waits for the partition" || info "writer-waits: the writer's state is ${w##*) }"
# A client's request is refused at once, not left waiting: the daemon reads nothing on the
# partition to answer. Root asks here, as the suspended daemon answers whoever reached its socket.
said_now="$(timeout 10 /usr/bin/kryptik-launch --info work 2>&1)"; rc=$?
if [[ "$rc" -eq 1 && "$said_now" == *"error: suspended"* ]]; then
    pass "client-told-suspended" "$said_now"
else
    fail "client-told-suspended" "exit ${rc}: ${said_now}"
fi
locked0="$(said locked)"; refused0="$(said refused)"; unlocked0="$(said unlocked)"
echo "GT KEY-LOCK 1"
# Started now by the compositor's key, the lock asks the daemon what unlocks and is told.
if wait_for 30 more locked "$locked0" && grep -q '^kryptik-lock: the state partition is suspended: its passphrase unlocks' "$slog"; then
    pass "lock-asks-for-state" "the lock started with the state partition suspended, and asks for its passphrase"
else
    fail "lock-asks-for-state" "$(grep '^kryptik-lock' "$slog" | tail -3 | tr '\n' ' ')"
fi
stuck="$(blocked)"
[[ -z "$stuck" ]] && pass "nothing-else-waits" "only the writer waits on the partition: the lock, dwl, the chrome, the daemon, the watchdog feeder and s6 run on" || fail "nothing-else-waits" "$stuck"
echo "GT LOCK-TYPE-STATE-WRONG"
if wait_for 60 more refused "$refused0" && grep '^kryptik-lock: refused' "$slog" | tail -1 | grep -q 'wrong passphrase$' && state_is 1; then
    pass "lock-refuses-wrong-passphrase" "$(grep '^kryptik-lock: refused' "$slog" | tail -1); the partition stays suspended"
else
    fail "lock-refuses-wrong-passphrase" "flag $(state_flag): $(grep '^kryptik-lock' "$slog" | tail -2 | tr '\n' ' ')"
fi
# Past the pause a wrong one starts.
sleep 3
echo "GT LOCK-TYPE-STATE 1"
if wait_for 60 more unlocked "$unlocked0" && state_is 0; then
    pass "passphrase-resumes" "the passphrase typed at the lock gave the partition its key, and unlocked"
else
    fail "passphrase-resumes" "flag $(state_flag): $(grep '^kryptik-lock' "$slog" | tail -3 | tr '\n' ' ')"
fi
# A zone with a volume stays frozen, its volume's key gone too, until its own passphrase.
if wait_for 15 thawed untrusted && waits work; then
    pass "zone-waits-for-its-passphrase" "untrusted thawed; work stays frozen, its volume suspended"
else
    fail "zone-waits-for-its-passphrase" "untrusted frozen $(zone_frozen untrusted); work frozen $(zone_frozen work), its volume's flag $(dm_flag kryptik-zone-work)"
fi
# The daemon serves the session's group, root not among it.
said_info="$(as_user "kryptik-launch --info work" 2>&1)"
grep -qx 'waiting yes' <<<"$said_info" && pass "info-says-waiting" "the daemon says work waits" \
    || fail "info-says-waiting" "$(tr '\n' ' ' <<<"$said_info")"
# Without a passphrase the launcher asks the daemon to run, which says why it will not.
said_run="$(as_user "kryptik-launch --no-display work -- true" 2>&1)"
[[ "$said_run" == *"waits for its volume's passphrase"* ]] && pass "launch-told-waiting" "$said_run" \
    || fail "launch-told-waiting" "$said_run"
# The menu names it WAITING, with the choice that gives its passphrase.
waits_line="$(as_user "printf 'q\\n' | XDG_RUNTIME_DIR=$RT /usr/bin/kryptik-chrome --menu" 2>&1 | grep -a ') work ' | tail -1)"
if [[ "$waits_line" == *"WAITING for its passphrase (p"[1-9]")"* ]]; then
    pass "menu-says-waiting" "$(sed 's/^ *//' <<<"$waits_line")"
else
    fail "menu-says-waiting" "${waits_line:-no line for work}"
fi
printf 'not-the-zone-pass\n' > "$OUT/wrong-pass"; chmod 600 "$OUT/wrong-pass"
if ! "$KD" volume resume work --passphrase-file "$OUT/wrong-pass" > "$OUT/resume-wrong.out" 2>&1 \
   && grep -q 'wrong passphrase' "$OUT/resume-wrong.out" && waits work; then
    pass "zone-refuses-wrong-passphrase" "$(tr '\n' ' ' < "$OUT/resume-wrong.out")and work still waits"
else
    fail "zone-refuses-wrong-passphrase" "$(tr '\n' ' ' < "$OUT/resume-wrong.out")"
fi
# With the state partition back, the chrome opens a window that asks for each waiting zone's
# passphrase on a terminal of zone 0's; the host types work's there.
asking() { pgrep -u "$USER_NAME" -f 'kryptik-launch --resume work' > /dev/null; }
if wait_for 20 asking; then
    pass "chrome-asks-waiting-zone" "a window of the chrome's asks for work's passphrase"
else
    fail "chrome-asks-waiting-zone" "$(pgrep -u "$USER_NAME" -af 'kryptik-chrome|kryptik-launch' | tr '\n' ';')"
fi
# The prompt is up a moment after the process.
sleep 1
echo "GT ZONE-PASS-TYPE 1"
if wait_for 30 thawed work && [[ "$(dm_flag kryptik-zone-work)" == 0 ]]; then
    pass "zone-passphrase-resumes" "typed in the chrome's window, work's passphrase gave its volume its key, and work thawed"
else
    fail "zone-passphrase-resumes" "flag $(dm_flag kryptik-zone-work), frozen $(zone_frozen work)"
fi
wait_for 15 none_frozen && pass "zones-thawed" "$(zones_frozen)" || fail "zones-thawed" "$(zones_frozen)"
# Its file is read only now: in the window, reading it would have waited too.
n_before="$(wc -l < "$WLOG")"
if wait_for 15 lines_past "$WLOG" "$n_before"; then
    pass "writer-resumes" "the writer goes on, past line ${n_before}"
else
    fail "writer-resumes" "still ${n_before} lines"
fi
t_work="$(ticks work)"; t_untrusted="$(ticks untrusted)"
if wait_for 15 ticks_past work "$t_work" && wait_for 15 ticks_past untrusted "$t_untrusted"; then
    pass "zones-tick-again" "work and untrusted count on"
else
    fail "zones-tick-again" "work $(ticks work) after ${t_work}, untrusted $(ticks untrusted) after ${t_untrusted}"
fi

# A page of the work zone's volume, cached until the sleep lets the clean pages go: the dump
# must not hold it.
head -c 4096 /dev/urandom > "$R/work/cache-mark"
sync
echo "GT CACHE-MARK $(head -c 32 "$R/work/cache-mark" | od -An -v -tx1 | tr -dc 0-9a-f)"

# --- a real sleep ----------------------------------------------------------------------------
# The user's own way, `kryptik suspend` as the guide has it: the lock, then the daemon. The host
# sees the guest sleep, dumps its memory, waits past the watchdog's timeout and wakes it; should
# the kernel refuse to sleep, the lock says so, and so does this script, for the host. The host
# hears of the sleep first: once the daemon has frozen this script, it says nothing more until
# the machine is back.
echo "GT SLEEPING 1"
as_user "/usr/bin/kryptik suspend" > "$OUT/lock-suspend.out" 2>&1 &
# The lock tells the daemon's answer once the machine is back, or once the kernel has refused.
wait_for 300 grep -q '^kryptik-lock: suspend: ' "$OUT/lock-suspend.out"
grep -q '^kryptik-lock: suspending' "$OUT/lock-suspend.out" || fail "suspend-asked" "$(tr '\n' ' ' < "$OUT/lock-suspend.out")"
answer="$(grep '^kryptik-lock: suspend: ' "$OUT/lock-suspend.out" | tail -1)"
case "$answer" in
    *": ok woke")
        state_is 1 && pass "slept-and-woke" "the machine slept and woke with the state partition suspended" \
            || fail "slept-and-woke" "woke, but the state partition's flag is $(state_flag)" ;;
    *"did not sleep"*)
        echo "GT DID-NOT-SLEEP 1"
        fail "slept-and-woke" "the kernel refused to sleep: ${answer#*did not sleep: }" ;;
    *)
        fail "slept-and-woke" "flag $(state_flag): $(tr '\n' ' ' < "$OUT/lock-suspend.out")" ;;
esac
grep -q '^kryptik-lock: the state partition is suspended: its passphrase unlocks' "$OUT/lock-suspend.out" \
    && pass "woke-to-state-prompt" "the lock asks for the state passphrase as soon as the machine is back" \
    || fail "woke-to-state-prompt" "$(tr '\n' ' ' < "$OUT/lock-suspend.out")"
# Minutes at the prompt, the caches dropped again: the feeder must go on feeding the watchdog,
# whose 60 s would otherwise reset the machine under the prompt.
echo 2 > /proc/sys/vm/drop_caches
sleep 180
if [[ "$(< /proc/sys/kernel/random/boot_id)" == "$boot_id" ]] && pgrep -f /usr/libexec/kryptik/watchdog.sh > /dev/null; then
    pass "prompt-outlasts-watchdog" "three minutes at the state prompt after waking, the same boot, the feeder running"
else
    fail "prompt-outlasts-watchdog" "boot_id $(< /proc/sys/kernel/random/boot_id), was ${boot_id}"
fi
echo "GT LOCK-TYPE-STATE 2"
if wait_for 60 grep -q '^kryptik-lock: unlocked' "$OUT/lock-suspend.out" && state_is 0; then
    pass "resumed-after-sleep" "the passphrase gave the partition its key after the sleep, and unlocked"
else
    fail "resumed-after-sleep" "flag $(state_flag): $(tail -3 "$OUT/lock-suspend.out" | tr '\n' ' ')"
fi
if wait_for 15 thawed untrusted && waits work; then
    pass "zone-waits-after-sleep" "untrusted thawed; work waits for its passphrase"
else
    fail "zone-waits-after-sleep" "untrusted frozen $(zone_frozen untrusted); work frozen $(zone_frozen work), its volume's flag $(dm_flag kryptik-zone-work)"
fi
# The chrome's window asks again. Enter alone there leaves the zone waiting, the daemon asked
# nothing; the host presses it whether or not the window came, so the rounds after go on.
wait_for 20 asking; asked=$?
sleep 1
echo "GT ZONE-PASS-SKIP"
not_asking() { ! asking; }
if [[ "$asked" -eq 0 ]] && wait_for 15 not_asking && waits work \
   && as_user "kryptik-launch --info work" 2>&1 | grep -qx 'waiting yes'; then
    pass "enter-leaves-zone-waiting" "Enter alone ended the window's ask, and work still waits"
else
    fail "enter-leaves-zone-waiting" "asked ${asked}: $(pgrep -u "$USER_NAME" -af 'kryptik-launch --resume' | tr '\n' ';') work frozen $(zone_frozen work), its volume's flag $(dm_flag kryptik-zone-work)"
fi
# Never given its passphrase, the zone stops all the same: its volume fails every read and write,
# the zone ends and the volume closes, its file whole for the next start.
if "$KD" stop work > "$OUT/stop-waiting.out" 2>&1 && wait_for 30 test ! -e /dev/mapper/kryptik-zone-work \
   && wait_for 30 test ! -e /run/kryptik/zones/work/init.pid; then
    pass "waiting-zone-stops" "$(tr '\n' ' ' < "$OUT/stop-waiting.out")"
else
    fail "waiting-zone-stops" "mappings: $(ls /dev/mapper | tr '\n' ' '); $(tr '\n' ' ' < "$OUT/stop-waiting.out")"
fi
as_user "kryptik-launch --no-display --passphrase-fd 3 work -- $(tick work) 3<$UPP" > "$OUT/launch-work-again.out" 2>&1 &
if wait_for 60 ticking work && t_work="$(ticks work)" && wait_for 30 ticks_past work "$t_work"; then
    pass "volume-opens-after-giving-up" "work started again on its volume, which checked clean, and counts on"
else
    fail "volume-opens-after-giving-up" "$(tail -2 "$OUT/launch-work-again.out" | tr '\n' ' ')"
fi
# The rounds below sleep with untrusted alone.
"$KD" stop work > /dev/null 2>&1
wait_for 30 test ! -e /dev/mapper/kryptik-zone-work
wait_for 15 none_frozen && pass "zones-thawed-after-sleep" "$(zones_frozen)" || fail "zones-thawed-after-sleep" "$(zones_frozen)"

# --- a sleep the kernel refuses ----------------------------------------------------------------
# A task waiting on the suspended partition's device where the freezer cannot stop it, here a
# read that bypasses the page cache, keeps the kernel from sleeping: it gives up after 20 s.
# Asked again with the partition suspended, the daemon's steps are only the sleep; its refusal
# is told, and the passphrase still brings the partition back.
dd if=/dev/zero of=/var/log/kryptik/suspend-reader bs=1M count=1 status=none
"$KD" suspend --awake > "$OUT/awake2.out" 2>&1 && state_is 1 || fail "suspended-again" "$(tr '\n' ' ' < "$OUT/awake2.out")"
dd if=/var/log/kryptik/suspend-reader of=/dev/null bs=4096 count=1 iflag=direct status=none &
reader=$!
sleep 2
r="$(< "/proc/$reader/stat")"
[[ "${r##*) }" == D* ]] || info "the reader on the device is in state ${r##*) }, not waiting on it"
locked0="$(said locked)"; unlocked0="$(said unlocked)"
echo "GT KEY-LOCK 2"
wait_for 30 more locked "$locked0" || fail "locked-again" "$(grep '^kryptik-lock' "$slog" | tail -2 | tr '\n' ' ')"
echo "GT SLEEPING 2"
# Root's way to the same sleep: the session's lock asks the daemon, which forks the same write.
"$KD" suspend > "$OUT/sleep2.out" 2>&1
case "$(< "$OUT/sleep2.out")" in
    *"did not sleep"*)
        echo "GT DID-NOT-SLEEP 2"
        pass "sleep-refusal-told" "$(grep -o 'did not sleep: [^;]*' "$OUT/sleep2.out")" ;;
    *woke*)
        info "the kernel slept with a read waiting on the device; the host woke it" ;;
    *)
        fail "sleep-refusal-told" "$(tr '\n' ' ' < "$OUT/sleep2.out")" ;;
esac
echo "GT LOCK-TYPE-STATE 3"
if wait_for 60 more unlocked "$unlocked0" && state_is 0 && wait_for 15 test ! -d "/proc/$reader"; then
    pass "resumed-after-refusal" "the passphrase gave the partition its key after the refused sleep, the read ended, and the lock opened"
else
    fail "resumed-after-refusal" "flag $(state_flag): $(grep '^kryptik-lock' "$slog" | tail -2 | tr '\n' ' ')"
    stuck_report
    # The rounds after this one need a lock that answers: the stuck lock is killed, and its
    # supervisor, whose pid the lock file holds, locks again as after any signal.
    sup="$(cat "$RT/kryptik/lock.pid" 2>/dev/null)"
    [[ -n "$sup" ]] && pkill -KILL -P "$sup" -x kryptik-lock
fi
wait_for 15 none_frozen || fail "zones-thawed-after-refusal" "$(zones_frozen)"

# --- what else has the machine sleep ---------------------------------------------------------
# dwl's power key runs kryptik-lock --suspend, the lock and then the sleep. With a lock up, the
# lock takes the key itself, and kryptik-lock --suspend has the lock that is up ask; the idle
# watcher has its own lock ask, --sleep after the lock. Each wake waits for the passphrase.
answers() { grep -c '^kryptik-lock: suspend: ' "$1" 2>/dev/null; }
answers_past() { [[ "$(answers "$1")" -gt "$2" ]]; }
unlocks_past() { [[ "$(grep -c '^kryptik-lock: unlocked' "$1" 2>/dev/null)" -gt "$2" ]]; }
slept() {   # slept LOG BEFORE N NAME: one more answer to a suspend in LOG; a refusal is told as N
    local a
    if ! wait_for 120 answers_past "$1" "$2"; then
        echo "GT DID-NOT-SLEEP $3"
        fail "$4" "no answer to the suspend: $(grep '^kryptik-lock' "$1" | tail -3 | tr '\n' ' ')"
        return
    fi
    a="$(grep '^kryptik-lock: suspend: ' "$1" | tail -1)"
    case "$a" in
        *": ok woke") pass "$4" "slept and woke, the state partition suspended (flag $(state_flag))" ;;
        *"did not sleep"*) echo "GT DID-NOT-SLEEP $3"; fail "$4" "the kernel refused to sleep: ${a#*did not sleep: }" ;;
        *) fail "$4" "$a" ;;
    esac
    # Keys in the second after the label changes go nowhere.
    sleep 2
}
resumed() {   # resumed LOG BEFORE NAME: unlocked once more, with the partition back and the zones thawed
    if wait_for 60 unlocks_past "$1" "$2" && state_is 0 && wait_for 15 none_frozen; then
        pass "$3" "the passphrase brought the partition back and unlocked"
    else
        fail "$3" "flag $(state_flag), zones $(zones_frozen): $(grep '^kryptik-lock' "$1" | tail -3 | tr '\n' ' ')"
    fi
}
a0="$(answers "$slog")"; u0="$(said unlocked)"
echo "GT POWER-KEY 1"
slept "$slog" "$a0" 3 "power-key-sleeps"
# The press that wakes some machines reaches the lock as a power key: one within 10 s of the
# wake is held off, and one after it is heeded.
heldoff() { [[ "$(grep -c '^kryptik-lock: held off a suspend' "$slog")" -gt "$1" ]]; }
h0="$(grep -c '^kryptik-lock: held off a suspend' "$slog")"; a1="$(answers "$slog")"
echo "GT POWER-KEY SOON"
if wait_for 15 heldoff "$h0"; then
    echo "GT DID-NOT-SLEEP 7"
    pass "power-key-held-off-after-wake" "a press a moment after the wake did not put the machine back to sleep"
else
    fail "power-key-held-off-after-wake" "$(grep '^kryptik-lock' "$slog" | tail -3 | tr '\n' ' ')"
fi
sleep 13
echo "GT POWER-KEY 3"
slept "$slog" "$a1" 8 "power-key-heeded-after-holdoff"
echo "GT LOCK-TYPE-STATE 4"
resumed "$slog" "$u0" "power-key-resumes"

locked0="$(said locked)"; a0="$(answers "$slog")"; u0="$(said unlocked)"
echo "GT KEY-LOCK 3"
wait_for 30 more locked "$locked0" || fail "locked-for-power-key" "$(grep '^kryptik-lock' "$slog" | tail -2 | tr '\n' ' ')"
echo "GT POWER-KEY 2"
slept "$slog" "$a0" 4 "power-key-sleeps-locked"
echo "GT LOCK-TYPE-STATE 5"
resumed "$slog" "$u0" "power-key-locked-resumes"

locked0="$(said locked)"; a0="$(answers "$slog")"; u0="$(said unlocked)"
echo "GT KEY-LOCK 4"
wait_for 30 more locked "$locked0" || fail "locked-for-hand-off" "$(grep '^kryptik-lock' "$slog" | tail -2 | tr '\n' ' ')"
pf="$RT/kryptik/lock.pid"
if wait_for 10 test -s "$pf" && [[ "$(stat -c '%u %a' "$pf")" == "${UID_} 600" ]]; then
    pass "lock-pid-written" "the lock that is up names its supervisor in a file of the user's own, mode 600"
else
    fail "lock-pid-written" "$(stat -c '%U %a %s' "$pf" 2>&1)"
fi
# Said before the hand-off, for the same reason as GT SLEEPING 1: the sleep can come before the
# hand-off returns.
echo "GT SLEEPING 3"
as_user "/usr/bin/kryptik-lock --suspend" > "$OUT/hand-off.out" 2>&1
if grep -q '^kryptik-lock: asked the lock that is up to suspend' "$OUT/hand-off.out"; then
    slept "$slog" "$a0" 5 "lock-up-sleeps"
else
    echo "GT DID-NOT-SLEEP 5"
    fail "lock-up-sleeps" "kryptik-lock --suspend did not hand over: $(tr '\n' ' ' < "$OUT/hand-off.out")"
fi
echo "GT LOCK-TYPE-STATE 6"
resumed "$slog" "$u0" "lock-up-resumes"
[[ ! -e "$pf" ]] && pass "lock-pid-removed" "the unlock takes the file away" || fail "lock-pid-removed" "$(cat "$pf")"

# Idle: no key from the host meanwhile, so the watcher locks after 8 s and asks 6 s later.
as_user "/usr/bin/kryptik-lock --idle 8 --blank 0 --sleep 6" > "$OUT/nap.out" 2>&1 &
nap_pid=$!
echo "GT SLEEPING 4"
slept "$OUT/nap.out" 0 6 "idle-sleeps"
echo "GT LOCK-TYPE-STATE 7"
resumed "$OUT/nap.out" 0 "idle-sleep-resumes"
pkill -u "$USER_NAME" -fx '/usr/bin/kryptik-lock --idle 8 --blank 0 --sleep 6' 2>/dev/null; wait "$nap_pid" 2>/dev/null

# --- teardown ------------------------------------------------------------------------------
kill "$writer" 2>/dev/null
for z in untrusted work; do "$KD" stop "$z" > /dev/null 2>&1; done
pkill -u "$USER_NAME" -x dwl 2>/dev/null
echo "GT SUMMARY passed=${PASS} failed=${FAIL}"
echo "GT END"
