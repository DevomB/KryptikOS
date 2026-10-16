#!/usr/bin/env bash
# Sound suite, run as root in the installed guest by tools/image/sound-test.sh, which boots it
# with two of QEMU's HD Audio cards: the first only plays, the second plays and records.
#   sound-check.sh USER    USER is the session's, whose chrome menu is typed into
# Verdicts: "GT PASS|FAIL name - detail".
set -u
cd / || exit 1
USER_NAME="${1:-tester}"
PASS=0; FAIL=0
pass() { echo "GT PASS $1${2:+ - $2}"; PASS=$((PASS + 1)); }
fail() { echo "GT FAIL $1${2:+ - $2}"; FAIL=$((FAIL + 1)); }
wait_for() {   # wait_for SECONDS CMD...
    local n="$1"; shift
    while [[ "$n" -gt 0 ]]; do "$@" >/dev/null 2>&1 && return 0; n=$((n - 1)); sleep 1; done
    return 1
}
klog() { dmesg | grep -iE 'snd|hda|sound' | tail -6 | tr '\n' ' '; }

# --- the cards -----------------------------------------------------------------------------
# eudev loads snd-hda-intel at coldplug, and a card registers once its codec has bound.
cards() { [[ "$(grep -c 'HDA-Intel' /proc/asound/cards)" -eq 2 ]]; }
if wait_for 30 cards; then
    pass "sound-card" "$(grep 'HDA-Intel' /proc/asound/cards | tr -s ' ' | tr '\n' ' ')"
else
    fail "sound-card" "cards: $(tr '\n' ' ' < /proc/asound/cards 2>&1) kernel: $(klog)"
fi

# QEMU's codecs have no driver of their own, so the generic parser takes them: it was loaded
# before the controllers probed, as the kernel could not load it then.
drivers=""
for c in hdaudioC0D0 hdaudioC1D0; do
    drv="$(readlink "/sys/bus/hdaudio/devices/$c/driver" 2>/dev/null)"
    drivers+="$c=${drv##*/} "
done
if [[ "$drivers" == "hdaudioC0D0=snd_hda_codec_generic hdaudioC1D0=snd_hda_codec_generic " ]]; then
    pass "codec-bound" "${drivers% }"
else
    fail "codec-bound" "${drivers% }; kernel: $(klog)"
fi

# Every codec driver modprobe.d names came with the controller, so a codec that has a driver
# of its own is never left to the generic parser.
missing=""
for m in $(grep -v '^[[:space:]]*#' /usr/lib/modprobe.d/sound.conf | grep -oE 'snd-hda-codec-[a-z0-9-]+'); do
    grep -q "^${m//-/_} " /proc/modules || missing+=" $m"
done
if [[ -z "$missing" ]]; then
    pass "codec-drivers-ahead" "$(grep -c '^snd_hda_codec_' /proc/modules) codec modules loaded with snd_hda_intel"
else
    fail "codec-drivers-ahead" "not loaded:${missing}"
fi

if [[ -c /dev/snd/pcmC0D0p && -c /dev/snd/pcmC1D0p && -c /dev/snd/pcmC1D0c ]]; then
    pass "pcm-nodes" "$(cd /dev/snd && echo *)"
else
    fail "pcm-nodes" "/dev/snd: $(ls /dev/snd 2>&1 | tr '\n' ' ')"
fi

# A zone's /proc/asound is empty: its PCM status would show when another zone plays or
# records, and its codec files name the machine's model.
asound="$(timeout -k 5 30 /usr/bin/kryptikd run untrusted --zones /usr/lib/kryptik/zones \
          --rootfs /var/lib/kryptik/zones -- sh -c 'echo "asound:[$(ls -A /proc/asound 2>&1)]"' 2>&1)"
if [[ "$asound" == *"asound:[]"* && -d /proc/asound/card0 ]]; then
    pass "zone-proc-asound-empty" "zone 0 has $(ls /proc/asound | tr '\n' ' ')and untrusted has nothing there"
else
    fail "zone-proc-asound-empty" "$(tr '\n' ' ' <<<"$asound")"
fi

# --- zone 0's mixer ------------------------------------------------------------------------
# The host reads what the first card played: a tone from untrusted alone, then untrusted's
# and work's together.
KD=/usr/bin/kryptikd
Z=/usr/lib/kryptik/zones
R=/var/lib/kryptik/zones
PROBE=/usr/libexec/kryptik/soundprobe
LOG=/var/log/kryptik/sound-check
mkdir -p "$LOG" /root/st
ctl() { /usr/libexec/kryptik/kryptik-sound --control "$*"; }
uncaught() { cat /run/uncaught-logs/@* /run/uncaught-logs/previous /run/uncaught-logs/current 2>/dev/null; }
mixer_said() { uncaught | grep -ac "kryptik-sound: $1"; }
zrun() {   # zrun ZONE TIMEOUT -- CMD...: sets ZRC, and ZOUT to its output on one line
    local zone="$1" t="$2"; shift 3
    local extra=()
    [[ "$zone" == work ]] && extra=(--passphrase-file /root/st/work.pass)
    timeout -k 5 "$t" "$KD" run "$zone" --zones "$Z" --rootfs "$R" "${extra[@]}" -- "$@" > "$LOG/$zone.out" 2>&1
    ZRC=$?
    ZOUT="$(tr '\n' ' ' < "$LOG/$zone.out")"
}

running() { [[ -S /run/kryptik-sound/control/socket ]] && ctl status > "$LOG/status.out" 2>&1; }
if wait_for 20 running; then
    pass "mixer-running" "$(tr '\n' ' ' < "$LOG/status.out")"
else
    fail "mixer-running" "$(uncaught | grep -a 'kryptik-sound' | tail -3 | tr '\n' ' ')"
fi
listed="$(sed -n 's/^zone \([a-z0-9_-]*\) .*/\1/p' "$LOG/status.out" 2>/dev/null | sort | tr '\n' ' ')"
if [[ "$listed" == "dev personal untrusted work " && ! -e /run/kryptik-sound/zones/vault ]]; then
    pass "mixer-zones" "a socket for ${listed}and none for vault or the net zone"
else
    fail "mixer-zones" "zones: ${listed:-none}"
fi

pid="$(pgrep -xo kryptik-sound)"
st="/proc/${pid:-0}/status"
if grep -Eq '^Uid:\s+87\s+87\s+87\s+87$' "$st" && grep -Eq '^Gid:\s+11\s+11\s+11\s+11$' "$st" \
   && grep -Eq '^Groups:\s*11\s*$' "$st"; then
    pass "mixer-own-user" "uid 87, group audio (11) alone"
else
    fail "mixer-own-user" "$(grep -E '^(Uid|Gid|Groups):' "$st" 2>&1 | tr -s '\t' ' ' | tr '\n' ';')"
fi

# A zone has its socket and nothing else of sound: no card, no control socket.
zrun untrusted 30 -- sh -c 'ls -l /run/kryptik/sound/socket; ls /dev/snd; ls /run/kryptik-sound'
if [[ "$ZOUT" == *"srw-rw-rw-"*"/run/kryptik/sound/socket"* && "$ZOUT" == *"'/dev/snd': No such file"* \
      && "$ZOUT" == *"'/run/kryptik-sound': No such file"* ]]; then
    pass "zone-socket-no-card" "the zone's socket at /run/kryptik/sound, no /dev/snd, no control socket"
else
    fail "zone-socket-no-card" "rc ${ZRC}: ${ZOUT}"
fi

echo "GT TONE 440"
zrun untrusted 60 -- "$PROBE" tone 440 4
if [[ "$ZRC" -eq 0 && "$ZOUT" == *"played 4 s of 440 Hz"* ]]; then
    pass "zone-plays" "untrusted played 4 s of 440 Hz through its default device"
else
    fail "zone-plays" "rc ${ZRC}: ${ZOUT} mixer: $(uncaught | grep -a 'kryptik-sound' | tail -2 | tr '\n' ' ')"
fi

printf 'work-pass\n' > /root/st/work.pass; chmod 600 /root/st/work.pass
"$KD" volume init work --size 64M --passphrase-file /root/st/work.pass > "$LOG/vol-work.out" 2>&1 \
    || fail "volume-init" "work: $(tail -2 "$LOG/vol-work.out" | tr '\n' ' ')"
echo "GT TONES 440 660"
( zrun untrusted 60 -- "$PROBE" tone 440 6 ) &
zrun work 90 -- "$PROBE" tone 660 6
wait
if [[ "$ZOUT" == *"played 6 s of 660 Hz"* && "$(cat "$LOG/untrusted.out")" == *"played 6 s of 440 Hz"* ]]; then
    pass "zones-play-together" "untrusted's 440 Hz and work's 660 Hz at once"
else
    fail "zones-play-together" "work: ${ZOUT} untrusted: $(tr '\n' ' ' < "$LOG/untrusted.out")"
fi

# --- the microphone ------------------------------------------------------------------------
zrun untrusted 30 -- "$PROBE" record 1
if [[ "$ZRC" -eq 1 && "$ZOUT" == *"not granted to this zone"* ]]; then
    pass "record-refused-ungranted" "untrusted was told the microphone is not granted to it"
else
    fail "record-refused-ungranted" "rc ${ZRC}: ${ZOUT}"
fi

granted="$(ctl grant untrusted 2>&1)"
# The mixer's record of who may record, which dwl's bar over a fullscreen window shows: the
# mixer's own file, which no one else may write, naming the zone.
holder="$(stat -c '%u %a %F' /run/kryptik-sound/marks/microphone 2>&1) $(cat /run/kryptik-sound/marks/microphone 2>&1)"
if [[ "$holder" == "87 644 regular file untrusted" ]]; then
    pass "holder-recorded" "the mixer records the grant for the compositor's bar: ${holder}"
else
    fail "holder-recorded" "${holder}"
fi
( zrun untrusted 30 -- "$PROBE" record 3 ) &
shown() { ctl status | grep -q '^zone untrusted .* granted recording$'; }
if [[ "$granted" == ok ]] && wait_for 15 shown; then
    pass "status-shows-recording" "$(ctl status | grep '^zone untrusted')"
else
    fail "status-shows-recording" "grant: ${granted}; status: $(ctl status | tr '\n' ' ')"
fi
wait
said="$(tr '\n' ' ' < "$LOG/untrusted.out")"
if [[ "$said" == *"recorded 144000 frames"* ]]; then
    pass "record-granted" "with the grant, untrusted recorded 3 s: ${said}"
else
    fail "record-granted" "${said}"
fi

# kryptikd takes the grant back when the zone stops, so the next zone's record is refused.
ungranted() { ! ctl status | grep -q ' granted'; }
zrun untrusted 30 -- "$PROBE" record 1
if wait_for 5 ungranted && [[ "$ZRC" -eq 1 && "$ZOUT" == *"not granted to this zone"* ]]; then
    pass "grant-ends-with-zone" "the grant went with the zone that held it"
    if [[ -f /run/kryptik-sound/marks/microphone && ! -s /run/kryptik-sound/marks/microphone ]]; then
        pass "holder-cleared" "the record names no zone once the grant is gone"
    else
        fail "holder-cleared" "$(stat -c '%u %a %s' /run/kryptik-sound/marks/microphone 2>&1): $(cat /run/kryptik-sound/marks/microphone 2>&1)"
    fi
else
    fail "grant-ends-with-zone" "status: $(ctl status | tr '\n' ' ') record: rc ${ZRC}: ${ZOUT}"
fi

# Another uid than the zone's own, root's here, is turned away at the zone's socket.
before="$(mixer_said 'zone untrusted: refused a peer')"
answer="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.connect("/run/kryptik-sound/zones/untrusted/socket")
try:
    s.sendall(b"play\n")
    print(repr(s.recv(64)))
except OSError as e:
    print("closed:", type(e).__name__)
PY
)"
if [[ ( "$answer" == "b''" || "$answer" == closed:* ) \
      && "$(mixer_said 'zone untrusted: refused a peer')" -gt "$before" ]]; then
    pass "foreign-uid-refused" "root's connection to untrusted's socket was closed unanswered"
else
    fail "foreign-uid-refused" "answer: ${answer}; refusals logged: ${before} then $(mixer_said 'zone untrusted: refused a peer')"
fi

# --- the chrome ----------------------------------------------------------------------------
# The trusted menu, typed into as the session's user: the gesture that grants the microphone and
# takes it back, the volume of all and of one zone, and mute. It names zones by number.
menu() {   # menu CHOICE: the menu's screen, with CHOICE typed into it, in $LOG/menu.out
    su -s /bin/sh "$USER_NAME" -c "printf '%s\nq\n' '$1' | XDG_RUNTIME_DIR=/run/user/$(id -u "$USER_NAME") /usr/bin/kryptik-chrome --menu" \
        > "$LOG/menu.out" 2>&1
}
menu r
n="$(sed -n 's/^ *\([0-9]\)) untrusted .*/\1/p' "$LOG/menu.out" | head -1)"
st() { ctl status | grep "^$1"; }
menu "c$n"
if [[ -n "$n" ]] && st "zone untrusted" | grep -q ' granted$'; then
    menu r
    if grep -q '^Sound: volume [0-9]*; the microphone: untrusted$' "$LOG/menu.out"; then
        pass "chrome-grants-microphone" "c${n} granted untrusted the microphone, which the menu names"
    else
        fail "chrome-grants-microphone" "granted, but the menu says: $(grep '^Sound:' "$LOG/menu.out")"
    fi
else
    fail "chrome-grants-microphone" "untrusted is ${n:-not listed}; status: $(ctl status | tr '\n' ' ')"
fi
menu c
if ! ctl status | grep -q ' granted'; then
    pass "chrome-takes-microphone-back" "c alone left no zone the microphone"
else
    fail "chrome-takes-microphone-back" "$(ctl status | tr '\n' ' ')"
fi
menu "v${n}0"; zone_vol="$(st "zone untrusted")"
menu v9; master_vol="$(st master)"
menu x; muted="$(st master)"
menu x; unmuted="$(st master)"
if [[ "$zone_vol" == "zone untrusted 0" && "$master_vol" == "master 100" && "$muted" == "master 100 muted" \
      && "$unmuted" == "master 100" ]]; then
    pass "chrome-sets-volume" "v${n}0 silenced untrusted, v9 set the volume to 100, x muted and x unmuted"
else
    fail "chrome-sets-volume" "after v${n}0: ${zone_vol}; v9: ${master_vol}; x: ${muted}; x: ${unmuted}"
fi
# The microphone's window, as the chrome opens it on a grant: it names the zone, says when it
# records, and closes when the grant goes.
watch="$LOG/microphone.out"
ctl grant untrusted > /dev/null
su -s /bin/sh "$USER_NAME" -c "/usr/bin/kryptik-chrome --microphone untrusted" > "$watch" 2>&1 &
wp=$!
( zrun untrusted 30 -- "$PROBE" record 3 ) &
rp=$!
said_rec() { grep -qx 'RECORDING NOW' "$watch"; }
wait_for 15 said_rec; wait "$rp"
# The zone stopped with the record, and its grant with it: the window says so and closes.
closed() { ! kill -0 "$wp" 2>/dev/null; }
if wait_for 15 closed && grep -q '^Zone untrusted .* holds the microphone' "$watch" && said_rec \
   && grep -q '^The microphone is no longer zone untrusted' "$watch"; then
    pass "microphone-window" "$(grep -v '^=' "$watch" | tr '\n' '|')"
else
    kill "$wp" 2>/dev/null
    fail "microphone-window" "$(tr '\n' '|' < "$watch")"
fi

# Taken back from the menu, the grant goes as it does with the zone: the window says so and
# closes.
watch="$LOG/microphone-taken.out"
ctl grant untrusted > /dev/null
su -s /bin/sh "$USER_NAME" -c "/usr/bin/kryptik-chrome --microphone untrusted" > "$watch" 2>&1 &
wp=$!
listening() { grep -qx 'not recording' "$watch"; }
wait_for 15 listening
menu c
if wait_for 15 closed && grep -q '^The microphone is no longer zone untrusted' "$watch"; then
    pass "microphone-window-taken-back" "c took the microphone back, and the window closed: $(grep -v '^=' "$watch" | tr '\n' '|')"
else
    kill "$wp" 2>/dev/null
    fail "microphone-window-taken-back" "$(tr '\n' '|' < "$watch"); status: $(ctl status | tr '\n' ' ')"
fi

# One zone at a time: while untrusted records, the menu says so, and a grant to work moves the
# microphone there and ends untrusted's record.
ctl grant untrusted > /dev/null
( zrun untrusted 60 -- "$PROBE" record 20 ) &
rp=$!
wait_for 15 shown
menu r
if grep -qx 'Sound: volume [0-9]*; the microphone: untrusted, RECORDING NOW' "$LOG/menu.out"; then
    pass "chrome-says-recording" "$(grep '^Sound:' "$LOG/menu.out")"
else
    fail "chrome-says-recording" "$(grep '^Sound:' "$LOG/menu.out"); status: $(ctl status | tr '\n' ' ')"
fi
ctl grant work > /dev/null
moved() { st "zone work" | grep -q ' granted$' && ! st "zone untrusted" | grep -q ' granted'; }
ended() { ! kill -0 "$rp" 2>/dev/null; }
if wait_for 5 moved && wait_for 15 ended && [[ "$(cat /run/kryptik-sound/marks/microphone 2>&1)" == work ]]; then
    pass "microphone-moves" "a grant to work took the microphone from untrusted, whose record ended: $(tr '\n' ' ' < "$LOG/untrusted.out")"
else
    fail "microphone-moves" "status: $(ctl status | tr '\n' ' '); holder: $(cat /run/kryptik-sound/marks/microphone 2>&1); untrusted: $(tr '\n' ' ' < "$LOG/untrusted.out")"
fi
# A record that did not end keeps untrusted up, which the rounds below start again.
kill "$rp" 2>/dev/null; "$KD" stop untrusted > /dev/null 2>&1; wait "$rp" 2>/dev/null
ctl revoke > /dev/null

# The keys' steps: dwl runs these for the volume keys.
ctl volume -5 > /dev/null; ctl volume -5 > /dev/null; stepped="$(st master)"
ctl volume +100 > /dev/null; top="$(st master)"
if [[ "$stepped" == "master 90" && "$top" == "master 100" ]]; then
    pass "volume-steps" "two steps down came to 90, and a step past the top stops at 100"
else
    fail "volume-steps" "${stepped}; ${top}"
fi

# The levels outlast the mixer, never the microphone's grant. A restart starts from the last
# mixer's record in /run; a boot, with /run empty, from what the finish script kept on the state
# partition. Removing the record stands in for the boot here.
REC=/run/kryptik-sound/control/levels KEPT=/var/lib/kryptik-sound/levels
restarted() { local p; p="$(pgrep -xo kryptik-sound)"; [[ -n "$p" && "$p" != "$was" ]] && running; }
restart_mixer() { was="$(pgrep -xo kryptik-sound)"; s6-svc -r /run/service/kryptik-sound; wait_for 20 restarted; }
ctl volume 35 > /dev/null; ctl mute on > /dev/null; ctl volume work 40 > /dev/null; ctl mute work on > /dev/null
ctl grant untrusted > /dev/null
if restart_mixer && [[ "$(st master)" == "master 35 muted" && "$(st "zone work")" == "zone work 40 muted" ]] \
   && ! ctl status | grep -q ' granted' && [[ "$(stat -c '%a %u' "$KEPT" 2>&1)" == "600 0" ]] \
   && grep -qx 'master 35 muted' "$KEPT" && grep -qx 'zone work 40 muted' "$KEPT"; then
    pass "levels-kept" "restarted at master 35 muted and work 40 muted, without the grant, and kept in ${KEPT}"
else
    fail "levels-kept" "mixer ${was}, now $(pgrep -xo kryptik-sound); status: $(ctl status 2>&1 | tr '\n' ' '); kept: $(stat -c '%a %u' "$KEPT" 2>&1) $(tr '\n' ' ' < "$KEPT" 2>&1)"
fi
ctl volume 45 > /dev/null; rm -f "$REC"
if restart_mixer && [[ "$(st master)" == "master 35 muted" && "$(st "zone work")" == "zone work 40 muted" ]]; then
    pass "levels-kept-boot" "with no record in /run, the mixer started at the kept levels, not at the 45 that never reached them"
else
    fail "levels-kept-boot" "status: $(ctl status 2>&1 | tr '\n' ' '); kept: $(tr '\n' ' ' < "$KEPT" 2>&1)"
fi
# The mixer's uid writes the record: root keeps only the lines a record holds.
printf 'master 20\nzone work 30 muted granted\nroot:x:0:0::/root:/bin/sh\nzone dev 101\n' > "$REC"
if restart_mixer && [[ "$(cat "$KEPT" 2>&1)" == "master 20" && "$(st master)" == "master 20" ]] && ! ctl status | grep -q ' granted'; then
    pass "levels-kept-filtered" "of a record with other lines, root kept only master 20, and the mixer granted nothing"
else
    fail "levels-kept-filtered" "kept: $(tr '\n' ' ' < "$KEPT" 2>&1); status: $(ctl status 2>&1 | tr '\n' ' ')"
fi
# And it is read with the mixer's rights: a record linked to a file only root may read keeps nothing.
( umask 077; echo 'master 7' > /run/sound-check-root-only )
ln -sfn /run/sound-check-root-only "$REC"
if restart_mixer && [[ "$(cat "$KEPT" 2>&1)" == "master 20" && "$(st master)" == "master 20" && ! -L "$REC" ]]; then
    pass "levels-kept-unread" "of a record linked to a file only root may read, nothing was kept or started from"
else
    fail "levels-kept-unread" "kept: $(tr '\n' ' ' < "$KEPT" 2>&1); record: $(ls -l "$REC" 2>&1); status: $(ctl status 2>&1 | tr '\n' ' ')"
fi
rm -f /run/sound-check-root-only
ctl mute off > /dev/null; ctl volume 100 > /dev/null; ctl mute work off > /dev/null; ctl volume work 100 > /dev/null

# --- a USB sound card ----------------------------------------------------------------------
# A USB card plugged in takes the sound: the mixer picks a card each time it opens one, a USB
# device first, and looks again each second while a stream runs, so a tone already playing
# moves to it (770 Hz, which the host does not listen for). The card closes after 5 s with
# nothing to play. Pulled out mid-tone, the card is closed and the rest of the tone goes to the
# built-in one, where the host hears it (550 Hz).
ctl volume untrusted 100 > /dev/null
pcm_running() { grep -q '^state: RUNNING' "/proc/asound/card$1/pcm0p/sub0/status" 2>/dev/null; }
usb_card() { sed -n 's/^ *\([0-9][0-9]*\) \[[^]]*\]: USB-Audio - .*/\1/p' /proc/asound/cards | head -1; }
usb_in() { [[ -n "$(usb_card)" ]]; }
usb_out() { [[ -z "$(usb_card)" ]]; }
( zrun untrusted 60 -- "$PROBE" tone 770 15 ) &
tp=$!
before=no
wait_for 15 pcm_running 0 && before=yes
echo "GT USB-SOUND-PLUG"
if wait_for 30 usb_in; then
    pass "usb-sound-card" "$(grep 'USB-Audio' /proc/asound/cards | tr -s ' ')"
else
    fail "usb-sound-card" "cards: $(tr '\n' ' ' < /proc/asound/cards) kernel: $(klog)"
fi
c="$(usb_card)"
if [[ "$before" == yes && -n "$c" ]] && wait_for 15 pcm_running "$c" && ! pcm_running 0; then
    pass "plug-moves-sound" "plugged in mid-tone, card ${c}, the USB one, took the tone from the built-in card, which closed"
else
    fail "plug-moves-sound" "built-in playing before the plug: ${before}; USB card ${c:-none}: $(head -1 "/proc/asound/card${c:-9}/pcm0p/sub0/status" 2>&1); card 0: $(head -1 /proc/asound/card0/pcm0p/sub0/status 2>&1)"
fi
wait "$tp"
mpid="$(pgrep -xo kryptik-sound)"; stopped="$(mixer_said 'the card stopped')"
sleep 6
( zrun untrusted 60 -- "$PROBE" tone 550 12 ) &
tp=$!
if [[ -n "$c" ]] && wait_for 15 pcm_running "$c" && ! pcm_running 0; then
    pass "plays-on-usb" "a zone's tone went to card ${c}, the USB one, and the built-in card stayed closed"
else
    fail "plays-on-usb" "USB card ${c:-none}: $(head -1 "/proc/asound/card${c:-9}/pcm0p/sub0/status" 2>&1); card 0: $(head -1 /proc/asound/card0/pcm0p/sub0/status 2>&1)"
fi
echo "GT USB-SOUND-PULL"
if wait_for 30 usb_out && wait_for 10 pcm_running 0 && [[ "$(pgrep -xo kryptik-sound)" == "$mpid" ]] \
   && [[ "$(mixer_said 'the card stopped')" -gt "$stopped" ]]; then
    pass "usb-pull-moves-sound" "pulled out mid-tone, the USB card was closed and the tone went on on the built-in card, the mixer running on"
else
    fail "usb-pull-moves-sound" "cards: $(tr '\n' ' ' < /proc/asound/cards); card 0: $(head -1 /proc/asound/card0/pcm0p/sub0/status 2>&1); mixer ${mpid}, now $(pgrep -xo kryptik-sound); $(uncaught | grep -a 'kryptik-sound' | tail -2 | tr '\n' ' ')"
fi
wait "$tp"
said="$(tr '\n' ' ' < "$LOG/untrusted.out")"
if [[ "$said" == *"played 12 s of 550 Hz"* ]]; then
    pass "usb-pull-zone-plays-on" "the zone played its tone to the end across the pull: ${said}"
else
    fail "usb-pull-zone-plays-on" "${said}"
fi

echo "GT SUMMARY passed=${PASS} failed=${FAIL}"
echo "GT END"
