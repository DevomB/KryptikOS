#!/usr/bin/env bash
# The camera granted to one zone at a time (docs/design/camera.md), run as root in the installed
# guest by tools/image/zones-test.sh. QEMU has no camera, so vivid, which only this loads, stands
# in for one.
#
#   camera-check.sh USER   USER is the session's user, who grants as the chrome does
#
# Output: "CT PASS|FAIL name - detail"; a check that cannot run fails.
set -u
Z=/usr/lib/kryptik/zones
R=/var/lib/kryptik/zones
KD=/usr/bin/kryptikd
LOG=/var/log/kryptik/camera-check
mkdir -p "$LOG"
USER_NAME="${1:-tester}"
pass() { echo "CT PASS $1${2:+ - $2}"; }
fail() { echo "CT FAIL $1${2:+ - $2}"; }
oneline() { tr '\n' ' ' | cut -c1-300; }
as_user() { su -s /bin/sh "$USER_NAME" -c "$*"; }
zrun() {   # zrun ZONE [--passphrase-file F] -- CMD...: sets ZRC and ZOUT
    local zone="$1"; shift
    local extra=()
    while [[ "$1" != "--" ]]; do extra+=("$1"); shift; done; shift
    timeout -k 5 120 "$KD" run "$zone" --zones "$Z" --rootfs "$R" "${extra[@]}" -- "$@" > "$LOG/$zone.out" 2>&1
    ZRC=$?
    ZOUT="$(cat "$LOG/$zone.out")"
}
loaded() { [[ -d "/sys/module/$1" ]]; }
holder() { "$KD" camera status 2>&1; }
wait_for() {   # wait_for FILE REGEX SECONDS
    for _ in $(seq 1 "$3"); do
        grep -qE "$2" "$1" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}
# A program in a zone: opens /dev/video0, asks the driver's name, reads a frame. With an
# argument it keeps reading every half second until a read fails; with WAIT it first waits for
# the camera to be given.
PROBE='import fcntl, os, sys, time
wait = "wait" in sys.argv
for _ in range(60 if wait else 1):
    try:
        fd = os.open("/dev/video0", os.O_RDWR)
        break
    except OSError as e:
        err = e.errno
        time.sleep(0.5)
else:
    print("OPEN-FAILED", err, flush=True)
    sys.exit(0)
cap = bytearray(104)
fcntl.ioctl(fd, 0x80685600, cap)
print("DRIVER", bytes(cap[:16]).rstrip(b"\0").decode(), flush=True)
print("FRAME", len(os.read(fd, 8 << 20)), flush=True)
if "hold" in sys.argv:
    print("HELD", flush=True)
    for _ in range(240):
        time.sleep(0.5)
        try:
            os.read(fd, 8 << 20)
        except OSError as e:
            print("READ-FAILED", e.errno, flush=True)
            sys.exit(0)
    print("STILL-READS", flush=True)'
[[ "$(id -u)" = 0 ]] || { fail "root" "this must run as root"; exit 1; }
untrusted_uid="$(sed -n 's/^uid_base *= *\([0-9]*\).*/\1/p' "$Z/untrusted.toml")"
node=/run/kryptik-camera/untrusted/video0

# A camera plugged in loads nothing: eudev loads by alias, and kmod skips a blacklisted module's
# own aliases, so a video-class device's alias, which uvcvideo claims, loads nothing.
alias='usb:v0000p0000d0000dcEFdsc02dp01ic0Eisc01ip00in00'
claims="$(grep -c 'ic0Eisc01ip00.* uvcvideo$' "/lib/modules/$(uname -r)/modules.alias" 2>&1)"
kept="$(modprobe -n -v -b "$alias" 2>&1)"
if [[ "$claims" -ge 1 && "$kept" != *uvcvideo* ]] && ! loaded uvcvideo; then
    pass "camera-not-by-alias" "uvcvideo claims the video class, and loading by a camera's alias loads nothing"
else
    fail "camera-not-by-alias" "uvcvideo's video-class aliases: ${claims}; loading by alias: $(oneline <<<"$kept"); loaded: $(loaded uvcvideo && echo yes || echo no)"
fi

modprobe vivid n_devs=1 node_types=0x1 2> "$LOG/vivid.err" || { fail "camera-stand-in" "$(oneline < "$LOG/vivid.err")"; exit 0; }
zrun untrusted -- python3 -c "$PROBE"
if grep -q '^OPEN-FAILED 2$' <<<"$ZOUT"; then pass "camera-not-granted" "untrusted finds no camera before a grant"; else fail "camera-not-granted" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi

for z in vault net; do
    said="$(as_user "kryptik-launch --camera-grant $z" 2>&1)"; rc=$?
    if [[ "$rc" -ne 0 && "$said" == *"refuses the camera"* && ! -e "/run/kryptik-camera/$z/video0" ]]; then
        pass "camera-refused-$z" "$said"
    else
        fail "camera-refused-$z" "rc ${rc}: ${said}"
    fi
done

# Granted: the driver loads, and the node, the zone's root's alone, is in the zone's directory.
said="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"; rc=$?
st="$(stat -c '%F %u %a' "$node" 2>&1)"
if [[ "$rc" -eq 0 ]] && loaded uvcvideo && [[ "$st" == "character special file ${untrusted_uid} 600" && "$(holder)" == "zone untrusted holds "* ]]; then
    pass "camera-granted" "${said}; ${st}"
else
    fail "camera-granted" "rc ${rc}: ${said}; node: ${st}; uvcvideo $(loaded uvcvideo && echo loaded || echo absent); $(holder)"
fi
zrun untrusted -- python3 -c "$PROBE"
if grep -q '^DRIVER vivid$' <<<"$ZOUT" && grep -qE '^FRAME [1-9][0-9]*$' <<<"$ZOUT"; then pass "camera-zone-captures" "$(oneline <<<"$ZOUT")"; else fail "camera-zone-captures" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi
if [[ "$(holder)" == none* && ! -e "$node" ]]; then pass "camera-ends-with-zone" "untrusted stopped, so its grant ended"; else fail "camera-ends-with-zone" "$(holder); node $(ls -l "$node" 2>&1)"; fi

# Another zone finds none while untrusted holds it.
as_user "kryptik-launch --camera-grant untrusted" > /dev/null 2>&1
zrun personal --passphrase-file /root/zt/personal.pass -- python3 -c "$PROBE"
if grep -q '^OPEN-FAILED 2$' <<<"$ZOUT"; then pass "camera-other-zone-none" "personal finds no camera"; else fail "camera-other-zone-none" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi

# k alone: the descriptor a program kept fails, the node goes, and the driver lets go of the
# stand-in and unloads.
"$KD" run untrusted --zones "$Z" --rootfs "$R" -- python3 -c "$PROBE" hold > "$LOG/holder.out" 2>&1 &
hp=$!
if wait_for "$LOG/holder.out" '^HELD' 60; then
    said="$(as_user "kryptik-launch --camera-revoke" 2>&1)"; rc=$?
    if [[ "$rc" -eq 0 && "$said" == untrusted* && ! -e "$node" ]] && ! loaded uvcvideo && [[ ! -e /sys/bus/platform/drivers/vivid/vivid.0 ]]; then
        pass "camera-revoked" "${said}: the node is gone, vivid.0 let go of and uvcvideo unloaded"
    else
        fail "camera-revoked" "rc ${rc}: ${said}; node $(ls -l "$node" 2>&1); uvcvideo $(loaded uvcvideo && echo loaded || echo absent)"
    fi
    if wait_for "$LOG/holder.out" '^READ-FAILED [0-9]+$' 30; then pass "camera-revoked-kept-descriptor" "$(grep '^READ-FAILED' "$LOG/holder.out")"; else fail "camera-revoked-kept-descriptor" "$(oneline < "$LOG/holder.out")"; fi
else
    fail "camera-revoked" "the program never held the camera: $(oneline < "$LOG/holder.out")"
    fail "camera-revoked-kept-descriptor" "not run"
fi
for _ in $(seq 1 60); do kill -0 "$hp" 2>/dev/null || break; sleep 1; done
kill "$hp" 2>/dev/null; wait "$hp" 2>/dev/null

# Granted again, to a zone already running, as to a browser waiting for it: the stand-in is
# taken again, and the node appears in the zone.
"$KD" run untrusted --zones "$Z" --rootfs "$R" -- python3 -c "$PROBE" wait > "$LOG/waiting.out" 2>&1 &
wp=$!
sleep 5
said="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"; rc=$?
if [[ "$rc" -eq 0 ]] && wait_for "$LOG/waiting.out" '^FRAME [1-9]' 60; then
    pass "camera-granted-again-while-running" "${said}; $(oneline < "$LOG/waiting.out")"
else
    fail "camera-granted-again-while-running" "rc ${rc}: ${said}; $(oneline < "$LOG/waiting.out")"
fi
for _ in $(seq 1 60); do kill -0 "$wp" 2>/dev/null || break; sleep 1; done
kill "$wp" 2>/dev/null; wait "$wp" 2>/dev/null
if [[ "$(holder)" == none* ]]; then pass "camera-ends-with-zone-again" "$(holder)"; else fail "camera-ends-with-zone-again" "$(holder)"; fi

# Taken away while granted, as a USB camera pulled out: udev's removal of its node ends the grant
# at once, before another camera plugged in could take the node's number.
said="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"; rc=$?
ended() { [[ "$(holder)" == none* && ! -e "$node" ]]; }
if [[ "$rc" -eq 0 && -e "$node" ]]; then
    modprobe -r vivid > "$LOG/vivid-gone.out" 2>&1
    ok=no
    for _ in $(seq 1 15); do ended && { ok=yes; break; }; sleep 1; done
    if [[ "$ok" == yes ]]; then
        pass "camera-gone-ends-grant" "vivid taken away while untrusted held it: the grant ended and the node went"
    else
        fail "camera-gone-ends-grant" "status: $(holder); node $(ls -l "$node" 2>&1); $(oneline < "$LOG/vivid-gone.out")"
    fi
else
    fail "camera-gone-ends-grant" "the grant: rc ${rc}: ${said}"
fi

modprobe -r vivid uvcvideo 2>/dev/null
echo "CT END"
