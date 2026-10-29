#!/usr/bin/env bash
# The camera granted to one zone at a time (docs/design/camera.md), run as root in the installed
# guest by tools/image/zones-test.sh. QEMU has no camera, so vivid, which only this loads, stands
# in for one.
#
#   camera-check.sh USER              USER is the session's user, who grants as the chrome does
#   camera-check.sh USER --hardware   the machine's own USB camera instead, vivid never loaded
#
# --hardware runs as root at a console (Ctrl+Alt+F2) of the installed laptop, with USER logged in,
# the screen unlocked and nothing using the camera since boot, and within the ten minutes before
# the idle lock, which takes the camera back. It checks what QEMU cannot: uvcvideo's capture, a
# program that keeps the camera past its grant holding the driver, and the camera taken away.
#
# Output: "CT PASS|FAIL name - detail"; a check that cannot run fails.
set -u
Z=/usr/lib/kryptik/zones
R=/var/lib/kryptik/zones
KD=/usr/bin/kryptikd
LOG=/var/log/kryptik/camera-check
mkdir -p "$LOG"
USER_NAME="${1:-tester}"
HW=0; [[ "${2:-}" == --hardware ]] && HW=1
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
# A program in a zone: opens /dev/video0, asks the driver's name and the formats it offers, and
# takes a frame by mmap streaming, as a browser does (uvcvideo has no read()). With HOLD it takes
# one every half second until that fails, and with KEEP then holds the descriptor two minutes
# more; with WAIT it first waits for the camera to be given.
PROBE='import fcntl, mmap, os, select, struct, sys, time
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
fmts = []
for i in range(64):
    d = bytearray(64)
    struct.pack_into("=II", d, 0, i, 1)
    try:
        fcntl.ioctl(fd, 0xc0405602, d)
    except OSError:
        break
    fmts.append(bytes(d[44:48]).decode("ascii", "replace"))
print("FORMATS", " ".join(fmts), flush=True)
def buf(i=0):
    b = bytearray(88)
    struct.pack_into("=II", b, 0, i, 1)
    struct.pack_into("=I", b, 60, 1)
    return b
req = bytearray(20)
struct.pack_into("=III", req, 0, 4, 1, 1)
fcntl.ioctl(fd, 0xc0145608, req)
maps = []
for i in range(struct.unpack_from("=I", req, 0)[0]):
    b = buf(i)
    fcntl.ioctl(fd, 0xc0585609, b)
    off, size = struct.unpack_from("=I", b, 64)[0], struct.unpack_from("=I", b, 72)[0]
    maps.append(mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=off))
    fcntl.ioctl(fd, 0xc058560f, b)
fcntl.ioctl(fd, 0x40045612, struct.pack("=i", 1))
def frame(secs):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if not select.select([fd], [], [], max(0.0, end - time.monotonic()))[0]:
            break
        b = buf()
        fcntl.ioctl(fd, 0xc0585611, b)
        used, flags = struct.unpack_from("=II", b, 8)
        fcntl.ioctl(fd, 0xc058560f, b)
        if used and not flags & 0x40:
            return used
    return 0
print("FRAME", frame(5), flush=True)
if "hold" in sys.argv:
    print("HELD", flush=True)
    for _ in range(240):
        time.sleep(0.5)
        try:
            frame(0.5)
        except OSError as e:
            print("DQBUF-FAILED", e.errno, flush=True)
            if "keep" in sys.argv:
                time.sleep(120)
            sys.exit(0)
    print("STILL-STREAMS", flush=True)'
# A video-class USB interface: a camera of the machine's own.
usb_camera() { grep -lsx 0e /sys/bus/usb/devices/*/bInterfaceClass | head -n 1; }
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

# The camera: the machine's own, met before any grant this boot, or vivid where there is none.
usb="$(usb_camera)"
if [[ "$HW" -eq 1 ]]; then
    if [[ -n "$usb" ]] && ! loaded uvcvideo && [[ "$(holder)" == none ]]; then
        pass "camera-hardware" "the USB camera at ${usb%/*}, untouched since boot"
    else
        fail "camera-hardware" "USB camera: ${usb:-none}; uvcvideo $(loaded uvcvideo && echo loaded || echo absent); $(holder)"
        exit 0
    fi
    DRV=uvcvideo
else
    [[ -z "$usb" ]] || { fail "camera-stand-in" "a USB camera is here (${usb%/*}): run with --hardware"; exit 0; }
    modprobe vivid n_devs=1 node_types=0x1 2> "$LOG/vivid.err" || { fail "camera-stand-in" "$(oneline < "$LOG/vivid.err")"; exit 0; }
    DRV=vivid
fi
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

# Granted: the driver loads, and the node, the zone's root's alone, is in the zone's directory,
# for the camera's own device.
said="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"; rc=$?
st="$(stat -c '%F %u %a' "$node" 2>&1)"
hn="$(holder | sed -n 's/.*(\(video[0-9]*\))$/\1/p')"
hd="$(basename "$(readlink -f "/sys/class/video4linux/${hn:-none}/device/driver")")"
if [[ "$rc" -eq 0 ]] && loaded uvcvideo && [[ "$st" == "character special file ${untrusted_uid} 600" && "$(holder)" == "zone untrusted holds "* && "$hd" == "$DRV" ]]; then
    pass "camera-granted" "${said}; ${st}; ${hn}, driven by ${hd}"
else
    fail "camera-granted" "rc ${rc}: ${said}; node: ${st}; uvcvideo $(loaded uvcvideo && echo loaded || echo absent); $(holder); ${hn:-no node}'s driver ${hd}"
fi
# A picture a browser shows: MJPG or YUYV among the formats, not only an infrared camera's grey.
zrun untrusted -- python3 -c "$PROBE"
if grep -q "^DRIVER ${DRV}$" <<<"$ZOUT" && grep -qE '^FORMATS (.* )?(MJPG|YUYV)( |$)' <<<"$ZOUT" && grep -qE '^FRAME [1-9][0-9]*$' <<<"$ZOUT"; then pass "camera-zone-captures" "$(oneline <<<"$ZOUT")"; else fail "camera-zone-captures" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi
if [[ "$(holder)" == none* && ! -e "$node" ]]; then pass "camera-ends-with-zone" "untrusted stopped, so its grant ended"; else fail "camera-ends-with-zone" "$(holder); node $(ls -l "$node" 2>&1)"; fi

# Another zone finds none while untrusted holds it. personal's passphrase is a file only the
# QEMU run's earlier checks make.
as_user "kryptik-launch --camera-grant untrusted" > /dev/null 2>&1
if [[ "$HW" -eq 0 ]]; then
    zrun personal --passphrase-file /root/zt/personal.pass -- python3 -c "$PROBE"
    if grep -q '^OPEN-FAILED 2$' <<<"$ZOUT"; then pass "camera-other-zone-none" "personal finds no camera"; else fail "camera-other-zone-none" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi
fi

# k alone: the descriptor a program kept fails, the node goes, and the driver lets go of the
# camera. vivid's node pins vivid, so uvcvideo unloads; a USB camera's pins uvcvideo, which stays
# loaded, and no grant is given until that program lets go, as the camera would come back with
# no capture node.
hold=(hold); [[ "$HW" -eq 0 ]] || hold+=(keep)
"$KD" run untrusted --zones "$Z" --rootfs "$R" -- python3 -c "$PROBE" "${hold[@]}" > "$LOG/holder.out" 2>&1 &
hp=$!
if wait_for "$LOG/holder.out" '^HELD' 60; then
    said="$(as_user "kryptik-launch --camera-revoke" 2>&1)"; rc=$?
    if [[ "$HW" -eq 0 && "$rc" -eq 0 && "$said" == untrusted* && ! -e "$node" ]] && ! loaded uvcvideo && [[ ! -e /sys/bus/platform/drivers/vivid/vivid.0 ]]; then
        pass "camera-revoked" "${said}: the node is gone, vivid.0 let go of and uvcvideo unloaded"
    elif [[ "$HW" -eq 1 && "$rc" -eq 0 && "$said" == "untrusted stayed" && ! -e "$node" ]] && loaded uvcvideo && [[ "$(holder)" == "none; its driver stayed loaded" ]]; then
        pass "camera-revoked" "${said}: the node is gone, and uvcvideo stays, held by the program"
    else
        fail "camera-revoked" "rc ${rc}: ${said}; node $(ls -l "$node" 2>&1); uvcvideo $(loaded uvcvideo && echo loaded || echo absent); $(holder)"
    fi
    if wait_for "$LOG/holder.out" '^DQBUF-FAILED [0-9]+$' 30; then pass "camera-revoked-kept-descriptor" "$(grep '^DQBUF-FAILED' "$LOG/holder.out")"; else fail "camera-revoked-kept-descriptor" "$(oneline < "$LOG/holder.out")"; fi
    if [[ "$HW" -eq 1 ]]; then
        said="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"; rc=$?
        if [[ "$rc" -ne 0 && "$said" == *"still holds the camera"* && ! -e "$node" ]]; then
            pass "camera-kept-refuses-grant" "$said"
        else
            fail "camera-kept-refuses-grant" "rc ${rc}: ${said}; $(holder)"
        fi
    fi
else
    fail "camera-revoked" "the program never held the camera: $(oneline < "$LOG/holder.out")"
    fail "camera-revoked-kept-descriptor" "not run"
fi
[[ "$HW" -eq 1 ]] || for _ in $(seq 1 60); do kill -0 "$hp" 2>/dev/null || break; sleep 1; done
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
# With nothing holding it this time, the driver unloads, and the mark that it stayed is gone.
h="$(holder)"
if { [[ "$HW" -eq 0 && "$h" == none* ]] || [[ "$HW" -eq 1 && "$h" == none ]]; } && ! loaded uvcvideo; then
    pass "camera-ends-with-zone-again" "$(holder)"
else
    fail "camera-ends-with-zone-again" "$(holder); uvcvideo $(loaded uvcvideo && echo loaded || echo absent)"
fi

# Taken away while granted, as a USB camera pulled out: udev's removal of its node ends the grant
# at once, before another camera plugged in could take the node's number. A built-in camera is
# taken away by deauthorizing its USB device; authorized again, it comes back loading nothing.
said="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"; rc=$?
ended() { [[ "$(holder)" == none* && ! -e "$node" ]]; }
# The granted node's USB device: its interface's parent.
hn="$(holder | sed -n 's/.*(\(video[0-9]*\))$/\1/p')"
dev="$(readlink -f "/sys/class/video4linux/${hn:-none}/device/..")"
if [[ "$HW" -eq 1 && ! ( -n "$hn" && -w "$dev/authorized" ) ]]; then
    fail "camera-gone-ends-grant" "no USB device for ${hn:-the granted node}: $(holder)"
    as_user "kryptik-launch --camera-revoke" > /dev/null 2>&1
elif [[ "$rc" -eq 0 && -e "$node" ]]; then
    if [[ "$HW" -eq 1 ]]; then echo 0 > "$dev/authorized"; else modprobe -r vivid; fi > "$LOG/gone.out" 2>&1
    ok=no
    for _ in $(seq 1 15); do ended && { ok=yes; break; }; sleep 1; done
    [[ "$HW" -eq 0 ]] || echo 1 > "$dev/authorized"
    if [[ "$ok" == yes ]]; then
        pass "camera-gone-ends-grant" "the camera taken away while untrusted held it: the grant ended and the node went"
    else
        fail "camera-gone-ends-grant" "status: $(holder); node $(ls -l "$node" 2>&1); $(oneline < "$LOG/gone.out")"
    fi
else
    fail "camera-gone-ends-grant" "the grant: rc ${rc}: ${said}"
fi
if [[ "$HW" -eq 1 ]]; then
    for _ in $(seq 1 10); do [[ -n "$(usb_camera)" ]] && break; sleep 1; done
    sleep 3
    if [[ -n "$(usb_camera)" ]] && ! loaded uvcvideo && [[ "$(holder)" == none* ]]; then
        pass "camera-back-loads-nothing" "the camera is back at ${dev}, and uvcvideo is not loaded"
    else
        fail "camera-back-loads-nothing" "USB camera: $(usb_camera); uvcvideo $(loaded uvcvideo && echo loaded || echo absent); $(holder)"
    fi
    modprobe -r uvcvideo 2>/dev/null
    echo "CT END"
    exit 0
fi

# Of two cameras, the first that offers a picture a browser reads: vivid.0's node offers only
# multi-planar formats, which Firefox does not read, so the grant passes it for vivid.1's, as it
# passes an infrared camera's grey.
modprobe -r vivid 2>/dev/null
if modprobe vivid n_devs=2 node_types=0x1,0x1 multiplanar=2,1 2> "$LOG/vivid-two.err"; then
    first="$(ls /sys/devices/platform/vivid.0/video4linux 2>&1)"
    want="$(ls /sys/devices/platform/vivid.1/video4linux 2>&1)"
    said="$(as_user "kryptik-launch --camera-grant untrusted" 2>&1)"; rc=$?
    if [[ "$rc" -eq 0 && "$(holder)" == "zone untrusted holds "*" (${want})" ]]; then
        pass "camera-colour-first" "${said}: vivid.1's ${want}, not vivid.0's ${first}"
    else
        fail "camera-colour-first" "rc ${rc}: ${said}; $(holder); vivid.0's ${first}, vivid.1's ${want}"
    fi
    as_user "kryptik-launch --camera-revoke" > /dev/null 2>&1
else
    fail "camera-colour-first" "$(oneline < "$LOG/vivid-two.err")"
fi

modprobe -r vivid uvcvideo 2>/dev/null
echo "CT END"
