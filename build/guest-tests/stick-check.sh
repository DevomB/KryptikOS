#!/usr/bin/env bash
# A USB stick given to a zone and taken back (docs/design/removable-storage.md), run as root in
# the installed guest by tools/image/zones-test.sh, which plugs and pulls the sticks through QEMU
# between the phases:
#
#   stick-check.sh plugged USER SHA  a FAT stick plugged in: partition 1 named DATA, hello.bin
#                                    on it with the sha256 SHA; untrusted reads it, writes to it
#                                    when given it to write, and loses it at eject and at its stop
#   stick-check.sh hold USER         untrusted given it again, a program there holding it
#   stick-check.sh pulled USER       the stick pulled out under that program, never ejected
#   stick-check.sh medium USER       the install medium plugged in
#   stick-check.sh card USER SHA     an exFAT card plugged in: partition 1 named CARD, the photo
#                                    DCIM/100CANON/IMG_0001.JPG on it with the sha256 SHA
#
# USER is the session's user, who gives sticks through the launch daemon as the chrome does.
# Output: "ST PASS|FAIL name - detail"; a check that cannot run fails.
set -u
Z=/usr/lib/kryptik/zones
R=/var/lib/kryptik/zones
KD=/usr/bin/kryptikd
LOG=/var/log/kryptik/stick-check
mkdir -p "$LOG"
PHASE="${1:-}"; USER_NAME="${2:-tester}"; SHA="${3:-}"
pass() { echo "ST PASS $1${2:+ - $2}"; }
fail() { echo "ST FAIL $1${2:+ - $2}"; }
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
held_by() { ls "/sys/class/block/$1/holders" 2>/dev/null | tr '\n' ' '; }
mapped() { dmsetup info "kryptik-stick-$1" > /dev/null 2>&1; }
# Device-mapper removes a mapping whose removal was deferred from a workqueue, after its last close.
unmapped() { for _ in $(seq 1 10); do mapped "$1" || return 0; sleep 1; done; return 1; }
stick_of() { as_user "kryptik-launch --info $1" 2>&1 | sed -n 's/^stick //p'; }
# The USB partition with GPT name $1, waited for: the host plugs the stick just before.
usb_part() {
    local u
    for _ in $(seq 1 30); do
        for u in /sys/class/block/sd*/uevent; do
            [[ -e "$u" ]] && grep -qx "PARTNAME=$1" "$u" && { basename "$(dirname "$u")"; return 0; }
        done
        sleep 1
    done
    return 1
}
# A program in untrusted holding the stick's descriptor from its broker, reading its first block
# every half second until a read fails.
HOLDER='import array, os, socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect("/run/kryptik/broker")
s.sendall(b"stick\n")
s.shutdown(socket.SHUT_WR)
msg, anc, _, _ = s.recvmsg(512, socket.CMSG_SPACE(4))
fds = [array.array("i", d[:4])[0] for l, k, d in anc if l == socket.SOL_SOCKET and k == socket.SCM_RIGHTS]
print("ANSWER", msg.decode().strip(), len(fds), flush=True)
os.pread(fds[0], 4096, 0)
print("HELD", flush=True)
for _ in range(240):
    time.sleep(0.5)
    try:
        os.pread(fds[0], 4096, 0)
    except OSError as e:
        print("READ-FAILED", e.errno, flush=True)
        sys.exit(0)
print("STILL-READS", flush=True)'
wait_for() {   # wait_for FILE REGEX SECONDS
    for _ in $(seq 1 "$3"); do
        grep -qE "$2" "$1" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}
[[ "$(id -u)" = 0 ]] || { fail "root" "this must run as root"; exit 1; }

case "$PHASE" in
plugged)
    P="$(usb_part DATA)" || { fail "stick-seen" "no USB partition named DATA after 30 s: $(ls /sys/class/block | oneline)"; exit 0; }
    pass "stick-seen" "partition ${P}, named DATA"
    disk="${P%%[0-9]*}"
    fstype="$(udevadm info --query=property --name="/dev/$P" 2>/dev/null | sed -n 's/^ID_FS_TYPE=//p')"
    if ! grep -q "^/dev/${disk}" /proc/mounts && [[ -z "$(held_by "$P")" && -z "$fstype" ]]; then
        pass "stick-untouched" "zone 0 mounted nothing of ${disk}, nothing holds ${P}, and eudev read no filesystem on it"
    else
        fail "stick-untouched" "mounts: $(grep "^/dev/${disk}" /proc/mounts | oneline); holders: $(held_by "$P"); ID_FS_TYPE=${fstype}"
    fi
    listed="$(as_user "kryptik-launch --sticks" 2>&1)"
    if grep -qE "^${P} .*partition 1 \(DATA\)$" <<<"$listed"; then pass "stick-listed" "$(grep "^${P} " <<<"$listed")"; else fail "stick-listed" "$(oneline <<<"$listed")"; fi
    said="$(as_user "kryptik-launch --stick-grant vault $P ro" 2>&1)"; rc=$?
    if [[ "$rc" -ne 0 && "$said" == *"refuses USB sticks"* && -z "$(held_by "$P")" ]]; then pass "stick-refused-vault" "$said"; else fail "stick-refused-vault" "rc ${rc}: ${said}"; fi
    said="$(as_user "kryptik-launch --stick-grant net $P ro" 2>&1)"; rc=$?
    if [[ "$rc" -ne 0 && -z "$(held_by "$P")" ]]; then pass "stick-refused-net" "$said"; else fail "stick-refused-net" "rc ${rc}: ${said}"; fi

    # Read-only: untrusted lists it, copies a file off it, and cannot write.
    said="$(as_user "kryptik-launch --stick-grant untrusted $P ro" 2>&1)"; rc=$?
    dm="$(held_by "$P" | awk '{ print $1 }')"
    if [[ "$rc" -eq 0 && "$dm" == dm-* && "$(cat "/sys/block/$dm/ro" 2>/dev/null)" = 1 && "$(stick_of untrusted)" == "ro "* ]]; then
        pass "stick-given-ro" "${said}; ${P} held by ${dm} alone, which is read-only"
    else
        fail "stick-given-ro" "rc ${rc}: ${said}; holders ${dm:-none}; ro $(cat "/sys/block/$dm/ro" 2>/dev/null); info stick $(stick_of untrusted)"
    fi
    # Nothing in zone 0 reads the stick through the mapping either (12-kryptik-stick.rules).
    udevadm settle -t 10 2>/dev/null
    probed="$(udevadm info --query=property --name="/dev/$dm" 2>/dev/null | grep '^ID_FS_')$(udevadm info --query=property --name="/dev/$P" 2>/dev/null | grep '^ID_FS_')"
    if [[ "$dm" == dm-* && -z "$probed" ]]; then pass "stick-mapping-unprobed" "eudev read no filesystem through ${dm}, nor on ${P}"; else fail "stick-mapping-unprobed" "${dm:-no mapping}: $(oneline <<<"$probed")"; fi
    zrun untrusted -- sh -c 'kryptik-stick; kryptik-stick list /; cd /tmp && kryptik-stick get /hello.bin . && echo "SHA:$(sha256sum hello.bin | cut -d" " -f1)"; echo w > /tmp/w && kryptik-stick put /tmp/w /; echo "PUT-RC=$?"; echo "DEV:" /dev/*'
    if grep -q 'read-only' <<<"$ZOUT" && grep -qE ' hello\.bin$' <<<"$ZOUT"; then pass "stick-zone-lists" "$(grep -m1 'FAT' <<<"$ZOUT")"; else fail "stick-zone-lists" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi
    if [[ -n "$SHA" ]] && grep -qx "SHA:${SHA}" <<<"$ZOUT"; then pass "stick-zone-copies" "hello.bin copied off whole"; else fail "stick-zone-copies" "want SHA:${SHA}: $(grep '^SHA:' <<<"$ZOUT")"; fi
    if grep -q '^PUT-RC=[1-9]' <<<"$ZOUT" && grep -q 'given to this zone read-only' <<<"$ZOUT"; then pass "stick-ro-refuses-write" "a write was refused"; else fail "stick-ro-refuses-write" "$(oneline <<<"$ZOUT")"; fi
    devs="$(grep '^DEV:' <<<"$ZOUT")"
    if [[ -n "$devs" && ! "$devs" =~ /dev/(sd|dm-|mapper|mmcblk) ]]; then pass "stick-no-node" "the zone's /dev has no node for it"; else fail "stick-no-node" "${devs:-no listing}"; fi
    if [[ "$(stick_of untrusted)" == none && -z "$(held_by "$P")" ]] && unmapped untrusted; then
        pass "stick-ends-with-zone" "untrusted stopped, so its grant ended and the mapping went"
    else
        fail "stick-ends-with-zone" "info stick $(stick_of untrusted); holders $(held_by "$P"); mapping $(mapped untrusted && echo kept || echo gone)"
    fi

    # Another zone asks and is refused.
    as_user "kryptik-launch --stick-grant untrusted $P ro" > /dev/null 2>&1
    zrun personal --passphrase-file /root/zt/personal.pass -- kryptik-stick
    if [[ "$ZRC" -ne 0 && "$ZOUT" == *"no USB stick is given to this zone"* ]]; then pass "stick-other-zone-refused" "personal: $(oneline <<<"$ZOUT")"; else fail "stick-other-zone-refused" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi

    # Eject: the descriptor untrusted kept fails, and the stick is free at once.
    "$KD" run untrusted --zones "$Z" --rootfs "$R" -- python3 -c "$HOLDER" > "$LOG/holder.out" 2>&1 &
    hp=$!
    if wait_for "$LOG/holder.out" '^HELD' 60; then
        said="$(as_user "kryptik-launch --stick-eject untrusted" 2>&1)"; rc=$?
        free="$(held_by "$P")"
        if [[ "$rc" -eq 0 && -z "$free" ]]; then pass "stick-eject-frees" "${P} is held by nothing while untrusted still has its descriptor"; else fail "stick-eject-frees" "rc ${rc}: ${said}; holders ${free}"; fi
        if wait_for "$LOG/holder.out" '^READ-FAILED 5$' 30; then pass "stick-eject-kept-descriptor" "the descriptor untrusted kept reads only EIO"; else fail "stick-eject-kept-descriptor" "$(oneline < "$LOG/holder.out")"; fi
    else
        fail "stick-eject-frees" "the holder never held the stick: $(oneline < "$LOG/holder.out")"
        fail "stick-eject-kept-descriptor" "not run"
    fi
    for _ in $(seq 1 60); do kill -0 "$hp" 2>/dev/null || break; sleep 1; done
    kill "$hp" 2>/dev/null; wait "$hp" 2>/dev/null
    if unmapped untrusted; then pass "stick-mapping-gone" "the ejected mapping went with its last descriptor"; else fail "stick-mapping-gone" "kryptik-stick-untrusted is still there after the zone exited"; fi

    # Read and write: what untrusted puts lands on the stick (the host reads it after pulling it).
    said="$(as_user "kryptik-launch --stick-grant untrusted $P rw" 2>&1)"; rc=$?
    zrun untrusted -- sh -c 'echo "written in untrusted" > /tmp/put.txt && kryptik-stick put /tmp/put.txt /'
    if [[ "$rc" -eq 0 && "$ZRC" -eq 0 && "$ZOUT" == *"onto the stick"* && "$(stick_of untrusted)" == none ]]; then
        pass "stick-written" "${said}; $(oneline <<<"$ZOUT")"
    else
        fail "stick-written" "grant rc ${rc}: ${said}; zone rc ${ZRC}: $(oneline <<<"$ZOUT")"
    fi
    ;;
hold)
    P="$(usb_part DATA)" || { fail "stick-holding" "no USB partition named DATA"; echo "ST HOLDING"; exit 0; }
    as_user "kryptik-launch --stick-grant untrusted $P ro" > "$LOG/hold-grant.out" 2>&1
    rm -f "$LOG/held.out"
    setsid -f "$KD" run untrusted --zones "$Z" --rootfs "$R" -- python3 -c "$HOLDER" > "$LOG/held.out" 2>&1 < /dev/null
    if wait_for "$LOG/held.out" '^HELD' 60; then pass "stick-holding" "untrusted holds ${P}'s descriptor"; else fail "stick-holding" "$(oneline < "$LOG/hold-grant.out") $(oneline < "$LOG/held.out")"; fi
    echo "stick-check: the stick is pulled out next" > /dev/kmsg
    echo "ST HOLDING"
    ;;
pulled)
    # Listing the sticks, as the chrome does when a block device goes, ends the grant.
    as_user "kryptik-launch --sticks" > /dev/null 2>&1
    if wait_for "$LOG/held.out" '^READ-FAILED 5$' 30; then pass "stick-pulled-reads-fail" "the descriptor untrusted held reads only EIO"; else fail "stick-pulled-reads-fail" "$(oneline < "$LOG/held.out")"; fi
    if [[ "$(stick_of untrusted)" == none ]]; then pass "stick-pulled-grant-ended" "untrusted holds no stick"; else fail "stick-pulled-grant-ended" "info stick $(stick_of untrusted)"; fi
    for _ in $(seq 1 30); do pgrep -f 'import array, os, socket' > /dev/null || break; sleep 1; done
    if unmapped untrusted; then pass "stick-pulled-mapping-gone" "the mapping went with the program that held it"; else fail "stick-pulled-mapping-gone" "kryptik-stick-untrusted is still there"; fi
    after="$(dmesg | sed -n '/stick-check: the stick is pulled out next/,$p')"
    oops="$(grep -E 'Oops|BUG:|Call Trace|general protection' <<<"$after" | head -3)"
    if [[ -n "$after" && -z "$oops" ]]; then pass "stick-no-oops" "the kernel log has no oops after the pull"; else fail "stick-no-oops" "${oops:-no marker in the kernel log}"; fi
    ;;
medium)
    E="$(usb_part kryptik-esp)" || { fail "medium-esp-offered" "no USB partition named kryptik-esp after 30 s"; exit 0; }
    root="${E%%[0-9]*}2"
    listed="$(as_user "kryptik-launch --sticks" 2>&1)"
    if grep -q "^${E} .*(kryptik-esp)$" <<<"$listed" && grep -q "^${root} " <<<"$listed"; then pass "medium-esp-offered" "$(grep "^${E} " <<<"$listed")"; else fail "medium-esp-offered" "$(oneline <<<"$listed")"; fi
    own="$(/usr/libexec/kryptik/devices.sh part kryptik-esp 2>&1)"
    if [[ "$own" == /dev/vda* ]]; then pass "medium-not-the-system" "the system's ESP is still ${own}"; else fail "medium-not-the-system" "devices.sh part kryptik-esp: ${own}"; fi
    as_user "kryptik-launch --stick-grant untrusted $E ro" > /dev/null 2>&1
    zrun untrusted -- kryptik-stick list /
    if [[ "$ZRC" -eq 0 && "$ZOUT" == *"EFI/"* ]]; then pass "medium-esp-read" "$(oneline <<<"$ZOUT")"; else fail "medium-esp-read" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi
    as_user "kryptik-launch --stick-grant untrusted $root ro" > /dev/null 2>&1
    zrun untrusted -- kryptik-stick list /
    if [[ "$ZRC" -ne 0 && "$ZOUT" == *"no FAT filesystem"* ]]; then pass "medium-root-refused" "$(oneline <<<"$ZOUT")"; else fail "medium-root-refused" "rc ${ZRC}: $(oneline <<<"$ZOUT")"; fi
    ;;
card)
    # Given to write, as a user might, an exFAT card is still only read: the reader writes FAT alone.
    P="$(usb_part CARD)" || { fail "card-exfat-lists" "no USB partition named CARD after 30 s: $(ls /sys/class/block | oneline)"; exit 0; }
    as_user "kryptik-launch --stick-grant untrusted $P rw" > "$LOG/card-grant.out" 2>&1
    zrun untrusted -- sh -c 'kryptik-stick; kryptik-stick list /dcim/100canon; cd /tmp && kryptik-stick get /DCIM/100CANON/img_0001.jpg . && echo "SHA:$(sha256sum img_0001.jpg | cut -d" " -f1)"; echo w > /tmp/w && kryptik-stick put /tmp/w /; echo "PUT-RC=$?"'
    if grep -q 'exFAT, read-only' <<<"$ZOUT" && grep -qE ' IMG_0001\.JPG$' <<<"$ZOUT"; then pass "card-exfat-lists" "$(grep -m1 'exFAT' <<<"$ZOUT")"; else fail "card-exfat-lists" "rc ${ZRC}: $(oneline <<<"$ZOUT") grant: $(oneline < "$LOG/card-grant.out")"; fi
    if [[ -n "$SHA" ]] && grep -qx "SHA:${SHA}" <<<"$ZOUT"; then pass "card-exfat-copies" "the photo came off whole"; else fail "card-exfat-copies" "want SHA:${SHA}: $(grep '^SHA:' <<<"$ZOUT")"; fi
    if grep -q '^PUT-RC=[1-9]' <<<"$ZOUT" && grep -q 'exFAT is read here, not written' <<<"$ZOUT"; then pass "card-exfat-not-written" "the write was refused, though the grant allowed one"; else fail "card-exfat-not-written" "$(oneline <<<"$ZOUT")"; fi
    if [[ "$(stick_of untrusted)" == none && -z "$(held_by "$P")" ]] && unmapped untrusted; then
        pass "card-ends-with-zone" "untrusted stopped, so its grant of the card ended and the mapping went"
    else
        fail "card-ends-with-zone" "info stick $(stick_of untrusted); holders $(held_by "$P"); mapping $(mapped untrusted && echo kept || echo gone)"
    fi
    ;;
*)
    fail "phase" "usage: stick-check.sh plugged|hold|pulled|medium|card USER [SHA]"
    ;;
esac
