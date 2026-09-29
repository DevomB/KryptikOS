#!/bin/sh
# Test control for install media, sourced by boot-time services. A disk
# labelled kryptik-testctl carries a key=value file, read only when booted from
# an install medium (kryptik.media=), so such a disk cannot reinstall or shut
# down an installed system, and only when the kryptik-testctl key the medium's
# anchor lists signed it, so no one else's disk can arm an install either.
#   testctl_load      0, with TESTCTL_FILE set, when a control file was read
#   testctl_get KEY   the value, or empty
# Keys: install_target=/dev/vdb   smoke_poweroff=1   preseed_user=NAME
#       preseed_password_hash=HASH  preseed_root_hash=HASH  install_wait=SECONDS
#       recover_disk=/dev/vda recover_slot=a|b recover_mode=restore|commit|status

TESTCTL_MNT=/run/kryptik/testctl
TESTCTL_FILE=""
TESTCTL_ANCHOR="${TESTCTL_ANCHOR:-/usr/share/kryptik/trust/release-signers}"

# The file and a signature over it by the kryptik-testctl key the anchor
# lists, in that key's own namespace: the holder of that key alone can arm an
# install on a machine that boots this medium.
testctl_signed() {   # testctl_signed FILE
    [ -r "$1" ] && [ -r "$1.sig" ] || return 1
    ssh-keygen -Y verify -f "$TESTCTL_ANCHOR" -I kryptik-testctl -n kryptik-testctl \
        -s "$1.sig" < "$1" > /dev/null 2>&1
}

testctl_media() {
    grep -qs '^media=.\+' /run/kryptik/boot-identity 2>/dev/null && return 0
    grep -qw 'kryptik\.media=[a-z]' /proc/cmdline 2>/dev/null
}

testctl_load() {
    TESTCTL_FILE=""
    testctl_media || return 1
    dev="$(blkid -t PARTLABEL=kryptik-testctl -o device 2>/dev/null | head -1)"
    [ -n "$dev" ] && [ -b "$dev" ] || return 1
    mkdir -p "$TESTCTL_MNT"
    if ! mountpoint -q "$TESTCTL_MNT"; then
        mount -o ro,nosuid,nodev,noexec "$dev" "$TESTCTL_MNT" 2>/dev/null || return 1
    fi
    [ -r "$TESTCTL_MNT/kryptik-test.conf" ] || return 1
    if ! testctl_signed "$TESTCTL_MNT/kryptik-test.conf"; then
        echo "testctl: the control file on ${dev} is not signed by this medium's kryptik-testctl key; ignored"
        umount "$TESTCTL_MNT" 2>/dev/null
        return 1
    fi
    TESTCTL_FILE="$TESTCTL_MNT/kryptik-test.conf"
    echo "testctl: control file read from ${dev} (install medium only)"
    return 0
}

testctl_get() {
    [ -n "$TESTCTL_FILE" ] || return 0
    sed -n "s/^$1=//p" "$TESTCTL_FILE" | head -1
}
