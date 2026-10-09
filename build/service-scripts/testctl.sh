#!/bin/sh
# Test control, sourced by boot services: key=value from a disk labelled kryptik-testctl.
# Read only on an install medium, so the disk cannot reinstall or shut down an installed
# system, and only when the anchor's kryptik-testctl key signed it, so no other disk can arm one.
#   testctl_load      0, with TESTCTL_FILE set, when a control file was read
#   testctl_take DIR  0, with TESTCTL_FILE set, when DIR's control file verifies
#   testctl_get KEY   the value, or empty
# Keys: install_target=/dev/vdb  install_replace=1  install_slot_mib=MIB  install_keyboard=NAME
#       install_wait=SECONDS  state_passphrase=TEXT  preseed_user=NAME  preseed_password_hash=HASH
#       preseed_root_hash=HASH  smoke_poweroff=1  recover_disk=/dev/vda  recover_slot=a|b
#       recover_mode=restore|commit|header|status

TESTCTL_MNT=/run/kryptik/testctl
TESTCTL_FILE=""
TESTCTL_ANCHOR="${TESTCTL_ANCHOR:-/usr/share/kryptik/trust/release-signers}"

# FILE.sig must verify with the anchor's kryptik-testctl key, in that key's own namespace.
testctl_signed() {   # testctl_signed FILE
    [ -r "$1" ] && [ -r "$1.sig" ] || return 1
    ssh-keygen -Y verify -f "$TESTCTL_ANCHOR" -I kryptik-testctl -n kryptik-testctl \
        -s "$1.sig" < "$1" > /dev/null 2>&1
}

# The file and its signature are copied once and the copy is what is verified
# and read: a disk that served other bytes on a later read changes nothing.
testctl_take() {   # testctl_take DIR
    TESTCTL_FILE=""
    _tc="$(mktemp -d "${TESTCTL_COPIES:-/run/kryptik}/testctl.XXXXXX")" || return 1
    if cp "$1/kryptik-test.conf" "$_tc/kryptik-test.conf" 2>/dev/null \
        && cp "$1/kryptik-test.conf.sig" "$_tc/kryptik-test.conf.sig" 2>/dev/null \
        && testctl_signed "$_tc/kryptik-test.conf"; then
        TESTCTL_FILE="$_tc/kryptik-test.conf"
        return 0
    fi
    rm -rf "$_tc"
    return 1
}

testctl_media() {
    grep -qs '^media=.\+' /run/kryptik/boot-identity 2>/dev/null && return 0
    grep -qE '(^| )kryptik\.media=[a-z]+( |$)' /proc/cmdline 2>/dev/null
}

testctl_load() {
    TESTCTL_FILE=""
    testctl_media || return 1
    dev="$(blkid -t PARTLABEL=kryptik-testctl -o device 2>/dev/null | head -1)"
    [ -n "$dev" ] && [ -b "$dev" ] || return 1
    mkdir -p "$TESTCTL_MNT"
    if ! mountpoint -q "$TESTCTL_MNT"; then
        mount -t vfat -o ro,nosuid,nodev,noexec "$dev" "$TESTCTL_MNT" 2>/dev/null || return 1
    fi
    [ -r "$TESTCTL_MNT/kryptik-test.conf" ] || return 1
    if ! testctl_take "$TESTCTL_MNT"; then
        echo "testctl: the control file on ${dev} is not signed by this medium's kryptik-testctl key; ignored"
        umount "$TESTCTL_MNT" 2>/dev/null
        return 1
    fi
    echo "testctl: control file read from ${dev} (install medium only)"
    return 0
}

testctl_get() {
    [ -n "$TESTCTL_FILE" ] || return 0
    sed -n "s/^$1=//p" "$TESTCTL_FILE" | head -1
}
