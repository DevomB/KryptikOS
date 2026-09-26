#!/bin/sh
# Test control for install media, sourced by boot-time services. A disk
# labelled kryptik-testctl carries a key=value file, read only when booted from
# an install medium (kryptik.media=), so such a disk cannot reinstall or shut
# down an installed system.
#   testctl_load      0, with TESTCTL_FILE set, when a control file was read
#   testctl_get KEY   the value, or empty
# Keys: install_target=/dev/vdb   smoke_poweroff=1   preseed_user=NAME
#       preseed_password_hash=HASH  preseed_root_hash=HASH  install_wait=SECONDS
#       recover_disk=/dev/vda recover_slot=a|b recover_mode=restore|commit|status

TESTCTL_MNT=/run/kryptik/testctl
TESTCTL_FILE=""

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
    TESTCTL_FILE="$TESTCTL_MNT/kryptik-test.conf"
    echo "testctl: control file read from ${dev} (install medium only)"
    return 0
}

testctl_get() {
    [ -n "$TESTCTL_FILE" ] || return 0
    sed -n "s/^$1=//p" "$TESTCTL_FILE" | head -1
}
