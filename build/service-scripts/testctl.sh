#!/bin/sh
# Test control, for install media ONLY. Sourced by the boot-time services.
#
# The kernel command line is compiled into the signed kernel, so
# a test can no longer arm itself with kryptik.smoke=1 or kryptik.install=.
# Instead a disposable disk labelled kryptik-testctl carries a plain
# key=value file, and it is honoured only when this system booted from an
# install medium (kryptik.media= on the command line): an installed system
# ignores such a disk entirely, so attaching one to a real machine can
# neither reinstall it nor shut it down. Test drivers reach an installed
# system through its serial login instead.
#
#   testctl_load            -> 0 and TESTCTL_* set when a control file was read
#   testctl_get KEY         -> the value, or empty
#
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
