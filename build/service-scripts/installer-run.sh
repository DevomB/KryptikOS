#!/bin/sh
# Unattended install (or recovery) for the VM tests: only on an install medium
# whose test control disk asks for it (testctl.sh). Users run kryptik-install.
set -u
. /usr/libexec/kryptik/testctl.sh

say() { echo "KRYPTIK_INSTALL: $*"; }

if ! testctl_media; then
    echo "installer: not an install medium; nothing to do"
    exit 0
fi
if ! testctl_load; then
    echo "installer: no kryptik-testctl control disk; nothing to do (run kryptik-install by hand)"
    exit 0
fi
# Recovery of an installed disk (kryptik-recover), armed the same way.
rdisk="$(testctl_get recover_disk)"
if [ -n "$rdisk" ]; then
    rslot="$(testctl_get recover_slot)"; rmode="$(testctl_get recover_mode)"
    echo
    echo "KRYPTIK_RECOVER: BEGIN disk=${rdisk} slot=${rslot} mode=${rmode}"
    logr=/run/kryptik-recover.log
    case "$rmode" in
        restore) /usr/sbin/kryptik-recover --disk "$rdisk" --restore-slot "$rslot" > "$logr" 2>&1 ;;
        commit)  /usr/sbin/kryptik-recover --disk "$rdisk" --commit-slot "$rslot" > "$logr" 2>&1 ;;
        *)       /usr/sbin/kryptik-recover --disk "$rdisk" --status > "$logr" 2>&1 ;;
    esac
    rrc=$?
    sed 's/^/KRYPTIK_RECOVER: /' "$logr"
    echo "KRYPTIK_RECOVER: rc=${rrc}"
    echo "KRYPTIK_RECOVER: END"
fi

target="$(testctl_get install_target)"
if [ -z "$target" ]; then
    echo "installer: control disk names no install_target; nothing to do"
    exit 0
fi

echo
say "BEGIN target=${target}"

if [ ! -x /usr/sbin/kryptik-install ]; then
    say "FAILED no /usr/sbin/kryptik-install in this image"
    say "rc=127"
    say "END"
    exit 0
fi

# An account for the test driver: the installer writes it to the new state
# partition, for kryptik-firstboot to consume once.
preseed_args=""
pu="$(testctl_get preseed_user)"; ph="$(testctl_get preseed_password_hash)"
rh="$(testctl_get preseed_root_hash)"
if [ -n "$pu" ] && [ -n "$ph" ]; then
    umask 077
    printf 'user=%s\npassword_hash=%s\nroot_password_hash=%s\n' "$pu" "$ph" "$rh" > /run/kryptik/firstboot.preseed
    preseed_args="--preseed /run/kryptik/firstboot.preseed"
fi

# No pipe into sed: rc must be the installer's status, not sed's.
logf=/run/kryptik-install.log
# The state passphrase goes in on stdin (printf is a builtin: no argv).
sp="$(testctl_get state_passphrase)"
# shellcheck disable=SC2086  # preseed_args is deliberately word-split
printf '%s\n' "$sp" | /usr/sbin/kryptik-install --target "$target" --yes $preseed_args > "$logf" 2>&1
rc=$?
sed 's/^/KRYPTIK_INSTALL: /' "$logf"
say "rc=${rc}"

if [ "$rc" -eq 0 ]; then
    # Check the disk independently of the installer's report, finding each
    # partition by label as the boot chain will.
    say "verify: table=$(sfdisk -l "$target" 2>/dev/null | grep -c "^${target}")"
    for lbl in kryptik-esp kryptik-a kryptik-b kryptik-state; do
        dev="$(blkid -t PARTLABEL="$lbl" -o device 2>/dev/null | grep "^${target}" | head -1)"
        say "verify: ${lbl}=${dev:-ABSENT} type=$(blkid -s TYPE -o value "$dev" 2>/dev/null || echo none)"
    done
    esp="$(blkid -t PARTLABEL=kryptik-esp -o device 2>/dev/null | grep "^${target}" | head -1)"
    mkdir -p /run/verify
    if [ -n "$esp" ] && mount -o ro "$esp" /run/verify 2>/dev/null; then
        say "verify: esp_files=$(cd /run/verify && find . -type f | sort | tr '\n' ' ')"
        say "verify: bootx64_sha256=$(sha256sum /run/verify/EFI/BOOT/BOOTX64.EFI 2>/dev/null | cut -c1-64)"
        say "verify: version_a=$(cat /run/verify/kryptik/version-a 2>/dev/null || echo none)"
        umount /run/verify
    else
        say "verify: could not mount the ESP read-only"
    fi
    st="$(blkid -t PARTLABEL=kryptik-state -o device 2>/dev/null | grep "^${target}" | head -1)"
    if [ -n "$st" ] && printf '%s' "$sp" | cryptsetup open --readonly --type luks2 --key-file=- "$st" kryptik-verify-state 2>/dev/null \
            && mount -o ro /dev/mapper/kryptik-verify-state /run/verify 2>/dev/null; then
        say "verify: state_marker=$([ -e /run/verify/.kryptik-state ] && echo yes || echo no)"
        say "verify: install_json=$([ -r /run/verify/lib/kryptik/install.json ] && echo yes || echo no)"
        say "verify: preseed=$([ -r /run/verify/lib/kryptik/firstboot.preseed ] && echo present || echo none)"
        umount /run/verify
    fi
    cryptsetup close kryptik-verify-state 2>/dev/null || true
    slot_a="$(blkid -t PARTLABEL=kryptik-a -o device 2>/dev/null | grep "^${target}" | head -1)"
    if [ -n "$slot_a" ]; then
        say "verify: slot_a_sha256=$(head -c "$(cat /etc/kryptik/root-image-bytes 2>/dev/null || echo 0)" "$slot_a" | sha256sum | cut -c1-64)"
        say "verify: image_sha256=$(sed -n 's/.*"root_image_sha256": *"\([0-9a-f]*\)".*/\1/p' /etc/kryptik-image.json 2>/dev/null)"
    fi
fi
say "END"
