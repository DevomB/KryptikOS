#!/bin/sh
# Run the installer, but only on an install medium and only when a test
# control disk asks for it (see testctl.sh). A person installs by logging in
# on the medium's console and running kryptik-install; this is the unattended
# path the VM tests use, and it is a no-op on an installed system.
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
# Recovery of an installed disk from this medium (kryptik-recover), armed
# the same way as an install and reported on its own prefix.
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

# Preseed for the installed system's first boot: an account the test driver
# can log in as. Written by the installer into the new state partition and
# consumed once by kryptik-firstboot there.
preseed_args=""
pu="$(testctl_get preseed_user)"; ph="$(testctl_get preseed_password_hash)"
rh="$(testctl_get preseed_root_hash)"
if [ -n "$pu" ] && [ -n "$ph" ]; then
    umask 077
    printf 'user=%s\npassword_hash=%s\nroot_password_hash=%s\n' "$pu" "$ph" "$rh" > /run/kryptik/firstboot.preseed
    preseed_args="--preseed /run/kryptik/firstboot.preseed"
fi

# Capture the status of the INSTALLER, not of the thing prefixing its output:
# `... | sed` followed by rc=$? reads sed's status, which is how a missing
# partitioner was once reported as rc=0.
logf=/run/kryptik-install.log
# shellcheck disable=SC2086  # preseed_args is deliberately word-split
/usr/sbin/kryptik-install --target "$target" --yes $preseed_args > "$logf" 2>&1
rc=$?
sed 's/^/KRYPTIK_INSTALL: /' "$logf"
say "rc=${rc}"

if [ "$rc" -eq 0 ]; then
    # Say what is actually on the disk now, from outside the installer, so the
    # claim does not rest on the installer's own report. Every partition by
    # label, as the boot chain will look for them.
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
    if [ -n "$st" ] && mount -o ro "$st" /run/verify 2>/dev/null; then
        say "verify: state_marker=$([ -e /run/verify/.kryptik-state ] && echo yes || echo no)"
        say "verify: install_json=$([ -r /run/verify/lib/kryptik/install.json ] && echo yes || echo no)"
        say "verify: preseed=$([ -r /run/verify/lib/kryptik/firstboot.preseed ] && echo present || echo none)"
        umount /run/verify
    fi
    slot_a="$(blkid -t PARTLABEL=kryptik-a -o device 2>/dev/null | grep "^${target}" | head -1)"
    if [ -n "$slot_a" ]; then
        say "verify: slot_a_sha256=$(head -c "$(cat /etc/kryptik/root-image-bytes 2>/dev/null || echo 0)" "$slot_a" | sha256sum | cut -c1-64)"
        say "verify: image_sha256=$(sed -n 's/.*"root_image_sha256": *"\([0-9a-f]*\)".*/\1/p' /etc/kryptik-image.json 2>/dev/null)"
    fi
fi
say "END"
