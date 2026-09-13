#!/bin/sh
# A/B boot-success tracking (Design 08). Runs late in the default bundle, so
# reaching it means the slot we booted brought the system up.
#
# State: /var/lib/kryptik/boot/trial (the slot armed by kryptik-update, if
# any) and /var/lib/kryptik/boot/last-result (what happened at the last boot,
# for the report and for the updater's refusal to re-arm a failed payload).
set -u
say() { echo "boot-success: $*"; }
B=/var/lib/kryptik/boot
mkdir -p "$B"
slot="$(sed -n 's/^slot=//p' /run/kryptik/boot-identity 2>/dev/null)"
media="$(sed -n 's/^media=//p' /run/kryptik/boot-identity 2>/dev/null)"

if [ -n "$media" ]; then
    say "install medium; no slot to track"
    exit 0
fi
if [ -z "$slot" ]; then
    say "no kryptik.slot= on the command line; nothing to track"
    echo "unknown-slot $(date -Iseconds 2>/dev/null)" > "$B/last-result"
    exit 0
fi

trial="$(cat "$B/trial" 2>/dev/null || true)"
esp="$(blkid -t PARTLABEL=kryptik-esp -o device 2>/dev/null | head -1)"

commit_slot() {   # commit_slot <slot>: make BOOTX64.EFI this slot's kernel
    [ -n "$esp" ] || { say "no ESP found by label; cannot commit"; return 1; }
    mkdir -p /run/kryptik/esp
    mount -o rw,nosuid,nodev,noexec "$esp" /run/kryptik/esp || { say "cannot mount ESP"; return 1; }
    src="/run/kryptik/esp/EFI/kryptik/kryptik-$1.efi"
    dst="/run/kryptik/esp/EFI/BOOT/BOOTX64.EFI"
    rc=1
    if [ -f "$src" ]; then
        if cmp -s "$src" "$dst"; then
            say "BOOTX64.EFI already is slot $1"; rc=0
        else
            # Complete copy, fsync, then one rename: the only non-atomic step
            # on FAT is the rename, and BOOTX64.EFI is replaced only after
            # this slot has demonstrably booted.
            cp "$src" "$dst.new" && sync -f "$dst.new" && mv -f "$dst.new" "$dst" && sync -f "$dst" && rc=0
            [ "$rc" -eq 0 ] && say "committed: BOOTX64.EFI is now slot $1"
        fi
        cp "/run/kryptik/esp/kryptik/version-$1" "/run/kryptik/esp/kryptik/version-committed" 2>/dev/null || true
        printf '%s\n' "$1" > "/run/kryptik/esp/kryptik/committed-slot.new" && \
            mv -f "/run/kryptik/esp/kryptik/committed-slot.new" "/run/kryptik/esp/kryptik/committed-slot"
    else
        say "no kernel for slot $1 on the ESP"
    fi
    sync
    umount /run/kryptik/esp
    return "$rc"
}

if [ -n "$trial" ]; then
    if [ "$trial" = "$slot" ]; then
        say "trial slot $slot booted successfully; committing"
        if commit_slot "$slot"; then
            rm -f "$B/trial"
            echo "commit $slot $(date -Iseconds 2>/dev/null)" > "$B/last-result"
            kryptik-efiboot clear-next >/dev/null 2>&1 || true
        else
            echo "commit-failed $slot $(date -Iseconds 2>/dev/null)" > "$B/last-result"
        fi
    else
        # The firmware consumed BootNext and we are back on the old slot: the
        # trial did not come up. Record it; the updater will not re-arm the
        # same payload without --retry.
        say "trial slot $trial did NOT boot; running slot $slot again"
        echo "trial-failed $trial $(date -Iseconds 2>/dev/null)" > "$B/last-result"
        mv -f "$B/trial" "$B/trial.failed"
    fi
else
    echo "ok $slot $(date -Iseconds 2>/dev/null)" > "$B/last-result"
    say "slot $slot up, no trial pending"
fi
# Record the running slot for tools that need it without parsing cmdline.
printf '%s\n' "$slot" > "$B/running-slot"
exit 0
