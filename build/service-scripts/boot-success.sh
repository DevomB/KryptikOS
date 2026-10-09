#!/bin/sh
# A/B boot success (docs/design/boot-and-updates.md): commit a healthy trial, reboot a failed one.
# A committed slot is only reported on, never rebooted; a slot booted from outside is rebooted from once.
set -u
say() { echo "boot-success: $*"; }
# The overrides are for tools/tests/boot-success.sh only.
RUN="${KRYPTIK_RUN:-/run/kryptik}"
B="${KRYPTIK_BOOT_STATE:-/var/lib/kryptik/boot}"
SVC="${KRYPTIK_SERVICE_DIR:-/run/service}"
ZONES="${KRYPTIK_ZONES:-/usr/lib/kryptik/zones}"
ESP_MNT="${RUN}/esp"
# shellcheck source=/dev/null
. "${KRYPTIK_DEVICES:-/usr/libexec/kryptik/devices.sh}"
mkdir -p "$B"

ident() { sed -n "s/^$1=//p" "$RUN/boot-identity" 2>/dev/null | head -1; }
other_slot() { case "$1" in a) echo b ;; b) echo a ;; esac; }
slot="$(ident slot)"; media="$(ident media)"; state="$(ident state)"
now() { date -Iseconds 2>/dev/null || date; }
# Drop FILE's clean pages, so the next read is what the device holds; best effort.
uncache() { dd if="$1" iflag=nocache count=0 status=none 2>/dev/null || :; }   # uncache FILE
result() { printf '%s %s\n' "$*" "$(now)" > "$B/last-result.new" && mv -f "$B/last-result.new" "$B/last-result"; }

if [ -n "$media" ]; then
    say "install medium; no slot to track"
    exit 0
fi
if [ -z "$slot" ]; then
    say "no kryptik.slot= on the command line; nothing to track"
    result "unknown-slot"
    exit 0
fi

# trial: the slot kryptik-update armed, then armed=0 (before BootNext was set) or armed=1.
trial=""; armed=""
if [ -r "$B/trial" ]; then
    trial="$(sed -n '1p' "$B/trial")"
    armed="$(sed -n 's/^armed=//p' "$B/trial" | head -1)"
    [ -n "$armed" ] || armed=1   # an older record has no armed= line: assume armed
fi

# --- the essential-readiness check ------------------------------------------
svc_up() {   # svc_up NAME [SECONDS]: supervised and up, waiting a little
    n="${2:-20}"
    while [ "$n" -gt 0 ]; do
        if [ "$(s6-svstat -o up "$SVC/$1" 2>/dev/null)" = "true" ]; then return 0; fi
        n=$((n - 1)); sleep 1
    done
    return 1
}
health() {   # prints one failure per line; nothing when healthy
    [ "$state" = "persistent" ] || echo "state is ${state:-unknown}$( [ -r "$RUN/state-degraded" ] && printf ' (%s)' "$(cat "$RUN/state-degraded")" )"
    for s in eudev seatd kryptikd-serve net-zone getty-tty1; do
        svc_up "$s" || echo "service $s is not up"
    done
    kryptikd check --zones "$ZONES" >/dev/null 2>&1 || echo "kryptikd check: no kernel support for zones"
    kryptikd list --zones "$ZONES" >/dev/null 2>&1 || echo "kryptikd cannot read the zone definitions in $ZONES"
    esp="$(kryptik_part kryptik-esp 2>/dev/null)"
    if [ -z "$esp" ]; then
        echo "no unambiguous kryptik-esp on this installation's disk ($(kryptik_part_count kryptik-esp 2>/dev/null || echo ?) found)"
    fi
}

# --- the commit ---------------------------------------------------------------
commit_slot() {   # commit_slot <slot>: make BOOTX64.EFI this slot's kernel
    esp="$(kryptik_part kryptik-esp 2>/dev/null)"
    [ -n "$esp" ] || { say "no unambiguous ESP on this installation's disk; cannot commit"; return 1; }
    mkdir -p "$ESP_MNT"
    mount -t vfat -o rw,nosuid,nodev,noexec "$esp" "$ESP_MNT" || { say "cannot mount ESP $esp"; return 1; }
    src="$ESP_MNT/EFI/kryptik/kryptik-$1.efi"
    dst="$ESP_MNT/EFI/BOOT/BOOTX64.EFI"
    rc=1
    if [ -f "$src" ]; then
        if cmp -s "$src" "$dst"; then
            say "BOOTX64.EFI already is slot $1"; rc=0
        else
            # Copy, fsync, compare as the device holds it, then rename: on FAT only the
            # rename is not atomic, and a copy that landed wrong never becomes the boot file.
            cp "$src" "$dst.new" && sync -f "$dst.new" && uncache "$dst.new" && cmp -s "$src" "$dst.new" && mv -f "$dst.new" "$dst" && sync -f "$dst" && rc=0
            [ "$rc" -eq 0 ] && say "committed: BOOTX64.EFI is now slot $1"
        fi
        # The record is part of the commit, and follows the boot file: kryptik-update
        # applies only from the slot it names, so it must not name one that does not boot.
        if [ "$rc" -eq 0 ]; then
            { printf '%s\n' "$1" > "$ESP_MNT/kryptik/committed-slot.new" && sync -f "$ESP_MNT/kryptik/committed-slot.new" && \
                mv -f "$ESP_MNT/kryptik/committed-slot.new" "$ESP_MNT/kryptik/committed-slot"; } \
                || { say "the committed-slot record could not be written; the trial stays, and the next boot commits again"; rc=1; }
        fi
    else
        say "no kernel for slot $1 on the ESP"
    fi
    sync
    umount "$ESP_MNT"
    return "$rc"
}

# However a trial ends: a stale slot entry would outrank BOOTX64.EFI at every cold boot,
# and the committed slot's own entry is a second way to it should that file be lost.
forget_entries() {   # forget_entries COMMITTED-SLOT
    if ! kryptik-efiboot forget >/dev/null 2>&1; then
        say "the firmware's Kryptik entries could not be removed; its own boot order may not name the committed slot"
        return 1
    fi
    kryptik-efiboot ensure "$1" >/dev/null 2>&1 \
        || say "slot $1 has no firmware entry of its own; BOOTX64.EFI is the only way to it"
    return 0
}

# The committed slot as the ESP names it, read whenever no trial is on record.
esp_committed() {
    e="$(kryptik_part kryptik-esp 2>/dev/null)" && [ -n "$e" ] || return 0
    mkdir -p "$ESP_MNT"
    mount -t vfat -o ro,nosuid,nodev,noexec "$e" "$ESP_MNT" 2>/dev/null || return 0
    sed -n 1p "$ESP_MNT/kryptik/committed-slot" 2>/dev/null
    umount "$ESP_MNT"
}
# With no trial on record, the slot that runs should be the committed one. On a
# degraded state the record is out of reach, so another slot is a trial. With
# the record readable, nothing of Kryptik's asked for this slot: the earlier
# release stays bootable for rollback, and a firmware entry or BootNext set
# from outside boots it.
unrecorded=""; stray=""
if [ -z "$trial" ]; then
    c="$(esp_committed)"
    case "$c" in a|b) ;; *) c="" ;; esac
    if [ "$c" = "$slot" ]; then
        rm -f "$B/uncommitted"
    elif [ -n "$c" ]; then
        if [ "$state" = persistent ]; then stray="$c"; else trial="$slot"; unrecorded=1; fi
    fi
fi

# --- the decision -------------------------------------------------------------
if [ -n "$trial" ]; then
    if [ "$trial" = "$slot" ]; then
        say "trial slot $slot is running; checking that the system is usable before committing"
        failures="$(health)"
        if [ -z "$failures" ]; then
            if commit_slot "$slot"; then
                rm -f "$B/trial"
                result "commit $slot"
                forget_entries "$slot"
                say "slot $slot is healthy and committed"
                # Its release's signed date becomes the clock's floor if it is the newest (docs/design/time.md).
                say "$(kryptikd time committed "$B/release-$slot" 2>&1)"
            else
                result "commit-failed $slot"
                say "slot $slot is healthy but the commit failed; the trial stays for the next boot"
            fi
        else
            say "trial slot $slot came up UNHEALTHY:"
            printf '%s\n' "$failures" | sed 's/^/boot-success:   - /'
            printf 'trial-unhealthy %s: %s\n' "$slot" "$(printf '%s' "$failures" | tr '\n' ';')" > "$B/last-result.new" \
                && mv -f "$B/last-result.new" "$B/last-result"
            [ ! -f "$B/trial" ] || mv -f "$B/trial" "$B/trial.failed"
            sync
            if ! forget_entries "$(other_slot "$slot")" && [ -n "$unrecorded" ]; then
                # No trial record: only removing its entries stops the next boot repeating it.
                say "not rebooting: with its entries still there the firmware could boot this trial again"
            elif [ "${KRYPTIK_NO_REBOOT:-0}" = 1 ]; then
                say "not rebooting (KRYPTIK_NO_REBOOT=1)"
            else
                say "BootNext was consumed by this boot; rebooting to the committed slot in 5 s"
                { echo "boot-success: trial slot $slot is not usable; rebooting to the committed slot"; } > /dev/console 2>&1 || true
                sleep 5
                reboot
            fi
        fi
    else
        if [ "$armed" = 1 ]; then
            # trial.failed stops kryptik-update re-arming this payload without --retry.
            say "trial slot $trial did NOT boot; running slot $slot again"
            result "trial-failed $trial"
            mv -f "$B/trial" "$B/trial.failed"
            forget_entries "$slot"
        else
            say "the arming of slot $trial was interrupted before BootNext was set; nothing was tried"
            result "arming-interrupted $trial"
            rm -f "$B/trial"
            forget_entries "$slot"
        fi
    fi
elif [ -n "$stray" ]; then
    say "slot $slot is running, slot $stray is the committed one and no trial was armed: the firmware was told to boot this slot"
    result "uncommitted $slot"
    # Once: an entry that is not Kryptik's own outlives the forgetting, and
    # the machine must stay up to be put right.
    if forget_entries "$stray" && [ ! -e "$B/uncommitted" ] && [ "${KRYPTIK_NO_REBOOT:-0}" != 1 ]; then
        : > "$B/uncommitted"; sync
        say "rebooting to the committed slot in 5 s"
        { echo "boot-success: slot $slot is not the committed one; rebooting to slot $stray"; } > /dev/console 2>&1 || true
        sleep 5
        reboot
    fi
else
    failures="$(health)"
    if [ -z "$failures" ]; then
        result "ok $slot"
        say "slot $slot up, no trial pending"
    else
        printf 'unhealthy %s: %s\n' "$slot" "$(printf '%s' "$failures" | tr '\n' ';')" > "$B/last-result.new" \
            && mv -f "$B/last-result.new" "$B/last-result"
        say "slot $slot is up but not fully usable (no trial pending; nothing to fall back to):"
        printf '%s\n' "$failures" | sed 's/^/boot-success:   - /'
    fi
fi
# Record the running slot for tools that need it without parsing cmdline.
printf '%s\n' "$slot" > "$B/running-slot"
exit 0
