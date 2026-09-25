#!/bin/sh
# A/B boot-success tracking (docs/design/boot-and-updates.md): decides, late in
# boot, whether the slot that booted is one to keep.
# /var/lib/kryptik/boot/trial holds the slot kryptik-update armed, then armed=0
# (before BootNext was set) or armed=1; last-result holds the last boot's
# outcome, which also stops the updater re-arming a failed payload.
# A trial slot that passes health() is committed (its kernel becomes
# BOOTX64.EFI). One that fails reboots, and with BootNext spent that lands on
# the committed slot. A committed slot is only reported on, never rebooted.
# The paths are overridable for tools/test-boot-success.sh only.
set -u
say() { echo "boot-success: $*"; }
RUN="${KRYPTIK_RUN:-/run/kryptik}"
B="${KRYPTIK_BOOT_STATE:-/var/lib/kryptik/boot}"
SVC="${KRYPTIK_SERVICE_DIR:-/run/service}"
ZONES="${KRYPTIK_ZONES:-/usr/lib/kryptik/zones}"
ESP_MNT="${RUN}/esp"
# shellcheck source=/dev/null
. "${KRYPTIK_DEVICES:-/usr/libexec/kryptik/devices.sh}"
mkdir -p "$B"

ident() { sed -n "s/^$1=//p" "$RUN/boot-identity" 2>/dev/null | head -1; }
slot="$(ident slot)"; media="$(ident media)"; state="$(ident state)"
now() { date -Iseconds 2>/dev/null || date; }
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

trial=""; armed=""
if [ -r "$B/trial" ]; then
    trial="$(sed -n '1p' "$B/trial")"
    armed="$(sed -n 's/^armed=//p' "$B/trial" | head -1)"
    [ -n "$armed" ] || armed=1   # a record from before the armed= line: assume it was
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
    mount -o rw,nosuid,nodev,noexec "$esp" "$ESP_MNT" || { say "cannot mount ESP $esp"; return 1; }
    src="$ESP_MNT/EFI/kryptik/kryptik-$1.efi"
    dst="$ESP_MNT/EFI/BOOT/BOOTX64.EFI"
    rc=1
    if [ -f "$src" ]; then
        if cmp -s "$src" "$dst"; then
            say "BOOTX64.EFI already is slot $1"; rc=0
        else
            # Copy, fsync, then rename: on FAT only the rename is not atomic.
            cp "$src" "$dst.new" && sync -f "$dst.new" && mv -f "$dst.new" "$dst" && sync -f "$dst" && rc=0
            [ "$rc" -eq 0 ] && say "committed: BOOTX64.EFI is now slot $1"
        fi
        cp "$ESP_MNT/kryptik/version-$1" "$ESP_MNT/kryptik/version-committed" 2>/dev/null || true
        printf '%s\n' "$1" > "$ESP_MNT/kryptik/committed-slot.new" && \
            mv -f "$ESP_MNT/kryptik/committed-slot.new" "$ESP_MNT/kryptik/committed-slot"
    else
        say "no kernel for slot $1 on the ESP"
    fi
    sync
    umount "$ESP_MNT"
    return "$rc"
}

# However a trial ends, remove BootNext and both slots' entries, so the
# firmware boots the disk's own entry (BOOTX64.EFI, the committed slot). A
# firmware re-adds that entry at the end of BootOrder when devices change, so a
# leftover Kryptik entry would win every cold boot.
forget_entries() {
    kryptik-efiboot forget >/dev/null 2>&1 && return 0
    say "the firmware's Kryptik entries could not be removed; its own boot order may not name the committed slot"
    return 1
}

# On a degraded state the trial record is unreadable; the ESP still names the
# committed slot, and any other slot is on trial.
esp_committed() {
    e="$(kryptik_part kryptik-esp 2>/dev/null)" && [ -n "$e" ] || return 0
    mkdir -p "$ESP_MNT"
    mount -o ro,nosuid,nodev,noexec "$e" "$ESP_MNT" 2>/dev/null || return 0
    sed -n 1p "$ESP_MNT/kryptik/committed-slot" 2>/dev/null
    umount "$ESP_MNT"
}
unrecorded=""
if [ -z "$trial" ] && [ "$state" != persistent ]; then
    c="$(esp_committed)"
    if [ -n "$c" ] && [ "$c" != "$slot" ]; then trial="$slot"; unrecorded=1; fi
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
                forget_entries
                say "slot $slot is healthy and committed"
            else
                result "commit-failed $slot"
                say "slot $slot is healthy but the commit failed; the committed slot is unchanged"
            fi
        else
            say "trial slot $slot came up UNHEALTHY:"
            printf '%s\n' "$failures" | sed 's/^/boot-success:   - /'
            printf 'trial-unhealthy %s: %s\n' "$slot" "$(printf '%s' "$failures" | tr '\n' ';')" > "$B/last-result.new" \
                && mv -f "$B/last-result.new" "$B/last-result"
            [ ! -f "$B/trial" ] || mv -f "$B/trial" "$B/trial.failed"
            sync
            if ! forget_entries && [ -n "$unrecorded" ]; then
                # With no record of this trial, only removing its entries
                # stops the next boot from repeating it.
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
            # BootNext is spent and the old slot is running: the trial did not
            # come up. The updater will not re-arm this payload without --retry.
            say "trial slot $trial did NOT boot; running slot $slot again"
            result "trial-failed $trial"
            mv -f "$B/trial" "$B/trial.failed"
            forget_entries
        else
            # The updater stopped before setting BootNext: nothing was tried.
            say "the arming of slot $trial was interrupted before BootNext was set; nothing was tried"
            result "arming-interrupted $trial"
            rm -f "$B/trial"
            forget_entries
        fi
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
