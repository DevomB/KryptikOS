#!/bin/sh
# A/B boot-success tracking (docs/design/boot-and-updates.md). Runs late in the default bundle,
# after the services a usable system needs, and decides whether the slot
# that booted is one to keep.
#
# State: /var/lib/kryptik/boot/trial (the slot armed by kryptik-update:
# line 1 the slot, line 2 armed=0 before BootNext was set and armed=1
# after) and /var/lib/kryptik/boot/last-result (what happened at the last
# boot, for the report and for the updater's refusal to re-arm a failed
# payload).
#
# WHAT "SUCCESS" MEANS HERE
#
# Reaching this script proves that sysinit and a few oneshots ran. That is
# not a usable system. A trial slot is committed - its kernel copied over
# BOOTX64.EFI, so the machine boots it from now on - only when the essential
# services are up: the persistent state is mounted (not degraded), eudev,
# seatd, the launch daemon, the net zone and the login getty are supervised
# and up, kryptikd finds kernel support and reads the shipped zones, and the
# ESP this installation boots from is unambiguous and carries the slot's
# kernel. A trial that boots but fails any of these is recorded as unhealthy
# and the machine reboots: the firmware consumed BootNext on the way in, so
# that reboot lands on the committed slot, which is the bounded fallback.
# Only a trial boot ever reboots from here; a committed slot that is
# unhealthy is reported and left running for whoever can log in.
#
# The paths are overridable for tools/test-boot-success.sh, which drives
# every decision here on a host with stand-ins; nothing else sets them.
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
            # Complete copy, fsync, then one rename: the only non-atomic step
            # on FAT is the rename, and BOOTX64.EFI is replaced only after
            # this slot has demonstrably booted and passed the checks above.
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

# --- the decision -------------------------------------------------------------
if [ -n "$trial" ]; then
    if [ "$trial" = "$slot" ]; then
        say "trial slot $slot is running; checking that the system is usable before committing"
        failures="$(health)"
        if [ -z "$failures" ]; then
            if commit_slot "$slot"; then
                rm -f "$B/trial"
                result "commit $slot"
                kryptik-efiboot clear-next >/dev/null 2>&1 || true
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
            mv -f "$B/trial" "$B/trial.failed"
            sync
            if [ "${KRYPTIK_NO_REBOOT:-0}" = 1 ]; then
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
            # The firmware consumed BootNext and we are back on the old slot:
            # the trial did not come up. Record it; the updater will not re-arm
            # the same payload without --retry.
            say "trial slot $trial did NOT boot; running slot $slot again"
            result "trial-failed $trial"
            mv -f "$B/trial" "$B/trial.failed"
        else
            # The record was written but BootNext never was: the updater was
            # interrupted between the two. Nothing was tried, so nothing failed.
            say "the arming of slot $trial was interrupted before BootNext was set; nothing was tried"
            result "arming-interrupted $trial"
            rm -f "$B/trial"
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
