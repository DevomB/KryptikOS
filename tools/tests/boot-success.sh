#!/usr/bin/env bash
# boot-success.sh's decision table, against a fake /run/kryptik, service directory and ESP, and
# fake s6-svstat, kryptikd, kryptik-efiboot, reboot and mount that record what they were asked.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/build/service-scripts/boot-success.sh"
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/run" "$T/boot" "$T/svc"
# --- stand-ins ---------------------------------------------------------------
# The script sources devices.sh; this one answers from the case's files.
cat > "$T/devices.sh" <<'EOF'
kryptik_root_disk() { cat "$KTEST/root_disk" 2>/dev/null; }
kryptik_part() { p="$(cat "$KTEST/part_$1" 2>/dev/null)"; [ -n "$p" ] && { echo "$p"; return 0; }; echo ""; return 1; }
kryptik_part_count() { cat "$KTEST/count_$1" 2>/dev/null || echo 0; }
kryptik_others() { :; }
EOF
cat > "$T/bin/s6-svstat" <<'EOF'
#!/bin/sh
# s6-svstat -o up DIR -> "true" if the service is marked up in the case
n="$(basename "$3")"
[ -e "$KTEST/svc/$n.up" ] && echo true || echo false
EOF
cat > "$T/bin/kryptikd" <<'EOF'
#!/bin/sh
case "$1" in
    check) [ -e "$KTEST/kernel_ok" ] ;;
    list)  [ -e "$KTEST/zones_ok" ] ;;
    time)  echo "kryptikd $*" >> "$KTEST/calls" ;;
    *) exit 2 ;;
esac
EOF
cat > "$T/bin/kryptik-efiboot" <<'EOF'
#!/bin/sh
echo "efiboot $*" >> "$KTEST/calls"
[ ! -e "$KTEST/efiboot_fails" ] && [ ! -e "$KTEST/efiboot_fails_$1" ]
EOF
cat > "$T/bin/reboot" <<'EOF'
#!/bin/sh
echo "reboot" >> "$KTEST/calls"
EOF
cat > "$T/bin/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
# mount/umount: the ESP is a directory the case prepares
cat > "$T/bin/mount" <<'EOF'
#!/bin/sh
echo "mount $*" >> "$KTEST/calls"
# last argument is the mount point: populate it from the fake ESP
mp="$(eval echo \${$#})"
mkdir -p "$mp"
cp -a "$KTEST/esp/." "$mp/" 2>/dev/null
exit 0
EOF
cat > "$T/bin/umount" <<'EOF'
#!/bin/sh
# copy the mount point back so the case can inspect what was written
cp -a "$1/." "$KTEST/esp/" 2>/dev/null
echo "umount $1" >> "$KTEST/calls"
EOF
cat > "$T/bin/sync" <<'EOF'
#!/bin/sh
echo "sync $*" >> "$KTEST/syncs"
EOF
chmod +x "$T"/bin/*

run_case() {   # run_case NAME SLOT MEDIA STATE TRIAL-CONTENT SERVICES...: stage a case
    local name="$1" slot="$2" media="$3" state="$4" trial="$5"; shift 5
    export KTEST="$T/case-$name"; rm -rf "$KTEST"; mkdir -p "$KTEST/svc" "$KTEST/run" "$KTEST/boot" "$KTEST/esp/EFI/BOOT" "$KTEST/esp/EFI/kryptik" "$KTEST/esp/kryptik"
    printf 'slot=%s\nmedia=%s\nstate=%s\n' "$slot" "$media" "$state" > "$KTEST/run/boot-identity"
    [[ "$state" == degraded ]] && echo "no kryptik-state on /dev/vda" > "$KTEST/run/state-degraded"
    [[ -n "$trial" ]] && printf '%b' "$trial" > "$KTEST/boot/trial"
    for s in "$@"; do : > "$KTEST/svc/$s.up"; done
    : > "$KTEST/kernel_ok"; : > "$KTEST/zones_ok"
    echo /dev/vda > "$KTEST/root_disk"; echo /dev/vda1 > "$KTEST/part_kryptik-esp"; echo 1 > "$KTEST/count_kryptik-esp"
    printf 'kernel-a' > "$KTEST/esp/EFI/kryptik/kryptik-a.efi"; printf 'kernel-b' > "$KTEST/esp/EFI/kryptik/kryptik-b.efi"
    printf 'kernel-a' > "$KTEST/esp/EFI/BOOT/BOOTX64.EFI"; printf 'a\n' > "$KTEST/esp/kryptik/committed-slot"
    printf '1.0\n' > "$KTEST/esp/kryptik/version-a"; printf '2.0\n' > "$KTEST/esp/kryptik/version-b"
}
go() {   # go: run the script on the current case; RESULT and CALLS are what it wrote
    _="$(PATH="$T/bin:$PATH" KRYPTIK_RUN="$KTEST/run" KRYPTIK_BOOT_STATE="$KTEST/boot" KRYPTIK_SERVICE_DIR="$KTEST/svc" \
           KRYPTIK_ZONES="$KTEST/zones" KRYPTIK_DEVICES="$T/devices.sh" sh "$SCRIPT" 2>&1)"
    RESULT="$(cut -d' ' -f1-2 "$KTEST/boot/last-result" 2>/dev/null | sed 's/ *$//')"
    CALLS="$(cat "$KTEST/calls" 2>/dev/null | tr '\n' ' ')"
}
reboots() { cat "$KTEST/calls" 2>/dev/null | grep -c reboot; }
ALL="eudev seatd kryptikd-serve net-zone getty-tty1"

echo "-- no trial"
run_case ok a "" persistent "" $ALL; go
check "healthy committed slot: ok" "$RESULT" "ok a"
check "a plain boot reads the committed slot off the ESP and does nothing more" "$CALLS" "mount -t vfat -o ro,nosuid,nodev,noexec /dev/vda1 $KTEST/run/esp umount $KTEST/run/esp "
run_case media "" usb tmpfs "" $ALL; go
check "install medium: nothing tracked" "$(cat "$KTEST/boot/last-result" 2>/dev/null)" ""
run_case unhealthy a "" persistent "" eudev seatd; go
check "committed slot with services down: reported unhealthy, left running" "${RESULT%%:*}" "unhealthy a"
check "no reboot for a committed slot" "$(reboots)" "0"

echo "-- a slot nothing asked for"
# The ESP names slot a as committed (run_case), no trial is on record, and
# slot b runs: a firmware entry or BootNext set from outside booted it.
run_case stray b "" persistent "" $ALL; go
check "the earlier slot booted from outside is reported as uncommitted, not as ok" "$RESULT" "uncommitted b"
check "its entries are forgotten, the committed slot gets its own, and the machine reboots" "$CALLS" "mount -t vfat -o ro,nosuid,nodev,noexec /dev/vda1 $KTEST/run/esp umount $KTEST/run/esp efiboot forget efiboot ensure a reboot "
check "BOOTX64.EFI and the committed slot are left as they were" "$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")|$(cat "$KTEST/esp/kryptik/committed-slot")" "kernel-a|a"
check "the reboot is on record" "$([[ -e "$KTEST/boot/uncommitted" ]] && echo marked || echo unmarked)" "marked"
run_case stray2 b "" persistent "" $ALL; : > "$KTEST/boot/uncommitted"; go
check "booted there again after that reboot: reported, and left running to be put right" "$RESULT|$(reboots)" "uncommitted b|0"
run_case stray3 b "" persistent "" $ALL; : > "$KTEST/efiboot_fails"; go
check "no reboot while the firmware's entries could not be removed" "$RESULT|$(reboots)" "uncommitted b|0"
run_case stray4 a "" persistent "" $ALL; : > "$KTEST/boot/uncommitted"; go
check "a boot of the committed slot clears the record, so the next such boot is rebooted from again" "$RESULT|$([[ -e "$KTEST/boot/uncommitted" ]] && echo marked || echo unmarked)" "ok a|unmarked"
run_case stray5 b "" persistent "" $ALL; rm -f "$KTEST/esp/kryptik/committed-slot"; go
check "an ESP that names no committed slot accuses nobody" "$RESULT" "ok b"
run_case stray6 b "" persistent "" $ALL; printf 'b; reboot\n' > "$KTEST/esp/kryptik/committed-slot"; go
check "nor does one that names something that is no slot" "$RESULT|$(reboots)" "ok b|0"

echo "-- a trial that booted"
run_case commit b "" persistent 'b\narmed=1\n' $ALL; go
check "healthy trial: committed" "$RESULT" "commit b"
check "BOOTX64.EFI is now the slot b kernel" "$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")" "kernel-b"
check "committed-slot records b" "$(cat "$KTEST/esp/kryptik/committed-slot")" "b"
check "the new committed-slot record is fsynced under its temporary name" "$(grep -c -x "sync -f $KTEST/run/esp/kryptik/committed-slot.new" "$KTEST/syncs" 2>/dev/null)" "1"
check "the trial record is gone" "$([[ -e "$KTEST/boot/trial" ]] && echo present || echo gone)" "gone"
check "the trial's firmware entries and BootNext are forgotten after the commit, the committed slot gets its own, and its release goes to the clock's floor" "$CALLS" "mount -t vfat -o rw,nosuid,nodev,noexec /dev/vda1 $KTEST/run/esp umount $KTEST/run/esp efiboot forget efiboot ensure b kryptikd time committed $KTEST/boot/release-b "
run_case commit0 b "" persistent 'b\narmed=0\n' $ALL; go
check "a trial that booted before its armed=1 line was written is still a trial: committed" "$RESULT" "commit b"

echo "-- a trial that booted unhealthy"
for missing in net-zone kryptikd-serve seatd getty-tty1 eudev; do
    svcs="${ALL/$missing/}"
    # shellcheck disable=SC2086
    run_case "un-$missing" b "" persistent 'b\narmed=1\n' $svcs; go
    check "trial with $missing down: not committed, recorded, rebooted" "${RESULT%%:*}|$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")|$([[ -e "$KTEST/boot/trial.failed" ]] && echo failed)|$(reboots)" "trial-unhealthy b|kernel-a|failed|1"
done
run_case unkernel b "" persistent 'b\narmed=1\n' $ALL; rm -f "$KTEST/kernel_ok"; go
check "trial without kernel zone support: not committed, rebooted" "${RESULT%%:*}|$(reboots)" "trial-unhealthy b|1"
run_case unzones b "" persistent 'b\narmed=1\n' $ALL; rm -f "$KTEST/zones_ok"; go
check "trial whose zones do not load: not committed" "${RESULT%%:*}" "trial-unhealthy b"
run_case unforget b "" persistent 'b\narmed=1\n' eudev; go
check "an unhealthy trial forgets its entries, gives the committed slot its own, then reboots" "$CALLS" "efiboot forget efiboot ensure a reboot "
run_case unforget2 b "" persistent 'b\narmed=1\n' eudev; : > "$KTEST/efiboot_fails"; go
check "... and reboots if they stay: its record, now trial.failed, keeps it from coming back" "$(reboots)" "1"
# On a degraded state /var is a tmpfs, so the trial record is out of reach.
run_case degraded b "" degraded "" $ALL; go
check "trial on a degraded state: known from the ESP, not committed, forgotten, rebooted" "${RESULT%%:*}|$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")|$CALLS" "trial-unhealthy b|kernel-a|mount -t vfat -o ro,nosuid,nodev,noexec /dev/vda1 $KTEST/run/esp umount $KTEST/run/esp efiboot forget efiboot ensure a reboot "
run_case degraded2 b "" degraded "" $ALL; : > "$KTEST/efiboot_fails"; go
check "... not rebooted while its entries stay: nothing else keeps the next boot from being it" "$(reboots)" "0"
run_case degraded3 a "" degraded "" $ALL; go
check "the committed slot on a degraded state: reported, left running" "${RESULT%%:*}|$(reboots)" "unhealthy a|0"
run_case ambig b "" persistent 'b\narmed=1\n' $ALL; : > "$KTEST/part_kryptik-esp"; echo 2 > "$KTEST/count_kryptik-esp"; go
check "trial with two kryptik-esp candidates: not committed (no guessing)" "${RESULT%%:*}|$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")" "trial-unhealthy b|kernel-a"
run_case noreboot b "" persistent 'b\narmed=1\n' eudev; go
check "KRYPTIK_NO_REBOOT is not set by default: the unhealthy trial rebooted" "$(reboots)" "1"
run_case noreboot2 b "" persistent 'b\narmed=1\n' eudev
_="$(PATH="$T/bin:$PATH" KRYPTIK_NO_REBOOT=1 KRYPTIK_RUN="$KTEST/run" KRYPTIK_BOOT_STATE="$KTEST/boot" KRYPTIK_SERVICE_DIR="$KTEST/svc" KRYPTIK_ZONES="$KTEST/zones" KRYPTIK_DEVICES="$T/devices.sh" sh "$SCRIPT" 2>&1)"
check "KRYPTIK_NO_REBOOT=1 records without rebooting" "$(reboots)" "0"
run_case noensure b "" persistent 'b\narmed=1\n' $ALL; : > "$KTEST/efiboot_fails_ensure"; go
check "a commit stands when the committed slot's own entry cannot be made" "$RESULT|$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")" "commit b|kernel-b"
run_case noensure2 b "" degraded "" $ALL; : > "$KTEST/efiboot_fails_ensure"; go
check "... and an unrecorded trial still reboots: its entries are gone, and that is what keeps it from coming back" "$(reboots)" "1"

echo "-- a trial that did not boot"
run_case failed a "" persistent 'b\narmed=1\n' $ALL; go
check "back on the old slot with BootNext consumed: trial-failed" "$RESULT" "trial-failed b"
check "the record moved to trial.failed" "$([[ -e "$KTEST/boot/trial.failed" ]] && cat "$KTEST/boot/trial.failed" | head -1)" "b"
check "BOOTX64.EFI untouched" "$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")" "kernel-a"
check "the failed trial's entries are forgotten, and the committed slot gets its own" "$CALLS" "efiboot forget efiboot ensure a "
run_case interrupted a "" persistent 'b\narmed=0\n' $ALL; go
check "old slot with an armed=0 record: arming was interrupted, nothing failed" "$RESULT" "arming-interrupted b"
check "the interrupted arming's entry is forgotten, and the committed slot gets its own" "$CALLS" "efiboot forget efiboot ensure a "
check "no trial.failed for an interruption" "$([[ -e "$KTEST/boot/trial.failed" ]] && echo present || echo none)" "none"
run_case legacy a "" persistent 'b\n' $ALL; go
check "a record without an armed line (older updater) counts as armed" "$RESULT" "trial-failed b"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
