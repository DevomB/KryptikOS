#!/usr/bin/env bash
#
# boot-success.sh's decisions, driven on a host with stand-ins.
#
# The script judges a booted slot from a handful of facts: the boot identity
# sysinit wrote, the trial record the updater wrote, whether the essential
# services are up, whether kryptikd finds kernel support and the zones, and
# whether the ESP is unambiguous. Every one of those is a file or a program
# on PATH, so every decision can be exercised here, in seconds, with a fake
# /run/kryptik, a fake service scan directory and fake s6-svstat / kryptikd /
# kryptik-efiboot / reboot / mount commands that record what they were asked.
# The real thing runs in the VM drivers; this is where the decision table is
# pinned so a change to it cannot slip through a VM run that only sees one
# path.
#
# Exit 0 when every case passes.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/build/service-scripts/boot-success.sh"
DEVICES="$ROOT/build/service-scripts/devices.sh"
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/run" "$T/boot" "$T/svc"
# --- stand-ins ---------------------------------------------------------------
# devices.sh is sourced by the script; a stand-in answers with what the
# case declares.
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
    *) exit 2 ;;
esac
EOF
cat > "$T/bin/kryptik-efiboot" <<'EOF'
#!/bin/sh
echo "efiboot $*" >> "$KTEST/calls"
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
exit 0
EOF
chmod +x "$T"/bin/*

run_case() {   # run_case NAME slot media state trial-content services... ; sets OUT, RESULT
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
go() {   # go: run the script for the current case
    OUT="$(PATH="$T/bin:$PATH" KRYPTIK_RUN="$KTEST/run" KRYPTIK_BOOT_STATE="$KTEST/boot" KRYPTIK_SERVICE_DIR="$KTEST/svc" \
           KRYPTIK_ZONES="$KTEST/zones" KRYPTIK_DEVICES="$T/devices.sh" sh "$SCRIPT" 2>&1)"
    RESULT="$(cut -d' ' -f1-2 "$KTEST/boot/last-result" 2>/dev/null | sed 's/ *$//')"
    CALLS="$(cat "$KTEST/calls" 2>/dev/null | tr '\n' ' ')"
}
ALL="eudev seatd kryptikd-serve net-zone getty-tty1"

echo "-- no trial"
run_case ok a "" persistent "" $ALL; go
check "healthy committed slot: ok" "$RESULT" "ok a"
check "no reboot, no commit on a plain boot" "$CALLS" ""
run_case media "" usb tmpfs "" $ALL; go
check "install medium: nothing tracked" "$(cat "$KTEST/boot/last-result" 2>/dev/null)" ""
run_case unhealthy a "" persistent "" eudev seatd; go
check "committed slot with services down: reported unhealthy, left running" "${RESULT%%:*}" "unhealthy a"
check "no reboot for a committed slot" "$CALLS" ""

echo "-- a trial that booted"
run_case commit b "" persistent 'b\narmed=1\n' $ALL; go
check "healthy trial: committed" "$RESULT" "commit b"
check "BOOTX64.EFI is now the slot b kernel" "$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")" "kernel-b"
check "committed-slot records b" "$(cat "$KTEST/esp/kryptik/committed-slot")" "b"
check "the trial record is gone" "$([[ -e "$KTEST/boot/trial" ]] && echo present || echo gone)" "gone"
check "BootNext cleared" "$CALLS" "mount -o rw,nosuid,nodev,noexec /dev/vda1 $KTEST/run/esp umount $KTEST/run/esp efiboot clear-next "
run_case commit0 b "" persistent 'b\narmed=0\n' $ALL; go
check "a trial that booted before its armed=1 line was written is still a trial: committed" "$RESULT" "commit b"

echo "-- a trial that booted unhealthy"
for missing in net-zone kryptikd-serve seatd getty-tty1 eudev; do
    svcs="${ALL/$missing/}"
    # shellcheck disable=SC2086
    run_case "un-$missing" b "" persistent 'b\narmed=1\n' $svcs; go
    check "trial with $missing down: not committed, recorded, rebooted" "${RESULT%%:*}|$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")|$([[ -e "$KTEST/boot/trial.failed" ]] && echo failed)|$(grep -c reboot "$KTEST/calls")" "trial-unhealthy b|kernel-a|failed|1"
done
run_case unkernel b "" persistent 'b\narmed=1\n' $ALL; rm -f "$KTEST/kernel_ok"; go
check "trial without kernel zone support: not committed, rebooted" "${RESULT%%:*}|$(grep -c reboot "$KTEST/calls")" "trial-unhealthy b|1"
run_case unzones b "" persistent 'b\narmed=1\n' $ALL; rm -f "$KTEST/zones_ok"; go
check "trial whose zones do not load: not committed" "${RESULT%%:*}" "trial-unhealthy b"
run_case degraded b "" degraded 'b\narmed=1\n' $ALL; go
check "trial on a degraded state: not committed, rebooted" "${RESULT%%:*}|$(grep -c reboot "$KTEST/calls")" "trial-unhealthy b|1"
run_case ambig b "" persistent 'b\narmed=1\n' $ALL; : > "$KTEST/part_kryptik-esp"; echo 2 > "$KTEST/count_kryptik-esp"; go
check "trial with two kryptik-esp candidates: not committed (no guessing)" "${RESULT%%:*}|$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")" "trial-unhealthy b|kernel-a"
run_case noreboot b "" persistent 'b\narmed=1\n' eudev; go
check "KRYPTIK_NO_REBOOT is not set by default: the unhealthy trial rebooted" "$(grep -c reboot "$KTEST/calls")" "1"
run_case noreboot2 b "" persistent 'b\narmed=1\n' eudev
OUT="$(PATH="$T/bin:$PATH" KRYPTIK_NO_REBOOT=1 KRYPTIK_RUN="$KTEST/run" KRYPTIK_BOOT_STATE="$KTEST/boot" KRYPTIK_SERVICE_DIR="$KTEST/svc" KRYPTIK_ZONES="$KTEST/zones" KRYPTIK_DEVICES="$T/devices.sh" sh "$SCRIPT" 2>&1)"
check "KRYPTIK_NO_REBOOT=1 records without rebooting" "$(grep -c reboot "$KTEST/calls" 2>/dev/null || echo 0)" "0"

echo "-- a trial that did not boot"
run_case failed a "" persistent 'b\narmed=1\n' $ALL; go
check "back on the old slot with BootNext consumed: trial-failed" "$RESULT" "trial-failed b"
check "the record moved to trial.failed" "$([[ -e "$KTEST/boot/trial.failed" ]] && cat "$KTEST/boot/trial.failed" | head -1)" "b"
check "BOOTX64.EFI untouched" "$(cat "$KTEST/esp/EFI/BOOT/BOOTX64.EFI")" "kernel-a"
run_case interrupted a "" persistent 'b\narmed=0\n' $ALL; go
check "old slot with an armed=0 record: arming was interrupted, nothing failed" "$RESULT" "arming-interrupted b"
check "no trial.failed for an interruption" "$([[ -e "$KTEST/boot/trial.failed" ]] && echo present || echo none)" "none"
run_case legacy a "" persistent 'b\n' $ALL; go
check "a record without an armed line (older updater) counts as armed" "$RESULT" "trial-failed b"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
