#!/usr/bin/env bash
# Boot the developer VM and assert on what actually happened.
#
# The point of this file is that "qemu exited 0" is not a boot. QEMU exits 0
# when the guest panics and -no-reboot stops it, when the guest hangs and the
# timeout fires cleanly, and when the guest powers off after doing nothing at
# all. So the pass criteria are the sentinels in the serial log, in order, and
# the serial log is kept either way.
#
# It also refuses to report a pass for a Kryptik boot it did not perform: the
# image records where its userspace came from, and if that is "host-binaries"
# this reports a HARNESS pass, not a Kryptik one.

set -uo pipefail

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
[[ -t 1 ]] || { C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""; }

PASS=0; FAIL=0
declare -a FAILED=()
pass() { printf '%s  PASS%s  %s\n' "$C_GRN" "$C_RST" "$1"; PASS=$((PASS+1)); }
fail() { printf '%s  FAIL%s  %s\n' "$C_RED" "$C_RST" "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
info() { printf '%s        %s%s\n' "$C_DIM" "$1" "$C_RST"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${1:-}"
[[ -n "$LOG" ]] || { printf 'usage: boot-smoke.sh SERIAL_LOG\n' >&2; exit 2; }
[[ -r "$LOG" ]] || { printf 'boot-smoke: serial log not readable: %s\n' "$LOG" >&2; exit 2; }

printf '%sKryptik VM boot smoke check%s\n' "$C_BLU" "$C_RST"
info "serial log: $LOG ($(stat -c %s "$LOG") bytes)"

have() { grep -qF "$1" "$LOG"; }
valueof() { sed -n "s/.*${1}=\\([^ $'\r']*\\).*/\\1/p" "$LOG" | tr -d '\r' | head -1; }

# --- did it get off the ground at all? --------------------------------------
if have "Linux version"; then
    pass "the kernel started"
    info "$(grep -m1 'Linux version' "$LOG" | cut -c1-120)"
else
    fail "no kernel banner in the serial log — the guest never started"
fi

if have "KRYPTIK_VM_STAGE1_OK"; then
    pass "stage 1 init ran and mounted /proc, /sys and /dev"
else
    fail "stage 1 init did not report — the initramfs /init did not run"
fi

if have "KRYPTIK_VM_SWITCHROOT"; then
    pass "the image switch_rooted off the initial rootfs"
else
    fail "no switch_root — pivot_root and therefore every zone start will fail"
fi

if have "KRYPTIK_VM_STAGE2_OK"; then
    pass "stage 2 init ran on the real root"
    rootfs="$(valueof KRYPTIK_VM_ROOTFS)"
    [[ -n "$rootfs" ]] && info "root filesystem type: $rootfs"
else
    fail "stage 2 init did not report"
fi

if have "KRYPTIK_VM_S6_START"; then
    pass "s6-svscan was started as the service supervisor"
else
    fail "s6 was never started"
fi

pid1="$(valueof KRYPTIK_VM_PID1)"
if [[ "$pid1" == "s6-svscan" ]]; then
    pass "PID 1 inside the VM is s6-svscan"
else
    fail "PID 1 is '${pid1:-unknown}', expected s6-svscan"
fi

# --- what kind of system is this, really? -----------------------------------
origin="$(valueof KRYPTIK_VM_USERSPACE)"
kver="$(valueof KRYPTIK_VM_KERNEL)"
info "guest kernel:    ${kver:-unknown}"
info "guest userspace: ${origin:-unknown}"

# --- the security features the zone model depends on ------------------------
cg="$(valueof KRYPTIK_VM_CGROUP2)"
if [[ "$cg" == "v2" ]]; then
    pass "cgroup v2 is mounted in the guest"
    ctl="$(valueof KRYPTIK_VM_CGROUP_CONTROLLERS)"
    [[ -n "$ctl" ]] && info "controllers: $ctl"
    # The zone limits that are not implemented yet need these two specifically,
    # so their absence is worth surfacing now rather than at implementation time.
    [[ "$ctl" == *memory* ]] || info "NOTE: the memory controller is not available here"
    [[ "$ctl" == *pids*   ]] || info "NOTE: the pids controller is not available here"
else
    fail "cgroup v2 not available in the guest (got '${cg:-none}')"
fi

sec="$(valueof KRYPTIK_VM_SECCOMP)"
if [[ "$sec" == "supported" ]]; then
    pass "the guest kernel supports seccomp"
else
    fail "the guest kernel does not report seccomp support (got '${sec:-none}')"
fi

abi="$(valueof KRYPTIK_VM_LANDLOCK_ABI)"
if [[ -n "$abi" ]] && (( abi >= 1 )); then
    pass "Landlock is available in the guest (ABI v$abi)"
    info "the WSL development host reports ABI v3; testing on both is the point of this VM"
else
    fail "Landlock is not available in the guest — zones refuse to start without it"
fi

lsm="$(valueof KRYPTIK_VM_LSM)"
if [[ -n "$lsm" && "$lsm" != "unknown" ]]; then
    info "active LSMs: $lsm"
    [[ "$lsm" == *landlock* ]] && pass "landlock is in the guest's active LSM list" \
                               || fail "landlock is NOT in the guest's active LSM list ($lsm)"
else
    info "LSM list unavailable (securityfs: $(valueof KRYPTIK_VM_SECURITYFS))"
fi

if have "KRYPTIK_VM_CHECK=pass"; then
    pass "kryptikd check passed inside the VM (kernel support + zone validation)"
elif have "KRYPTIK_VM_CHECK=fail"; then
    fail "kryptikd check FAILED inside the VM"
    sed -n '/KRYPTIK_VM_CHECK_BEGIN/,/KRYPTIK_VM_CHECK_END/p' "$LOG" | sed 's/^/        /' | head -30
else
    fail "kryptikd check never ran"
fi

# --- the real launcher suite, inside the VM ---------------------------------
lrc="$(valueof KRYPTIK_VM_LAUNCHER_RC)"
case "$lrc" in
    0)  pass "the real-launcher suite passed inside the VM"
        grep -E '^ *(PASS|FAIL|SKIP) ' "$LOG" >/dev/null 2>&1 && \
            info "$(grep -cE '^ *PASS ' "$LOG") PASS lines in the guest log"
        ;;
    missing) fail "the launcher suite was not present in the image" ;;
    "")      fail "the launcher suite never ran (no result line in the log)" ;;
    *)       fail "the launcher suite exited $lrc inside the VM"
             sed -n '/KRYPTIK_VM_LAUNCHER_BEGIN/,/KRYPTIK_VM_LAUNCHER_END/p' "$LOG" \
                 | grep -E 'FAIL|failed:' | sed 's/^/        /' | head -20
        ;;
esac

arc="$(valueof KRYPTIK_VM_ADVERSARIAL_RC)"
case "$arc" in
    0)  pass "the adversarial primitive suite passed inside the VM" ;;
    "") info "the adversarial suite was not run in this image" ;;
    *)  fail "the adversarial suite exited $arc inside the VM" ;;
esac

# --- did it end cleanly? ----------------------------------------------------
if have "KRYPTIK_VM_SMOKE_END"; then
    pass "the smoke payload ran to completion"
else
    fail "the smoke payload did not finish — the log ends early"
fi

if have "KRYPTIK_VM_POWEROFF"; then
    pass "the guest reached a clean poweroff"
else
    fail "the guest never powered off cleanly"
fi

if grep -qE 'Kernel panic|BUG: |Oops: ' "$LOG"; then
    fail "the guest kernel panicked or oopsed"
    grep -m3 -E 'Kernel panic|BUG: |Oops: ' "$LOG" | sed 's/^/        /'
else
    pass "no kernel panic, oops or BUG in the serial log"
fi

# --- summary ----------------------------------------------------------------
printf '\n%s==>%s summary\n' "$C_BLU" "$C_RST"
printf '  %s%d passed%s, %s%d failed%s\n' "$C_GRN" "$PASS" "$C_RST" "$C_RED" "$FAIL" "$C_RST"
if (( FAIL > 0 )); then
    printf '\n%sfailed:%s\n' "$C_RED" "$C_RST"
    for f in "${FAILED[@]}"; do printf '  - %s\n' "$f"; done
    printf '\n%sVM BOOT SMOKE FAILED%s\n' "$C_RED" "$C_RST"
    exit 1
fi

printf '\n'
if [[ "$origin" == "kryptik-sysroot" ]]; then
    printf '%sVM BOOT SMOKE PASSED%s — a Kryptik userspace booted and the suites ran.\n' \
        "$C_GRN" "$C_RST"
else
    printf '%sVM BOOT SMOKE PASSED (HARNESS ONLY)%s\n' "$C_YEL" "$C_RST"
    printf 'The guest booted, s6 came up and the suites ran — but its userspace is\n'
    printf '"%s" and its kernel is "%s".\n' "${origin:-unknown}" "${kver:-unknown}"
    printf 'This validates the VM harness. It is NOT a Kryptik boot, and must not be\n'
    printf 'reported as one until --sysroot and the Kryptik kernel are supplied.\n'
fi
exit 0
