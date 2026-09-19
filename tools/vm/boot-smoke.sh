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

LOG="${1:-}"
[[ -n "$LOG" ]] || { printf 'usage: boot-smoke.sh SERIAL_LOG\n' >&2; exit 2; }
[[ -r "$LOG" ]] || { printf 'boot-smoke: serial log not readable: %s\n' "$LOG" >&2; exit 2; }

printf '%sKryptik VM boot smoke check%s\n' "$C_BLU" "$C_RST"
info "serial log: $LOG ($(stat -c %s "$LOG") bytes)"

have() { grep -qF "$1" "$LOG"; }
valueof() { sed -n "s/.*${1}=\\([^ $'\r']*\\).*/\\1/p" "$LOG" | tr -d '\r' | head -1; }
# valueof stops at the first space, which is right for a token and wrong for a
# value that contains spaces - /proc/version is one.
lineof() { sed -n "s/.*${1}=\\(.*\\)/\\1/p" "$LOG" | tr -d '\r' | head -1; }

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

# Two ways to satisfy one requirement: / must not be the initial ramfs, because
# pivot_root(2) returns EINVAL there and every zone start would fail. An
# initramfs image gets off rootfs by copying itself onto a tmpfs and
# switch_root'ing. A disk image was never on rootfs at all - the kernel mounted
# its ext4 root directly - and demanding the switch_root line from both made the
# first disk boot report "every zone start will fail" about a run in which zones
# started perfectly well.
if grep -q 'KRYPTIK_VM_ROOTFS=disk' "$LOG"; then
    pass "the root filesystem is a real disk, so pivot_root works without a switch_root"
elif have "KRYPTIK_VM_SWITCHROOT"; then
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

devfd="$(valueof KRYPTIK_VM_DEVFD)"
case "$devfd" in
    ok)  pass "/dev/fd works in the guest (shell process substitution)" ;;
    "")  info "no /dev/fd probe in this image" ;;
    *)   fail "/dev/fd is $devfd in the guest — process substitution fails, and every shell script using < <(...) breaks" ;;
esac

# --- the user-facing command -------------------------------------------------
crc="$(valueof KRYPTIK_VM_CLI_RC)"
case "$crc" in
    0)  pass "the user-facing \`kryptik\` command works inside the VM" ;;
    "") info "the kryptik command's suite was not in this image" ;;
    *)  fail "the kryptik command's suite exited $crc inside the VM"
        sed -n '/KRYPTIK_VM_CLI_BEGIN/,/KRYPTIK_VM_CLI_END/p' "$LOG" \
            | grep -E 'FAIL' | sed 's/^/        /' | head -10
        ;;
esac

# --- restart, when the log is from a restart run ----------------------------
if grep -q 'KRYPTIK_VM_BOOT_NUMBER=' "$LOG"; then
    boots="$(grep -c 'KRYPTIK_VM_BOOT_NUMBER=' "$LOG")"
    second="$(grep -c 'KRYPTIK_VM_BOOT_NUMBER=2' "$LOG")"
    if [ "$second" -ge 1 ]; then
        pass "the guest rebooted and came back ($boots boots in one run)"
    else
        fail "the guest never reached a second boot — restart is unproven"
    fi
    for k in RESTART_PRE RESTART_POST RESTART_ZONE; do
        v="$(valueof "KRYPTIK_VM_$k")"
        case "$v" in
            ok|ran) pass "restart: $k = $v" ;;
            "")     fail "restart: $k was never reported" ;;
            *)      fail "restart: $k = $v" ;;
        esac
    done
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

# The same suite with the userns restriction ON. This is the check that makes
# any privileged result target-relevant: without it, every group K number was
# measured on a kernel that allows what the target forbids.
rrc="$(valueof KRYPTIK_VM_RESTRICTED_RC)"
rknob="$(valueof KRYPTIK_VM_RESTRICTED_KNOB)"
case "$rrc" in
    0)  if [ "$rknob" = "native" ]; then
            pass "unprivileged user namespaces are restricted BY THIS KERNEL, and the suite passed under it"
            info "not emulated: the kernel refuses unshare(CLONE_NEWUSER) without CAP_SYS_ADMIN by its own configuration, so the run above IS the restricted run"
        elif [ "$rknob" = "apparmor-emulated" ]; then
            pass "the launcher suite passed again with unprivileged user namespaces RESTRICTED (emulated)"
            info "emulated with kernel.apparmor_restrict_unprivileged_userns=1, not the target kernel's own build option"
        else
            pass "the launcher suite passed again with the restriction on"
        fi
        ;;
    "")     info "no restricted run in this image" ;;
    2)      fail "the restricted run refused to start (exit 2) and tested nothing"
            info "the suite exits 2 when it declines to run at all - a stale binary, or a zone left running by the run before it"
            sed -n '/KRYPTIK_VM_RESTRICTED_BEGIN/,/KRYPTIK_VM_RESTRICTED_END/p' "$LOG"                 | tail -6 | sed 's/^/        /'
        ;;
    nokno*) fail "the restriction could not be turned on, so the privileged path is untested against it" ;;
    "$lrc") fail "the launcher suite exited $rrc with the restriction on, the same way it did without it"
            info "identical exit codes: whatever is failing is not about the restriction — read the unrestricted run's failures first"
        ;;
    *)      fail "the launcher suite exited $rrc with the restriction on - the privileged path does not hold on the target's rule"
            sed -n '/KRYPTIK_VM_RESTRICTED_BEGIN/,/KRYPTIK_VM_RESTRICTED_END/p' "$LOG" \
                | grep -E 'FAIL' | sed 's/^/        /' | head -20
        ;;
esac

# The privileged launch contract, if the security probe shipped.
prc="$(valueof KRYPTIK_VM_PRIVCONTRACT_RC)"
knob="$(valueof KRYPTIK_VM_USERNS_KNOB)"
case "$prc" in
    "")  info "the privileged-contract probe was not in this image" ;;
    0)   pass "the privileged launch contract probe passed inside the VM"
         [[ "$knob" == "apparmor-emulated" ]] && \
            info "NOTE: the userns restriction was EMULATED with the AppArmor sysctl on a stock kernel — this is NOT target-kernel evidence"
         ;;
    *)   fail "the privileged launch contract probe reported $prc failure(s)"
         sed -n '/KRYPTIK_VM_PRIVCONTRACT_BEGIN/,/KRYPTIK_VM_PRIVCONTRACT_END/p' "$LOG" \
             | grep -E 'FAIL|NOT RUN' | sed 's/^/        /' | head -10
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

# Two faults the original three patterns would have missed. A general
# protection fault and a NULL pointer dereference both print a Call Trace, and
# an x86 GPF in particular need not be followed by "Oops:" or "BUG: " in the
# same line, so a run could fault and still be reported as a clean boot.
#
# Note what is deliberately NOT here: "Call Trace" on its own. The launcher
# suite's memory-limit check asks the kernel to OOM-kill a zone on purpose, and the OOM report carries a stack
# trace. Matching that would turn a test doing exactly what it was written to
# do into a kernel bug.
KPANIC='Kernel panic|BUG: |Oops: |general protection fault|kernel NULL pointer'
if grep -qE "$KPANIC" "$LOG"; then
    fail "the guest kernel panicked or oopsed"
    grep -m3 -E "$KPANIC" "$LOG" | sed 's/^/        /'
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
    # Two separate claims, and conflating them is the failure this harness was
    # written to prevent: whose USERSPACE booted, and whose KERNEL booted.
    #
    # The userspace claim rests on what the running system says about itself,
    # not on the build-time stamp. An earlier version compared the stamped
    # triple against the running shell's triple - which broke the moment a
    # complete sysroot existed, because stage 04 rebuilds bash natively and
    # config.guess then reports the BUILD system (x86_64-pc-linux-gnu),
    # correctly. The discriminator that survives is the target compiler: a
    # Kryptik userspace carries a gcc that says x86_64-kryptik-linux-gnu.
    gcc_triple="$(valueof KRYPTIK_VM_GCC_TRIPLE)"
    os_id="$(valueof KRYPTIK_VM_OSRELEASE_ID)"
    if [[ "$gcc_triple" == *-kryptik-linux-* ]]; then
        printf '%sVM BOOT SMOKE PASSED%s — a Kryptik USERSPACE booted and the suites ran.\n' \
            "$C_GRN" "$C_RST"
        printf 'Measured in the running guest: gcc -dumpmachine = %s' "$gcc_triple"
        [[ -n "$os_id" ]] && printf ', /etc/os-release ID=%s' "$os_id"
        printf '\n'
    elif [[ "$os_id" == "kryptik" ]]; then
        printf '%sVM BOOT SMOKE PASSED (WEAK USERSPACE EVIDENCE)%s\n' "$C_YEL" "$C_RST"
        printf 'The image was stamped kryptik-sysroot and the guest'"'"'s /etc/os-release says\n'
        printf 'ID=kryptik, but nothing in the running system was measured: there is no gcc\n'
        printf 'in it to name the target. os-release is a text file. Treat this as a harness\n'
        printf 'result until a measured one is available.\n'
    else
        printf '%sMISMATCH%s: the image was stamped kryptik-sysroot, but the running guest\n' \
            "$C_RED" "$C_RST"
        printf 'reports neither a Kryptik gcc target (%s) nor ID=kryptik (%s).\n' \
            "${gcc_triple:-none}" "${os_id:-none}"
        printf 'The image was assembled from one tree and stamped from another.\n'
        exit 1
    fi
    # The kernel is a separate question, and it is not answered by looking for
    # the word "kryptik" in a version string. That test called
    # 6.18.50-hardened1 - built by Kryptik's own build, carrying Kryptik's LSM set,
    # refusing unprivileged user namespaces by its own configuration - "NOT
    # Kryptik's kernel", which understated the strongest result this harness
    # has produced. Understating a result is the same defect as overstating
    # one. Two questions, each answered by something measured:
    #
    #   1. IS the running kernel the file the harness booted? The guest reports
    #      /proc/version; the host reports the version string compiled into the
    #      bzImage it handed to qemu. They are independent, and they must agree.
    #   2. Is it hardened the way Kryptik intends? Decided by what it refuses,
    #      not by what it is called.
    kfile="$(valueof KRYPTIK_HOST_KERNEL_FILE)"
    ksha="$(valueof KRYPTIK_HOST_KERNEL_SHA256)"
    kfilever="$(lineof KRYPTIK_HOST_KERNEL_VERSION)"
    procver="$(lineof KRYPTIK_VM_PROC_VERSION)"
    printf 'Kernel: %s\n' "${kver:-unknown}"
    if [[ -n "$kfile" ]]; then
        printf '  booted from  %s\n' "$kfile"
        [[ -n "$ksha" ]] && printf '  sha256       %s\n' "$ksha"
    fi
    if [[ -n "$kfilever" && -n "$procver" ]]; then
        if [[ "$procver" == *"$kfilever"* ]]; then
            printf '  identity     the guest reports a /proc/version carrying the version\n'
            printf '               string compiled into that exact file, so that file is\n'
            printf '               what ran\n'
        else
            printf '%s  MISMATCH     the guest is running %s\n' "$C_RED" "${procver:-unknown}"
            printf '               but the file booted was built as %s%s\n' "$kfilever" "$C_RST"
            FAILED+=("the running kernel is not the file the harness booted")
        fi
    fi
    if [[ "$lsm" == *apparmor* ]]; then
        printf '%s  hardening    a DISTRIBUTION kernel: apparmor is in its LSM list, and\n' "$C_YEL"
        printf '               Kryptik does not enable it. The LSM set, the hardening\n'
        printf '               options and any userns restriction here are the\n'
        printf '               distribution'"'"'s, not the ones Kryptik intends to ship.%s\n' "$C_RST"
    elif [[ "$rknob" == "native" ]]; then
        printf '%s  hardening    unprivileged user namespaces are refused BY THIS KERNEL,\n' "$C_GRN"
        printf '               with no sysctl set by this harness. LSMs: %s.\n' "${lsm:-unknown}"
        printf '               Landlock ABI %s. That is Kryptik'"'"'s configuration, and it\n' "${abi:-unknown}"
        printf '               was measured in the running guest.%s\n' "$C_RST"
    else
        printf '  hardening    LSMs: %s; landlock ABI %s. This kernel does NOT refuse\n' \
               "${lsm:-unknown}" "${abi:-unknown}"
        printf '               unprivileged user namespaces on its own.\n'
    fi
else
    printf '%sVM BOOT SMOKE PASSED (HARNESS ONLY)%s\n' "$C_YEL" "$C_RST"
    printf 'The guest booted, s6 came up and the suites ran — but its userspace is\n'
    printf '"%s" and its kernel is "%s".\n' "${origin:-unknown}" "${kver:-unknown}"
    printf 'This validates the VM harness. It is NOT a Kryptik boot, and must not be\n'
    printf 'reported as one until --sysroot and the Kryptik kernel are supplied.\n'
fi
exit 0
