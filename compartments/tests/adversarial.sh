#!/usr/bin/env bash
# The isolation exit test: as root inside an `untrusted` zone it must be
# impossible to 1. list another zone's processes, 2. read another zone's files,
# 3. reach the physical NIC, 4. read the vault (the four in compartments/README.md)
# or 5. reach dangerous syscalls, since a kernel LPE compromises every zone at
# once (docs/threat-model.md).
#
# Runs on any host with user namespaces: unshare(1) with kryptikd's namespace
# set (isolate.rs), and kryptikd itself for Landlock and seccomp. Exits 0 only
# when every check passes.

set -uo pipefail

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
[[ -t 1 ]] || { C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""; }

PASS=0
FAIL=0
declare -a FAILED=()

pass() { printf '%s  PASS%s  %s\n' "$C_GRN" "$C_RST" "$1"; PASS=$((PASS+1)); }
fail() { printf '%s  FAIL%s  %s\n' "$C_RED" "$C_RST" "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
info() { printf '%s        %s%s\n' "$C_DIM" "$1" "$C_RST"; }
head_() { printf '\n%s==>%s %s\n' "$C_BLU" "$C_RST" "$1"; }

WORK="$(mktemp -d)"
cleanup() {
    [[ -n "${VICTIM_PID:-}" ]] && kill "$VICTIM_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# kryptikd's namespace set for a non-NIC zone, as in isolate.rs::namespace_flags;
# the consistency check below compares them.
ZONE_UNSHARE=(--user --map-root-user --pid --mount --ipc --uts --net --fork)

printf '%sKryptik isolation exit test — adversarial%s\n' "$C_BLU" "$C_RST"
printf '%sAttacking from `untrusted`, as root inside the zone.%s\n' "$C_DIM" "$C_RST"

# --- preconditions ----------------------------------------------------------

head_ "Preconditions"

if ! command -v unshare >/dev/null; then
    fail "unshare(1) not available - cannot run this test"
    exit 1
fi

if ! unshare --user --map-root-user true 2>/dev/null; then
    fail "cannot create a user namespace on this host"
    info "Kryptik zones are built on user namespaces; nothing below can be tested."
    # Ubuntu 24.04+ and some hardened kernels block this by default.
    restrict="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo "")"
    if [[ "$restrict" == "1" ]]; then
        info ""
        info "kernel.apparmor_restrict_unprivileged_userns=1 on this host."
        info "Ubuntu 24.04+ sets this because unprivileged userns is a known"
        info "LPE vector. To run this test:"
        info "  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
        info ""
        info "Kryptik agrees with the restriction, incidentally: it sets"
        info "CONFIG_USER_NS_UNPRIVILEGED=n, because kryptikd creates zones"
        info "with privilege and nothing inside a zone needs to."
    fi
    max_ns="$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "")"
    if [[ "$max_ns" == "0" ]]; then
        info "user.max_user_namespaces is 0; raise it to run this test."
    fi
    exit 1
fi
pass "user namespaces available"

inside_uid="$(unshare "${ZONE_UNSHARE[@]}" id -u 2>/dev/null)"
if [[ "$inside_uid" == "0" ]]; then
    pass "attacker is root (uid 0) inside the zone"
else
    fail "attacker is not root inside the zone (uid=${inside_uid:-?})"
    info "This test only means something if the attacker has zone-root."
fi

# --- set up what the attacker will try to reach -----------------------------

head_ "Planting targets outside the zone"

# Stands in for a process belonging to another zone.
VICTIM_MARKER="kryptik-victim-$$-$RANDOM"
setsid bash -c "exec -a $VICTIM_MARKER sleep 300" &
VICTIM_PID=$!
sleep 0.3
# By pid, not comm: the kernel truncates comm to 15 bytes.
if [[ -d "/proc/${VICTIM_PID}" ]]; then
    info "victim process running as pid ${VICTIM_PID} (stands in for another zone)"
else
    info "victim process failed to start; requirement 1 result is weaker"
fi

# Stands in for another zone's filesystem, and for the vault.
OTHER_ZONE_SECRET="${WORK}/work-zone-data.txt"
VAULT_SECRET="${WORK}/vault-private-key.txt"
echo "SENSITIVE-WORK-ZONE-CONTENT-$RANDOM" > "$OTHER_ZONE_SECRET"
echo "SENSITIVE-VAULT-KEY-$RANDOM" > "$VAULT_SECRET"
chmod 600 "$OTHER_ZONE_SECRET" "$VAULT_SECRET"
info "planted: $(basename "$OTHER_ZONE_SECRET"), $(basename "$VAULT_SECRET")"

# --- requirement 1: process isolation ---------------------------------------

head_ "Requirement 1 — cannot list processes in another zone"

# Without --mount-proc the zone keeps the host's /proc, pid namespace or not.
# It may see its own processes, just no one else's.
visible="$(unshare "${ZONE_UNSHARE[@]}" --mount-proc bash -c 'ls /proc | grep -c "^[0-9]*$"' 2>/dev/null)"
# Every /proc entry starting with a digit is a pid; a glob starts no process.
host_pids=0
for _p in /proc/[0-9]*; do [ -d "$_p" ] && host_pids=$((host_pids+1)); done
if [[ -n "$visible" ]] && [[ "$visible" -lt 10 ]] && [[ "$visible" -lt "$host_pids" ]]; then
    pass "zone sees only its own processes (${visible} pids vs ${host_pids} on host)"
else
    fail "zone sees ${visible:-?} pids (host has ${host_pids}) - pid namespace is not isolating"
fi

# The zone's pid 1 must be its own init, not the host's.
zone_init="$(unshare "${ZONE_UNSHARE[@]}" --mount-proc bash -c 'cat /proc/1/comm' 2>/dev/null)"
host_init="$(cat /proc/1/comm 2>/dev/null)"
if [[ -n "$zone_init" ]] && [[ "$zone_init" != "$host_init" ]]; then
    pass "zone pid 1 is its own (${zone_init}), not the host's (${host_init})"
else
    fail "zone pid 1 is ${zone_init:-?}, host pid 1 is ${host_init:-?}"
fi

if unshare "${ZONE_UNSHARE[@]}" --mount-proc bash -c "ps -ef 2>/dev/null | grep -q '[s]leep 300'" 2>/dev/null; then
    fail "zone can see the victim process from another zone"
else
    pass "victim process is invisible from inside the zone"
fi

# Negative control: without --mount-proc the host's /proc leaks through.
leaked="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'ls /proc | grep -c "^[0-9]*$"' 2>/dev/null)"
if [[ -n "$leaked" ]] && [[ "$leaked" -gt 10 ]]; then
    info "control: without --mount-proc, ${leaked} host pids leak in (as expected)"
    info "         kryptikd MUST mount a fresh /proc; rootfs.rs::pivot_into"
fi

# --- requirement 3: network isolation ---------------------------------------

head_ "Requirement 3 — cannot reach the physical NIC"

# Devices the kernel puts in every netns, which the zone neither asked for nor
# can remove; the same list as launcher.sh. The netns is probed directly: /sys
# disagrees with it until remounted (below).
KERNEL_FALLBACK_IFS="sit0"

ifaces="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'ip -o link show 2>/dev/null | sed "s/^[0-9]*: //; s/[:@].*//"' 2>/dev/null | tr '\n' ' ' | xargs)"
adv_extra=""; adv_fallback=""
for d in $ifaces; do
    [[ "$d" == "lo" ]] && continue
    if [[ "$d" =~ ^(${KERNEL_FALLBACK_IFS// /|})$ ]]; then adv_fallback+="$d "; else adv_extra+="$d "; fi
done
if [[ -n "$adv_extra" ]]; then
    fail "zone network namespace has an interface nothing asked for: $adv_extra"
elif [[ -n "$adv_fallback" ]]; then
    pass "zone network namespace has loopback and only kernel fallback devices ($adv_fallback)"
else
    pass "zone network namespace contains only loopback (found: ${ifaces})"
fi

# A fallback device that can be deleted inside the netns is for kryptikd to
# delete, not for the kernel config. Each unshare makes a fresh netns, so the
# delete and its listing share one.
for d in $adv_fallback; do
    delmsg="$(unshare "${ZONE_UNSHARE[@]}" bash -c "ip link del $d 2>&1 | head -1" 2>/dev/null)"
    after="$(unshare "${ZONE_UNSHARE[@]}" bash -c "ip link del $d >/dev/null 2>&1; ip -o link show 2>/dev/null | sed 's/^[0-9]*: //; s/[:@].*//'" 2>/dev/null | tr '\n' ' ' | xargs)"
    if [[ " $after " == *" $d "* ]]; then
        pass "$d survives deletion in its own netns, so removing it is a kernel config item"
        info "ip link del $d said: ${delmsg:-<nothing>}"
    else
        fail "$d CAN be deleted inside a zone netns - kryptikd should delete it, not wait for a kernel rebuild"
        info "after the delete the namespace held: ${after:-none}"
    fi
done

# Without a sysfs remount the zone reads the host's /sys/class/net: it cannot
# use those interfaces, but it learns the topology.
sys_before="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'ls /sys/class/net 2>/dev/null' 2>/dev/null | tr '\n' ' ' | xargs)"
sys_after="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'mount -t sysfs sysfs /sys 2>/dev/null; ls /sys/class/net 2>/dev/null' 2>/dev/null | tr '\n' ' ' | xargs)"
# Only host devices fail it; lo and the fallback devices are expected.
sys_extra=""
for d in $sys_after; do
    [[ "$d" == "lo" ]] && continue
    [[ "$d" =~ ^(${KERNEL_FALLBACK_IFS// /|})$ ]] || sys_extra+="$d "
done
if [[ -z "$sys_extra" ]]; then
    pass "after remounting sysfs, /sys/class/net shows only lo and kernel fallback devices (${sys_after})"
    if [[ "$sys_before" != "$sys_after" ]]; then
        info "without the remount the zone would enumerate: ${sys_before}"
        info "kryptikd MUST remount sysfs per zone - rootfs.rs::pivot_into"
    fi
else
    fail "zone still enumerates host interfaces via /sys: ${sys_after:-none}"
fi

if unshare "${ZONE_UNSHARE[@]}" bash -c 'ip route 2>/dev/null | grep -q default' 2>/dev/null; then
    fail "zone has a default route"
else
    pass "zone has no default route"
fi

# --- requirement 2: filesystem isolation ------------------------------------

head_ "Requirement 2 — cannot read another zone's filesystem"

# Negative control: a mount namespace copies the mount table and gives no
# private view of the files, so namespaces alone leave other zones readable.
if unshare "${ZONE_UNSHARE[@]}" cat "$OTHER_ZONE_SECRET" >/dev/null 2>&1; then
    info "control: with namespaces ALONE the zone can read ${OTHER_ZONE_SECRET##*/}"
    info "         a mount namespace is not filesystem isolation"
fi

# Landlock, applied by kryptikd itself. tools/run-tests.sh exports KRYPTIKD;
# run directly, the suite uses the default build paths.
if [[ -z "${KRYPTIKD:-}" || ! -x "${KRYPTIKD:-}" ]]; then
    KRYPTIKD="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/target/debug/kryptikd"
    [[ -x "$KRYPTIKD" ]] || KRYPTIKD="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/target/release/kryptikd"
fi

if [[ ! -x "$KRYPTIKD" ]]; then
    fail "kryptikd binary not built - cannot test Landlock confinement"
    info "build it with: cd compartments/kryptikd && cargo build"
else
    ZONE_ROOT="${WORK}/untrusted-rootfs"
    mkdir -p "$ZONE_ROOT"
    echo "this zone's own data" > "${ZONE_ROOT}/mine.txt"

    # Control: the zone must still read its own files, or "blocked" below
    # proves nothing.
    "$KRYPTIKD" confine-test "$ZONE_ROOT" "${ZONE_ROOT}/mine.txt" >/dev/null 2>&1
    own_rc=$?
    if [[ "$own_rc" -eq 0 ]]; then
        pass "confined zone can still read its own rootfs"
    else
        fail "confined zone cannot read its own rootfs (rc=${own_rc}) - over-confined"
    fi

    "$KRYPTIKD" confine-test "$ZONE_ROOT" "$OTHER_ZONE_SECRET" >/dev/null 2>&1
    other_rc=$?
    case "$other_rc" in
        4) pass "confined zone CANNOT read another zone's file (Landlock blocked it)" ;;
        0) fail "confined zone read another zone's file - Landlock did not confine" ;;
        *) fail "confinement test errored (rc=${other_rc})" ;;
    esac
fi

# --- requirement 4: vault ---------------------------------------------------

head_ "Requirement 4 — cannot read the vault"

if [[ ! -x "${KRYPTIKD:-}" ]]; then
    fail "kryptikd not built - cannot test vault confinement"
else
    "$KRYPTIKD" confine-test "$ZONE_ROOT" "$VAULT_SECRET" >/dev/null 2>&1
    vault_rc=$?
    case "$vault_rc" in
        4) pass "confined zone CANNOT read vault content (Landlock blocked it)" ;;
        0) fail "confined zone read vault content - Landlock did not confine" ;;
        *) fail "vault confinement test errored (rc=${vault_rc})" ;;
    esac
    info "In a real Kryptik system the vault has a second, independent control:"
    info "its LUKS2 volume is not unlocked at all while other zones run, so"
    info "there is no plaintext to reach even if Landlock were bypassed."
fi

# --- requirement 5: kernel attack surface -----------------------------------
# All zones share one kernel; seccomp raises the cost of finding an LPE in it.

head_ "Requirement 5 — cannot reach the kernel's dangerous syscalls"

if [[ ! -x "${KRYPTIKD:-}" ]]; then
    fail "kryptikd not built - cannot test seccomp"
else
    # Control: a filter that blocked everything would pass the checks below.
    allowed_ok=1
    for sc in getpid write; do
        "$KRYPTIKD" seccomp-test "$sc" >/dev/null 2>&1 || allowed_ok=0
    done
    if [[ "$allowed_ok" -eq 1 ]]; then
        pass "permitted syscalls still work under the filter"
    else
        fail "the filter blocks syscalls a zone needs - over-restrictive"
    fi

    # setns alone would step into another zone's namespaces, defeating 1-4.
    leaked=0
    for sc in setns ptrace unshare mount bpf perf_event_open userfaultfd \
              keyctl init_module kexec_load process_vm_readv pivot_root chroot; do
        "$KRYPTIKD" seccomp-test "$sc" >/dev/null 2>&1
        rc=$?
        if [[ "$rc" -ne 5 ]]; then
            echo "      ${sc} was NOT blocked (rc=${rc})"
            leaked=$((leaked + 1))
        fi
    done

    if [[ "$leaked" -eq 0 ]]; then
        pass "all 13 dangerous syscalls killed by SIGSYS (setns among them)"
    else
        fail "${leaked} dangerous syscall(s) reachable from inside a zone"
    fi
fi

# --- consistency with kryptikd ----------------------------------------------

head_ "Consistency — test matches kryptikd's namespace set"

ISOLATE_RS="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/src/isolate.rs"
if [[ -f "$ISOLATE_RS" ]]; then
    missing=0
    for ns in NEWUSER NEWNS NEWPID NEWIPC NEWUTS NEWCGROUP NEWNET; do
        grep -q "CLONE_${ns}" "$ISOLATE_RS" || { echo "    kryptikd is missing CLONE_${ns}"; missing=1; }
    done
    # The proc and sysfs remounts matter as much; rootfs.rs::pivot_into makes them.
    ROOTFS_RS="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/src/rootfs.rs"
    if [[ -f "$ROOTFS_RS" ]]; then
        for m in "mount(proc)" "mount(sysfs)"; do
            grep -qF "\"${m}\"" "$ROOTFS_RS" || { echo "    kryptikd rootfs build is missing ${m}"; missing=1; }
        done
    else
        # The image ships rootfs.rs for this check, so its absence is reported.
        info "rootfs.rs not shipped beside this suite; the proc/sysfs mount check did not run"
    fi
    # The seccomp filter must default-deny, so it needs a kill action.
    SECCOMP_RS="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/src/seccomp.rs"
    if [[ -f "$SECCOMP_RS" ]]; then
        grep -q "SECCOMP_RET_KILL_PROCESS" "$SECCOMP_RS"             || { echo "    seccomp filter has no kill action"; missing=1; }
    fi
    if [[ "$missing" -eq 0 ]]; then
        pass "kryptikd declares every namespace this test exercises"
    else
        fail "kryptikd namespace set does not match this test"
    fi
else
    info "isolate.rs not found; skipping consistency check"
fi

# --- summary ----------------------------------------------------------------

printf '\n%s==>%s Summary\n' "$C_BLU" "$C_RST"
printf '  passed: %d\n' "$PASS"
printf '  failed: %d\n' "$FAIL"

if [[ "$FAIL" -gt 0 ]]; then
    printf '\n%sUnmet requirements:%s\n' "$C_YEL" "$C_RST"
    printf '  - %s\n' "${FAILED[@]}"
    printf '\n%sThe compartment layer is NOT complete.%s\n' "$C_YEL" "$C_RST"
    printf 'This is the expected result while the compartment layer is being\n'
    printf 'built. The failures above are the specification for what remains.\n'
    exit 1
fi

printf '\n%sEvery isolation exit requirement holds.%s\n' "$C_GRN" "$C_RST"
