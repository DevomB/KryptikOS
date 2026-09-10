#!/usr/bin/env bash
# Phase 5 exit test — adversarial.
#
# docs/architecture.md states the requirement plainly: from inside `untrusted`,
# WITH ROOT IN THAT ZONE, each of the following must be demonstrably impossible.
#
#   1. Listing processes in another zone
#   2. Reading another zone's filesystem
#   3. Reaching the physical NIC
#   4. Reading anything in `vault`
#
# This script attacks a zone rather than describing one. A zone model that has
# not been attacked has not been tested.
#
# It is written to be run on ANY host with the required kernel features, not
# only on Kryptik, so the isolation primitives can be validated long before
# there is a bootable system. It uses unshare(1) with exactly the namespace set
# kryptikd applies (see compartments/kryptikd/src/isolate.rs).
#
# Exit status is the point: 0 only when all four requirements hold. While
# Phase 5 is incomplete this script is EXPECTED to fail, and the failures name
# precisely what is left to build.

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

# The namespace set kryptikd uses for a non-NIC zone. Kept in sync by hand with
# isolate.rs::namespace_flags; the mismatch test below checks that.
ZONE_UNSHARE=(--user --map-root-user --pid --mount --ipc --uts --net --fork)

printf '%sKryptik Phase 5 exit test — adversarial%s\n' "$C_BLU" "$C_RST"
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
    # Ubuntu 24.04+ and some hardened kernels block this by default. Name the
    # exact knob rather than leaving people to guess.
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

# Confirm we really do get uid 0 inside - the whole test is meaningless if the
# attacker is not root in the zone.
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
# Check the pid directly rather than matching on comm: the kernel truncates
# comm to 15 bytes, so a longer marker never matches and the test would report
# its own victim as missing.
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

# --mount-proc is what makes the pid namespace visible through /proc. Without
# it a zone inherits the host /proc and can enumerate every process on the
# system even though its pid namespace is correct.
# The zone legitimately sees its OWN processes - bash, plus whatever it runs.
# The requirement is that it sees no process belonging to another zone, not
# that /proc is empty. An earlier version of this asserted "<= 2 pids" and
# reported a correctly isolated zone as a failure.
visible="$(unshare "${ZONE_UNSHARE[@]}" --mount-proc bash -c 'ls /proc | grep -c "^[0-9]*$"' 2>/dev/null)"
host_pids="$(ls /proc 2>/dev/null | grep -c "^[0-9]*$")"
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

# And the negative control: WITHOUT --mount-proc the host /proc leaks through.
# This is documented deliberately - it is the exact mistake that makes a
# correct pid namespace useless, and kryptikd must never skip the proc mount.
leaked="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'ls /proc | grep -c "^[0-9]*$"' 2>/dev/null)"
if [[ -n "$leaked" ]] && [[ "$leaked" -gt 10 ]]; then
    info "control: without --mount-proc, ${leaked} host pids leak in (as expected)"
    info "         kryptikd MUST mount a fresh /proc; isolate.rs::mount_proc"
fi

# --- requirement 3: network isolation ---------------------------------------
# Done before requirement 2 because it is the one that currently holds.

head_ "Requirement 3 — cannot reach the physical NIC"

# Probe the network namespace itself, not /sys - see the sysfs check below for
# why those two disagree.
ifaces="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'ip -o link show 2>/dev/null | sed "s/^[0-9]*: //; s/:.*//"' 2>/dev/null | tr '\n' ' ' | xargs)"
if [[ "$ifaces" == "lo" ]]; then
    pass "zone network namespace contains only loopback (found: ${ifaces})"
else
    fail "zone network namespace has interfaces: ${ifaces:-none}"
fi

# sysfs is NOT namespaced by unshare alone. Without remounting it the zone reads
# the HOST's /sys/class/net and can enumerate every interface on the machine. It
# cannot use them, but it learns the network topology - reconnaissance a
# compromised `untrusted` zone should not get for free.
sys_before="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'ls /sys/class/net 2>/dev/null' 2>/dev/null | tr '\n' ' ' | xargs)"
sys_after="$(unshare "${ZONE_UNSHARE[@]}" bash -c 'mount -t sysfs sysfs /sys 2>/dev/null; ls /sys/class/net 2>/dev/null' 2>/dev/null | tr '\n' ' ' | xargs)"
if [[ "$sys_after" == "lo" ]]; then
    pass "after remounting sysfs, /sys/class/net shows only lo"
    if [[ "$sys_before" != "lo" ]]; then
        info "without the remount the zone would enumerate: ${sys_before}"
        info "kryptikd MUST remount sysfs per zone - isolate.rs::mount_sysfs"
    fi
else
    fail "zone still enumerates host interfaces via /sys: ${sys_after:-none}"
fi

# There is no interface to route through, so this is not a firewall rule that
# could be dropped - it is an absent device.
if unshare "${ZONE_UNSHARE[@]}" bash -c 'ip route 2>/dev/null | grep -q default' 2>/dev/null; then
    fail "zone has a default route"
else
    pass "zone has no default route"
fi

# --- requirement 2: filesystem isolation ------------------------------------

head_ "Requirement 2 — cannot read another zone's filesystem"

# First, the negative control that motivated Landlock in the first place.
# A mount namespace gives a zone its own mount TABLE, not its own view of the
# files, so namespaces alone leave every other zone's data readable.
if unshare "${ZONE_UNSHARE[@]}" cat "$OTHER_ZONE_SECRET" >/dev/null 2>&1; then
    info "control: with namespaces ALONE the zone can read ${OTHER_ZONE_SECRET##*/}"
    info "         a mount namespace is not filesystem isolation"
fi

# Now the real check: Landlock confinement, applied by kryptikd itself.
KRYPTIKD="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/target/debug/kryptikd"
if [[ ! -x "$KRYPTIKD" ]]; then
    KRYPTIKD="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/target/release/kryptikd"
fi

if [[ ! -x "$KRYPTIKD" ]]; then
    fail "kryptikd binary not built - cannot test Landlock confinement"
    info "build it with: cd compartments/kryptikd && cargo build"
else
    ZONE_ROOT="${WORK}/untrusted-rootfs"
    mkdir -p "$ZONE_ROOT"
    echo "this zone's own data" > "${ZONE_ROOT}/mine.txt"

    # Sanity: the zone must still reach its OWN files, or "blocked" below
    # would just mean we broke everything rather than confined correctly.
    "$KRYPTIKD" confine-test "$ZONE_ROOT" "${ZONE_ROOT}/mine.txt" >/dev/null 2>&1
    own_rc=$?
    if [[ "$own_rc" -eq 0 ]]; then
        pass "confined zone can still read its own rootfs"
    else
        fail "confined zone cannot read its own rootfs (rc=${own_rc}) - over-confined"
    fi

    # The actual requirement.
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

# --- consistency with kryptikd ----------------------------------------------

head_ "Consistency — test matches kryptikd's namespace set"

ISOLATE_RS="$(dirname "${BASH_SOURCE[0]}")/../kryptikd/src/isolate.rs"
if [[ -f "$ISOLATE_RS" ]]; then
    missing=0
    for ns in NEWUSER NEWNS NEWPID NEWIPC NEWUTS NEWCGROUP NEWNET; do
        grep -q "CLONE_${ns}" "$ISOLATE_RS" || { echo "    kryptikd is missing CLONE_${ns}"; missing=1; }
    done
    # The proc and sysfs remounts are as load-bearing as the namespaces.
    for fn in mount_proc mount_sysfs; do
        grep -q "fn ${fn}" "$ISOLATE_RS" || { echo "    kryptikd is missing ${fn}()"; missing=1; }
    done
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
    printf '\n%sPhase 5 is NOT complete.%s\n' "$C_YEL" "$C_RST"
    printf 'This is the expected result while the compartment layer is being\n'
    printf 'built. The failures above are the specification for what remains.\n'
    exit 1
fi

printf '\n%sAll Phase 5 exit requirements hold.%s\n' "$C_GRN" "$C_RST"
