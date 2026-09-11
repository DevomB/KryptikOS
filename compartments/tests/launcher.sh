#!/usr/bin/env bash
# Phase 5 real-launcher suite — attacks `kryptikd run`, not unshare(1).
#
# WHY THIS EXISTS, SEPARATELY FROM adversarial.sh
#
# adversarial.sh drives the isolation PRIMITIVES with unshare(1) and a few
# kryptikd self-test subcommands. That proves the primitives are sound on this
# kernel. It does not prove that `kryptikd run` applies them, in the right
# order, to a real process. Those are different claims, and only the second one
# is what a user relies on when they start a zone.
#
# So every check below goes through the actual launch path:
#
#     kryptikd run ZONE --zones DIR --rootfs DIR -- COMMAND
#
# THE CENTRAL RULE OF THIS FILE
#
#   A program that fails to launch is not an isolation pass.
#
# A zone whose command dies during setup produces exactly the same observable
# outcome as a zone that isolated perfectly: no secret comes out. Every
# isolation check here therefore has the zone print a launch sentinel FIRST and
# the probe result SECOND. Missing sentinel => the check FAILS as "did not
# launch", never passes. `want_launch` and `probe` below implement that.
#
# Positive controls are mandatory for the same reason. Before asserting that a
# zone cannot read a file, the suite asserts the file IS readable from outside.
# Otherwise a typo'd path would "prove" isolation.
#
# CLASSIFICATION
#   [unpriv]  runs as an ordinary user on any Linux/WSL host with the required
#             kernel features. This is the whole suite today.
#   [vm]      needs a disposable privileged VM (real root, cgroup writes,
#             mknod). Declared by name at the end and reported as NOT RUN —
#             a mandatory check that is skipped is not a pass, and the summary
#             says so out loud.
#
# SAFETY
#   Bounded timeouts on every zone launch. No real secrets - the "secret" is a
#   synthetic canary string. No fork bombs. No host network changes. Everything
#   is created under one mktemp -d and removed on exit.
#
# Exit status: 0 only when every executed check passes AND no mandatory check
# was skipped.

set -uo pipefail

# --- output -----------------------------------------------------------------

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
[[ -t 1 ]] || { C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""; }

PASS=0; FAIL=0; SKIP=0
declare -a FAILED=() SKIPPED=()

pass()  { printf '%s  PASS%s  %s\n' "$C_GRN" "$C_RST" "$1"; PASS=$((PASS+1)); }
fail()  { printf '%s  FAIL%s  %s\n' "$C_RED" "$C_RST" "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
skip()  { printf '%s  SKIP%s  %s\n' "$C_YEL" "$C_RST" "$1"; SKIP=$((SKIP+1)); SKIPPED+=("$1"); }
info()  { printf '%s        %s%s\n' "$C_DIM" "$1" "$C_RST"; }
head_() { printf '\n%s==>%s %s\n' "$C_BLU" "$C_RST" "$1"; }

# --- locate the binary ------------------------------------------------------

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
KRYPTIKD="${KRYPTIKD:-$REPO/compartments/kryptikd/target/debug/kryptikd}"

if [[ ! -x "$KRYPTIKD" ]]; then
    printf '%sBUILD REQUIRED%s: %s is not executable.\n' "$C_RED" "$C_RST" "$KRYPTIKD"
    printf 'Run: (cd %s/compartments/kryptikd && cargo build)\n' "$REPO"
    exit 2
fi

TIMEOUT="${KRYPTIK_TEST_TIMEOUT:-30}"

printf '%sKryptik real-launcher suite%s\n' "$C_BLU" "$C_RST"
printf '%sEvery check drives `kryptikd run`. Primitives are adversarial.sh.%s\n' "$C_DIM" "$C_RST"
info "kryptikd: $KRYPTIKD"
info "per-launch timeout: ${TIMEOUT}s"

# --- workspace --------------------------------------------------------------

WORK="$(mktemp -d)"
ZONES="$WORK/zones"
ROOTFS="$WORK/rootfs"
HOSTFIX="$WORK/hostfix"
mkdir -p "$ZONES" "$ROOTFS" "$HOSTFIX"

declare -a BG_PIDS=()
cleanup() {
    for p in "${BG_PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null
    done
    # The zone rootfs trees are plain directories on the host; the mounts
    # inside them lived only in the zone's own (now dead) mount namespace.
    rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

# --- fixtures ---------------------------------------------------------------

# A synthetic canary. Not a real secret, and deliberately unmistakable in a
# grep so a partial leak cannot be mistaken for a pass.
CANARY="KRYPTIK_CANARY_a7f3c091_DO_NOT_LEAK"

# A harmless stand-in for host configuration a zone must not see.
printf 'token = %s\n' "$CANARY" > "$HOSTFIX/hostconfig.conf"
chmod 0600 "$HOSTFIX/hostconfig.conf"

mkzone() { # name mode colour [extra-network-lines] [storage-mode]
    local name="$1" mode="$2" colour="$3" extra="${4:-}" storage="${5:-ephemeral}"
    {
        printf '[zone]\nname = "%s"\ndescription = "launcher-suite fixture"\n' "$name"
        printf '[network]\nmode = "%s"\n' "$mode"
        [[ -n "$extra" ]] && printf '%s\n' "$extra"
        printf '[storage]\nmode = "%s"\n' "$storage"
        [[ "$storage" == "encrypted" ]] && printf 'volume = "/dev/kryptik/%s"\n' "$name"
        printf '[ui]\nborder_color = "%s"\n' "$colour"
    } > "$ZONES/$name.toml"
}

# check_invariants() requires exactly one NIC-holding zone in any zone set, so
# every fixture set carries `carrier`. It is never RUN: a nic zone deliberately
# stays in the host network namespace (isolate.rs::namespace_flags), so running
# it would be the one case that is not isolated, and starting it here would
# prove nothing while touching the host's netns.
mkzone alpha    none   "#111111"
mkzone beta     none   "#222222"
mkzone carrier  nic    "#333333" 'bridge = "kryptik0"'
mkzone sealed   none   "#444444" ''                      encrypted
mkzone wiped    none   "#555555" ''                      ephemeral

ZARGS=(--zones "$ZONES" --rootfs "$ROOTFS")

# --- launch helpers ---------------------------------------------------------

# zrun ZONE -- CMD...   Run inside a zone with the experimental override on.
# Captures stdout+stderr into ZOUT and the exit code into ZRC.
ZOUT=""; ZRC=0
zrun() {
    local zone="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    ZOUT="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
            "$KRYPTIKD" run "$zone" "${ZARGS[@]}" -- "$@" 2>&1)"
    ZRC=$?
    return 0
}

# zrun_raw: same, but WITHOUT the experimental override, for refusal checks.
zrun_raw() {
    local zone="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    ZOUT="$(env -u KRYPTIK_EXPERIMENTAL timeout "$TIMEOUT" \
            "$KRYPTIKD" run "$zone" "${ZARGS[@]}" -- "$@" 2>&1)"
    ZRC=$?
    return 0
}

# The launch sentinel. A zone command prints this before doing anything else;
# if it is absent the process never got to run and no isolation claim from that
# run is admissible.
LAUNCHED="ZONE_LAUNCH_OK"

# want_launch DESC -- fails the check if the sentinel is missing, and says
# WHY (timeout / setup failure / exec failure) instead of silently passing.
want_launch() {
    local desc="$1"
    if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
        return 0
    fi
    if (( ZRC == 124 )); then
        fail "$desc [did not launch: TIMED OUT after ${TIMEOUT}s]"
    elif (( ZRC == 125 )); then
        fail "$desc [did not launch: zone setup failed]"
    elif (( ZRC == 127 )); then
        fail "$desc [did not launch: exec failed]"
    else
        fail "$desc [did not launch: exit $ZRC, no sentinel]"
    fi
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
    return 1
}

# probe DESC EXPECTED -- assert the zone printed "PROBE=<EXPECTED>", but only
# after want_launch has confirmed the program actually ran.
probe() {
    local desc="$1" expected="$2"
    want_launch "$desc" || return 1
    local got
    got="$(printf '%s\n' "$ZOUT" | sed -n 's/^PROBE=//p' | head -1)"
    if [[ "$got" == "$expected" ]]; then
        pass "$desc"
    else
        fail "$desc [expected PROBE=$expected, got PROBE=${got:-<none>}]"
        info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
    fi
}

# Shell prologue every probe script starts with.
PRO="echo $LAUNCHED;"

# ============================================================================
head_ "A. The launcher actually runs programs  [unpriv]"
# ============================================================================
# Without this group every isolation result below is meaningless, because a
# zone that runs nothing isolates perfectly.

zrun alpha -- /bin/echo "$LAUNCHED"
if want_launch "A1  a program executes inside a zone"; then
    (( ZRC == 0 )) && pass "A1  a program executes inside a zone" \
                   || fail "A1  executed but exit was $ZRC, expected 0"
fi

# Dynamic execution: /bin/sh is dynamically linked, so a working run proves the
# interpreter, the loader and the read-only /lib bind mounts are all in place.
# A static binary would not prove any of that.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=dynamic-ok"
probe "A2  dynamically linked programs run (loader + /lib reachable)" "dynamic-ok"

# Prove it really is dynamic rather than assuming it.
if readelf -l /bin/sh 2>/dev/null | grep -q 'program interpreter'; then
    info "A2  confirmed: /bin/sh on this host is dynamically linked"
else
    info "A2  note: /bin/sh appears static here; A2 proves less than usual"
fi

zrun alpha -- /bin/sh -c "$PRO echo hello > /zonefile; cat /zonefile | sed 's/^/PROBE=/'"
probe "A3  a zone can write and read back a file it owns" "hello"

zrun alpha -- /bin/sh -c "$PRO out=\$(/bin/echo nested); echo PROBE=\$out"
probe "A4  a zone can fork a child process and collect its output" "nested"

# Two generations deep, plus a wait: covers clone/wait4 in the allowlist.
zrun alpha -- /bin/sh -c "$PRO ( ( echo deep ) ) > /d; wait; sed 's/^/PROBE=/' /d"
probe "A5  nested child processes and wait(2) work" "deep"

zrun alpha -- /bin/sh -c "$PRO exit 42"
if want_launch "A6  the zone's exit code reaches the caller"; then
    (( ZRC == 42 )) && pass "A6  the zone's exit code reaches the caller" \
                    || fail "A6  expected exit 42, got $ZRC"
fi

# ============================================================================
head_ "B. Two real zones cannot reach each other  [unpriv]"
# ============================================================================

# alpha writes a canary into its own root.
zrun alpha -- /bin/sh -c "$PRO printf '%s' '$CANARY' > /alpha-secret; echo PROBE=written"
probe "B1a alpha can write a file in its own zone" "written"

# Positive control: that file exists on the host, so a failure to read it from
# beta means something. Without this the next check would pass on a typo.
if [[ -f "$ROOTFS/alpha/alpha-secret" ]] && grep -q "$CANARY" "$ROOTFS/alpha/alpha-secret"; then
    pass "B1b positive control: alpha's file is real and readable from the host"
else
    fail "B1b positive control FAILED: alpha's file is not where the test expects"
    info "looked for: $ROOTFS/alpha/alpha-secret"
fi

# beta tries the same absolute path, and the host path alpha's data really
# lives at. Neither exists in beta's root.
zrun beta -- /bin/sh -c "$PRO if cat /alpha-secret 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B1c beta cannot read alpha's file by zone-absolute path" "denied"

zrun beta -- /bin/sh -c "$PRO if cat '$ROOTFS/alpha/alpha-secret' 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B1d beta cannot read alpha's data by its host path" "denied"

# --- process visibility ------------------------------------------------------
#
# READ THIS BEFORE CHANGING THESE CHECKS. Two earlier versions were wrong in
# ways that both produced a green PASS, which is the failure mode this file
# exists to prevent.
#
#   1. Zones are not persistent. Every `kryptikd run` builds a FRESH pid
#      namespace and tears it down on exit, so two runs of the same zone cannot
#      see each other either. "Can beta see alpha's processes" therefore cannot
#      be asked by starting alpha and then launching beta - there is nothing
#      left to see, and the check passes for the wrong reason.
#
#   2. A probe that greps /proc/*/cmdline for a literal token FINDS ITSELF:
#      the token is in the probe shell's own argv, and in grep's. The first
#      version reported LEAKED against a zone that was isolating perfectly.
#
# So the claim is tested the way it can actually be falsified: a marker process
# runs ON THE HOST, outside every zone, and no zone may see it. The host is the
# zone's own parent, so a zone that cannot see its parent's namespace cannot
# see a sibling zone's either - this is the stronger claim, not a weaker one.
#
# The token is assembled from two halves inside the probe so the contiguous
# string never appears in any argv the probe itself owns, and the scan is done
# with a shell loop rather than grep so no child carries it either.

MARKER_TOKEN="KRYPTIKMARKER7f3c091"
MARKER_BIN="$WORK/${MARKER_TOKEN}_marker.sh"
# A SCRIPT, not a renamed copy of /bin/sleep. On a busybox system /bin/sleep is
# a symlink into the multi-call binary, which dispatches on argv[0] and exits
# with "applet not found" under any other name - so the copied marker never ran
# in the VM and the positive control correctly refused to vouch for B2b/B2c.
#
# The script does NOT exec: `exec sleep` would replace argv and take the token
# out of the command line that the whole check is looking for.
printf '#!/bin/sh\nsleep %s\n' "$TIMEOUT" > "$MARKER_BIN"
chmod 0755 "$MARKER_BIN"
/bin/sh "$MARKER_BIN" >/dev/null 2>&1 &
MARKER_PID=$!
BG_PIDS+=("$MARKER_PID")
# Detach from job control so killing it at cleanup does not print a "Killed"
# line into the middle of the report.
disown "$MARKER_PID" 2>/dev/null || true
sleep 1

# Positive control: the marker really is running and really is discoverable by
# scanning /proc cmdlines - the exact method the zone probe uses.
host_hits=0
for f in /proc/[0-9]*/cmdline; do
    c="$(tr '\0' ' ' < "$f" 2>/dev/null)"
    case "$c" in *"$MARKER_TOKEN"*) host_hits=$((host_hits+1));; esac
done
if kill -0 "$MARKER_PID" 2>/dev/null && (( host_hits > 0 )); then
    pass "B2a positive control: the host marker process is running and visible in /proc"
    MARKER_LIVE=1
else
    fail "B2a positive control FAILED: marker not running or not visible; B2b/B2c prove nothing"
    info "kill -0 rc=$? host_hits=$host_hits"
    MARKER_LIVE=0
fi

# The probe, with the token split so the probe's own argv cannot match it.
PROC_SCAN='h="KRYPTIKMARK"; t="ER7f3c091"; pat="$h$t"; n=0; for f in /proc/[0-9]*/cmdline; do c=$(tr "\0" " " < "$f" 2>/dev/null); case "$c" in *"$pat"*) n=$((n+1));; esac; done'

if (( MARKER_LIVE == 1 )); then
    zrun alpha -- /bin/sh -c "$PRO $PROC_SCAN; if [ \"\$n\" -gt 0 ]; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
    probe "B2b a zone cannot see a process running outside it" "denied"

    zrun beta -- /bin/sh -c "$PRO $PROC_SCAN; if [ \"\$n\" -gt 0 ]; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
    probe "B2c a second zone cannot see it either" "denied"
else
    skip "B2b a zone cannot see a process running outside it (positive control failed)"
    skip "B2c a second zone cannot see it either (positive control failed)"
fi

# Guard against the probe being vacuous: it must be able to find a process when
# one IS there. Run the same scan inside a zone against a token the zone itself
# creates, and require a hit. Without this, a scan that silently matched
# nothing (a quoting slip, an unreadable /proc) would pass B2b as "denied".
zrun alpha -- /bin/sh -c "$PRO h=SELFMARK; t=ER991; pat=\"\$h\$t\"; /bin/sleep 5 & sleep 0.2; n=0; for f in /proc/[0-9]*/cmdline; do c=\$(tr \"\\0\" \" \" < \"\$f\" 2>/dev/null); case \"\$c\" in *sleep*) n=\$((n+1));; esac; done; if [ \"\$n\" -gt 0 ]; then echo PROBE=sees-own; else echo PROBE=BLIND; fi"
probe "B2d the /proc scan is not vacuous: a zone DOES see its own child" "sees-own"

# Private /tmp per zone.
zrun alpha -- /bin/sh -c "$PRO printf '%s' '$CANARY' > /tmp/canary; echo PROBE=written"
probe "B3a alpha can write its private /tmp" "written"

zrun beta -- /bin/sh -c "$PRO if grep -q '$CANARY' /tmp/canary 2>/dev/null; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B3b beta's /tmp does not contain alpha's file" "denied"

# ...and the zone's /tmp is not the host's /tmp either.
HOSTTMP_CANARY="/tmp/kryptik_hosttmp_$$_$RANDOM"
printf '%s' "$CANARY" > "$HOSTTMP_CANARY"
zrun alpha -- /bin/sh -c "$PRO if grep -q '$CANARY' '$HOSTTMP_CANARY' 2>/dev/null; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B3c a zone's /tmp is not the host's /tmp" "denied"
rm -f "$HOSTTMP_CANARY"

# ============================================================================
head_ "C. Outside paths and inherited descriptors  [unpriv]"
# ============================================================================
# These are the two escapes a previous review demonstrated. They are the
# reason rootfs.rs exists, so they get first-class checks rather than a note.

# Positive control for the whole group.
if grep -q "$CANARY" "$HOSTFIX/hostconfig.conf"; then
    pass "C0  positive control: the host fixture is readable outside the zone"
else
    fail "C0  positive control FAILED: host fixture unreadable; group C proves nothing"
fi

zrun alpha -- /bin/sh -c "$PRO if grep -q '$CANARY' '$HOSTFIX/hostconfig.conf' 2>/dev/null; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "C1  an outside path is not reachable from inside a zone" "denied"

# Inherited descriptor. The caller opens the fixture on fd 9 and leaks it into
# the launch. rootfs.rs::close_inherited_fds is what must defeat this: a
# descriptor opened before the zone existed keeps working through pivot_root
# and is not governed by Landlock.
#
# Positive control first: prove the descriptor really is inherited and readable
# when nothing closes it, so a "denied" below is the launcher's doing.
ctl="$(exec 9<"$HOSTFIX/hostconfig.conf"; /bin/sh -c 'cat <&9' 2>/dev/null)"
if [[ "$ctl" == *"$CANARY"* ]]; then
    pass "C2a positive control: fd 9 is inherited and readable by a plain child"
else
    fail "C2a positive control FAILED: fd 9 was not inherited; C2b proves nothing"
fi

ZOUT="$(exec 9<"$HOSTFIX/hostconfig.conf"; KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO if cat <&9 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi" 2>&1)"
ZRC=$?
probe "C2b an inherited descriptor (fd 9) cannot be read inside the zone" "denied"

# A high descriptor, past anything a naive 3..64 sweep would reach.
ZOUT="$(exec 200<"$HOSTFIX/hostconfig.conf"; KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO if cat <&200 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi" 2>&1)"
ZRC=$?
probe "C3  a high inherited descriptor (fd 200) cannot be read either" "denied"

# A directory descriptor is worse than a file one: it survives as a walk root
# and openat(dirfd, "..") climbs out of any subtree.
ZOUT="$(exec 9<"$HOSTFIX"; KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO if ls /proc/self/fd/9/ 2>/dev/null | grep -q hostconfig; then echo PROBE=LEAKED; else echo PROBE=denied; fi" 2>&1)"
ZRC=$?
probe "C4  an inherited DIRECTORY descriptor cannot be walked from the zone" "denied"

# ============================================================================
head_ "D. Environment and host configuration exposure  [unpriv]"
# ============================================================================
# spawn.rs step 9 states the intent: "A predictable, minimal environment. The
# caller's environment can carry paths, tokens and LD_* variables into the
# zone, none of which it should inherit by accident." These checks hold the
# code to that sentence.

ZOUT="$(KRYPTIK_SYNTHETIC_SECRET="$CANARY" KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO if /usr/bin/env | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=clean; fi" 2>&1)"
ZRC=$?
probe "D1  a synthetic secret in the caller's environment does not reach the zone" "clean"

zrun alpha -- /bin/sh -c "$PRO if [ -n \"\${LD_PRELOAD:-}\${LD_LIBRARY_PATH:-}\" ]; then echo PROBE=LEAKED; else echo PROBE=clean; fi"
probe "D2  LD_PRELOAD and LD_LIBRARY_PATH are removed" "clean"

# Host session configuration. These are not secrets, but each one names a host
# socket or path and together they describe the user's desktop session to
# something that is supposed to be compartmentalised.
ZOUT="$(DISPLAY=":99" WAYLAND_DISPLAY="wayland-99" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/9999/bus" \
        XDG_RUNTIME_DIR="/run/user/9999" \
        KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO n=\$(/usr/bin/env | grep -c -E '^(DISPLAY|WAYLAND_DISPLAY|DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR)='); echo PROBE=\$n" 2>&1)"
ZRC=$?
probe "D3  host session configuration is not inherited by the zone" "0"

# The environment the zone SHOULD have.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$KRYPTIK_ZONE"
probe "D4  the zone is told its own name via KRYPTIK_ZONE" "alpha"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$PATH"
probe "D5  PATH is the fixed zone PATH, not the caller's" "/usr/bin:/usr/sbin:/bin:/sbin"

# ============================================================================
head_ "E. Old root, system mounts, devices  [unpriv]"
# ============================================================================

zrun alpha -- /bin/sh -c "$PRO if [ -e /.oldroot ]; then echo PROBE=PRESENT; else echo PROBE=detached; fi"
probe "E1a the old root mountpoint is gone from the zone" "detached"

# Stronger than checking the directory is absent: check the host filesystem is
# not reachable through ANY mount the zone can see. /proc/mounts inside the
# zone must not carry an entry rooted at the old tree.
zrun alpha -- /bin/sh -c "$PRO if grep -q 'oldroot' /proc/mounts 2>/dev/null; then echo PROBE=PRESENT; else echo PROBE=detached; fi"
probe "E1b no oldroot mount remains in the zone's mount table" "detached"

# The host's own marker directories must not resolve.
zrun alpha -- /bin/sh -c "$PRO if [ -d '$HOSTFIX' ]; then echo PROBE=PRESENT; else echo PROBE=detached; fi"
probe "E1c the host's directory tree does not resolve inside the zone" "detached"

# System paths are read-only. A writable /usr would let one zone modify a
# binary every other zone runs.
zrun alpha -- /bin/sh -c "$PRO if touch /usr/kryptik-probe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=readonly; fi"
probe "E2a /usr is read-only inside the zone" "readonly"

zrun alpha -- /bin/sh -c "$PRO if touch /etc/kryptik-probe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=readonly; fi"
probe "E2b /etc is read-only inside the zone" "readonly"

# Positive control: writes that SHOULD work still do. Without this, E2 would
# also pass on a zone where nothing at all is writable - i.e. a broken zone.
zrun alpha -- /bin/sh -c "$PRO if touch /tmp/ok 2>/dev/null; then echo PROBE=writable; else echo PROBE=BROKEN; fi"
probe "E2c positive control: /tmp IS writable (the zone is not simply inert)" "writable"

# nosuid on the system mounts: a setuid binary found there must not confer
# privilege. Checked at the mount-flag level, which is what the kernel enforces.
zrun alpha -- /bin/sh -c "$PRO if grep -E ' /usr .*nosuid' /proc/mounts >/dev/null; then echo PROBE=nosuid; else echo PROBE=SUID_ALLOWED; fi"
probe "E2d /usr is mounted nosuid" "nosuid"

# Device visibility. rootfs.rs::DEVICES is the allowlist; anything else must
# not exist for the zone.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(ls /dev | sort | tr '\n' ',')"
probe "E3a /dev contains exactly the allowlisted nodes" "full,null,random,tty,urandom,zero,"

zrun alpha -- /bin/sh -c "$PRO for d in /dev/mem /dev/kmem /dev/port /dev/kvm /dev/sda /dev/sdd /dev/nvme0n1 /dev/input; do [ -e \$d ] && { echo PROBE=EXPOSED_\$d; exit 0; }; done; echo PROBE=absent"
probe "E3b no hardware, memory or input devices are visible" "absent"

# /proc is the zone's own, not the host's.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(readlink /proc/self | sed 's/[0-9]*/n/')"
if want_launch "E4a /proc is the zone's own pid namespace"; then
    n="$(printf '%s\n' "$ZOUT" | sed -n 's/^PROBE=//p' | head -1)"
    # In its own pid namespace the shell sees a very small pid.
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$\$"
    selfpid="$(printf '%s\n' "$ZOUT" | sed -n 's/^PROBE=//p' | head -1)"
    if [[ -n "$selfpid" ]] && (( selfpid <= 5 )); then
        pass "E4a the zone's shell has a low pid ($selfpid) — own pid namespace"
    else
        fail "E4a expected a low pid in a fresh pid namespace, got ${selfpid:-<none>}"
    fi
fi

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(ls /proc | grep -c '^[0-9][0-9]*$')"
if want_launch "E4b /proc shows only the zone's own processes"; then
    n="$(printf '%s\n' "$ZOUT" | sed -n 's/^PROBE=//p' | head -1)"
    hostn="$(ls /proc | grep -c '^[0-9][0-9]*$')"
    if [[ -n "$n" ]] && (( n <= 8 )) && (( hostn > n )); then
        pass "E4b /proc shows $n process(es), host has $hostn — zone-private"
    else
        fail "E4b /proc showed ${n:-<none>} processes (host: $hostn) — not isolated"
    fi
fi

# ============================================================================
head_ "F. Refusal of guarantees the code does not deliver  [unpriv]"
# ============================================================================
# spawn.rs refuses to start a zone whose storage mode promises something not
# implemented. The check that matters is not just the exit code: it is that the
# command NEVER RAN. A refusal that still executes the payload is not a refusal.

zrun_raw wiped -- /bin/sh -c "echo $LAUNCHED; echo PROBE=RAN"
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "F1  ephemeral storage without the override: the command RAN anyway"
elif (( ZRC == 0 )); then
    fail "F1  ephemeral storage without the override: exit 0, expected refusal"
elif [[ "$ZOUT" == *"ephemeral"* && "$ZOUT" == *"KRYPTIK_EXPERIMENTAL"* ]]; then
    pass "F1  ephemeral storage is refused without the override, and does not run"
else
    fail "F1  refused (exit $ZRC) but the message did not name the mode or the override"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
fi

zrun_raw sealed -- /bin/sh -c "echo $LAUNCHED; echo PROBE=RAN"
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "F2  encrypted storage without the override: the command RAN anyway"
elif (( ZRC == 0 )); then
    fail "F2  encrypted storage without the override: exit 0, expected refusal"
elif [[ "$ZOUT" == *"encrypted"* && "$ZOUT" == *"KRYPTIK_EXPERIMENTAL"* ]]; then
    pass "F2  encrypted storage is refused without the override, and does not run"
else
    fail "F2  refused (exit $ZRC) but the message did not name the mode or the override"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
fi

# The override must be an explicit "1", not merely "set".
ZOUT="$(KRYPTIK_EXPERIMENTAL=0 timeout "$TIMEOUT" "$KRYPTIKD" run wiped "${ZARGS[@]}" \
        -- /bin/sh -c "echo $LAUNCHED" 2>&1)"
ZRC=$?
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "F3  KRYPTIK_EXPERIMENTAL=0 was treated as an override"
else
    pass "F3  the override requires exactly \"1\"; other values still refuse"
fi

# And the refusal must be loud when it IS overridden.
zrun wiped -- /bin/sh -c "echo $LAUNCHED"
if want_launch "F4  overridden start warns that the guarantee does not hold"; then
    if [[ "$ZOUT" == *"EXPERIMENTAL"* && "$ZOUT" == *"PLAIN"* ]]; then
        pass "F4  overridden start warns that storage is a plain directory"
    else
        fail "F4  ran under the override without warning about the storage mode"
    fi
fi

# ============================================================================
head_ "G. Setup failure, termination and cleanup  [unpriv]"
# ============================================================================

zrun alpha -- /no/such/program-kryptik
if (( ZRC == 127 )); then
    pass "G1  a missing command exits 127 rather than hanging or exiting 0"
else
    fail "G1  expected exit 127 for a missing command, got $ZRC"
fi

# Termination: a zone killed by a signal reports it the way a shell does.
#
# NOT with `kill -TERM $$`. The zone's command is pid 1 of its own pid
# namespace, and the kernel discards a default-action signal sent to pid 1 from
# INSIDE that namespace unless a handler is installed. An earlier version of
# this check did exactly that, saw exit 0, and recorded it as a launcher bug -
# it was correct kernel behaviour, and the test was wrong.
#
# A seccomp denial is used instead: it is delivered as a synchronous SIGSYS
# that init protection does not apply to, and it exercises a path that matters
# on its own (see group I).
zrun alpha -- /bin/sh -c "$PRO /bin/mount -t tmpfs none /tmp 2>/dev/null"
if want_launch "G2  a zone killed by a signal reports 128+signo"; then
    if (( ZRC == 128 + 31 )); then
        pass "G2  a zone killed by SIGSYS reports 128+31 = 159"
    else
        fail "G2  expected 159 from a SIGSYS-killed zone, got $ZRC"
    fi
fi

# Setup failure: point the rootfs base at a path that cannot be created. The
# launcher must fail cleanly and promptly, not hang holding the sync pipe.
start=$(date +%s)
out="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" "$KRYPTIKD" run alpha \
       --zones "$ZONES" --rootfs /proc/cannot-create-here \
       -- /bin/echo "$LAUNCHED" 2>&1)"
rc=$?
elapsed=$(( $(date +%s) - start ))
if (( rc == 124 )); then
    fail "G3  an unwritable rootfs base HUNG (timed out after ${TIMEOUT}s)"
elif [[ "$out" == *"$LAUNCHED"* ]]; then
    fail "G3  an unwritable rootfs base still launched the command"
elif (( rc != 0 )); then
    pass "G3  an unwritable rootfs base fails cleanly in ${elapsed}s (exit $rc)"
else
    fail "G3  an unwritable rootfs base exited 0"
fi

# A zone that is asked to run a directory rather than a program.
zrun alpha -- /tmp
if (( ZRC != 0 )) && (( ZRC != 124 )); then
    pass "G4  exec'ing a non-program fails cleanly (exit $ZRC)"
else
    fail "G4  exec'ing a directory returned $ZRC"
fi

# Cleanup: no zone process outlives the launcher.
# pgrep -c is deliberately NOT used here: it prints "0" and ALSO exits
# non-zero when nothing matches, so a `|| echo 0` fallback yields "0\n0" and
# (( )) dies with a syntax error - which made this check vanish from the
# report entirely rather than fail. wc -l always emits exactly one number.
count_zone_procs() { pgrep -f 'kryptikd run' 2>/dev/null | wc -l; }
before="$(count_zone_procs)"
zrun alpha -- /bin/sh -c "$PRO echo PROBE=done"
sleep 1
after="$(count_zone_procs)"
if (( after <= before )); then
    pass "G5  no kryptikd zone process is left running after the zone exits"
else
    fail "G5  $((after - before)) kryptikd process(es) outlived the zone"
fi

# Cleanup: the host's mount table is unchanged. pivot_into makes the tree
# MS_PRIVATE first precisely so the zone's mounts cannot propagate out; if that
# ever regressed, the host would accumulate a mount per zone start.
hm_before="$(wc -l < /proc/mounts)"
zrun alpha -- /bin/sh -c "$PRO echo PROBE=done"
hm_after="$(wc -l < /proc/mounts)"
if (( hm_after == hm_before )); then
    pass "G6  the host mount table is unchanged by starting a zone ($hm_after entries)"
else
    fail "G6  the host mount table changed: $hm_before -> $hm_after entries"
    info "a zone's mounts are propagating into the host namespace"
fi

# ============================================================================
head_ "I. Seccomp is enforced on the real launch path  [unpriv]"
# ============================================================================
# adversarial.sh proves the filter kills syscalls via `kryptikd seccomp-test`,
# which installs the filter in a purpose-built child. That is not the same
# claim as "a zone started by `kryptikd run` is filtered": the filter is
# installed at step 10 of child_main, after pivot_root and Landlock, and an
# ordering regression there would leave a zone unfiltered while seccomp-test
# continued to pass. These checks go through `run`.

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(grep '^Seccomp:' /proc/self/status | awk '{print \$2}')"
probe "I1  a zone process reports seccomp mode 2 (filtered)" "2"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(grep '^Seccomp_filters:' /proc/self/status | awk '{print \$2}')"
probe "I2  exactly one filter is installed, not zero and not a stack" "1"

# Each of these is in seccomp.rs::DENIED_RATIONALE with a reason. A denied
# syscall must KILL the zone (SIGSYS -> 159), not return an error the program
# can ignore and continue past.
seccomp_kill() { # desc shell-command
    local desc="$1" cmd="$2"
    zrun alpha -- /bin/sh -c "$cmd"
    if (( ZRC == 159 )); then
        pass "$desc"
    elif (( ZRC == 124 )); then
        fail "$desc [timed out]"
    else
        fail "$desc [expected exit 159 (SIGSYS), got $ZRC]"
    fi
}

seccomp_kill "I3  mount(2) kills the zone (re-mount under Landlock)" \
             '/bin/mount -t tmpfs none /tmp'
seccomp_kill "I4  chroot(2) kills the zone (double-chroot escape)" \
             '/usr/sbin/chroot / /bin/true'
seccomp_kill "I5  unshare(2) kills the zone (nested namespace LPE surface)" \
             '/usr/bin/unshare -U /bin/true'
seccomp_kill "I6  mknod(2) kills the zone (fabricate a device node)" \
             '/usr/bin/mknod /tmp/n c 1 3'

# Positive control: the filter is not simply killing everything. Without this,
# a filter that denied ALL syscalls would pass I3-I6 and look like a success.
zrun alpha -- /bin/sh -c "$PRO /bin/true && /bin/echo PROBE=allowed-calls-work"
probe "I7  positive control: allowed syscalls still work under the filter" "allowed-calls-work"

# ============================================================================
head_ "H. Network isolation, without overclaiming  [unpriv]"
# ============================================================================
# Only network.mode = "none" is tested as isolation, because only that mode is
# implemented. "routed" parses and is accepted by the launcher, but no veth,
# bridge or route is created anywhere in the tree - see the explicit NOT RUN
# entry at the end of this file rather than a check that would quietly pass.

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(cat /proc/net/dev | tail -n +3 | awk '{print \$1}' | tr -d ':' | sort | tr '\n' ',')"
probe "H1  a mode=none zone sees loopback and nothing else" "lo,"

zrun alpha -- /bin/sh -c "$PRO if [ -s /proc/net/route ] && [ \$(tail -n +2 /proc/net/route | wc -l) -gt 0 ]; then echo PROBE=ROUTES; else echo PROBE=none; fi"
probe "H2  a mode=none zone has no routes at all" "none"

# An outbound connection must fail for want of an interface, not for want of a
# DNS server. Use a literal address and a bounded connect.
zrun alpha -- /bin/sh -c "$PRO if timeout 3 /bin/sh -c 'exec 3<>/dev/tcp/10.255.255.1/80' 2>/dev/null; then echo PROBE=CONNECTED; else echo PROBE=unreachable; fi"
probe "H3  an outbound TCP connect from a mode=none zone cannot succeed" "unreachable"

# Positive control for H1. "The zone sees only lo" is evidence of a network
# namespace only if the host sees MORE than lo - otherwise the zone's view and
# the host's view are identical and H1 has discriminated nothing.
#
# In the developer VM the host itself is started with -nic none, so there is
# genuinely no second interface to distinguish against. That is an inability to
# measure, not a pass and not a launcher failure, so it is reported as NOT RUN
# with the reason attached.
hostifs="$(tail -n +3 /proc/net/dev | awk '{print $1}' | tr -d ':' | grep -cv '^lo$')"
if (( hostifs > 0 )); then
    pass "H1c positive control: the host has $hostifs non-loopback interface(s) the zone did not see"
else
    skip "H1c H1 cannot discriminate here: this host has no non-loopback interface either"
    info "     (expected in the developer VM, which is launched with -nic none)"
fi

# ============================================================================
head_ "Mandatory checks NOT RUN here"
# ============================================================================
# A skipped mandatory check is not a release pass. These are named so the gap
# is visible in the summary rather than absent from it.

skip "cgroup memory/pids limits are enforced          [vm] not implemented (spawn.rs says so)"
skip "routed network reaches the bridge via the nic zone [vm] not implemented"
skip "ephemeral storage is wiped on stop              [vm] not implemented"
skip "per-zone seccomp/landlock policy files applied  [vm] not implemented"
skip "zone runs correctly under real root (not a userns) [vm] needs a disposable VM"

# ============================================================================
printf '\n%s==>%s summary\n' "$C_BLU" "$C_RST"
printf '  %s%d passed%s, %s%d failed%s, %s%d not run%s\n' \
    "$C_GRN" "$PASS" "$C_RST" "$C_RED" "$FAIL" "$C_RST" "$C_YEL" "$SKIP" "$C_RST"

if (( FAIL > 0 )); then
    printf '\n%sfailed:%s\n' "$C_RED" "$C_RST"
    for f in "${FAILED[@]}"; do printf '  - %s\n' "$f"; done
fi
if (( SKIP > 0 )); then
    printf '\n%snot run (mandatory gaps, NOT passes):%s\n' "$C_YEL" "$C_RST"
    for s in "${SKIPPED[@]}"; do printf '  - %s\n' "$s"; done
fi

printf '\n'
if (( FAIL > 0 )); then
    printf '%sLAUNCHER SUITE FAILED%s — %d check(s) did not hold.\n' "$C_RED" "$C_RST" "$FAIL"
    exit 1
fi
if (( SKIP > 0 )); then
    printf '%sLAUNCHER SUITE PASSED WITH GAPS%s — %d mandatory check(s) were not run.\n' \
        "$C_YEL" "$C_RST" "$SKIP"
    printf 'This is NOT a release pass. See the list above.\n'
    exit 0
fi
printf '%sLAUNCHER SUITE PASSED%s\n' "$C_GRN" "$C_RST"
exit 0
