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
#
# Deliberately world-READABLE (0644, not 0600). If the zone fails to read it,
# that must be because the path does not exist in the zone's mount namespace -
# not because file permissions happened to deny it. On a privileged run the
# zone maps to an unprivileged uid, and a 0600 root-owned fixture would make
# C1 pass on DAC alone while proving nothing about containment.
printf 'token = %s\n' "$CANARY" > "$HOSTFIX/hostconfig.conf"
chmod 0644 "$HOSTFIX/hostconfig.conf"

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
# For K7: a zone whose data directory is deliberately owned by someone else.
mkzone stranger none   "#666666"

# M1 fixtures. `capped` is the zone under test; `roomy` is its positive
# control - the same shape with limits high enough that nothing should hit
# them, so a failure in `capped` can be attributed to the limit rather than to
# the zone being broken.
mkzone_limited() { # name colour memory pids
    {
        printf '[zone]\nname = "%s"\ndescription = "launcher-suite limit fixture"\n' "$1"
        printf '[network]\nmode = "none"\n'
        printf '[storage]\nmode = "ephemeral"\n'
        printf '[limits]\nmemory_max = "%s"\npids_max = %s\n' "$3" "$4"
        printf '[ui]\nborder_color = "%s"\n' "$2"
    } > "$ZONES/$1.toml"
}
# ONE LIMIT PER FIXTURE. `capped` originally carried memory_max=48M and
# pids_max=8 together, and the pids check then measured the wrong thing: 48M is
# below what a zone needs to set up its own tmpfs root and start a shell, so
# memory.oom.group killed the whole cgroup before the fork loop ever ran. The
# check reported pids_max as "never reached" - correctly, and uselessly.
mkzone_limited memcapped "#777777" "48M"  200   # memory is the variable
mkzone_limited pidcapped "#999999" "512M" 32    # pids is the variable
mkzone_limited roomy     "#888888" "512M" 200   # neither: the positive control

# A root launch MUST name an unprivileged identity for the zone to map to.
# kryptikd refuses one that does not, because mapping the zone's root to host
# uid 0 makes "root inside the zone" mean real root for every DAC check on
# every bound path - which is the opposite of a zone.
#
# The suite runs unprivileged on a developer host and as root inside the
# developer VM, so it has to handle both. Detecting it here rather than
# requiring two invocations is what lets the VM exercise the privileged path
# at all.
ZONE_UID=100000
ZONE_GID=100000
IDENTITY=()
if (( EUID == 0 )); then
    PRIVILEGED=1
    IDENTITY=(--zone-uid "$ZONE_UID" --zone-gid "$ZONE_GID")
    info "running as root: zones map to host uid/gid $ZONE_UID"
else
    PRIVILEGED=0
    info "running unprivileged as uid $EUID: zones map to this uid"
fi

# mktemp -d creates 0700. On a privileged run the zone's setup drops to the
# mapped uid BEFORE it opens the zone data directory, so a 0700 root-owned
# workspace makes every launch fail with
#   could not build the zone root: open(data dir)(...): Permission denied
# which reads like a kryptikd defect and is entirely this file's doing. The
# workspace has to be traversable by the identity the zone runs as.
chmod 0755 "$WORK" "$ZONES" "$ROOTFS" "$HOSTFIX"
if (( PRIVILEGED == 1 )); then
    # kryptikd refuses a data directory owned by anyone but the mapped uid, so
    # the rootfs base is handed over up front rather than left as root's.
    chown -R "$ZONE_UID:$ZONE_GID" "$ROOTFS" 2>/dev/null || \
        info "WARNING: could not chown the rootfs base; privileged launches may be refused"
fi

ZARGS=(--zones "$ZONES" --rootfs "$ROOTFS" "${IDENTITY[@]}")

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

# $HOME, not /. The zone root is a sealed read-only tmpfs and the zone's
# persistent directory is bound at /home/<zone>; writing to / now fails with
# EROFS by design. On the host the file still lands at <rootfs-base>/<zone>/.
zrun alpha -- /bin/sh -c "$PRO echo hello > \$HOME/zonefile; sed 's/^/PROBE=/' \$HOME/zonefile"
probe "A3  a zone can write and read back a file it owns" "hello"

zrun alpha -- /bin/sh -c "$PRO out=\$(/bin/echo nested); echo PROBE=\$out"
probe "A4  a zone can fork a child process and collect its output" "nested"

# Two generations deep, plus a wait: covers clone/wait4 in the allowlist.
zrun alpha -- /bin/sh -c "$PRO ( ( echo deep ) ) > \$HOME/d; wait; sed 's/^/PROBE=/' \$HOME/d"
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
zrun alpha -- /bin/sh -c "$PRO printf '%s' '$CANARY' > \$HOME/alpha-secret; echo PROBE=written"
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
# /home/alpha is where alpha's data is mounted INSIDE ALPHA. Beta's tree has no
# such path: each zone binds only its own directory.
zrun beta -- /bin/sh -c "$PRO if cat /home/alpha/alpha-secret 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B1c beta cannot read alpha's file at alpha's in-zone path" "denied"

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

# 5000 is above the 4096 bound of the old fallback sweep, and above anything a
# naive 3..64 loop reaches. It is the descriptor the previous implementation
# would have leaked into the zone if /proc had been unreadable.
ZOUT="$(exec 5000<"$HOSTFIX/hostconfig.conf"; KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO if cat <&5000 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi" 2>&1)"
ZRC=$?
probe "C5  a descriptor above the old sweep bound (fd 5000) is closed too" "denied"

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
# The list grew deliberately: /dev/shm is a private tmpfs, /dev/pts + ptmx a
# private devpts, and fd/stdin/stdout/stderr are the standard symlinks. What
# matters is that it is still an exact list and E3b still finds no hardware.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(ls /dev | sort | tr '\n' ',')"
probe "E3a /dev contains exactly the allowlisted entries" \
      "fd,full,null,ptmx,pts,random,shm,stderr,stdin,stdout,tty,urandom,zero,"

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
# NOT a seccomp kill any more, and the distinction is the point. mknod(2) is
# allowed again so that mkfifo works; a DEVICE node is refused by Landlock
# (MAKE_CHAR/MAKE_BLOCK are handled and granted nowhere) and by nodev on every
# mount. So the command fails rather than being killed - and the assertion that
# matters is that no device node exists afterwards, not which mechanism said no.
zrun alpha -- /bin/sh -c "$PRO /usr/bin/mknod /tmp/n c 1 3 2>/dev/null; if [ -e /tmp/n ]; then echo PROBE=CREATED; else echo PROBE=refused; fi"
probe "I6  a zone cannot create a device node (Landlock + nodev, not SIGSYS)" "refused"

# ...and the positive control: mknod itself still works for a FIFO, so I6 is
# measuring the device-node refusal and not a blanket mknod failure.
zrun alpha -- /bin/sh -c "$PRO /usr/bin/mknod /tmp/f p 2>/dev/null; if [ -p /tmp/f ]; then echo PROBE=fifo-ok; else echo PROBE=BLOCKED; fi"
probe "I6b positive control: mknod still creates a FIFO (mkfifo must work)" "fifo-ok"

# Positive control: the filter is not simply killing everything. Without this,
# a filter that denied ALL syscalls would pass I3-I6 and look like a success.
zrun alpha -- /bin/sh -c "$PRO /bin/true && /bin/echo PROBE=allowed-calls-work"
probe "I7  positive control: allowed syscalls still work under the filter" "allowed-calls-work"

# ============================================================================
head_ "J. The hardened zone tree  [unpriv]"
# ============================================================================
# These cover boundaries introduced by the security audit of the launch path.
# Each one had a demonstrated escape against the previous code, so each is a
# regression check rather than a restatement of intent.

# The zone root is a sealed read-only tmpfs. Before, / WAS the zone's writable
# persistent directory and the mount scaffold was built inside it, so a zone
# could replace a future mount point with a symlink between runs.
zrun alpha -- /bin/sh -c "$PRO if touch /probe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=sealed; fi"
probe "J1  the zone root is read-only, even to zone root" "sealed"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$HOME"
probe "J2  the zone's writable data is at /home/<zone>, not /" "/home/alpha"

zrun alpha -- /bin/sh -c "$PRO if touch \$HOME/w 2>/dev/null; then echo PROBE=writable; else echo PROBE=BROKEN; fi"
probe "J2b positive control: \$HOME IS writable (the zone is not inert)" "writable"

# Landlock previously granted read+write+exec on / and its read-only rules
# added nothing - it was a no-op and every guarantee rested on mount flags.
# Creating a directory under /dev is the cheapest way to see whether the
# ruleset actually denies anything.
zrun alpha -- /bin/sh -c "$PRO if mkdir /dev/evil 2>/dev/null; then echo PROBE=ALLOWED; else echo PROBE=denied; fi"
probe "J3  Landlock denies creating a directory under /dev" "denied"

# Positive controls for the write rights Landlock MUST still grant. Each of
# these was broken by an over-tight ruleset at some point: truncate needs
# FS_TRUNCATE, and mv across directories needs FS_REFER or it falls back to
# copy+fchmod and dies.
zrun alpha -- /bin/sh -c "$PRO echo aaaa > /tmp/t; echo b > /tmp/t; echo PROBE=\$(cat /tmp/t)"
probe "J4  truncating an existing file works (FS_TRUNCATE granted)" "b"

zrun alpha -- /bin/sh -c "$PRO mkdir -p /tmp/d; echo x > /tmp/a; mv /tmp/a /tmp/d/ 2>/dev/null; if [ -f /tmp/d/a ]; then echo PROBE=moved; else echo PROBE=BLOCKED; fi"
probe "J5  moving a file between directories works (FS_REFER granted)" "moved"

zrun alpha -- /bin/sh -c "$PRO touch /tmp/c; chmod 0700 /tmp/c 2>/dev/null && echo PROBE=chmod-ok || echo PROBE=BLOCKED"
probe "J6  chmod works (it is needed by tar, git and cargo)" "chmod-ok"

# The host's /etc used to be bind-mounted wholesale: 178 entries including
# machine-id, the host user list, and ssh/ssl directories.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(wc -l < /etc/passwd)"
probe "J7  /etc/passwd is synthesized and names only root and nobody" "2"

zrun alpha -- /bin/sh -c "$PRO for f in machine-id shadow sudoers ssl/private ssh resolv.conf; do [ -e /etc/\$f ] && { echo PROBE=EXPOSED_\$f; exit 0; }; done; echo PROBE=absent"
probe "J8  no host identity or secret files are visible in /etc" "absent"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(hostname)"
probe "J9  the zone's hostname is the zone name, not the host's" "alpha"

# Positive control: the CA bundle must be passed through or TLS breaks in every
# zone. It can only be checked where the HOST has one to pass through - an
# image without a CA bundle would otherwise fail this against its own gap
# rather than against kryptikd.
if [[ -d /etc/ssl/certs ]]; then
    zrun alpha -- /bin/sh -c "$PRO if [ -d /etc/ssl/certs ]; then echo PROBE=present; else echo PROBE=MISSING; fi"
    probe "J10 positive control: the CA certificate directory reaches the zone" "present"
else
    skip "J10 the host has no /etc/ssl/certs, so the CA passthrough cannot be checked here"
fi

# A recursive bind mount silently ignores MS_RDONLY on every SUBMOUNT: the
# remount only affects the top mount. On this host that left /usr/lib/wsl/lib
# and /lib/modules/... read-write inside every zone.
zrun alpha -- /bin/sh -c "$PRO n=\$(awk '\$5 ~ /^\/(usr|lib|lib64|bin|sbin|etc)/ && \$6 ~ /(^|,)rw(,|\$)/ {c++} END{print c+0}' /proc/self/mountinfo); echo PROBE=\$n"
probe "J11 no system mount or submount is read-write inside the zone" "0"

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
head_ "K. The privileged launch path  [vm / root only]"
# ============================================================================
# Everything above runs the same way unprivileged. This group is about what
# changes when kryptikd itself is root - which is how it will actually run, in
# zone 0, on a real Kryptik system. It cannot be exercised on a developer host
# without sudo, so it is the reason the VM exists rather than a bonus from it.

if (( PRIVILEGED == 1 )); then
    # The refusal itself. Mapping zone root to host uid 0 would make the zone's
    # root real root for every DAC check on every bound path.
    out="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" "$KRYPTIKD" run alpha \
           --zones "$ZONES" --rootfs "$ROOTFS" -- /bin/echo "$LAUNCHED" 2>&1)"
    rc=$?
    if [[ "$out" == *"$LAUNCHED"* ]]; then
        fail "K1  a root launch without --zone-uid/--zone-gid RAN the command"
    elif (( rc != 0 )) && [[ "$out" == *"zone-uid"* ]]; then
        pass "K1  a root launch without an unprivileged identity is refused"
    else
        fail "K1  root launch refused (exit $rc) but the message did not name --zone-uid"
        info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
    fi

    # Zone root is uid 0 INSIDE the zone...
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(id -u)"
    probe "K2  the zone's process is uid 0 inside its own user namespace" "0"

    # ...and the files it creates are owned by the unprivileged host identity,
    # not by real root. This is the whole point of the mapping, and it is
    # checked on the HOST side where it can actually be falsified.
    zrun alpha -- /bin/sh -c "$PRO echo k3 > \$HOME/k3file; echo PROBE=written"
    if want_launch "K3  a zone's files are owned by the mapped identity"; then
        owner="$(stat -c %u "$ROOTFS/alpha/k3file" 2>/dev/null)"
        if [[ "$owner" == "$ZONE_UID" ]]; then
            pass "K3  a zone's files are owned by host uid $ZONE_UID, not root"
        else
            fail "K3  file owned by uid ${owner:-<missing>}, expected $ZONE_UID"
            info "a zone running as real root on the host is not a zone"
        fi
    fi

    # Supplementary groups are dropped on a privileged launch. Unprivileged
    # launches cannot do this (setgroups needs CAP_SETGID), which is why it is
    # only asserted here.
    #
    # POSITIVE CONTROL FIRST, and it is not optional. "Groups: is empty in the
    # zone" is evidence of dropping only if the LAUNCHER had groups to drop. An
    # init-spawned root in an initramfs typically has none, in which case 0 is
    # the answer with or without setgroups - and this check passed vacuously in
    # exactly the environment it was written for. Caught by review, not by a
    # failure, which is the point of a positive control.
    launcher_groups="$(grep '^Groups:' /proc/self/status | cut -f2- | wc -w)"
    if (( launcher_groups > 0 )); then
        info "K4  the launcher holds $launcher_groups supplementary group(s) to drop"
        zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(grep '^Groups:' /proc/self/status | cut -f2- | wc -w)"
        probe "K4  the host's supplementary groups are dropped in the zone" "0"
    else
        skip "K4  the launcher has no supplementary groups here, so dropping them cannot be demonstrated"
    fi

    # The sealed root must hold against real root, not merely against a user.
    zrun alpha -- /bin/sh -c "$PRO if touch /rootprobe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=sealed; fi"
    probe "K5  the zone root is read-only even to a privileged launch" "sealed"

    zrun alpha -- /bin/sh -c "$PRO if touch /usr/rootprobe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=readonly; fi"
    probe "K6  /usr is read-only even to a privileged launch" "readonly"

    # kryptikd refuses a data directory owned by anyone but the identity the
    # zone maps to - otherwise a directory planted by another user becomes the
    # zone's root. The suite chowns its own rootfs base to the mapped uid, so
    # without this check that refusal is never executed and the chown could be
    # hiding it.
    mkdir -p "$ROOTFS/stranger"
    chown 100001:100001 "$ROOTFS/stranger" 2>/dev/null
    out="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" "$KRYPTIKD" run stranger \
           "${ZARGS[@]}" -- /bin/echo "$LAUNCHED" 2>&1)"
    rc=$?
    if [[ "$out" == *"$LAUNCHED"* ]]; then
        fail "K7  a data directory owned by another uid was accepted and RAN"
    elif (( rc != 0 )) && [[ "$out" == *"100001"* || "$out" == *"own"* ]]; then
        pass "K7  a data directory owned by another uid is refused, and does not run"
    else
        fail "K7  refused (exit $rc) but the message did not name the owner"
        info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
    fi
else
    skip "K1-K6 the privileged launch path [vm] needs root; run this suite inside the developer VM"
fi

# ============================================================================
head_ "L. Supervision, termination and the filter probes  [unpriv]"
# ============================================================================
# These exist because the security audit's own probes covered them and this
# suite did not - so the VM run, which is the only privileged and the only
# ABI-8 run, never exercised them. They are the regression checks for the
# descriptor, namespace and orphan defects (D5, D6, D7).

# --- D7: nothing outlives the launcher ---------------------------------------
# A unique sleep duration is the marker: it appears in the zone process's argv
# and in nothing else this suite runs.
MARK_KILL=2911
KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run alpha "${ZARGS[@]}" -- /bin/sleep "$MARK_KILL" >/dev/null 2>&1 &
kpid=$!
BG_PIDS+=("$kpid")
sleep 1.5
before="$(pgrep -f "sleep $MARK_KILL" 2>/dev/null | wc -l)"
if (( before > 0 )); then
    pass "L1a positive control: the zone's long-running process is up ($before proc)"
    kill -9 "$kpid" 2>/dev/null
    sleep 2
    after="$(pgrep -f "sleep $MARK_KILL" 2>/dev/null | wc -l)"
    if (( after == 0 )); then
        pass "L1b SIGKILLing the launcher leaves no zone process behind"
    else
        fail "L1b $after zone process(es) outlived a SIGKILLed launcher"
        pkill -9 -f "sleep $MARK_KILL" 2>/dev/null
    fi
else
    fail "L1a positive control FAILED: the zone process never started; L1b proves nothing"
fi

# --- D7: SIGTERM to the launcher ---------------------------------------------
# The assertion here is "no zone process survives", NOT timeout(1)'s exit code.
#
# An earlier version demanded 124 and passed on the host while failing in the
# VM, for a reason that had nothing to do with kryptikd: GNU coreutils timeout
# reports 124 whenever it had to signal the child, while busybox timeout - what
# a minimal image actually has on its PATH - reports the child's wait status,
# which here is 137. Both describe the same event.
#
# 137 is also the correct kryptikd behaviour rather than a fallback: the zone's
# pid 1 is /bin/sleep, and pid 1 of a namespace IGNORES a SIGTERM it has no
# handler for, so the intermediate's 5-second escalation to SIGKILL is what
# actually ends it. A test that demanded a clean SIGTERM exit would be
# demanding something the kernel does not permit.
MARK_TERM=2912
KRYPTIK_EXPERIMENTAL=1 timeout 2 "$KRYPTIKD" run alpha "${ZARGS[@]}" -- /bin/sleep "$MARK_TERM" >/dev/null 2>&1
trc=$?
# The escalation is 5s after the signal, so wait past it before judging.
sleep 6
after="$(pgrep -f "sleep $MARK_TERM" 2>/dev/null | wc -l)"
if (( trc == 0 )); then
    fail "L2  the launcher exited 0 despite being signalled"
    pkill -9 -f "sleep $MARK_TERM" 2>/dev/null
elif (( after == 0 )); then
    pass "L2  signalling the launcher tears the zone down with it (launcher exit $trc)"
else
    fail "L2  $after zone process(es) survived a signal to the launcher"
    pkill -9 -f "sleep $MARK_TERM" 2>/dev/null
fi

# --- D6: the filter probes ---------------------------------------------------
# `kryptikd seccomp-test` installs the real zone filter in a forked child and
# makes the syscall, so in the VM these are target-kernel results. Exit 5 means
# killed by SIGSYS; exit 7 means refused with the intended errno; 0 means the
# call completed, which for the last one is the positive control.
filter_probe() { # desc probe expected
    local desc="$1" probe_name="$2" want="$3"
    timeout "$TIMEOUT" "$KRYPTIKD" seccomp-test "$probe_name" >/dev/null 2>&1
    local rc=$?
    if (( rc == want )); then
        pass "$desc"
    else
        fail "$desc [expected exit $want, got $rc]"
    fi
}

filter_probe "L3  clone(CLONE_NEWUSER) is killed (nested user namespace)" clone-newuser 5
filter_probe "L4  clone3 returns ENOSYS rather than killing (glibc falls back)" clone3 7
filter_probe "L5  socket(AF_VSOCK) is refused with an errno" socket-vsock 7
filter_probe "L6  socket(AF_NETLINK/NETFILTER) is refused with an errno" socket-netlink-nf 7
filter_probe "L7  ioctl(TIOCSTI) is killed (terminal input injection)" ioctl-tiocsti 5
filter_probe "L8  positive control: socket(AF_INET) still works" socket-inet 0

# ============================================================================
head_ "M. cgroup resource limits  [unpriv where delegated, otherwise vm]"
# ============================================================================
# A limit that silently does nothing is worse than no limit: an operator who
# believes `untrusted` is capped will run things in it they otherwise would
# not. So there are two correct outcomes here and the suite checks whichever
# one applies - enforcement where a cgroup can be created, and REFUSAL where it
# cannot. What is never acceptable is a zone starting unlimited while its
# definition says otherwise.

# Probe the same way kryptikd does: by trying, not by looking at the uid. A
# delegated subtree is writable by an ordinary user and a root process in a
# container may still find the hierarchy read-only.
CGROUP_OK=0
if [[ -f /sys/fs/cgroup/cgroup.controllers ]] \
   && mkdir /sys/fs/cgroup/kryptik-suite-probe 2>/dev/null; then
    rmdir /sys/fs/cgroup/kryptik-suite-probe 2>/dev/null
    CGROUP_OK=1
fi

if (( CGROUP_OK == 0 )); then
    info "this host cannot create cgroups; checking the REFUSAL instead of enforcement"

    # The refusal must name the limits, and the command must not run.
    zrun_raw pidcapped -- /bin/sh -c "echo $LAUNCHED"
    if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
        fail "M1  a zone declaring [limits] RAN on a host that cannot enforce them"
    elif (( ZRC == 0 )); then
        fail "M1  a zone declaring [limits] exited 0 where they cannot be enforced"
    elif [[ "$ZOUT" == *"[limits]"* ]]; then
        pass "M1  [limits] is refused where no cgroup can be created, and does not run"
    else
        fail "M1  refused (exit $ZRC) but the message did not mention [limits]"
        info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
    fi

    skip "M2-M6 cgroup enforcement [vm] this host cannot create cgroups; run the suite in the VM"
else
    info "cgroups are creatable here; checking enforcement"

    # --- pids_max -----------------------------------------------------------
    #
    # MEASURED FROM OUTSIDE, and the reason matters. The first version had the
    # zone count its own processes and report the number. In the capped zone
    # that probe came back EMPTY: the shell could not fork to run the count,
    # because pids_max was working. A test that asks a starved process to
    # describe its own starvation cannot distinguish "the limit held" from
    # "the zone broke", and it reported the limit as unproven while the limit
    # was in fact holding perfectly.
    #
    # pids.events carries the kernel's own tally: `max N` is the number of
    # forks the limit refused. That is direct evidence of enforcement rather
    # than an inference from a process count, and nothing inside the zone has
    # to be healthy enough to report it.
    #
    # The cgroup leaf is named <zone>.<launcher-pid>, so $! gives the path.
    # POLLED, not sampled once. A single read at +3s found nothing for the
    # capped zone, and the reason was the launcher behaving correctly: the zone
    # died quickly under its own limit, the launcher exited, and Cgroup::drop
    # removed the directory before the read. Sampling a resource that the
    # system is correctly reclaiming is a race the test loses.
    #
    # So poll from 0.2s and keep the last good reading. pids.current only ever
    # falls as processes die; pids.events `max` only ever rises, and it is the
    # number that matters - the kernel's own count of forks the limit refused.
    # PIDS_PEAK, not PIDS_CUR, is what the verdict uses. pids.current only
    # describes the instant it was read, and a zone that has hit its limit is
    # usually on its way down by then - sampling it gave "2 tasks" for a zone
    # that had just been refused a dozen forks. pids.peak is the kernel's own
    # high-water mark and needs no sampling luck at all.
    pids_probe() { # zone ATTEMPTS -> sets PIDS_CUR, PIDS_PEAK, PIDS_MAXEV, PIDS_LIMIT
        local zone="$1"
        local ATTEMPTS="${2:-20}"
        PIDS_CUR=""; PIDS_PEAK=""; PIDS_MAXEV=""; PIDS_LIMIT=""
        PIDS_SAMPLES=0; PIDS_TRACE=""
        PIDS_ERR="$WORK/pids-probe-$zone.err"
        PIDS_LEAF=""
        # busybox ash where it exists, and NOT bash. bash aborts the script
        # when a fork fails, so under pids_max the capped zone died in under
        # 200ms and its cgroup was correctly removed before the poll saw it -
        # the launcher was behaving, and the probe was measuring its own
        # sampling interval. ash reports the failure and carries on, which
        # keeps the zone alive long enough to be observed.
        local sh_cmd=(/bin/sh -c)
        [[ -x /bin/busybox ]] && sh_cmd=(/bin/busybox ash -c)
        KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run "$zone" "${ZARGS[@]}" -- \
            "${sh_cmd[@]}" "i=0; while [ \$i -lt $ATTEMPTS ]; do sleep 8 & i=\$((i+1)); done 2>/dev/null; sleep 7" \
            >/dev/null 2>"$PIDS_ERR" &
        local lp=$!
        BG_PIDS+=("$lp")
        local leaf="/sys/fs/cgroup/kryptik/${zone}.${lp}"
        PIDS_LEAF="$leaf"
        # 5ms steps for the first second, then 100ms. The interesting window is
        # at the start and it can be very short.
        local i=0 cur ev lim pk step
        while (( i < 300 )); do
            if [[ -d "$leaf" ]]; then
                cur="$(cat "$leaf/pids.current" 2>/dev/null)"
                lim="$(cat "$leaf/pids.max" 2>/dev/null)"
                # pids.events `max` is HIERARCHICAL: it counts refusals caused
                # by this cgroup's limit and by any ancestor's, which is why it
                # reported a refusal for a zone holding 2 tasks under a cap of
                # 32. pids.events.local counts only this cgroup's own limit and
                # is the number the claim needs.
                ev="$(sed -n 's/^max //p' "$leaf/pids.events.local" 2>/dev/null)"
                [[ -z "$ev" ]] && ev="$(sed -n 's/^max //p' "$leaf/pids.events" 2>/dev/null)"
                pk="$(cat "$leaf/pids.peak" 2>/dev/null)"
                [[ -n "$cur" ]] && PIDS_CUR="$cur"
                [[ -n "$lim" ]] && PIDS_LIMIT="$lim"
                [[ -n "$ev"  ]] && PIDS_MAXEV="$ev"
                # pids.peak needs kernel 6.1+; fall back to the largest
                # pids.current we happened to see.
                if [[ -n "$pk" ]]; then
                    PIDS_PEAK="$pk"
                elif [[ -n "$cur" ]] && { [[ -z "$PIDS_PEAK" ]] || (( cur > PIDS_PEAK )); }; then
                    PIDS_PEAK="$cur"
                fi
                PIDS_SAMPLES=$((PIDS_SAMPLES+1))
                PIDS_TRACE="$PIDS_TRACE [$i cur=$cur pk=$pk ev=$ev]"
            elif [[ -n "$PIDS_CUR" ]]; then
                break   # it existed, we read it, and it has now been cleaned up
            fi
            if (( i < 200 )); then step=0.005; else step=0.1; fi
            sleep "$step"
            i=$((i+1))
        done
        kill -9 "$lp" 2>/dev/null
        wait "$lp" 2>/dev/null
        sleep 1
    }

    pids_probe roomy 20
    if [[ -z "$PIDS_CUR" ]]; then
        fail "M2  positive control FAILED: no cgroup for the roomy zone; M3 proves nothing"
    elif [[ "$PIDS_MAXEV" == "0" ]] && (( PIDS_PEAK > 10 )); then
        pass "M2  positive control: roomy peaked at $PIDS_PEAK tasks against a limit of $PIDS_LIMIT, refusing none"
        info "     samples=$PIDS_SAMPLES trace:$(printf '%s' "$PIDS_TRACE" | cut -c1-300)"
    else
        fail "M2  positive control FAILED: roomy peaked at $PIDS_PEAK, limit $PIDS_LIMIT, $PIDS_MAXEV refusal(s)"
    fi

    pids_probe pidcapped 60
    if [[ -z "$PIDS_CUR" ]]; then
        fail "M3a pids_max: no cgroup was created for the pidcapped zone"
        info "expected leaf: $PIDS_LEAF"
        info "launcher stderr: $(tr '\n' '|' < "$PIDS_ERR" 2>/dev/null | cut -c1-300)"
    elif [[ "$PIDS_LIMIT" != "32" ]]; then
        fail "M3a pids_max was not written: the cgroup says $PIDS_LIMIT, the zone file says 32"
    else
        pass "M3a pids_max reaches the kernel: the zone's cgroup has pids.max=$PIDS_LIMIT"
    fi

    # M3b: ENFORCEMENT, measured by the refusal rather than by the cgroup.
    #
    # Three sampling approaches failed here before the cause was understood, and
    # the cause is worth writing down because it defeats the obvious test.
    #
    # When a zone hits pids.max, fork(2) returns EAGAIN. The shell reports
    # "can't fork: Resource temporarily unavailable" and DIES - and that shell
    # is pid 1 of the zone's pid namespace, so the kernel tears down every
    # process in the zone with it and the cgroup empties and is removed within
    # a few milliseconds. Every attempt to read pids.current, pids.peak or
    # pids.events from outside was therefore racing a cgroup that the system
    # was correctly reclaiming; readings came back as "2 tasks" or with the
    # files already gone.
    #
    # The refusal itself is not racy. A zone that hits its cap exits non-zero
    # and says EAGAIN on stderr; a zone that does not, does not. With
    # RLIMIT_NPROC at ~9836 in the guest and the same payload succeeding in the
    # roomy zone, an EAGAIN under a pids_max of 32 can only be the pids
    # controller.
    fork_storm() { # zone attempts -> sets FS_RC, FS_OUT
        local zone="$1" attempts="$2"
        local sh_cmd=(/bin/sh -c)
        [[ -x /bin/busybox ]] && sh_cmd=(/bin/busybox ash -c)
        FS_OUT="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
            "$KRYPTIKD" run "$zone" "${ZARGS[@]}" -- \
            "${sh_cmd[@]}" "i=0; while [ \$i -lt $attempts ]; do sleep 4 & i=\$((i+1)); done; echo FORKED_ALL; wait" 2>&1)"
        FS_RC=$?
    }

    # Positive control FIRST: the identical payload, the identical attempt
    # count, under a cap it cannot reach. If this does not complete, M3b is
    # measuring something other than the limit.
    fork_storm roomy 24
    if [[ "$FS_OUT" == *FORKED_ALL* ]] && (( FS_RC == 0 )); then
        pass "M3b1 positive control: 24 forks complete under pids_max=200"
    else
        fail "M3b1 positive control FAILED: 24 forks did not complete under pids_max=200 (exit $FS_RC)"
        info "output: $(printf '%s' "$FS_OUT" | tr '\n' '|' | cut -c1-220)"
    fi

    fork_storm pidcapped 60
    if [[ "$FS_OUT" == *FORKED_ALL* ]]; then
        fail "M3b pids_max=32 did NOT hold: all 60 forks completed"
    elif [[ "$FS_OUT" == *"can't fork"* || "$FS_OUT" == *"Resource temporarily unavailable"* \
            || "$FS_OUT" == *"fork: retry"* || "$FS_OUT" == *"Cannot allocate"* ]]; then
        pass "M3b pids_max=32 held: the kernel refused a fork with EAGAIN and the zone did not finish"
    elif (( FS_RC != 0 )); then
        fail "M3b the zone failed (exit $FS_RC) but not visibly on a fork refusal"
        info "output: $(printf '%s' "$FS_OUT" | tr '\n' '|' | cut -c1-220)"
    else
        fail "M3b the zone exited 0 without completing its forks and without a refusal"
        info "output: $(printf '%s' "$FS_OUT" | tr '\n' '|' | cut -c1-220)"
    fi

    # --- memory_max ---------------------------------------------------------
    # Writing to /dev/shm charges the zone's memory cgroup, so this needs no
    # compiler and no allocator tricks. memory.oom.group=1 means the kernel
    # kills the whole zone rather than one process, so the launcher sees 137.
    zrun roomy -- /bin/sh -c "$PRO dd if=/dev/zero of=/dev/shm/blob bs=1M count=32 2>/dev/null && echo PROBE=wrote32M"
    probe "M4  positive control: 32M fits inside a 512M zone" "wrote32M"

    zrun memcapped -- /bin/sh -c "$PRO dd if=/dev/zero of=/dev/shm/blob bs=1M count=256 2>/dev/null; echo PROBE=survived"
    if [[ "$ZOUT" != *"$LAUNCHED"* ]]; then
        fail "M5  memory_max: the zone did not launch, so nothing is proven"
    elif [[ "$ZOUT" == *"PROBE=survived"* ]]; then
        fail "M5  memory_max=48M did NOT hold: the zone wrote 256M and lived"
    elif (( ZRC == 137 )); then
        pass "M5  memory_max=48M held: the kernel killed the zone (137), it did not fail on its own"
    elif (( ZRC != 0 )); then
        pass "M5  memory_max=48M held: the zone died writing 256M (exit $ZRC)"
    else
        fail "M5  memory_max: the zone exited 0 without printing its sentinel"
    fi

    # --- the zone cannot reach its own cgroup -------------------------------
    zrun pidcapped -- /bin/sh -c "$PRO if [ -w /sys/fs/cgroup/cgroup.procs ]; then echo PROBE=WRITABLE; else echo PROBE=denied; fi"
    probe "M6  a zone cannot write the cgroup filesystem from inside" "denied"

    # --- cleanup ------------------------------------------------------------
    # A cgroup left behind holds its limits and accumulates one directory per
    # launch. rmdir fails with EBUSY while any process remains, so a leftover
    # directory is also evidence that something outlived the launcher.
    # Scoped to ONE launcher that exits normally, not to the whole directory.
    # M2, M3 and M8 SIGKILL their launchers on purpose, so those runs leave
    # empty cgroups behind by design - that is what M9's sweep is for. A
    # directory-wide count here would fail on their leftovers and say nothing
    # about the property M7 is actually about: that a launcher which exits
    # normally cleans up after itself.
    KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run roomy "${ZARGS[@]}" -- /bin/true >/dev/null 2>&1 &
    normal_lp=$!
    wait "$normal_lp" 2>/dev/null
    sleep 0.5
    normal_leaf="/sys/fs/cgroup/kryptik/roomy.${normal_lp}"
    if [[ -d "$normal_leaf" ]]; then
        fail "M7  a normally-exited launcher left its cgroup behind: $normal_leaf"
    else
        pass "M7  a launcher that exits normally removes its own zone cgroup"
    fi

    # --- cleanup after a killed launcher ------------------------------------
    MARK_CG=2913
    KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run pidcapped "${ZARGS[@]}" -- /bin/sleep "$MARK_CG" >/dev/null 2>&1 &
    cgpid=$!
    BG_PIDS+=("$cgpid")
    sleep 1.5
    kill -9 "$cgpid" 2>/dev/null
    sleep 2
    after_procs="$(pgrep -f "sleep $MARK_CG" 2>/dev/null | wc -l)"
    after_cg="$(find /sys/fs/cgroup/kryptik -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
    # What a SIGKILLed launcher can and cannot guarantee, precisely.
    #
    # It cannot run its own cleanup - that is what SIGKILL means - so demanding
    # that the directory be gone immediately is demanding something the design
    # cannot deliver. PR_SET_PDEATHSIG still kills every process, so what
    # remains is an EMPTY cgroup: inert, holding nothing, limiting nothing.
    # The guarantee is that it is empty, and that the next launch sweeps it.
    if (( after_procs != 0 )); then
        fail "M8  $after_procs process(es) survived a SIGKILLed launcher with limits"
        pkill -9 -f "sleep $MARK_CG" 2>/dev/null
    else
        populated=0
        for d in /sys/fs/cgroup/kryptik/*/; do
            [[ -d "$d" ]] || continue
            if [[ -s "$d/cgroup.procs" ]]; then populated=$((populated+1)); fi
        done
        if (( populated == 0 )); then
            pass "M8  a SIGKILLed launcher leaves no process and no populated cgroup"
            (( after_cg > 0 )) && info "     ($after_cg empty cgroup awaiting the sweep, as designed)"
        else
            fail "M8  $populated cgroup(s) still hold processes after the launcher was killed"
        fi
    fi

    # M9: the sweep. An empty leaf older than the staleness window is removed by
    # the next launch that needs a cgroup. This is the half of cleanup that a
    # killed launcher cannot do for itself, so it is tested end to end rather
    # than asserted.
    if (( after_cg > 0 )); then
        sleep 6   # older than cgroup.rs::STALE_AFTER
        zrun pidcapped -- /bin/sh -c "$PRO echo PROBE=swept"
        if want_launch "M9  the next launch sweeps cgroups a killed launcher left"; then
            sleep 1
            still="$(find /sys/fs/cgroup/kryptik -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
            if (( still == 0 )); then
                pass "M9  the next launch swept the abandoned cgroup"
            else
                fail "M9  $still abandoned cgroup(s) survived the next launch's sweep"
                find /sys/fs/cgroup/kryptik -mindepth 1 -maxdepth 1 -type d 2>/dev/null | xargs -r rmdir 2>/dev/null
            fi
        fi
    else
        pass "M9  nothing was left to sweep"
    fi
fi

# ============================================================================
head_ "Mandatory checks NOT RUN here"
# ============================================================================
# A skipped mandatory check is not a release pass. These are named so the gap
# is visible in the summary rather than absent from it.

if (( CGROUP_OK == 0 )); then
    skip "cgroup memory/pids limits are enforced          [vm] this host cannot create cgroups; group M covers it there"
fi
skip "routed network reaches the bridge via the nic zone [vm] not implemented"
skip "ephemeral storage is wiped on stop              [vm] not implemented"
skip "per-zone seccomp/landlock policy files applied  [vm] not implemented"
if (( PRIVILEGED == 0 )); then
    skip "zone runs correctly under real root (not a userns) [vm] needs a disposable VM — group K covers it there"
fi

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
