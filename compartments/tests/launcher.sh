#!/usr/bin/env bash
# The real-launcher suite: every check goes through `kryptikd run ZONE --zones
# DIR --rootfs DIR -- COMMAND`; adversarial.sh tests the primitives alone.
#
# A zone that dies in setup leaks nothing either, so each isolation check has
# the zone print a launch sentinel before its probe result, and a missing
# sentinel fails as "did not launch" (want_launch, probe). Positive controls
# first show that the target is reachable from outside.
#
# [unpriv] groups run as any user on a Linux host with the kernel features;
# [vm] groups need root in a disposable VM and are otherwise NOT RUN, which is
# not a pass. Launches are time-bounded and all state lives under one mktemp -d.
#
# Exit status: 1 if any check failed, 2 if the suite could not start. A run
# with checks NOT RUN exits 0 but reports gaps, which is not a release pass.

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

# A kryptikd older than its sources makes every check fail as "did not launch"
# with nothing pointing at the binary. Only in a build tree (Cargo.toml): an
# image ships isolate.rs for adversarial.sh, newer than its installed binary.
if [[ -z "${KRYPTIK_SKIP_STALE_CHECK:-}" && -f "$REPO/compartments/kryptikd/Cargo.toml" ]]; then
    newer="$(find "$REPO/compartments/kryptikd/src" "$REPO/compartments/kryptikd/Cargo.toml" \
                  -newer "$KRYPTIKD" 2>/dev/null | head -3)"
    if [[ -n "$newer" ]]; then
        printf '%sSTALE BINARY%s: %s is older than its sources.\n' "$C_YEL" "$C_RST" "$KRYPTIKD"
        printf 'Every check would report "did not launch" and none of them would say why.\n'
        printf 'Newer than the binary:\n'
        printf '  %s\n' $newer
        printf '\nRun: (cd %s/compartments/kryptikd && cargo build)\n' "$REPO"
        printf 'Set KRYPTIK_SKIP_STALE_CHECK=1 to run anyway.\n'
        exit 2
    fi
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
    # Zone mounts lived in the zones' own mount namespaces; only directories remain.
    rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

# --- fixtures ---------------------------------------------------------------

# A synthetic canary, unmistakable in a grep.
CANARY="KRYPTIK_CANARY_a7f3c091_DO_NOT_LEAK"

# Stand-in host configuration a zone must not see. World-readable, so a zone
# that cannot read it is contained, not merely refused by file permissions.
printf 'token = %s\n' "$CANARY" > "$HOSTFIX/hostconfig.conf"
chmod 0644 "$HOSTFIX/hostconfig.conf"

mkzone() { # name mode colour [extra-network-lines] [storage-mode]
    local name="$1" mode="$2" colour="$3" extra="${4:-}" storage="${5:-ephemeral}"
    {
        printf '[zone]\nname = "%s"\ndescription = "launcher-suite fixture"\n' "$name"
        printf '[network]\nmode = "%s"\n' "$mode"
        [[ -n "$extra" ]] && printf '%s\n' "$extra"
        printf '[storage]\nmode = "%s"\n' "$storage"
        # storage.size is required for ephemeral and refused for encrypted.
        [[ "$storage" == "ephemeral" ]] && printf 'size = "64M"\n'
        # An encrypted fixture's volume lives under $WORK (F4 creates it as
        # root), never in /var/lib/kryptik.
        [[ "$storage" == "encrypted" ]] && printf 'volume = "%s/volumes/%s.luks"\n' "$WORK" "$name"
        printf '[ui]\nborder_color = "%s"\n' "$colour"
    } > "$ZONES/$name.toml"
}

# A zone set needs exactly one NIC zone, hence `carrier`. Only group NETR,
# in a disposable VM, starts it.
mkzone alpha    none   "#111111"
mkzone beta     none   "#222222"
mkzone carrier  nic    "#333333"
mkzone sealed   none   "#444444" ''                      encrypted
mkzone wiped    none   "#555555" ''                      ephemeral
# The persistent fixture. `sealed` needs a volume and a passphrase (group F),
# so checks that only need a kept directory use this one.
mkzone keeper   none   "#4a4a4a" ''                      persistent
# K7: a zone whose data directory is owned by someone else.
mkzone stranger none   "#666666"
mkzone lczone   none   "#0a0a0a"

# Group M fixtures, and `roomy`: the same shape with limits nothing should hit,
# as the positive control.
mkzone_limited() { # name colour memory pids
    {
        printf '[zone]\nname = "%s"\ndescription = "launcher-suite limit fixture"\n' "$1"
        printf '[network]\nmode = "none"\n'
        # Under every memory_max here (memcapped's is 48M): a tmpfs larger than
        # the memory limit is refused, since its pages are charged to it.
        printf '[storage]\nmode = "ephemeral"\nsize = "32M"\n'
        printf '[limits]\nmemory_max = "%s"\npids_max = %s\n' "$3" "$4"
        printf '[ui]\nborder_color = "%s"\n' "$2"
    } > "$ZONES/$1.toml"
}
# One limit per fixture: under a 48M memory limit the OOM killer takes the zone
# before a fork loop could reach a pids limit.
mkzone_limited memcapped "#777777" "48M"  200   # memory is the variable
mkzone_limited pidcapped "#999999" "512M" 32    # pids is the variable
mkzone_limited roomy     "#888888" "512M" 200   # neither: the positive control

# A root launch must map the zone to an unprivileged identity: kryptikd refuses
# to make zone root host uid 0.
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

# mktemp -d makes 0700, but a privileged zone's setup drops to the mapped uid
# before it opens its data directory.
chmod 0755 "$WORK" "$ZONES" "$ROOTFS" "$HOSTFIX"
if (( PRIVILEGED == 1 )); then
    # kryptikd refuses a data directory not owned by the mapped uid.
    chown -R "$ZONE_UID:$ZONE_GID" "$ROOTFS" 2>/dev/null || \
        info "WARNING: could not chown the rootfs base; privileged launches may be refused"
fi

ZARGS=(--zones "$ZONES" --rootfs "$ROOTFS" "${IDENTITY[@]}")

# --- launch helpers ---------------------------------------------------------

# zrun ZONE -- CMD...: run in a zone with KRYPTIK_EXPERIMENTAL=1; output to
# ZOUT, exit code to ZRC. zrun_raw: without the override, for refusal checks.
ZOUT=""; ZRC=0
zrun_with() {  # zrun_with with|without ZONE -- CMD...
    local mode="$1" zone="$2"; shift 2
    [[ "${1:-}" == "--" ]] && shift
    # A zone that declares [identity] refuses --zone-uid/--zone-gid: the file
    # decides who owns its data (tools/kryptik does the same).
    local -a za=("${ZARGS[@]}")
    if (( ${#IDENTITY[@]} )) && grep -q '^\[identity\]' "$ZONES/$zone.toml" 2>/dev/null; then
        za=(--zones "$ZONES" --rootfs "$ROOTFS")
    fi
    case "$mode" in
        with)
            ZOUT="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
                    "$KRYPTIKD" run "$zone" "${za[@]}" -- "$@" 2>&1)" ;;
        without)
            ZOUT="$(env -u KRYPTIK_EXPERIMENTAL timeout "$TIMEOUT" \
                    "$KRYPTIKD" run "$zone" "${za[@]}" -- "$@" 2>&1)" ;;
        *) echo "zrun_with: bad mode ${mode}" >&2; return 2 ;;
    esac
    ZRC=$?
    return 0
}
zrun()     { zrun_with with "$@"; }
zrun_raw() { zrun_with without "$@"; }

# The launch sentinel, printed first by every zone command.
LAUNCHED="ZONE_LAUNCH_OK"

# kryptikd's zone registry, derived as base() does; groups K and LC read it.
REG="${XDG_RUNTIME_DIR:-/tmp/kryptik-$(id -u)}/kryptik/zones"
[[ "$EUID" -eq 0 ]] && REG=/run/kryptik/zones

# Preflight: a second `run` of a running zone is refused, so one leftover
# launcher would fail dozens of checks. Only this suite's names count: the
# registry is per uid, shared with every other checkout on the machine.
mine="$(cd "$ZONES" && ls ./*.toml 2>/dev/null | sed 's|^\./||; s|\.toml$||' | tr '\n' '|')"
mine="${mine%|}"
if running="$("$KRYPTIKD" list --running 2>/dev/null)"; then
    if [[ -n "$mine" ]]; then
        running="$(printf '%s\n' "$running" | grep -E "^(${mine})[[:space:]]" || true)"
    fi
    if [[ "$running" != *"no zones are running"* && -n "${running//[[:space:]]/}" ]]; then
        printf '\n%s\n' "kryptikd reports zones already running:" >&2
        printf '%s\n' "$running" | sed 's/^/    /' >&2
        cat >&2 <<'PRE'

This suite reuses these zone names, and the registry refuses a second launch of
a name that is already running - so it would report dozens of failures that are
all this one fact. Stop the launcher (or run `kryptikd gc` if it is dead) and
try again.
PRE
        exit 2
    fi
fi

# want_launch DESC: unless the sentinel is there, fail the check and say why.
want_launch() {
    local desc="$1"
    if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
        return 0
    fi

    # A launch the target kernel refuses by design is NOT RUN, not failed:
    # kryptikd ignores KRYPTIK_EXPERIMENTAL for a root launch on a kernel that
    # restricts unprivileged user namespaces (docs/design/privileged-launch.md).
    if [[ "$ZOUT" == *"KRYPTIK_EXPERIMENTAL is ignored"* ]]; then
        skip "$desc [needs a zone whose guarantees are unmet; this kernel correctly refuses to start one]"
        return 1
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

# probe DESC EXPECTED: the zone launched and printed PROBE=<EXPECTED>.
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
# A zone that runs nothing isolates perfectly, so this group comes first.

zrun alpha -- /bin/echo "$LAUNCHED"
if want_launch "A1  a program executes inside a zone"; then
    (( ZRC == 0 )) && pass "A1  a program executes inside a zone" \
                   || fail "A1  executed but exit was $ZRC, expected 0"
fi

# /bin/sh is dynamically linked, so this also proves the loader and /lib binds.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=dynamic-ok"
probe "A2  dynamically linked programs run (loader + /lib reachable)" "dynamic-ok"

if readelf -l /bin/sh 2>/dev/null | grep -q 'program interpreter'; then
    info "A2  confirmed: /bin/sh on this host is dynamically linked"
else
    info "A2  note: /bin/sh appears static here; A2 proves less than usual"
fi

# $HOME, not /: the zone root is a sealed read-only tmpfs, and the data
# directory (<rootfs-base>/<zone> on the host) is bound at /home/<zone>.
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

# keeper writes a canary into its own home. Not the ephemeral alpha: its writes
# never reach the host, and B1b needs a file to find.
zrun keeper -- /bin/sh -c "$PRO printf '%s' '$CANARY' > \$HOME/alpha-secret; echo PROBE=written"
probe "B1a a persistent zone can write a file in its own zone" "written"

# Positive control: the file exists on the host.
if [[ -f "$ROOTFS/keeper/alpha-secret" ]] && grep -q "$CANARY" "$ROOTFS/keeper/alpha-secret"; then
    pass "B1b positive control: the file is real and readable from the host"
else
    fail "B1b positive control FAILED: the file is not where the test expects"
    info "looked for: $ROOTFS/keeper/alpha-secret"
fi

# A second launch: the zone's namespaces are gone, and the file must remain.
zrun keeper -- /bin/sh -c "$PRO if grep -q '$CANARY' \$HOME/alpha-secret 2>/dev/null; then echo PROBE=kept; else echo PROBE=LOST; fi"
probe "B1e a persistent zone still has its file on the NEXT launch" "kept"

# Control: the same sequence in an ephemeral zone must lose the file.
zrun wiped -- /bin/sh -c "$PRO printf '%s' '$CANARY' > \$HOME/eph-secret; echo PROBE=written"
probe "B1f control: an ephemeral zone can write the same file" "written"

zrun wiped -- /bin/sh -c "$PRO if grep -q '$CANARY' \$HOME/eph-secret 2>/dev/null; then echo PROBE=KEPT; else echo PROBE=gone; fi"
probe "B1g control: the ephemeral zone does NOT have it on its next launch" "gone"

# beta tries keeper's in-zone path and its host path; each zone binds only its
# own directory.
zrun beta -- /bin/sh -c "$PRO if cat /home/keeper/alpha-secret 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B1c another zone cannot read it at its in-zone path" "denied"

zrun beta -- /bin/sh -c "$PRO if cat '$ROOTFS/keeper/alpha-secret' 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B1d another zone cannot read it by its host path" "denied"

# --- process visibility ------------------------------------------------------
# A marker process runs on the host, the parent of every zone, and no zone may
# see it. (One zone looking for another proves nothing: each run's pid
# namespace is gone when it exits.) The probe builds the token from two halves
# and scans /proc with a shell loop, so neither its argv nor a child's matches.

MARKER_TOKEN="KRYPTIKMARKER7f3c091"
MARKER_BIN="$WORK/${MARKER_TOKEN}_marker.sh"
# A script, not a renamed sleep: busybox dispatches on argv[0]. It must not
# exec, or the token would leave its command line.
printf '#!/bin/sh\nsleep %s\n' "$TIMEOUT" > "$MARKER_BIN"
chmod 0755 "$MARKER_BIN"
/bin/sh "$MARKER_BIN" >/dev/null 2>&1 &
MARKER_PID=$!
BG_PIDS+=("$MARKER_PID")
# Disowned, so killing it at cleanup prints no "Killed" line.
disown "$MARKER_PID" 2>/dev/null || true
sleep 1

# Positive control: the probe's own /proc scan finds the marker from the host.
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

# The same scan must find a process that is there: the zone's own child.
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
# The two escapes rootfs.rs exists to close.

# Positive control for the whole group.
if grep -q "$CANARY" "$HOSTFIX/hostconfig.conf"; then
    pass "C0  positive control: the host fixture is readable outside the zone"
else
    fail "C0  positive control FAILED: host fixture unreadable; group C proves nothing"
fi

zrun alpha -- /bin/sh -c "$PRO if grep -q '$CANARY' '$HOSTFIX/hostconfig.conf' 2>/dev/null; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "C1  an outside path is not reachable from inside a zone" "denied"

# A descriptor opened before the zone existed survives pivot_root and is not
# governed by Landlock, so rootfs.rs::close_inherited_fds must close it. The
# control shows fd 9 is inherited when nothing closes it.
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

# Above 4096, where a fixed-bound sweep would stop.
ZOUT="$(exec 5000<"$HOSTFIX/hostconfig.conf"; KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO if cat <&5000 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi" 2>&1)"
ZRC=$?
probe "C5  a descriptor above the old sweep bound (fd 5000) is closed too" "denied"

# ============================================================================
head_ "D. Environment and host configuration exposure  [unpriv]"
# ============================================================================
# The zone gets a fixed, minimal environment (spawn.rs::zone_environment):
# none of the caller's paths, tokens or LD_* variables.

ZOUT="$(KRYPTIK_SYNTHETIC_SECRET="$CANARY" KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO if /usr/bin/env | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=clean; fi" 2>&1)"
ZRC=$?
probe "D1  a synthetic secret in the caller's environment does not reach the zone" "clean"

zrun alpha -- /bin/sh -c "$PRO if [ -n \"\${LD_PRELOAD:-}\${LD_LIBRARY_PATH:-}\" ]; then echo PROBE=LEAKED; else echo PROBE=clean; fi"
probe "D2  LD_PRELOAD and LD_LIBRARY_PATH are removed" "clean"

# Host session variables are not secrets, but they name host sockets and paths.
ZOUT="$(DISPLAY=":99" WAYLAND_DISPLAY="wayland-99" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/9999/bus" \
        XDG_RUNTIME_DIR="/run/user/9999" \
        KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
        "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO n=\$(/usr/bin/env | grep -c -E '^(DISPLAY|WAYLAND_DISPLAY|DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR)='); echo PROBE=\$n" 2>&1)"
ZRC=$?
probe "D3  host session configuration is not inherited by the zone" "0"

# The environment the zone should have.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$KRYPTIK_ZONE"
probe "D4  the zone is told its own name via KRYPTIK_ZONE" "alpha"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$PATH"
probe "D5  PATH is the fixed zone PATH, not the caller's" "/usr/bin:/usr/sbin:/bin:/sbin"

# Machine-wide state that links zones or times keystrokes (rootfs.rs:
# PROC_MASKED, SYSFS_KEPT, the zone's own boot_id).
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(cat /proc/interrupts /proc/softirqs /proc/stat 2>/dev/null | wc -c)"
probe "D6  the interrupt counts are hidden from the zone" "0"

HOST_BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
zrun alpha -- /bin/sh -c "$PRO b=\$(cat /proc/sys/kernel/random/boot_id); if [ -n \"\$b\" ] && [ \"\$b\" != '$HOST_BOOT_ID' ]; then echo PROBE=own; else echo PROBE=HOSTS; fi"
probe "D7  the zone's boot_id is its own, not the one every zone would share" "own"

zrun alpha -- /bin/sh -c "$PRO x=\$( { ls /sys | grep -vx -e class -e devices; ls /sys/class | grep -vx net; ls /sys/devices | grep -vx -e virtual -e system; } 2>/dev/null ); if [ -z \"\$x\" ]; then echo PROBE=narrow; else echo PROBE=WIDE; fi"
probe "D8  /sys holds only the zone's interfaces and the CPU layout" "narrow"

if [[ -f /etc/dhcpcd.conf ]]; then
    zrun alpha -- /bin/sh -c "$PRO if [ -e /etc/dhcpcd.conf ]; then echo PROBE=PRESENT; else echo PROBE=absent; fi"
    probe "D9  the nic zone's configuration is not bound into another zone" "absent"
else
    info "D9  not applicable: this host has no /etc/dhcpcd.conf"
fi

# ============================================================================
head_ "E. Old root, system mounts, devices  [unpriv]"
# ============================================================================

zrun alpha -- /bin/sh -c "$PRO if [ -e /.oldroot ]; then echo PROBE=PRESENT; else echo PROBE=detached; fi"
probe "E1a the old root mountpoint is gone from the zone" "detached"

# Stronger than E1a: no mount the zone can see may be rooted at the old tree.
zrun alpha -- /bin/sh -c "$PRO if grep -q 'oldroot' /proc/mounts 2>/dev/null; then echo PROBE=PRESENT; else echo PROBE=detached; fi"
probe "E1b no oldroot mount remains in the zone's mount table" "detached"

# The host's own marker directories must not resolve.
zrun alpha -- /bin/sh -c "$PRO if [ -d '$HOSTFIX' ]; then echo PROBE=PRESENT; else echo PROBE=detached; fi"
probe "E1c the host's directory tree does not resolve inside the zone" "detached"

# A writable /usr would let one zone change a binary every other zone runs.
zrun alpha -- /bin/sh -c "$PRO if touch /usr/kryptik-probe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=readonly; fi"
probe "E2a /usr is read-only inside the zone" "readonly"

zrun alpha -- /bin/sh -c "$PRO if touch /etc/kryptik-probe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=readonly; fi"
probe "E2b /etc is read-only inside the zone" "readonly"

# Positive control: a zone where nothing is writable would pass E2 as well.
zrun alpha -- /bin/sh -c "$PRO if touch /tmp/ok 2>/dev/null; then echo PROBE=writable; else echo PROBE=BROKEN; fi"
probe "E2c positive control: /tmp IS writable (the zone is not simply inert)" "writable"

# A setuid binary on a system mount must confer nothing: check the mount flags.
zrun alpha -- /bin/sh -c "$PRO if grep -E ' /usr .*nosuid' /proc/mounts >/dev/null; then echo PROBE=nosuid; else echo PROBE=SUID_ALLOWED; fi"
probe "E2d /usr is mounted nosuid" "nosuid"

# rootfs.rs::DEVICES, a private /dev/shm tmpfs, a private devpts (pts, ptmx) and
# the fd/stdin/stdout/stderr symlinks; nothing else.
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
    # Every /proc entry starting with a digit is a pid; a glob starts no process.
    hostn=0
    for p in /proc/[0-9]*; do [[ -d "$p" ]] && hostn=$((hostn+1)); done
    if [[ -n "$n" ]] && (( n <= 8 )) && (( hostn > n )); then
        pass "E4b /proc shows $n process(es), host has $hostn — zone-private"
    else
        fail "E4b /proc showed ${n:-<none>} processes (host: $hostn) — not isolated"
    fi
fi

# ============================================================================
head_ "F. Encrypted storage: refused without its passphrase, real with it  [unpriv; F4 root]"
# ============================================================================
# An encrypted zone starts only with its passphrase; without it the command
# never runs, override or not. F1 checks the converse: an implemented storage
# mode is not refused.
zrun_raw wiped -- /bin/sh -c "echo $LAUNCHED; echo PROBE=RAN"
if [[ "$ZOUT" == *"$LAUNCHED"* ]] && (( ZRC == 0 )); then
    pass "F1  ephemeral storage no longer needs the override: it is implemented"
elif [[ "$ZOUT" == *"KRYPTIK_EXPERIMENTAL"* ]]; then
    fail "F1  ephemeral storage is still being refused although it is implemented"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
else
    fail "F1  an ephemeral zone did not start without the override (exit $ZRC)"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
fi

zrun_raw sealed -- /bin/sh -c "echo $LAUNCHED; echo PROBE=RAN"
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "F2  an encrypted zone without a passphrase: the command RAN anyway"
elif (( ZRC == 0 )); then
    fail "F2  an encrypted zone without a passphrase: exit 0, expected refusal"
elif [[ "$ZOUT" == *"encrypted"* && "$ZOUT" == *"passphrase"* ]]; then
    pass "F2  an encrypted zone without a passphrase is refused, says what it needs, and does not run"
else
    fail "F2  refused (exit $ZRC) but the message did not say the zone is encrypted and needs a passphrase"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
fi

# The development override covers unimplemented guarantees, not this one.
zrun sealed -- /bin/sh -c "echo $LAUNCHED"
if [[ "$ZOUT" == *"$LAUNCHED"* ]] || (( ZRC == 0 )); then
    fail "F3  KRYPTIK_EXPERIMENTAL=1 started an encrypted zone without its passphrase"
elif [[ "$ZOUT" == *"passphrase"* ]]; then
    pass "F3  the override does not apply to encryption: still refused for want of a passphrase"
else
    fail "F3  refused under the override, but not for the passphrase (exit $ZRC)"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
fi

# With a volume and its passphrase the zone starts, its home on the dm-crypt
# mapping. Root only (cryptsetup, dm-crypt, a loop device).
if (( PRIVILEGED == 1 )) && command -v cryptsetup >/dev/null 2>&1 && [[ -e /dev/mapper/control ]]; then
    F4PASS="$WORK/sealed.pass"; printf 'fixture-passphrase' > "$F4PASS"; chmod 600 "$F4PASS"
    if ! F4INIT="$("$KRYPTIKD" volume init sealed --zones "$ZONES" --size 32M --passphrase-file "$F4PASS" "${IDENTITY[@]}" 2>&1)"; then
        fail "F4  volume init for the encrypted fixture failed"
        info "output: $(printf '%s' "$F4INIT" | tr '\n' '|' | cut -c1-220)"
    else
        ZOUT="$(timeout "$TIMEOUT" "$KRYPTIKD" run sealed "${ZARGS[@]}" --passphrase-file "$F4PASS" \
                -- /bin/sh -c "echo $LAUNCHED; awk '\$2==\"/home/sealed\" {print \"PROBE=\" \$1}' /proc/mounts" 2>&1)"
        ZRC=$?
        if want_launch "F4  an encrypted zone starts on its LUKS2 volume with the passphrase"; then
            if [[ "$ZOUT" == *"PROBE=/dev/mapper/"* || "$ZOUT" == *"PROBE=/dev/dm-"* ]]; then
                pass "F4  an encrypted zone starts, and its home is the dm-crypt mapping"
            else
                fail "F4  the zone started but its home is not on the mapping"
                info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
            fi
        fi
        if [[ -e /dev/mapper/kryptik-zone-sealed ]]; then
            fail "F4b the mapping is still open after the zone exited"
            "$KRYPTIKD" stop sealed --now >/dev/null 2>&1 || true
        else
            pass "F4b the mapping is closed when the zone exits"
        fi
        # stop --now kills the zone's pid 1, so the launcher outlives it and
        # closes the volume; killing the launcher left it open.
        "$KRYPTIKD" run sealed "${ZARGS[@]}" --passphrase-file "$F4PASS" -- /bin/sleep 60 >/dev/null 2>&1 &
        BG_PIDS+=("$!")
        f4c_open=0
        for _ in $(seq 50); do
            [[ "$("$KRYPTIKD" volume status sealed --zones "$ZONES" 2>/dev/null)" == *"(OPEN)"* ]] && { f4c_open=1; break; }
            sleep 0.2
        done
        "$KRYPTIKD" stop sealed --now >/dev/null 2>&1
        if (( f4c_open == 0 )); then
            fail "F4c the encrypted zone did not open its volume within 10 s"
        elif [[ "$("$KRYPTIKD" volume status sealed --zones "$ZONES" 2>/dev/null)" == *"(closed)"* ]]; then
            pass "F4c stop --now leaves the volume closed"
        else
            fail "F4c the volume is still open after stop --now"
            "$KRYPTIKD" gc >/dev/null 2>&1
        fi
    fi
else
    skip "F4  an encrypted zone starts on its LUKS2 volume [root + cryptsetup] - the VM runs this as root"
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

# A zone killed by a signal reports 128+signo, as a shell does. Not with
# `kill -TERM $$`: the command is pid 1 of its pid namespace, and the kernel
# drops default-action signals sent to it from inside. A seccomp SIGSYS is
# synchronous and not subject to that.
zrun alpha -- /bin/sh -c "$PRO /bin/mount -t tmpfs none /tmp 2>/dev/null"
if want_launch "G2  a zone killed by a signal reports 128+signo"; then
    if (( ZRC == 128 + 31 )); then
        pass "G2  a zone killed by SIGSYS reports 128+31 = 159"
    else
        fail "G2  expected 159 from a SIGSYS-killed zone, got $ZRC"
    fi
fi

# A rootfs base that cannot be created must fail promptly, not hang on the
# sync pipe.
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

# No zone process outlives the launcher. Scoped to this launch by a marker in
# its argv, as other runs may be live. Counted with wc -l: pgrep -c prints 0
# and also fails when nothing matches.
G5MARK="G5PROBE_${$}_${RANDOM}"
KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
    /bin/sh -c "$PRO echo PROBE=done; /bin/sleep 3; : $G5MARK" \
    > "$WORK/g5.out" 2>&1 &
g5pid=$!
BG_PIDS+=("$g5pid")
sleep 1
g5live="$(pgrep -f "$G5MARK" 2>/dev/null | wc -l)"
if (( g5live > 0 )); then
    pass "G5a positive control: this launch is visible as $g5live process(es) while it runs"
    wait "$g5pid" 2>/dev/null
    sleep 1
    g5left="$(pgrep -f "$G5MARK" 2>/dev/null | wc -l)"
    if (( g5left == 0 )); then
        pass "G5  no kryptikd zone process is left running after the zone exits"
    else
        fail "G5  $g5left kryptikd process(es) outlived the zone"
        pkill -9 -f "$G5MARK" 2>/dev/null
    fi
else
    fail "G5a positive control FAILED: the launch was never visible; G5 proves nothing"
    info "output: $(tr '\n' '|' < "$WORK/g5.out" 2>/dev/null | cut -c1-200)"
fi

# The host's mount table is unchanged: pivot_into makes the tree MS_PRIVATE
# first, so zone mounts cannot propagate out.
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
# adversarial.sh tests the filter in a purpose-built child (`kryptikd
# seccomp-test`); these check that `run` installs it, after pivot_root and
# Landlock.

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(grep '^Seccomp:' /proc/self/status | awk '{print \$2}')"
probe "I1  a zone process reports seccomp mode 2 (filtered)" "2"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(grep '^Seccomp_filters:' /proc/self/status | awk '{print \$2}')"
probe "I2  exactly one filter is installed, not zero and not a stack" "1"

# Each is in seccomp.rs::DENIED_RATIONALE. A denied syscall kills the zone
# (SIGSYS, exit 159) rather than returning an error it could ignore.
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
# mknod(2) is allowed so mkfifo works; a device node is refused by Landlock
# (MAKE_CHAR/MAKE_BLOCK granted nowhere) and by nodev on every mount.
zrun alpha -- /bin/sh -c "$PRO /usr/bin/mknod /tmp/n c 1 3 2>/dev/null; if [ -e /tmp/n ]; then echo PROBE=CREATED; else echo PROBE=refused; fi"
probe "I6  a zone cannot create a device node (Landlock + nodev, not SIGSYS)" "refused"

# Positive control: mknod still makes a FIFO, so I6 is not a blanket failure.
zrun alpha -- /bin/sh -c "$PRO /usr/bin/mknod /tmp/f p 2>/dev/null; if [ -p /tmp/f ]; then echo PROBE=fifo-ok; else echo PROBE=BLOCKED; fi"
probe "I6b positive control: mknod still creates a FIFO (mkfifo must work)" "fifo-ok"

# Positive control: a filter that denied everything would pass I3-I6 too.
zrun alpha -- /bin/sh -c "$PRO /bin/true && /bin/echo PROBE=allowed-calls-work"
probe "I7  positive control: allowed syscalls still work under the filter" "allowed-calls-work"

# ============================================================================
head_ "J. The hardened zone tree  [unpriv]"
# ============================================================================

# The zone root is a sealed read-only tmpfs, so a zone cannot plant a symlink
# on a future mount point for its next run.
zrun alpha -- /bin/sh -c "$PRO if touch /probe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=sealed; fi"
probe "J1  the zone root is read-only, even to zone root" "sealed"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$HOME"
probe "J2  the zone's writable data is at /home/<zone>, not /" "/home/alpha"

zrun alpha -- /bin/sh -c "$PRO if touch \$HOME/w 2>/dev/null; then echo PROBE=writable; else echo PROBE=BROKEN; fi"
probe "J2b positive control: \$HOME IS writable (the zone is not inert)" "writable"

# The cheapest way to see that the Landlock ruleset denies anything at all.
zrun alpha -- /bin/sh -c "$PRO if mkdir /dev/evil 2>/dev/null; then echo PROBE=ALLOWED; else echo PROBE=denied; fi"
probe "J3  Landlock denies creating a directory under /dev" "denied"

# Write rights Landlock must still grant: truncate needs FS_TRUNCATE, and mv
# across directories FS_REFER (without it mv falls back to copy+fchmod and fails).
zrun alpha -- /bin/sh -c "$PRO echo aaaa > /tmp/t; echo b > /tmp/t; echo PROBE=\$(cat /tmp/t)"
probe "J4  truncating an existing file works (FS_TRUNCATE granted)" "b"

zrun alpha -- /bin/sh -c "$PRO mkdir -p /tmp/d; echo x > /tmp/a; mv /tmp/a /tmp/d/ 2>/dev/null; if [ -f /tmp/d/a ]; then echo PROBE=moved; else echo PROBE=BLOCKED; fi"
probe "J5  moving a file between directories works (FS_REFER granted)" "moved"

zrun alpha -- /bin/sh -c "$PRO touch /tmp/c; chmod 0700 /tmp/c 2>/dev/null && echo PROBE=chmod-ok || echo PROBE=BLOCKED"
probe "J6  chmod works (it is needed by tar, git and cargo)" "chmod-ok"

# /etc is synthesized: no host machine-id, user list or ssh/ssl directories.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(wc -l < /etc/passwd)"
probe "J7  /etc/passwd is synthesized and names only root and nobody" "2"

zrun alpha -- /bin/sh -c "$PRO for f in machine-id shadow sudoers ssl/private ssh resolv.conf; do [ -e /etc/\$f ] && { echo PROBE=EXPOSED_\$f; exit 0; }; done; echo PROBE=absent"
probe "J8  no host identity or secret files are visible in /etc" "absent"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(hostname)"
probe "J9  the zone's hostname is the zone name, not the host's" "alpha"

# Positive control: without the CA bundle TLS breaks in every zone. Checked
# only where the host has one.
if [[ -d /etc/ssl/certs ]]; then
    zrun alpha -- /bin/sh -c "$PRO if [ -d /etc/ssl/certs ]; then echo PROBE=present; else echo PROBE=MISSING; fi"
    probe "J10 positive control: the CA certificate directory reaches the zone" "present"
else
    skip "J10 the host has no /etc/ssl/certs, so the CA passthrough cannot be checked here"
fi

# Remounting a recursive bind MS_RDONLY only affects the top mount, not its
# submounts.
zrun alpha -- /bin/sh -c "$PRO n=\$(awk '\$5 ~ /^\/(usr|lib|lib64|bin|sbin|etc)/ && \$6 ~ /(^|,)rw(,|\$)/ {c++} END{print c+0}' /proc/self/mountinfo); echo PROBE=\$n"
probe "J11 no system mount or submount is read-write inside the zone" "0"

# ============================================================================
head_ "H. Network isolation, without overclaiming  [unpriv]"
# ============================================================================
# network.mode = "none". Routed zones are group NETR.

# Devices the kernel creates in every new netns, which the zone cannot remove
# (sit0: CONFIG_IPV6_SIT=y adds a fallback tunnel to each). H1 allows these
# names and no others, and every device but lo must be down with no address.
# The same list as adversarial.sh.
KERNEL_FALLBACK_IFS="sit0"
FALLBACK_RE="lo|${KERNEL_FALLBACK_IFS// /|}"

zrun alpha -- /bin/sh -c "$PRO ifs=\$(sed 1,2d /proc/net/dev | sed 's/:.*//' | tr -d ' ' | sort | tr '\n' ','); up=''; for f in /sys/class/net/*/flags; do d=\${f%/flags}; d=\${d##*/}; fl=\$(cat \"\$f\" 2>/dev/null || echo 0); [ \$((fl & 1)) -eq 1 ] && up=\"\$up\$d,\"; done; v6=\$(awk '{print \$NF}' /proc/net/if_inet6 2>/dev/null | sort -u | tr '\n' ','); echo PROBE=if:\$ifs~up:\$up~v6:\$v6"
if want_launch "H1  a mode=none zone has loopback and nothing that can carry traffic"; then
    h_got="$(printf '%s\n' "$ZOUT" | sed -n 's/^PROBE=//p' | head -1)"
    h_if="${h_got#if:}";   h_if="${h_if%%~*}"
    h_up="${h_got#*~up:}"; h_up="${h_up%%~*}"
    h_v6="${h_got##*~v6:}"
    h_extra=""; h_live=""; h_others=""
    for d in ${h_if//,/ }; do
        [[ -z "$d" || "$d" == "lo" ]] && continue
        h_others+="$d "
        [[ "$d" =~ ^(${KERNEL_FALLBACK_IFS// /|})$ ]] || h_extra+="$d "
    done
    # Up, or holding an address: either makes a device live.
    for d in ${h_up//,/ } ${h_v6//,/ }; do
        [[ -z "$d" || "$d" == "lo" ]] && continue
        h_live+="$d "
    done
    if [[ -n "$h_extra" ]]; then
        fail "H1  a mode=none zone has a network device nothing asked for: $h_extra"
        info "full view: $h_got"
    elif [[ -n "$h_live" ]]; then
        fail "H1  a device in a mode=none zone is UP or has an address: $h_live"
        info "full view: $h_got"
    else
        pass "H1  a mode=none zone has loopback and nothing that can carry traffic"
        [[ -n "$h_others" ]] && info "kernel fallback devices, present and inert: $h_others"
    fi
fi

zrun alpha -- /bin/sh -c "$PRO if [ -s /proc/net/route ] && [ \$(tail -n +2 /proc/net/route | wc -l) -gt 0 ]; then echo PROBE=ROUTES; else echo PROBE=none; fi"
probe "H2  a mode=none zone has no routes at all" "none"

# A literal address, so the connect fails for want of an interface, not of DNS.
zrun alpha -- /bin/sh -c "$PRO if timeout 3 /bin/sh -c 'exec 3<>/dev/tcp/10.255.255.1/80' 2>/dev/null; then echo PROBE=CONNECTED; else echo PROBE=unreachable; fi"
probe "H3  an outbound TCP connect from a mode=none zone cannot succeed" "unreachable"

# Positive control for H1, which only discriminates if the host has more than
# lo. The developer VM has no NIC (-nic none), so there it is NOT RUN.
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
# What changes when kryptikd is root, as it runs in zone 0 on Kryptik.

if (( PRIVILEGED == 1 )); then
    # Mapping zone root to host uid 0 would make it real root for every DAC
    # check on every bound path.
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

    # Zone root is uid 0 inside the zone...
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(id -u)"
    probe "K2  the zone's process is uid 0 inside its own user namespace" "0"

    # ...and its files belong to the mapped host identity, checked on the host
    # side. `keeper`, since an ephemeral zone writes nothing there.
    zrun keeper -- /bin/sh -c "$PRO echo k3 > \$HOME/k3file; echo PROBE=written"
    if want_launch "K3  a zone's files are owned by the mapped identity"; then
        owner="$(stat -c %u "$ROOTFS/keeper/k3file" 2>/dev/null)"
        if [[ "$owner" == "$ZONE_UID" ]]; then
            pass "K3  a zone's files are owned by host uid $ZONE_UID, not root"
        else
            fail "K3  file owned by uid ${owner:-<missing>}, expected $ZONE_UID"
            info "a zone running as real root on the host is not a zone"
        fi
    fi

    # Supplementary groups are dropped on a privileged launch (setgroups needs
    # CAP_SETGID). That only shows if the launcher has groups to drop, and a
    # root started by init often has none, so it is given some.
    K4_GROUPS="4,27"
    K4_WRAP=()
    launcher_groups="$(grep '^Groups:' /proc/self/status | cut -f2- | wc -w)"
    if (( launcher_groups == 0 )); then
        # busybox setpriv has no --groups; s6-applyuidgid -G does, and the image
        # ships s6. A wrapper that grants no groups is discarded.
        for k4_cand in "setpriv --groups=$K4_GROUPS --" "s6-applyuidgid -G $K4_GROUPS"; do
            read -ra k4_try <<< "$k4_cand"
            command -v "${k4_try[0]}" >/dev/null 2>&1 || continue
            k4_got="$("${k4_try[@]}" sh -c \
                "grep '^Groups:' /proc/self/status | cut -f2- | wc -w" 2>/dev/null)"
            if [[ -n "$k4_got" ]] && (( k4_got > 0 )); then
                K4_WRAP=("${k4_try[@]}")
                launcher_groups="$k4_got"
                break
            fi
        done
    fi

    if (( launcher_groups > 0 )); then
        if (( ${#K4_WRAP[@]} > 0 )); then
            # s6-applyuidgid also keeps the primary group: report the measured count.
            info "K4  positive control: \`${K4_WRAP[*]}\` gave the launcher $launcher_groups supplementary group(s) to drop"
        else
            info "K4  the launcher holds $launcher_groups supplementary group(s) to drop"
        fi
        ZOUT="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" "${K4_WRAP[@]}" \
                "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
                /bin/sh -c "$PRO echo PROBE=\$(grep '^Groups:' /proc/self/status | cut -f2- | wc -w)" 2>&1)"
        ZRC=$?
        probe "K4  the host's supplementary groups are dropped in the zone" "0"
    else
        skip "K4  the launcher has no supplementary groups and neither setpriv nor s6-applyuidgid could give it any"
    fi

    # The sealed root must hold against real root, not merely against a user.
    zrun alpha -- /bin/sh -c "$PRO if touch /rootprobe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=sealed; fi"
    probe "K5  the zone root is read-only even to a privileged launch" "sealed"

    zrun alpha -- /bin/sh -c "$PRO if touch /usr/rootprobe 2>/dev/null; then echo PROBE=WRITABLE; else echo PROBE=readonly; fi"
    probe "K6  /usr is read-only even to a privileged launch" "readonly"

    # A data directory owned by anyone but the zone's identity is refused, or
    # one planted by another user would become the zone's. The suite's own
    # chown never exercises that.
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

# --- T11: the zone as the host sees it --------------------------------------
# Every other identity check asks the zone. This reads the zone's pid 1 (from
# the registry) in /proc from outside: a zone mapped to real root, with a
# capability left effective or a namespace shared with pid 1 fails here even
# if every in-zone check passes.
if (( PRIVILEGED == 1 )); then
    KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO echo PROBE=up; /bin/sleep 30" > "$WORK/t11.out" 2>&1 &
    t11launcher=$!
    BG_PIDS+=("$t11launcher")

    t11init=""
    for _ in $(seq 1 200); do
        # "<pid> <starttime>": the start time makes the pid safe to use.
        t11init="$(awk '{print $1; exit}' "$REG/alpha/init.pid" 2>/dev/null || true)"
        [[ -n "$t11init" && -d "/proc/$t11init" ]] && break
        t11init=""
        sleep 0.05
    done

    if [[ -z "$t11init" ]]; then
        fail "T11 the registry never recorded a pid 1 for the zone, so nothing can be checked from the host"
        info "output: $(tr '\n' '|' < "$WORK/t11.out" 2>/dev/null | cut -c1-200)"
    else
        t11st="/proc/$t11init/status"
        t11uid="$(awk '/^Uid:/{print $2" "$3" "$4" "$5}' "$t11st" 2>/dev/null)"
        t11gid="$(awk '/^Gid:/{print $2" "$3" "$4" "$5}' "$t11st" 2>/dev/null)"
        t11grp="$(awk '/^Groups:/{$1=""; print}' "$t11st" 2>/dev/null | tr -d ' \t')"
        t11eff="$(awk '/^CapEff:/{print $2}' "$t11st" 2>/dev/null)"
        t11prm="$(awk '/^CapPrm:/{print $2}' "$t11st" 2>/dev/null)"
        t11bnd="$(awk '/^CapBnd:/{print $2}' "$t11st" 2>/dev/null)"
        t11nnp="$(awk '/^NoNewPrivs:/{print $2}' "$t11st" 2>/dev/null)"
        t11sec="$(awk '/^Seccomp:/{print $2}' "$t11st" 2>/dev/null)"

        want_ids="$ZONE_UID $ZONE_UID $ZONE_UID $ZONE_UID"
        want_gids="$ZONE_GID $ZONE_GID $ZONE_GID $ZONE_GID"
        t11bad=()
        [[ "$t11uid" == "$want_ids"  ]] || t11bad+=("Uid is '$t11uid', not '$want_ids'")
        [[ "$t11gid" == "$want_gids" ]] || t11bad+=("Gid is '$t11gid', not '$want_gids'")
        [[ -z "$t11grp" ]] || t11bad+=("Groups is '$t11grp', not empty")
        [[ "$t11eff" == "0000000000000400" ]] || t11bad+=("CapEff is $t11eff, not 0000000000000400")
        [[ "$t11prm" == "0000000000000400" ]] || t11bad+=("CapPrm is $t11prm, not 0000000000000400")
        [[ "$t11bnd" == "0000000000000400" ]] || t11bad+=("CapBnd is $t11bnd, not 0000000000000400")
        [[ "$t11nnp" == "1" ]] || t11bad+=("NoNewPrivs is '$t11nnp', not 1")
        [[ "$t11sec" == "2" ]] || t11bad+=("Seccomp is '$t11sec', not 2 (filter mode)")

        for ns in user pid mnt net; do
            a="$(readlink "/proc/$t11init/ns/$ns" 2>/dev/null)"
            b="$(readlink "/proc/1/ns/$ns" 2>/dev/null)"
            if [[ -z "$a" ]]; then
                t11bad+=("ns/$ns unreadable")
            elif [[ "$a" == "$b" ]]; then
                t11bad+=("ns/$ns is SHARED with pid 1 ($a)")
            fi
        done

        if (( ${#t11bad[@]} == 0 )); then
            pass "T11 from the host, the zone's pid 1 is uid/gid $ZONE_UID, no groups, CapEff=CapPrm=CapBnd=0000000000000400, NoNewPrivs, seccomp filtered, and in its own user/pid/mnt/net namespaces"
        else
            fail "T11 the host's view of the zone's pid 1 ($t11init) is wrong in ${#t11bad[@]} way(s)"
            for b in "${t11bad[@]}"; do info "     $b"; done
        fi
    fi
    kill -9 "$t11launcher" 2>/dev/null
    wait "$t11launcher" 2>/dev/null
    "$KRYPTIKD" gc >/dev/null 2>&1 || true
fi

# ============================================================================
head_ "L. Supervision, termination and the filter probes  [unpriv]"
# ============================================================================

# --- nothing outlives the launcher -------------------------------------------
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

# --- SIGTERM to the launcher -------------------------------------------------
# The check is that no zone process survives, not timeout(1)'s exit code: 124
# from coreutils, the child's status (137) from busybox. The zone's pid 1
# ignores SIGTERM, so the launcher's SIGKILL 5 s later is what ends it.
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

# --- the filter probes -------------------------------------------------------
# `kryptikd seccomp-test` makes the syscall in a child under the real zone
# filter. Exit 5: killed by SIGSYS; 7: refused with the intended errno; 0: the
# call completed (the positive control).
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

# seccomp-trace names each refused call and lets the program carry on:
# reboot(2) is refused by the zone filter and fails with ENOSYS (38), and so
# does inotify_init1(2), marked soft since a zone gets ENOSYS for it too.
out="$(timeout "$TIMEOUT" "$KRYPTIKD" seccomp-trace -- python3 -c \
    'import ctypes; c = ctypes.CDLL(None, use_errno=True); [print(c.syscall(nr, 0, 0, 0, 0), ctypes.get_errno()) for nr in (169, 294)]' 2>&1)"
if grep -qx 'KRYPTIK_SECCOMP_DENIED 169 reboot' <<<"$out" \
    && grep -qx 'KRYPTIK_SECCOMP_DENIED 294 inotify_init1 soft' <<<"$out" \
    && [[ "$(grep -cx -e '-1 38' <<<"$out")" == 2 ]]; then
    pass "L9  seccomp-trace names refused calls, soft ones marked, and the program goes on"
else
    fail "L9  seccomp-trace did not report reboot(2) and inotify_init1(2) [$(tr '\n' ' ' <<<"$out")]"
fi

# ncurses brackets each terminfo open with setfsuid and setfsgid. The filter
# answers them with EPERM; a kill would take every terminal program with it
# (tput would end with 159, SIGSYS).
if command -v tput > /dev/null 2>&1; then
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(tput -T xterm cols 2>/dev/null || echo exit-\$?)"
    probe "L10 a terminal program opens terminfo in a zone and lives" "80"
else
    info "L10 not run: this host has no tput"
fi

# cp -a and gzip give what they make its source's owner (tar does too, as
# root); with chown refused neither would finish.
zrun alpha -- /bin/sh -c "$PRO cd /tmp && echo x > o && cp -a o o2 && gzip -k o && echo PROBE=kept"
probe "L11 cp -a and gzip keep an owner in a zone and live" "kept"

# install(1) resets a file's ACL through its xattrs, and Python's asyncio
# watches a child through a pidfd; both were killed.
zrun alpha -- /bin/sh -c "$PRO echo x > /tmp/src && install -D -m 644 /tmp/src /tmp/i/x && echo PROBE=installed"
probe "L12 install(1) sets a mode in a zone and lives" "installed"
if command -v python3 > /dev/null 2>&1; then
    zrun alpha -- /bin/sh -c "$PRO python3 -c 'import asyncio
async def m():
    p = await asyncio.create_subprocess_exec(\"true\")
    await p.wait()
    print(\"PROBE=spawned\")
asyncio.run(m())'"
    probe "L13 an asyncio program runs a child in a zone and lives" "spawned"
    # timeout(1) arms a POSIX timer and mmap.flush is msync; both were killed.
    zrun alpha -- /bin/sh -c "$PRO timeout 20 python3 -c 'import mmap
f = open(\"/tmp/m\", \"w+b\"); f.write(bytes(4096)); f.flush()
m = mmap.mmap(f.fileno(), 4096); m[0:1] = b\"y\"; m.flush(); print(\"PROBE=flushed\")'"
    probe "L14 timeout(1) and a flushed mapping live in a zone" "flushed"
    # sudo, su and daemons dropping privilege call the set*id family as root:
    # refused with EPERM, they can say so instead of dying of SIGSYS.
    zrun alpha -- /bin/sh -c "$PRO python3 -c 'import os
try:
    os.setgroups([]); os.setgid(65534); os.setuid(65534); print(\"PROBE=CHANGED\")
except PermissionError:
    print(\"PROBE=refused\")'"
    probe "L15 a privilege drop in a zone is refused, not killed" "refused"
else
    info "L13 to L15 not run: this host has no python3"
fi

# ============================================================================
head_ "M. cgroup resource limits  [unpriv where delegated, otherwise vm]"
# ============================================================================
# Where a cgroup can be created the limits must be enforced, and where one
# cannot the zone must be refused: never started unlimited.

# Probe as kryptikd does, by trying: a delegated subtree is writable by a user,
# and root in a container may find the hierarchy read-only.
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
    # Measured from outside: a zone out of pids cannot fork to report on itself.
    # The cgroup leaf is <zone>.<launcher-pid>, so $! gives the path. Polled from
    # 0.2 s, keeping the last good reading, as the cgroup goes when the zone
    # dies. The verdict uses pids.events `max` (forks refused) and pids.peak;
    # pids.current only describes the instant it was read.
    pids_probe() { # zone ATTEMPTS -> sets PIDS_CUR, PIDS_PEAK, PIDS_MAXEV, PIDS_LIMIT
        local zone="$1"
        local ATTEMPTS="${2:-20}"
        PIDS_CUR=""; PIDS_PEAK=""; PIDS_MAXEV=""; PIDS_LIMIT=""
        PIDS_SAMPLES=0; PIDS_TRACE=""
        PIDS_ERR="$WORK/pids-probe-$zone.err"
        PIDS_LEAF=""
        # busybox ash, not bash: bash aborts when a fork fails and the zone is
        # gone before the poll sees it; ash reports the failure and carries on.
        local sh_cmd=(/bin/sh -c)
        [[ -x /bin/busybox ]] && sh_cmd=(/bin/busybox ash -c)
        KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run "$zone" "${ZARGS[@]}" -- \
            "${sh_cmd[@]}" "i=0; while [ \$i -lt $ATTEMPTS ]; do sleep 8 & i=\$((i+1)); done 2>/dev/null; sleep 7" \
            >/dev/null 2>"$PIDS_ERR" &
        local lp=$!
        BG_PIDS+=("$lp")
        local leaf="/sys/fs/cgroup/kryptik/${zone}.${lp}"
        PIDS_LEAF="$leaf"
        # 5 ms steps for the first second, then 100 ms: the window is early and short.
        local i=0 cur ev lim pk step
        while (( i < 300 )); do
            if [[ -d "$leaf" ]]; then
                cur="$(cat "$leaf/pids.current" 2>/dev/null)"
                lim="$(cat "$leaf/pids.max" 2>/dev/null)"
                # pids.events also counts refusals by an ancestor's limit;
                # pids.events.local only this cgroup's.
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

    # M3b: enforcement, measured by the refusal. At pids.max fork(2) fails with
    # EAGAIN and the shell, the zone's pid 1, dies and takes the zone and its
    # cgroup with it within milliseconds, so reading the cgroup races its
    # removal. The EAGAIN on stderr does not race, and with the same payload
    # fine in roomy it can only come from the pids controller.
    fork_storm() { # zone attempts -> sets FS_RC, FS_OUT
        local zone="$1" attempts="$2"
        local sh_cmd=(/bin/sh -c)
        [[ -x /bin/busybox ]] && sh_cmd=(/bin/busybox ash -c)
        FS_OUT="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
            "$KRYPTIKD" run "$zone" "${ZARGS[@]}" -- \
            "${sh_cmd[@]}" "i=0; while [ \$i -lt $attempts ]; do sleep 4 & i=\$((i+1)); done; echo FORKED_ALL; wait" 2>&1)"
        FS_RC=$?
    }

    # Positive control: the same payload under a cap it cannot reach.
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
    # Writing to /dev/shm charges the zone's memory cgroup. memory.oom.group=1
    # kills the whole zone rather than one process, so the launcher sees 137.
    zrun roomy -- /bin/sh -c "$PRO dd if=/dev/zero of=/dev/shm/blob bs=1M count=32 2>/dev/null && echo PROBE=wrote32M"
    probe "M4  positive control: 32M fits inside a 512M zone" "wrote32M"

    # M5 reads the kernel's oom_kill counter: exit 137 alone is what any SIGKILL
    # gives.
    MEM_OOM=""; MEM_GROUP=""; MEM_LEAF=""; MEM_RC=""

    # The zone's leaf goes milliseconds after the OOM kill, so polling it
    # usually misses. memory.events is hierarchical and the parent outlives
    # every zone: its counter, read either side of this one launch, gives the
    # delta. The leaf poll names the exact cgroup when it does win.
    MEM_PARENT="/sys/fs/cgroup/kryptik"
    mem_ev() { sed -n "s/^$1 //p" "$MEM_PARENT/memory.events" 2>/dev/null; }
    MEM_P_BEFORE="$(mem_ev oom_kill)"
    MEM_PG_BEFORE="$(mem_ev oom_group_kill)"

    KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run memcapped "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO dd if=/dev/zero of=/dev/shm/blob bs=1M count=256 2>/dev/null; echo PROBE=survived" \
        > "$WORK/mem.out" 2>&1 &
    mempid=$!
    BG_PIDS+=("$mempid")
    MEM_LEAF="$MEM_PARENT/memcapped.${mempid}"
    # Poll for as long as the launcher lives: in the emulated VM the OOM lands
    # around 36 s.
    i=0
    while (( i < 1200 )); do                       # 120s hard ceiling
        if [[ -d "$MEM_LEAF" ]]; then
            v="$(sed -n 's/^oom_kill //p' "$MEM_LEAF/memory.events" 2>/dev/null)"
            g="$(sed -n 's/^oom_group_kill //p' "$MEM_LEAF/memory.events" 2>/dev/null)"
            [[ -n "$v" ]] && (( v > 0 )) && MEM_OOM="$v"
            [[ -n "$g" ]] && (( g > 0 )) && MEM_GROUP="$g"
        fi
        kill -0 "$mempid" 2>/dev/null || break     # the launcher is done
        sleep 0.1
        i=$((i+1))
    done
    wait "$mempid" 2>/dev/null
    MEM_RC=$?
    memout="$(cat "$WORK/mem.out" 2>/dev/null)"

    # One count, and a statement of where it came from.
    MEM_KILLS=""; MEM_GROUP_KILLS=0; MEM_SRC=""
    if [[ -n "$MEM_OOM" ]]; then
        MEM_KILLS="$MEM_OOM"; MEM_GROUP_KILLS="${MEM_GROUP:-0}"
        MEM_SRC="memory.events oom_kill=$MEM_OOM in the zone's own cgroup"
    elif [[ -n "$MEM_P_BEFORE" ]]; then
        p_after="$(mem_ev oom_kill)"; g_after="$(mem_ev oom_group_kill)"
        if [[ -n "$p_after" ]]; then
            MEM_KILLS=$(( p_after - MEM_P_BEFORE ))
            MEM_GROUP_KILLS=$(( ${g_after:-0} - ${MEM_PG_BEFORE:-0} ))
            MEM_SRC="kryptik/memory.events oom_kill rose $MEM_P_BEFORE->$p_after across this launch"
        fi
    fi

    if [[ "$memout" != *"$LAUNCHED"* ]]; then
        fail "M5  memory_max: the zone did not launch, so nothing is proven"
        info "output: $(printf '%s' "$memout" | tr '\n' '|' | cut -c1-200)"
    elif [[ "$memout" == *"PROBE=survived"* ]]; then
        fail "M5  memory_max=48M did NOT hold: the zone wrote 256M and lived"
    elif [[ -n "$MEM_KILLS" ]] && (( MEM_KILLS > 0 )) && (( MEM_RC == 137 )); then
        pass "M5  memory_max=48M held: the kernel OOM-killed the zone ($MEM_SRC, exit $MEM_RC)"
        if (( MEM_GROUP_KILLS > 0 )); then
            pass "M5b memory.oom.group killed the WHOLE zone, not one process (oom_group_kill +$MEM_GROUP_KILLS)"
        else
            info "M5b oom_group_kill not reported by this kernel; oom.group is still set"
        fi
    elif [[ -z "$MEM_SRC" ]]; then
        skip "M5  memory_max: no readable oom_kill counter (leaf $MEM_LEAF, parent $MEM_PARENT)"
        info "     exit was $MEM_RC, which on its own is also what a SIGKILL from the test would give,"
        info "     so this run neither proves nor disproves the limit"
        info "     launcher said: $(printf '%s' "$memout" | tr '\n' '|' | cut -c1-260)"
    elif [[ -n "$MEM_KILLS" ]] && (( MEM_KILLS > 0 )); then
        # A pass needs both signals. The kernel counted an OOM kill but the
        # launcher did not exit 137: not a pass, and not a failed limit either.
        skip "M5  the kernel OOM-killed the zone but the launcher exited $MEM_RC, not 137"
        info "     $MEM_SRC"
    else
        fail "M5  memory_max=48M: the zone died (exit $MEM_RC) but the kernel recorded no OOM kill"
        info "     $MEM_SRC"
        info "     so it was not the memory limit that stopped it"
    fi

    # --- the zone cannot reach its own cgroup -------------------------------
    zrun pidcapped -- /bin/sh -c "$PRO if [ -w /sys/fs/cgroup/cgroup.procs ]; then echo PROBE=WRITABLE; else echo PROBE=denied; fi"
    probe "M6  a zone cannot write the cgroup filesystem from inside" "denied"

    # --- cleanup ------------------------------------------------------------
    # A launcher that exits normally removes its cgroup (rmdir fails with EBUSY
    # while a process remains). One launch only: M2, M3 and M8 kill their
    # launchers and leave empty cgroups for M9's sweep.
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
    # Leaves whose launcher (the pid in the name) is gone. A live launcher's
    # leaf is a running zone, such as the installed system's net zone.
    abandoned_leaves() {
        local d n p
        for d in /sys/fs/cgroup/kryptik/*/; do
            [[ -d "$d" ]] || continue
            n="$(basename "$d")"; p="${n##*.}"
            [[ "$p" =~ ^[0-9]+$ && -e "/proc/$p" ]] && continue
            printf '%s\n' "$d"
        done
    }
    after_cg="$(abandoned_leaves | wc -l)"
    # A SIGKILLed launcher cannot clean up, but PR_SET_PDEATHSIG kills every
    # process: its cgroup must be empty, for the next launch to sweep (M9).
    if (( after_procs != 0 )); then
        fail "M8  $after_procs process(es) survived a SIGKILLed launcher with limits"
        pkill -9 -f "sleep $MARK_CG" 2>/dev/null
    else
        # Read the file: a cgroup file's size is 0 whatever it holds.
        populated=0
        while IFS= read -r d; do
            [[ -n "$d" && -n "$(cat "$d/cgroup.procs" 2>/dev/null)" ]] && populated=$((populated+1))
        done < <(abandoned_leaves)
        if (( populated == 0 )); then
            pass "M8  a SIGKILLed launcher leaves no process and no populated cgroup"
            (( after_cg > 0 )) && info "     ($after_cg empty cgroup awaiting the sweep, as designed)"
        else
            fail "M8  $populated cgroup(s) still hold processes after the launcher was killed"
        fi
    fi

    # M9: the next launch that needs a cgroup removes empty leaves older than
    # the staleness window.
    if (( after_cg > 0 )); then
        sleep 6   # older than cgroup.rs::STALE_AFTER
        zrun pidcapped -- /bin/sh -c "$PRO echo PROBE=swept"
        if want_launch "M9  the next launch sweeps cgroups a killed launcher left"; then
            sleep 1
            still="$(abandoned_leaves | wc -l)"
            if (( still == 0 )); then
                pass "M9  the next launch swept the abandoned cgroup"
            else
                fail "M9  $still abandoned cgroup(s) survived the next launch's sweep"
                # Which, and why: what the leaf holds, and what rmdir itself
                # says about it.
                while IFS= read -r d; do
                    [[ -n "$d" ]] || continue
                    info "     $(basename "$d"): procs=[$(tr '\n' ' ' < "$d/cgroup.procs" 2>/dev/null)]; $(tr '\n' ' ' < "$d/cgroup.events" 2>/dev/null); rmdir: $(rmdir "$d" 2>&1 && echo ok)"
                done < <(abandoned_leaves)
                info "     launcher output: $(printf '%s' "$ZOUT" | grep -i 'cgroup\|sweep' | head -2 | tr '\n' ' ')"
            fi
        fi
    else
        pass "M9  nothing was left to sweep"
    fi
fi

# ============================================================================
head_ "E-EPH. Ephemeral zones keep nothing  [unpriv]"
# ============================================================================
# An ephemeral $HOME is a per-launch tmpfs in the zone's mount namespace. The
# kernel frees it when the namespace dies, so there is no teardown for a crash
# to skip. It is not secure erasure (tmpfs pages can be swapped out), and EPH8
# checks that the tooling says so.

# A dedicated rootfs base, so leftovers from other groups cannot confuse EPH4.
EPHROOT="$WORK/ephroot"
mkdir -p "$EPHROOT"
chmod 0755 "$EPHROOT"
(( PRIVILEGED == 1 )) && chown -R "$ZONE_UID:$ZONE_GID" "$EPHROOT" 2>/dev/null
EPHARGS=(--zones "$ZONES" --rootfs "$EPHROOT" "${IDENTITY[@]}")

ephrun() { # zone -- cmd...
    local zone="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    ZOUT="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
            "$KRYPTIKD" run "$zone" "${EPHARGS[@]}" -- "$@" 2>&1)"
    ZRC=$?
    return 0
}

# EPH1, the positive control: $HOME works.
ephrun alpha -- /bin/sh -c "$PRO printf '%s' '$CANARY' > \$HOME/secret; cat \$HOME/secret | sed 's/^/PROBE=/'"
probe "EPH1 positive control: an ephemeral zone can write and read its \$HOME" "$CANARY"

# EPH2: the zone's directory on the host stays empty.
if [[ -d "$EPHROOT/alpha" ]]; then
    n="$(find "$EPHROOT/alpha" -mindepth 1 2>/dev/null | wc -l)"
    if (( n == 0 )); then
        pass "EPH2 the persistent directory is still empty after the zone wrote to \$HOME"
    else
        fail "EPH2 the zone's writes reached the persistent directory ($n entr(ies))"
        find "$EPHROOT/alpha" -mindepth 1 2>/dev/null | head -3 | sed 's/^/        /'
    fi
else
    fail "EPH2 the persistent directory was not created at all"
fi

# EPH3: a second launch cannot see the first launch's data.
ephrun alpha -- /bin/sh -c "$PRO if [ -e \$HOME/secret ]; then echo PROBE=RECOVERED; else echo PROBE=gone; fi"
probe "EPH3 a later launch cannot recover the previous run's data" "gone"

# EPH4: the same after the launcher is SIGKILLed.
MARK_EPH=2914
KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run beta "${EPHARGS[@]}" -- \
    /bin/sh -c "printf '%s' '$CANARY' > \$HOME/crashfile; sleep $MARK_EPH" >/dev/null 2>&1 &
ephpid=$!
BG_PIDS+=("$ephpid")
sleep 2
kill -9 "$ephpid" 2>/dev/null
sleep 1
host_left="$(find "$EPHROOT/beta" -mindepth 1 2>/dev/null | wc -l)"
ephrun beta -- /bin/sh -c "$PRO if [ -e \$HOME/crashfile ]; then echo PROBE=RECOVERED; else echo PROBE=gone; fi"
if want_launch "EPH4 a crashed launcher leaves nothing recoverable"; then
    got="$(printf '%s\n' "$ZOUT" | sed -n 's/^PROBE=//p' | head -1)"
    if [[ "$got" == "gone" ]] && (( host_left == 0 )); then
        pass "EPH4 a SIGKILLed launcher leaves nothing on disk and nothing recoverable"
    elif [[ "$got" != "gone" ]]; then
        fail "EPH4 the next launch recovered the crashed run's data"
    else
        fail "EPH4 the crashed run left $host_left entr(ies) in the persistent directory"
    fi
fi

# EPH5: the zone's tmpfs never appears in the host's mount table.
hm_before="$(wc -l < /proc/mounts)"
ephrun alpha -- /bin/sh -c "$PRO echo PROBE=done"
hm_after="$(wc -l < /proc/mounts)"
if (( hm_before == hm_after )) && ! grep -q "$EPHROOT" /proc/mounts 2>/dev/null; then
    pass "EPH5 the ephemeral tmpfs never appears in the host mount table"
else
    fail "EPH5 the host mount table changed ($hm_before -> $hm_after) or names the zone path"
    grep "$EPHROOT" /proc/mounts 2>/dev/null | sed 's/^/        /' | head -3
fi

# EPH6: storage.size bounds the tmpfs: 128M written into a 64M zone.
ephrun alpha -- /bin/sh -c "$PRO dd if=/dev/zero of=\$HOME/big bs=1M count=128 2>/dev/null; s=\$(wc -c < \$HOME/big 2>/dev/null || echo 0); if [ \"\$s\" -gt 100000000 ]; then echo PROBE=UNBOUNDED; else echo PROBE=bounded; fi"
probe "EPH6 storage.size bounds the tmpfs (128M into a 64M zone is truncated)" "bounded"

# EPH7: an ephemeral zone will not start over data it did not write, and
# kryptikd refuses rather than deleting it.
mkdir -p "$EPHROOT/wiped"
(( PRIVILEGED == 1 )) && chown "$ZONE_UID:$ZONE_GID" "$EPHROOT/wiped" 2>/dev/null
echo "left over from an earlier build" > "$EPHROOT/wiped/stale.txt"
(( PRIVILEGED == 1 )) && chown "$ZONE_UID:$ZONE_GID" "$EPHROOT/wiped/stale.txt" 2>/dev/null
ephrun wiped -- /bin/sh -c "echo $LAUNCHED"
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "EPH7 an ephemeral zone STARTED over data from an earlier run"
elif (( ZRC == 0 )); then
    fail "EPH7 exit 0 for an ephemeral zone with stale data"
elif [[ "$ZOUT" == *"persistent data"* ]] && [[ -f "$EPHROOT/wiped/stale.txt" ]]; then
    pass "EPH7 an ephemeral zone with stale data is refused, and the data is left alone"
elif [[ ! -f "$EPHROOT/wiped/stale.txt" ]]; then
    fail "EPH7 kryptikd DELETED data it did not write"
else
    fail "EPH7 refused (exit $ZRC) but not for the stale-data reason"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-200)"
fi
rm -rf "$EPHROOT/wiped"

# EPH8: the tooling must not let "ephemeral" be read as secure erasure.
expl="$("$KRYPTIKD" explain alpha "${EPHARGS[@]}" 2>&1)"
if [[ "$expl" == *tmpfs* && "$expl" == *swap* && "$expl" == *"NOT secure erasure"* ]]; then
    pass "EPH8 explain says what ephemeral is, and that swap makes it not erasure"
else
    fail "EPH8 explain does not state the swap caveat"
    info "output: $(printf '%s' "$expl" | tr '\n' '|' | cut -c1-240)"
fi

# ============================================================================
head_ "CAP. The capability bounding set  [unpriv]"
# ============================================================================
# Zone root keeps only CAP_NET_BIND_SERVICE (bit 10, 0x400). NET_ADMIN and
# NET_RAW matter most: in a zone that owns a veth they would let it re-address
# its link and send raw frames on the bridge segment.

# Positive control: 0x400 in the zone shows a drop only if the launcher's
# bounding set is wider.
host_capbnd="$(grep -m1 '^CapBnd:' /proc/self/status | awk '{print $2}')"
if [[ -n "$host_capbnd" && "$host_capbnd" != "0000000000000400" ]]; then
    pass "CAP0 positive control: the launcher's bounding set is $host_capbnd, wider than a zone's"
else
    fail "CAP0 positive control FAILED: the launcher's own bounding set is already ${host_capbnd:-unknown}"
    info "     the zone's set cannot be shown to be narrower than the launcher's"
fi

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(grep -m1 '^CapBnd:' /proc/self/status | awk '{print \$2}')"
probe "CAP1 the zone's bounding set is CAP_NET_BIND_SERVICE and nothing else" "0000000000000400"

zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(grep -m1 '^CapEff:' /proc/self/status | awk '{print \$2}')"
probe "CAP2 the zone's effective set is the same single capability" "0000000000000400"

# The ones that matter most, by number so a failure names them: 21 SYS_ADMIN,
# 12 NET_ADMIN, 13 NET_RAW, 16 SYS_MODULE, 19 SYS_PTRACE, 27 MKNOD.
zrun alpha -- /bin/sh -c "$PRO b=\$(grep -m1 '^CapBnd:' /proc/self/status | awk '{print \$2}'); v=\$(printf '%d' 0x\$b); bad=''; for c in 21 12 13 16 19 27; do if [ \$(( (v >> c) & 1 )) -eq 1 ]; then bad=\"\$bad \$c\"; fi; done; if [ -n \"\$bad\" ]; then echo PROBE=KEPT\$bad; else echo PROBE=dropped; fi"
probe "CAP3 SYS_ADMIN, NET_ADMIN, NET_RAW, SYS_MODULE, PTRACE and MKNOD are gone" "dropped"

# Positive control: an empty bounding set would pass CAP1-CAP3 and break every
# zone.
zrun alpha -- /bin/sh -c "$PRO echo hi > \$HOME/capfile && cat \$HOME/capfile | sed 's/^/PROBE=/'"
probe "CAP4 positive control: the zone still runs normally after the drop" "hi"

# ============================================================================
head_ "BRK. The broker channel  [unpriv + vm]"
# ============================================================================
# The launcher serves /run/kryptik/broker for its zone and identifies the peer
# by SO_PEERCRED, never by what the zone sends. The client is python: bash has
# no AF_UNIX and busybox nc no -U. A refused peer can be answered and closed
# before it sends, so EPIPE is ignored and the answer read anyway.
BRK_CLIENT='import socket,sys
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sys.argv[1])
try:
    s.sendall(sys.argv[2].encode()+b"\n")
except BrokenPipeError:
    pass
sys.stdout.write(s.recv(256).decode(errors="replace").strip())'

if command -v python3 >/dev/null 2>&1; then
    # The broker names the zone from the connecting uid; a zone cannot ask to
    # be another.
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(python3 -c '$BRK_CLIENT' /run/kryptik/broker version 2>&1)"
    probe "BRK1 a zone's broker answers version, naming that zone" "kryptik-broker 1 zone=alpha"

    # The server parses rather than echoes.
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(python3 -c '$BRK_CLIENT' /run/kryptik/broker notaverb 2>&1)"
    probe "BRK2 an unknown verb is refused rather than echoed" "error: unknown verb"

    # A wider mode would let anything in the zone's uid range talk to it.
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(stat -c %a /run/kryptik/broker 2>/dev/null)"
    probe "BRK3 the broker socket is 0600" "600"
else
    skip "BRK1-BRK3 need python3 for an AF_UNIX client; this environment has none"
fi

# BRK4, the authentication, needs two uids: only a privileged launch gives each
# zone its own.
if (( PRIVILEGED == 1 )) && command -v python3 >/dev/null 2>&1; then
    KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO echo PROBE=up; /bin/sleep 20" > "$WORK/brk.out" 2>&1 &
    brkpid=$!
    BG_PIDS+=("$brkpid")
    brk_sock=""
    for _ in $(seq 1 200); do
        [[ -S "$REG/alpha/broker" ]] && { brk_sock="$REG/alpha/broker"; break; }
        kill -0 "$brkpid" 2>/dev/null || break
        sleep 0.05
    done
    if [[ -z "$brk_sock" ]]; then
        fail "BRK4 the zone's broker socket never appeared in the registry"
    else
        # Root (uid 0) connecting to a zone mapped to 100000 must be refused.
        out="$(python3 -c "$BRK_CLIENT" "$brk_sock" version 2>&1)"
        if [[ "$out" == *"unidentified peer"* ]]; then
            pass "BRK4 the broker refuses a peer that is not its zone (root asking got: $out)"
        elif [[ "$out" == *"zone=alpha"* ]]; then
            fail "BRK4 the broker ANSWERED a peer that is not its zone - identity is not enforced"
        else
            fail "BRK4 unexpected answer to a foreign peer: $out"
        fi
    fi
    kill -9 "$brkpid" 2>/dev/null
    wait "$brkpid" 2>/dev/null
    "$KRYPTIKD" gc >/dev/null 2>&1 || true
else
    skip "BRK4 broker authentication needs a privileged launch, where zones have distinct host uids"
fi

# ============================================================================
head_ "NETR. Routed networking, end to end  [vm / root only]"
# ============================================================================
# The nic zone holds the bridge (and any physical interfaces it names); a
# routed zone gets a veth into it. Starting a nic zone can take interfaces
# from zone 0, so this runs only in a disposable VM that says so
# (KRYPTIK_VM_DISPOSABLE=1), never as root on a real machine.
if (( PRIVILEGED == 1 )) && [[ "${KRYPTIK_VM_DISPOSABLE:-}" == "1" ]]; then
    # A routed fixture. `carrier` already holds the nic.
    mkzone router none "#0f0f0f"
    sed -i 's/^mode = "none"$/mode = "routed"/' "$ZONES/router.toml"
    # A routed zone's bridge address comes from its uid_base
    # (netzone::host_number); without one it starts with loopback only.
    printf '[identity]\nuid_base = 393216\n' >> "$ZONES/router.toml"

    # The nic zone must be running for a routed zone to attach to it.
    KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run carrier "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO echo PROBE=nic-up; /bin/sleep 60" > "$WORK/nic.out" 2>&1 &
    nicpid=$!
    BG_PIDS+=("$nicpid")

    nic_ready=0
    for _ in $(seq 1 200); do
        grep -q "$LAUNCHED" "$WORK/nic.out" 2>/dev/null && { nic_ready=1; break; }
        kill -0 "$nicpid" 2>/dev/null || break
        sleep 0.1
    done

    if (( nic_ready == 0 )); then
        fail "NETR1 the nic zone did not start, so nothing can be routed through it"
        info "output: $(tr '\n' '|' < "$WORK/nic.out" 2>/dev/null | cut -c1-240)"
    else
        pass "NETR1 the nic zone started and holds the interface"

        # Counted from /proc/net/dev (no iproute2 needed), without the kernel
        # fallback devices, or sit0 could pass for NETR3's interface.
        zrun router -- /bin/sh -c "$PRO n=\$(sed 1,2d /proc/net/dev | sed 's/:.*//' | tr -d ' ' | grep -vxE '$FALLBACK_RE' | wc -l); r=\$(sed 1d /proc/net/route | wc -l); echo PROBE=if=\$n,routes=\$r"
        if want_launch "NETR2 a routed zone starts while the nic zone is up"; then
            # A plumb failure does not stop the launch, so check the zone was
            # plumbed before NETR3 and NETR4 judge the result.
            if [[ "$ZOUT" == *"has no network path"* ]]; then
                fail "NETR2b the routed zone was never plumbed, so NETR3/NETR4 measure nothing"
                info "kryptikd said: $(printf '%s\n' "$ZOUT" | grep -a 'no network path' | head -1)"
            else
                pass "NETR2b the launch reported no plumbing failure"
            fi
            got="$(printf '%s\n' "$ZOUT" | sed -n 's/^PROBE=//p' | head -1)"
            ifn="${got#if=}"; ifn="${ifn%%,*}"
            rts="${got##*routes=}"
            if [[ "${ifn:-0}" -ge 1 ]]; then
                pass "NETR3 the routed zone has $ifn interface(s) besides loopback"
            else
                fail "NETR3 the routed zone has no interface besides loopback ($got)"
            fi
            if [[ "${rts:-0}" -ge 1 ]]; then
                pass "NETR4 the routed zone has $rts route(s)"
            else
                fail "NETR4 the routed zone has no routes ($got)"
            fi
        fi

        # Control: with the nic zone up, a mode=none zone still sees only
        # loopback, so NETR3 measured routing and not something every zone gets.
        zrun alpha -- /bin/sh -c "$PRO n=\$(sed 1,2d /proc/net/dev | sed 's/:.*//' | tr -d ' ' | grep -vxE '$FALLBACK_RE' | wc -l); echo PROBE=\$n"
        probe "NETR5 control: an airgapped zone still sees only loopback while the nic zone runs" "0"
    fi

    kill -9 "$nicpid" 2>/dev/null
    wait "$nicpid" 2>/dev/null
    "$KRYPTIKD" gc >/dev/null 2>&1 || true
elif (( PRIVILEGED == 1 )); then
    skip "NETR routed networking [vm] needs a disposable VM: this check MOVES THE PHYSICAL NIC into a zone, and will not do that to a machine it did not build"
else
    skip "NETR routed networking [vm] needs root and a disposable VM"
fi

# ============================================================================
head_ "POL. Per-zone policy files  [unpriv]"
# ============================================================================
# Checked by what a file changes in the zone, not by what kryptikd says it
# read: a keep-capability shows in the zone's bounding set.
mkdir -p "$ZONES/policy"

# A zone whose file keeps one extra capability...
cat > "$ZONES/policy/widened.seccomp" <<'POLICY'
# launcher.sh fixture: one directive with an effect that can be seen from
# inside the zone with nothing but /proc/self/status.
#
# CAP_SYS_NICE and not CAP_NET_RAW: the network capabilities may be kept ONLY
# by the zone that owns the NIC, which POL2b checks. This fixture is a
# mode=none zone, so asking for CAP_NET_RAW here is refused - correctly - and
# the check would be measuring that refusal instead of the widening.
keep-capability CAP_SYS_NICE
POLICY
mkzone_policy() { # name colour policyfile
    {
        printf '[zone]\nname = "%s"\ndescription = "policy fixture"\n' "$1"
        printf '[network]\nmode = "none"\n'
        printf '[storage]\nmode = "ephemeral"\nsize = "32M"\n'
        [[ -n "${3:-}" ]] && printf '[policy]\nseccomp = "%s"\n' "$3"
        printf '[ui]\nborder_color = "%s"\n' "$2"
    } > "$ZONES/$1.toml"
}
mkzone_policy widened "#0b0b0b" "policy/widened.seccomp"
mkzone_policy plainpol "#0c0c0c" ""

CAPBND='grep ^CapBnd /proc/self/status | tr -d "\t" | sed s/CapBnd://'

zrun plainpol -- /bin/sh -c "$PRO echo PROBE=\$($CAPBND)"
probe "POL1 positive control: a zone with no policy file keeps only CAP_NET_BIND_SERVICE" \
      "0000000000000400"

# CAP_SYS_NICE is bit 23 (0x800000) on top of CAP_NET_BIND_SERVICE, bit 10.
zrun widened -- /bin/sh -c "$PRO echo PROBE=\$($CAPBND)"
probe "POL2 a policy file's keep-capability reaches the zone's bounding set" \
      "0000000000800400"

# Only the zone that owns the NIC may keep the network capabilities; another
# zone asking is refused, naming the rule.
cat > "$ZONES/policy/netraw.seccomp" <<'POLICY'
keep-capability CAP_NET_RAW
POLICY
mkzone_policy netgrab "#1a1a1a" "policy/netraw.seccomp"
zrun netgrab -- /bin/sh -c "$PRO echo PROBE=ran"
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "POL2b a zone that does not own the NIC kept CAP_NET_RAW"
elif [[ "$ZOUT" == *"owns the NIC"* || "$ZOUT" == *CAP_NET_RAW* ]]; then
    pass "POL2b only the NIC-owning zone may keep the network capabilities"
else
    fail "POL2b refused, but not for the reason being tested"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-200)"
fi

# An unknown name refuses the launch rather than being ignored.
cat > "$ZONES/policy/typo.seccomp" <<'POLICY'
keep-capability CAP_NET_RWA
POLICY
mkzone_policy typoed "#0d0d0d" "policy/typo.seccomp"
zrun typoed -- /bin/sh -c "$PRO echo PROBE=ran"
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "POL3 a policy file with an unknown capability started the zone anyway"
elif [[ "$ZOUT" == *CAP_NET_RWA* || "$ZOUT" == *typo.seccomp* ]]; then
    pass "POL3 an unknown name in a policy file refuses the launch and names it"
else
    fail "POL3 refused, but the message named neither the file nor the bad name"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-200)"
fi

# And a file must not be able to re-allow something the base policy denies.
cat > "$ZONES/policy/escalate.seccomp" <<'POLICY'
allow-syscall ptrace
POLICY
mkzone_policy escalated "#0e0e0e" "policy/escalate.seccomp"
zrun escalated -- /bin/sh -c "$PRO echo PROBE=ran"
if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
    fail "POL4 a policy file RE-ALLOWED ptrace, which the base policy denies"
else
    pass "POL4 a policy file cannot re-allow a syscall the base policy denies"
fi

# Per-zone Landlock files are applied; the boundary probes (group E) show one
# narrowing where a zone may write.
lp="$("$KRYPTIKD" explain widened --zones "$ZONES" 2>&1 | sed -n 's/^policy *//p' | head -1)"
if [[ -n "$lp" ]]; then
    pass "POL5 explain reports what the policy file adds ($lp)"
else
    fail "POL5 explain does not report the policy file's additions"
fi

# seccomp-trace --zone traces under that zone's filter, so a call its policy
# file allows is no longer reported, and the program gets it.
cat > "$ZONES/policy/tracer.seccomp" <<'POLICY'
allow-syscall sched_setscheduler
POLICY
mkzone_policy tracer "#1b1b1b" "policy/tracer.seccomp"
if command -v python3 > /dev/null 2>&1; then
    prog='import os; os.sched_setscheduler(0, os.SCHED_OTHER, os.sched_param(0)); print("set")'
    base="$(timeout "$TIMEOUT" "$KRYPTIKD" seccomp-trace -- python3 -c "$prog" 2>&1)"
    own="$(timeout "$TIMEOUT" "$KRYPTIKD" seccomp-trace --zones "$ZONES" --zone tracer -- python3 -c "$prog" 2>&1)"
    if [[ "$base" == *"DENIED 144 sched_setscheduler"* && "$own" != *sched_setscheduler* && "$own" == *set* ]]; then
        pass "POL6 seccomp-trace --zone traces under the zone's own filter"
    else
        fail "POL6 --zone did not widen the trace [base: $(tr '\n' ' ' <<<"$base") | zone: $(tr '\n' ' ' <<<"$own")]"
    fi
else
    info "POL6 not run: this host has no python3"
fi

# ============================================================================
head_ "LC. Zone lifecycle: registry, stop, concurrency  [unpriv]"
# ============================================================================
# The registry is how one kryptikd finds another's zone
# (docs/design/zone-registry.md). Liveness is a lock, not a pid: the launcher
# holds flock(LOCK_EX) on its entry for life, so a crash frees it. The pid is
# kept, with its start time, only so `stop` can signal it and never a reused pid.

info "registry: $REG"

lc_cleanup() {
    "$KRYPTIKD" stop lczone --now >/dev/null 2>&1
    "$KRYPTIKD" gc >/dev/null 2>&1
}
lc_cleanup

# --- LC1: one instance per zone ---------------------------------------------
# Two launchers of one zone would share a data directory, a cgroup name and,
# for a routed zone, a veth name.
KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run lczone "${ZARGS[@]}" -- /bin/sleep 20 >/dev/null 2>&1 &
lc1=$!
BG_PIDS+=("$lc1")
sleep 1.5
out="$(KRYPTIK_EXPERIMENTAL=1 timeout 20 "$KRYPTIKD" run lczone "${ZARGS[@]}" -- /bin/echo SECOND 2>&1)"
rc=$?
if [[ "$out" == *SECOND* ]]; then
    fail "LC1 a second launch of the same zone RAN"
elif (( rc != 0 )) && [[ "$out" == *"already running"* || "$out" == *"already being started"* ]]; then
    pass "LC1 a second launch of a running zone is refused, and does not run"
else
    fail "LC1 second launch exited $rc without saying the zone is already running"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

# LC8a: while it runs, the registry says so.
st="$("$KRYPTIKD" status lczone 2>&1)"
if [[ "$st" == *running* ]]; then
    pass "LC8a status reports a running zone as running"
    info "     $st"
else
    fail "LC8a status did not report the running zone: $st"
fi

# LC10: init.pid is the zone's pid 1: another pid namespace, NSpid ending in 1.
initpid="$(awk '{print $1}' "$REG/lczone/init.pid" 2>/dev/null)"
if [[ -n "$initpid" ]] && [[ -r "/proc/$initpid/status" ]]; then
    ourns="$(readlink /proc/self/ns/pid 2>/dev/null)"
    zns="$(readlink "/proc/$initpid/ns/pid" 2>/dev/null)"
    nspid="$(awk '/^NSpid:/{print $NF}' "/proc/$initpid/status" 2>/dev/null)"
    if [[ "$zns" != "$ourns" && "$nspid" == "1" ]]; then
        pass "LC10 init.pid $initpid is pid 1 of its own pid namespace"
    else
        fail "LC10 init.pid $initpid: ns=$zns (ours $ourns) NSpid=$nspid"
    fi
    # LC17: the zone has a core-scheduling cookie of its own, so a core's
    # sibling threads run its tasks or nothing. /proc does not show cookies;
    # `kryptikd status` asks the kernel (PR_SCHED_CORE_GET). "no-smt": no core
    # has a second thread online (ENODEV, as under nosmt), and the zone must
    # still launch. "unavailable": no CONFIG_SCHED_CORE.
    cs="$("$KRYPTIKD" status lczone 2>/dev/null | grep -o 'core-sched [a-z-]*' | head -1)"
    case "$cs" in
        "core-sched own")   pass "LC17 the zone's pid 1 has a core-scheduling cookie of its own" ;;
        "core-sched no-smt") pass "LC17 no sibling threads online: the zone shares a core with nothing, and launched without a cookie" ;;
        "core-sched unavailable") skip "LC17 core-scheduling cookie: this kernel has no CONFIG_SCHED_CORE" ;;
        *)                  fail "LC17 the zone's pid 1 has no cookie of its own (status says: ${cs:-nothing about core-sched})" ;;
    esac
else
    fail "LC10 no usable init.pid in the registry entry"
fi

# LC7: the registry names running zones, their identities and cgroups, so only
# the launching uid may read it.
mode="$(stat -c '%a %u' "$REG" 2>/dev/null)"
if [[ "$mode" == "700 $EUID" ]]; then
    pass "LC7 the registry is 0700 and owned by the launching uid ($mode)"
else
    fail "LC7 registry mode/owner is '$mode', expected '700 $EUID'"
fi

# --- LC2: stop ends a cooperative zone --------------------------------------
t0=$SECONDS
"$KRYPTIKD" stop lczone >/dev/null 2>&1
rc=$?
elapsed=$(( SECONDS - t0 ))
sleep 0.5
if (( rc == 0 )) && [[ ! -d "$REG/lczone" ]]; then
    pass "LC2 stop ended the zone and removed its entry (${elapsed}s)"
else
    fail "LC2 stop exited $rc and the entry is $([[ -d "$REG/lczone" ]] && echo present || echo gone)"
fi
wait "$lc1" 2>/dev/null

# LC8b: and afterwards it is absent.
st="$("$KRYPTIKD" status lczone 2>&1)"
[[ "$st" == *absent* ]] && pass "LC8b status reports a stopped zone as absent" \
                        || fail "LC8b status after stop: $st"

# --- LC9: stop waits, so `stop && run` works --------------------------------
KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run lczone "${ZARGS[@]}" -- /bin/sleep 20 >/dev/null 2>&1 &
lc9=$!
BG_PIDS+=("$lc9")
sleep 1.5
if "$KRYPTIKD" stop lczone >/dev/null 2>&1 && \
   KRYPTIK_EXPERIMENTAL=1 timeout 20 "$KRYPTIKD" run lczone "${ZARGS[@]}" -- /bin/echo AFTER >/dev/null 2>&1; then
    pass "LC9 stop waits for the zone to be gone, so 'stop && run' succeeds"
else
    fail "LC9 'stop && run' did not succeed"
fi
wait "$lc9" 2>/dev/null

# --- LC3: a zone that ignores SIGTERM still dies ----------------------------
# A zone that traps TERM must not keep itself alive: stop escalates to SIGKILL
# after 5 s.
KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run lczone "${ZARGS[@]}" -- \
    /bin/sh -c 'trap "" TERM; sleep 60' >/dev/null 2>&1 &
lc3=$!
BG_PIDS+=("$lc3")
sleep 1.5
t0=$SECONDS
"$KRYPTIKD" stop lczone >/dev/null 2>&1
rc=$?
elapsed=$(( SECONDS - t0 ))
if (( rc == 0 )) && (( elapsed >= 3 )) && (( elapsed <= 20 )); then
    pass "LC3 a zone that ignores SIGTERM is killed by the escalation (${elapsed}s)"
elif (( rc == 0 )) && (( elapsed < 3 )); then
    fail "LC3 the zone died in ${elapsed}s - too fast for the 5s grace to have been real"
else
    fail "LC3 stop exited $rc after ${elapsed}s against a zone that ignores TERM"
fi
wait "$lc3" 2>/dev/null
lc_cleanup

# --- LC4: a stale entry is reclaimed, never signalled -----------------------
KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run lczone "${ZARGS[@]}" -- /bin/sleep 30 >/dev/null 2>&1 &
lc4=$!
BG_PIDS+=("$lc4")
sleep 1.5
kill -9 "$lc4" 2>/dev/null
wait "$lc4" 2>/dev/null
sleep 1
st="$("$KRYPTIKD" status lczone 2>&1)"
if [[ "$st" == *stale* ]]; then
    pass "LC4a a killed launcher leaves the entry STALE, not running"
else
    fail "LC4a status after kill -9: $st"
fi
out="$("$KRYPTIKD" stop lczone 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == *stale* ]]; then
    pass "LC4b stop reclaims a stale entry and says so"
else
    fail "LC4b stop on a stale entry: exit $rc, $out"
fi
if KRYPTIK_EXPERIMENTAL=1 timeout 20 "$KRYPTIKD" run lczone "${ZARGS[@]}" -- /bin/echo OK >/dev/null 2>&1; then
    pass "LC4c the zone can be started again after the stale entry is reclaimed"
else
    fail "LC4c could not start the zone after reclaiming its stale entry"
fi

# --- LC5: a reused pid is never signalled -----------------------------------
# A stale entry whose recorded pid now belongs to another process, which
# kryptikd must leave alone.
lc_cleanup
mkdir -p "$REG/lczone"
/bin/sleep 25 & victim=$!
BG_PIDS+=("$victim")
# The victim's pid, recorded with the wrong start time.
victim_start="$(awk '{print $22}' "/proc/$victim/stat" 2>/dev/null)"
printf '%s %s\n' "$victim" "$(( ${victim_start:-1} + 7 ))" > "$REG/lczone/launcher.pid"
: > "$REG/lczone/lock"
out="$("$KRYPTIKD" stop lczone 2>&1)"; rc=$?
sleep 0.5
if kill -0 "$victim" 2>/dev/null; then
    pass "LC5 a stale entry naming a reused pid did NOT signal that process"
else
    fail "LC5 kryptikd killed an unrelated process whose pid the entry had reused"
fi
if [[ ! -d "$REG/lczone" ]]; then
    pass "LC5b and the stale entry was reclaimed (exit $rc)"
else
    fail "LC5b the stale entry survived: $out"
fi
kill -9 "$victim" 2>/dev/null
lc_cleanup

# --- LC6: the registry is invisible inside a zone ---------------------------
# A zone has /run/kryptik/broker but must not see /run/kryptik/zones, which
# names every other zone's pid and cgroup.
zrun alpha -- /bin/sh -c "$PRO if [ -e /run/kryptik/zones ]; then echo PROBE=VISIBLE; else echo PROBE=absent; fi"
probe "LC6 the zone registry is not visible inside a zone" "absent"

# Control: /run/kryptik is there, holding only the broker socket.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(ls -A /run/kryptik 2>/dev/null | tr '
' ',')"
probe "LC6b control: /run/kryptik is present and contains only the broker socket" "broker,"

# LC15: the registry directory must not be plantable. base() can fall back to
# world-writable /tmp, where another user could create or symlink it first.
# XDG_RUNTIME_DIR points base() into $WORK, leaving the real registry alone.
# Unprivileged only: as root base() is /run/kryptik/zones, which nobody else
# can plant, and a plant there would displace the entries of running zones.
if (( PRIVILEGED == 1 )); then
    skip "LC15/LC16 the plantable-registry checks cover the UNPRIVILEGED base path; as root base() is /run/kryptik and ignores XDG_RUNTIME_DIR — the host run exercises them"
else

LC_XDG="$WORK/xdgplant"
mkdir -p "$LC_XDG"
ln -s "$WORK/elsewhere" "$LC_XDG/kryptik"
mkdir -p "$WORK/elsewhere/zones"
out="$(XDG_RUNTIME_DIR="$LC_XDG" KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
       "$KRYPTIKD" run alpha "${ZARGS[@]}" -- /bin/sh -c "$PRO echo PROBE=ran" 2>&1)"
rc=$?
if [[ "$out" == *"$LAUNCHED"* ]]; then
    fail "LC15 a zone started with its registry inside a planted symlink"
elif (( rc != 0 )) && [[ "$out" == *"$LC_XDG/kryptik"* ]]; then
    pass "LC15 a registry directory that is a symlink is refused, naming the path"
elif (( rc != 0 )); then
    fail "LC15 refused (exit $rc) but did not name the planted path"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-220)"
else
    fail "LC15 exited 0 with a planted registry directory"
fi
rm -f "$LC_XDG/kryptik"

# LC16, the control for LC15: the same launch with a real directory starts.
mkdir -p "$LC_XDG/kryptik"
chmod 0700 "$LC_XDG/kryptik"
out="$(XDG_RUNTIME_DIR="$LC_XDG" KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
       "$KRYPTIKD" run alpha "${ZARGS[@]}" -- /bin/sh -c "$PRO echo PROBE=ran" 2>&1)"
if [[ "$out" == *"$LAUNCHED"* && "$out" == *"PROBE=ran"* ]]; then
    pass "LC16 positive control: the same launch works with a registry directory we own"
else
    fail "LC16 positive control FAILED: the zone did not start even with a good directory"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-220)"
fi

fi   # end of the unprivileged-only LC15/LC16 pair

# ============================================================================
head_ "Mandatory checks NOT RUN here"
# ============================================================================
# Named, so the gaps show in the summary.

if (( CGROUP_OK == 0 )); then
    skip "cgroup memory/pids limits are enforced          [vm] this host cannot create cgroups; group M covers it there"
fi
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
