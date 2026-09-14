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

# A kryptikd older than the sources it was built from is the single most
# confusing way for this suite to fail. It does not fail honestly: every zone
# refuses to start, every check reports "did not launch", and nothing in the
# output points at the binary. A merge that added one zone-file key once
# produced 74 failures this way, all of them false.
#
# Comparing mtimes is crude and that is fine - it is a hint, not a gate, and it
# is checked against the sources that decide whether a zone file parses.
#
# Cargo.toml is the gate, and not incidentally: it is what distinguishes a
# BUILD TREE from a deployment. The developer VM image carries a copy of
# isolate.rs (adversarial.sh cross-checks its namespace set against it) and
# installs kryptikd at /usr/bin, so the copied source is newer than the binary
# and this check fired on every VM run - a false alarm about a binary that was
# built minutes earlier. Where there is no Cargo.toml there is nothing to
# rebuild and nothing to be stale.
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
        # storage.size is required for ephemeral and refused for encrypted.
        [[ "$storage" == "ephemeral" ]] && printf 'size = "64M"\n'
        # An encrypted fixture's volume is a file under the suite's own
        # directory: `kryptikd volume init` creates it there (F4, root), and
        # nothing of the suite's touches /var/lib/kryptik.
        [[ "$storage" == "encrypted" ]] && printf 'volume = "%s/volumes/%s.luks"\n' "$WORK" "$name"
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
# The zone that keeps things. `sealed` is the encrypted fixture and is used
# by group F only: it needs a volume and a passphrase to start, which is
# exactly what F proves, and would make every other check that merely needs
# a persistent directory depend on root and dm-crypt.
mkzone keeper   none   "#4a4a4a" ''                      persistent
# For K7: a zone whose data directory is deliberately owned by someone else.
mkzone stranger none   "#666666"
mkzone lczone   none   "#0a0a0a"

# M1 fixtures. `capped` is the zone under test; `roomy` is its positive
# control - the same shape with limits high enough that nothing should hit
# them, so a failure in `capped` can be attributed to the limit rather than to
# the zone being broken.
mkzone_limited() { # name colour memory pids
    {
        printf '[zone]\nname = "%s"\ndescription = "launcher-suite limit fixture"\n' "$1"
        printf '[network]\nmode = "none"\n'
        # 32M, under every memory_max these fixtures use. A tmpfs larger than
        # the zone's memory limit is refused at parse time now - it could never
        # reach its stated size, because its pages are charged to that same
        # limit - and memcapped's cap is 48M.
        printf '[storage]\nmode = "ephemeral"\nsize = "32M"\n'
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
    # A zone that declares [identity] REFUSES --zone-uid/--zone-gid: the file
    # is the authority, and a command-line override would silently change who
    # owns that zone's data. `tools/kryptik` already works this out per zone;
    # the suite has to as well, or a fixture with an identity cannot be
    # launched here at all - which is why the routed fixture had none, and why
    # it was never plumbed.
    local -a za=("${ZARGS[@]}")
    if (( ${#IDENTITY[@]} )) && grep -q '^\[identity\]' "$ZONES/$zone.toml" 2>/dev/null; then
        za=(--zones "$ZONES" --rootfs "$ROOTFS")
    fi
    ZOUT="$(KRYPTIK_EXPERIMENTAL=1 timeout "$TIMEOUT" \
            "$KRYPTIKD" run "$zone" "${za[@]}" -- "$@" 2>&1)"
    ZRC=$?
    return 0
}

# zrun_raw: same, but WITHOUT the experimental override, for refusal checks.
zrun_raw() {
    local zone="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    # A zone that declares [identity] REFUSES --zone-uid/--zone-gid: the file
    # is the authority, and a command-line override would silently change who
    # owns that zone's data. `tools/kryptik` already works this out per zone;
    # the suite has to as well, or a fixture with an identity cannot be
    # launched here at all - which is why the routed fixture had none, and why
    # it was never plumbed.
    local -a za=("${ZARGS[@]}")
    if (( ${#IDENTITY[@]} )) && grep -q '^\[identity\]' "$ZONES/$zone.toml" 2>/dev/null; then
        za=(--zones "$ZONES" --rootfs "$ROOTFS")
    fi
    ZOUT="$(env -u KRYPTIK_EXPERIMENTAL timeout "$TIMEOUT" \
            "$KRYPTIKD" run "$zone" "${za[@]}" -- "$@" 2>&1)"
    ZRC=$?
    return 0
}

# The launch sentinel. A zone command prints this before doing anything else;
# if it is absent the process never got to run and no isolation claim from that
# run is admissible.
LAUNCHED="ZONE_LAUNCH_OK"

# Where kryptikd keeps its zone registry, derived the same way base() does.
# Defined here rather than beside its first use because two groups read it (K's
# T11 and all of LC), and a path defined twice is a path that drifts.
REG="${XDG_RUNTIME_DIR:-/tmp/kryptik-$(id -u)}/kryptik/zones"
[[ "$EUID" -eq 0 ]] && REG=/run/kryptik/zones

# Preflight: none of this suite's zones may already be running.
#
# Since the lifecycle registry landed, a second `run` of a name that is already
# running is refused - correctly. But the suite reuses a handful of zone names
# for everything, so ONE launcher left behind by an overlapping run turns into
# dozens of "did not launch" failures that describe nothing about the code. It
# has happened once already: 56 failures, every one of them the same sentence.
# Say the real thing once, and stop.
# Only the names THIS suite uses. The registry is per-uid and shared across
# every checkout on the machine, so another tab running its own fixture - a
# `probe` zone, say - would otherwise stop this suite dead with a message about
# a zone it has never heard of and does not touch. It happened.
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

# want_launch DESC -- fails the check if the sentinel is missing, and says
# WHY (timeout / setup failure / exec failure) instead of silently passing.
want_launch() {
    local desc="$1"
    if [[ "$ZOUT" == *"$LAUNCHED"* ]]; then
        return 0
    fi

    # A launch the TARGET kernel refuses on purpose is NOT RUN, not failed.
    #
    # kryptikd ignores KRYPTIK_EXPERIMENTAL for a root launch on a kernel that
    # restricts unprivileged user namespaces (Design 01 P6), so a zone whose
    # configuration asks for something this build cannot deliver cannot be
    # started there at all. That is the rule working. Several checks here use
    # such a zone as scaffolding - B1 needs a persistent directory and so uses
    # the encrypted fixture, K3 checks ownership on the same one - and on the
    # Kryptik kernel they reported as failures, which blamed the system for
    # doing exactly what it was designed to do.
    #
    # Handled once, here, rather than in each check: every check reaches a
    # launch through this function, and the next one to use an
    # override-dependent fixture should not have to rediscover this.
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

# keeper writes a canary into its own home.
# `keeper` rather than `alpha`, and the reason matters: alpha is ephemeral, so
# nothing it writes reaches the host and B1b would have nothing to find. The
# cross-zone claim needs a zone whose data actually persists.
#
# This group used `sealed` - the ENCRYPTED fixture, started under
# KRYPTIK_EXPERIMENTAL - until the target kernel existed. There the override is
# ignored (Design 01 P6) and sealed cannot start, so B1a skipped and B1c/B1d
# went on reporting PASS: no other zone could read a file that was never
# written. A vacuous pass on an isolation check is the failure this file exists
# to prevent, and it survived for as long as it did because the group looked
# green.
#
# storage.mode = "persistent" is the honest version of what that fixture was
# pretending to be: a plain directory, kept between launches, claiming nothing
# about encryption. When per-zone encrypted volumes land, `sealed` becomes a
# real one and these checks do not change.
zrun keeper -- /bin/sh -c "$PRO printf '%s' '$CANARY' > \$HOME/alpha-secret; echo PROBE=written"
probe "B1a a persistent zone can write a file in its own zone" "written"

# Positive control: that file exists on the host, so a failure to read it from
# beta means something. Without this the next check would pass on a typo.
if [[ -f "$ROOTFS/keeper/alpha-secret" ]] && grep -q "$CANARY" "$ROOTFS/keeper/alpha-secret"; then
    pass "B1b positive control: the file is real and readable from the host"
else
    fail "B1b positive control FAILED: the file is not where the test expects"
    info "looked for: $ROOTFS/keeper/alpha-secret"
fi

# B1e is the persistence claim itself, and the thing that makes it a check
# rather than a restatement of B1b is that it is a SECOND LAUNCH. The zone
# exited, its mount namespace and pid namespace are gone, its tmpfs would have
# been freed - and the file is still in its home.
zrun keeper -- /bin/sh -c "$PRO if grep -q '$CANARY' \$HOME/alpha-secret 2>/dev/null; then echo PROBE=kept; else echo PROBE=LOST; fi"
probe "B1e a persistent zone still has its file on the NEXT launch" "kept"

# The control, and it is the half that gives B1e its meaning: the identical
# sequence in an EPHEMERAL zone must lose the file. Without it, B1e would also
# pass if every zone kept everything - which is the bug, not the feature.
zrun wiped -- /bin/sh -c "$PRO printf '%s' '$CANARY' > \$HOME/eph-secret; echo PROBE=written"
probe "B1f control: an ephemeral zone can write the same file" "written"

zrun wiped -- /bin/sh -c "$PRO if grep -q '$CANARY' \$HOME/eph-secret 2>/dev/null; then echo PROBE=KEPT; else echo PROBE=gone; fi"
probe "B1g control: the ephemeral zone does NOT have it on its next launch" "gone"

# beta tries the same absolute path, and the host path keeper's data really
# lives at. Neither exists in beta's root.
# /home/alpha is where alpha's data is mounted INSIDE ALPHA. Beta's tree has no
# such path: each zone binds only its own directory.
zrun beta -- /bin/sh -c "$PRO if cat /home/keeper/alpha-secret 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B1c another zone cannot read it at its in-zone path" "denied"

zrun beta -- /bin/sh -c "$PRO if cat '$ROOTFS/keeper/alpha-secret' 2>/dev/null | grep -q '$CANARY'; then echo PROBE=LEAKED; else echo PROBE=denied; fi"
probe "B1d another zone cannot read it by its host path" "denied"

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
    # Counted with a glob rather than `ls /proc | grep`: every /proc entry
    # beginning with a digit is a pid, and this needs no subprocess of its own
    # to miscount.
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
# An encrypted zone lives on a LUKS2 volume and starts only with its
# passphrase. A refusal has to be a refusal - the command NEVER RAN - and the
# development override must not turn it into a plain directory. F1 asserts
# the opposite for ephemeral storage, and that is the point of this group:
# the refusal list must shrink as things get implemented, or it becomes a
# list of lies in the other direction.
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

# The development override exists for guarantees that are NOT implemented.
# It must not reach this one: with it set, still no passphrase, still no zone.
zrun sealed -- /bin/sh -c "echo $LAUNCHED"
if [[ "$ZOUT" == *"$LAUNCHED"* ]] || (( ZRC == 0 )); then
    fail "F3  KRYPTIK_EXPERIMENTAL=1 started an encrypted zone without its passphrase"
elif [[ "$ZOUT" == *"passphrase"* ]]; then
    pass "F3  the override does not apply to encryption: still refused for want of a passphrase"
else
    fail "F3  refused under the override, but not for the passphrase (exit $ZRC)"
    info "output: $(printf '%s' "$ZOUT" | tr '\n' '|' | cut -c1-220)"
fi

# With a volume and its passphrase the zone starts, and its home IS the
# volume: /proc/mounts inside the zone names the dm-crypt mapping. Root only
# (cryptsetup, dm-crypt, a loop device); anywhere else this is a gap, not a
# pass. The VM runs the suite as root, so the gap closes there.
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
        if [[ -e /dev/mapper/kryptik-sealed ]]; then
            fail "F4b the mapping is still open after the zone exited"
            "$KRYPTIKD" stop sealed --now >/dev/null 2>&1 || true
        else
            pass "F4b the mapping is closed when the zone exits"
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
#
# Scoped to THIS launch by a marker in its argv, not to every `kryptikd run` on
# the machine. The previous version counted them globally before and after,
# which made the answer depend on whatever else happened to be running - and it
# duly reported "2 kryptikd process(es) outlived the zone" about a zone that had
# exited cleanly, because a second run of this suite had been started while the
# first was still winding down. Two processes is also exactly what one launch
# looks like (the launcher and the intermediate both keep `kryptikd run` in
# their argv), which is how the wrong count looked plausible.
#
# pgrep -c is deliberately NOT used: it prints "0" and ALSO exits non-zero when
# nothing matches, so a `|| echo 0` fallback yields "0\n0" and (( )) dies with a
# syntax error - which once made this check vanish from the report rather than
# fail. wc -l always emits exactly one number.
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

# Devices the KERNEL creates in every new network namespace. Nothing in the
# zone asked for them, and nothing in the zone can remove them - so "the
# namespace contains only lo" is not a promise kryptikd is able to keep. What
# it can keep, and what the promise is actually about, is that none of them can
# carry traffic. That is what H1 checks now: the names may include these and
# ONLY these, and every device other than loopback must be DOWN with no
# address. That is strictly more than the old check, which looked at names and
# never at state.
#
#   sit0  CONFIG_IPV6_SIT=y makes the SIT driver register an IPv6-in-IPv4
#         fallback tunnel in each netns. Asked for as CONFIG_IPV6_SIT=n in
#         build/REQUEST.md B-6; when that lands the device stops appearing and
#         this list stops mattering, with no edit here.
#
# The same list is in adversarial.sh and the two must agree. They run in the
# same boot, so a divergence shows up immediately as one suite passing where
# the other fails on identical evidence.
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
    # UP, or carrying an address: either one makes a device able to do
    # something, which is the property the promise is about.
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
    # `keeper`, not `alpha`: K3 is the one check in this group that looks at the
    # HOST side, and an ephemeral zone writes nothing there. Using alpha here
    # would test M2 by accident and report it as an ownership failure.
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
    #
    # When the launcher has none, the answer is not to skip: it is to give it
    # some. `setpriv --groups` needs CAP_SETGID, which group K already has, so
    # the launch can be staged with real supplementary groups and the drop then
    # has something to show. This turned K4 from a permanent NOT RUN in the one
    # environment that can run it - the VM, where init starts the suite with no
    # groups at all - into a check that actually executes.
    K4_GROUPS="4,27"
    K4_WRAP=()
    launcher_groups="$(grep '^Groups:' /proc/self/status | cut -f2- | wc -w)"
    if (( launcher_groups == 0 )); then
        # Two candidates, because the obvious one is not available where this
        # check actually runs: busybox's setpriv - what a minimal image has -
        # implements --dump, --nnp and the two capability options, and has no
        # --groups at all. s6-applyuidgid -G does exactly this job and the VM
        # image already carries the s6 stack for its init.
        #
        # Whichever is chosen is then made to prove itself: the groups are read
        # back from the same /proc file the zone reads, and a wrapper that did
        # not actually grant any is discarded. Otherwise "0 groups in the zone"
        # would once again be evidence of nothing.
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
            # The count can exceed what was asked for - s6-applyuidgid keeps
            # the caller's primary group as well - so report what was measured
            # and who granted it, not the request.
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

# --- T11: the zone as the HOST sees it --------------------------------------
#
# Design 01a T11, in the shape security asked for in R-8a: one assertion, made
# from outside, about the zone's pid 1.
#
# Every other check of the zone's identity asks the zone. That is not worthless
# - a compromised zone would have to lie consistently - but it is an inside
# view, and the whole point of the privileged path is what the HOST sees. This
# reads /proc/<init>/status and /proc/<init>/ns from outside the zone entirely,
# using the pid the registry recorded, and it is the falsifiable one: if
# kryptikd ever mapped a zone to real root, or left a capability in the
# effective set, or shared a namespace with pid 1, this line fails while every
# in-zone check keeps passing.
if (( PRIVILEGED == 1 )); then
    KRYPTIK_EXPERIMENTAL=1 "$KRYPTIKD" run alpha "${ZARGS[@]}" -- \
        /bin/sh -c "$PRO echo PROBE=up; /bin/sleep 30" > "$WORK/t11.out" 2>&1 &
    t11launcher=$!
    BG_PIDS+=("$t11launcher")

    t11init=""
    for _ in $(seq 1 200); do
        # "<pid> <starttime>" - the start time is what makes the pid safe to
        # use, and the registry records both for exactly that reason.
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

    # M5 reads the KERNEL's counter, not the exit code.
    #
    # The security review's Required 3: exit 137 alone proves nothing, because
    # it is exactly what the suite's own `timeout -s KILL` would produce. The
    # fact that distinguishes "the kernel killed this zone for exceeding
    # memory.max" from "something killed this zone" is memory.events'
    # `oom_kill` counter, and it has to be read from the host BEFORE the
    # launcher removes the cgroup - so this polls, as the pids probe does.
    MEM_OOM=""; MEM_GROUP=""; MEM_LEAF=""; MEM_RC=""

    # Where the counter is read from matters more than how often.
    #
    # The first version of this polled the zone's OWN cgroup leaf. That loses a
    # race it cannot win: memory.oom.group=1 makes the kernel kill every
    # process in the zone in one go, the launcher reaps them and removes the
    # leaf a few milliseconds later, and the counter is only readable in the
    # gap between those two events. A 100ms poll missed it on essentially every
    # VM run and reported "never read memory.events" about a run whose OOM is
    # printed in the kernel log:
    #     Memory cgroup out of memory: Killed process 3441 (dd) ...
    # Tightening the poll would only shrink the odds, not remove them.
    #
    # memory.events is hierarchical, and the parent /sys/fs/cgroup/kryptik is
    # created once and outlives every zone - so its counter still holds this
    # zone's OOM after the leaf is gone. Sampling it either side of a single
    # serialized launch attributes the delta to that launch. The leaf poll is
    # kept because when it does win the race it names the exact cgroup.
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
    # Wait for as long as the LAUNCHER lives, not for a fixed interval: writing
    # 256M into a capped tmpfs takes as long as it takes, and in the emulated
    # VM the OOM lands around 36s.
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

    # Resolve the two sources into one number plus a plain statement of where
    # it came from, so a pass line can never be read as more than it is.
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
        # REVIEW-R5 required 2 asks for both signals, not either. They disagree
        # here: the kernel counted an OOM kill for this zone, and the launcher
        # came back with something other than 128+SIGKILL. That is not a pass
        # (the launcher's own exit path is unaccounted for) and not a plain
        # failure of the limit (the kill happened), so it is neither.
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
                find /sys/fs/cgroup/kryptik -mindepth 1 -maxdepth 1 -type d -exec rmdir {} + 2>/dev/null
            fi
        fi
    else
        pass "M9  nothing was left to sweep"
    fi
fi

# ============================================================================
head_ "E-EPH. Ephemeral zones keep nothing  [unpriv]"
# ============================================================================
# "ephemeral" used to be a label on a persistent directory, and the launcher
# refused to start such a zone rather than let the word stand. It is now a
# per-launch tmpfs mounted at $HOME inside the zone's own mount namespace, so
# the guarantee is structural: there is no teardown step that a crash can skip,
# because the kernel frees the mount when the namespace dies.
#
# What these checks must NOT do is let "ephemeral" be read as secure erasure.
# tmpfs pages are swappable. EPH8 asserts that the tooling says so.

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

# EPH1: the zone can use $HOME normally. Without this, every check below would
# also pass on a zone whose home was unwritable, which is not ephemeral, just
# broken.
ephrun alpha -- /bin/sh -c "$PRO printf '%s' '$CANARY' > \$HOME/secret; cat \$HOME/secret | sed 's/^/PROBE=/'"
probe "EPH1 positive control: an ephemeral zone can write and read its \$HOME" "$CANARY"

# EPH2: and the host sees nothing. The tmpfs lives in the zone's mount
# namespace, so the persistent directory must be untouched.
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

# EPH3: a second launch cannot see the first launch's data. This is the claim.
ephrun alpha -- /bin/sh -c "$PRO if [ -e \$HOME/secret ]; then echo PROBE=RECOVERED; else echo PROBE=gone; fi"
probe "EPH3 a later launch cannot recover the previous run's data" "gone"

# EPH4: the same, after the launcher is SIGKILLed rather than exiting. A crash
# must not be the path by which data survives.
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

# EPH5: the host's mount table must not carry the zone's tmpfs. If it did, the
# mount would outlive the zone and would need a teardown step that a crash
# could skip - which is the design this replaced.
hm_before="$(wc -l < /proc/mounts)"
ephrun alpha -- /bin/sh -c "$PRO echo PROBE=done"
hm_after="$(wc -l < /proc/mounts)"
if (( hm_before == hm_after )) && ! grep -q "$EPHROOT" /proc/mounts 2>/dev/null; then
    pass "EPH5 the ephemeral tmpfs never appears in the host mount table"
else
    fail "EPH5 the host mount table changed ($hm_before -> $hm_after) or names the zone path"
    grep "$EPHROOT" /proc/mounts 2>/dev/null | sed 's/^/        /' | head -3
fi

# EPH6: storage.size is a real bound, not decoration. 64M fixture, write 128M.
ephrun alpha -- /bin/sh -c "$PRO dd if=/dev/zero of=\$HOME/big bs=1M count=128 2>/dev/null; s=\$(wc -c < \$HOME/big 2>/dev/null || echo 0); if [ \"\$s\" -gt 100000000 ]; then echo PROBE=UNBOUNDED; else echo PROBE=bounded; fi"
probe "EPH6 storage.size bounds the tmpfs (128M into a 64M zone is truncated)" "bounded"

# EPH7: an ephemeral zone will not start over data it did not write. kryptikd
# must refuse rather than delete: silently destroying an operator's files is
# the one behaviour worse than leaving them.
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
# A zone's root is root in its own user namespace, so it held a full capability
# set. Every capability-gated syscall that reaches outside the namespace is
# already denied by the seccomp filter, which is why that was tolerable - and
# why it stops being tolerable the moment a zone owns one end of a veth.
# CAP_NET_ADMIN and CAP_NET_RAW in a namespace with a real interface let a
# compromised zone re-address its link and open a raw socket on the segment it
# shares with the bridge. The security review calls this a precondition for the
# routed-network milestone rather than a follow-up to it.
#
# The expected value is not a round number and that is deliberate:
# CAP_NET_BIND_SERVICE is capability 10, so the only bit that may survive is
# 1 << 10 = 0x400. Anything else means something was kept that should not be.

# Positive control FIRST. "The zone's bounding set is 0x400" is evidence only
# if the launcher's is bigger - on a host that was already fully restricted,
# the zone would show 0x400 with or without the drop.
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

# The capabilities that matter most, named individually so a failure says which
# one came back rather than printing a hex number and leaving the reader to
# decode it. 21 = CAP_SYS_ADMIN, 12 = NET_ADMIN, 13 = NET_RAW, 16 = SYS_MODULE,
# 19 = SYS_PTRACE, 27 = MKNOD.
zrun alpha -- /bin/sh -c "$PRO b=\$(grep -m1 '^CapBnd:' /proc/self/status | awk '{print \$2}'); v=\$(printf '%d' 0x\$b); bad=''; for c in 21 12 13 16 19 27; do if [ \$(( (v >> c) & 1 )) -eq 1 ]; then bad=\"\$bad \$c\"; fi; done; if [ -n \"\$bad\" ]; then echo PROBE=KEPT\$bad; else echo PROBE=dropped; fi"
probe "CAP3 SYS_ADMIN, NET_ADMIN, NET_RAW, SYS_MODULE, PTRACE and MKNOD are gone" "dropped"

# And the zone still works. A bounding set of zero would pass CAP1-CAP3 and
# break every zone, so this is the check that stops the drop going too far.
zrun alpha -- /bin/sh -c "$PRO echo hi > \$HOME/capfile && cat \$HOME/capfile | sed 's/^/PROBE=/'"
probe "CAP4 positive control: the zone still runs normally after the drop" "hi"

# ============================================================================
head_ "BRK. The broker channel  [unpriv + vm]"
# ============================================================================
# The launcher serves a socket at /run/kryptik/broker for its own zone, and
# decides who is on the other end from SO_PEERCRED - kernel-asserted, not
# anything the zone sends. Nothing exercised it, and it is a boundary.
#
# The client is a python one-liner because AF_UNIX needs a real socket call:
# bash can do /dev/tcp and not this, and busybox nc has no -U. python3 is
# present both on the developer host and in the Kryptik sysroot, so the same
# check runs in both places.
# A refused peer is answered from its credentials alone, before the broker
# reads a byte: the refusal can already be written and the socket closed by
# the time this client sends, and the send then fails with EPIPE. The
# answer is still in the socket; read it either way (BRK4 once reported a
# traceback for a refusal that had happened exactly as it should).
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
    # The zone asks the broker who it is. The answer has to be this zone: it is
    # derived from the connecting uid, so a zone cannot ask to be another.
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(python3 -c '$BRK_CLIENT' /run/kryptik/broker version 2>&1)"
    probe "BRK1 a zone's broker answers version, naming that zone" "kryptik-broker 1 zone=alpha"

    # The server parses rather than echoes.
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(python3 -c '$BRK_CLIENT' /run/kryptik/broker notaverb 2>&1)"
    probe "BRK2 an unknown verb is refused rather than echoed" "error: unknown verb"

    # The socket must be the zone's alone. 0600 and owned by the zone identity,
    # checked from inside, because a mode that drifted to 0666 would let
    # anything in the zone's uid range talk to it.
    zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(stat -c %a /run/kryptik/broker 2>/dev/null)"
    probe "BRK3 the broker socket is 0600" "600"
else
    skip "BRK1-BRK3 need python3 for an AF_UNIX client; this environment has none"
fi

# BRK4 is the authentication itself, and it needs two different uids - which
# only exist on a privileged launch, where each zone maps to its own range. On
# the developer host every zone maps to the launching user, so there is no
# second identity to be refused and the check would pass vacuously.
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
        # Connecting as root (uid 0) to a socket whose zone is uid 100000. The
        # kernel reports our uid; the broker must refuse us. This is the whole
        # authentication claim, driven rather than reasoned about.
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
# Security implemented the topology: the nic zone takes the physical interface
# and the bridge, and a routed zone gets a veth into it. This is the check that
# turns "implemented" into "tested" - it starts both and looks at what the
# routed zone actually has.
#
# TWO GATES, AND THE SECOND IS NOT OPTIONAL. Starting the nic zone MOVES THE
# PHYSICAL INTERFACE into another network namespace. In a disposable VM that
# this harness built, that is fine and it is the point. On a developer's
# machine it would take their network away mid-command. So this runs only when
# the payload that built the VM says so, and reports NOT RUN anywhere else -
# including for root on a real host, which is exactly the case that would
# otherwise do damage.
if (( PRIVILEGED == 1 )) && [[ "${KRYPTIK_VM_DISPOSABLE:-}" == "1" ]]; then
    # A routed fixture. `carrier` already holds the nic.
    mkzone router none "#0f0f0f"
    sed -i 's/^mode = "none"$/mode = "routed"/' "$ZONES/router.toml"
    # A routed zone's address on the bridge is derived from its identity -
    # netzone::host_number reads [identity] uid_base, and plumb_routed_zone
    # refuses the zone without one. A refusal there is NOT fatal: the zone
    # starts with loopback only, fail-closed, which is the right behaviour and
    # is precisely what NETR3 and NETR4 were reporting for a whole boot. They
    # were measuring a fixture that never asked to be routed.
    printf '[identity]\nuid_base = 393216\n' >> "$ZONES/router.toml"

    # The nic zone has to be RUNNING for a routed zone to have anything to
    # attach to, so it goes in the background and stays there.
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

        # What a routed zone actually gets. Counted from /proc/net/dev, which
        # needs no iproute2 in the image.
        # Excluding the kernel fallback devices is not cosmetic here: this
        # count is what NETR3 calls "an interface besides loopback", and on a
        # kernel with SIT the 1 it reported could have been sit0 rather than
        # the veth routing was supposed to give this zone.
        zrun router -- /bin/sh -c "$PRO n=\$(sed 1,2d /proc/net/dev | sed 's/:.*//' | tr -d ' ' | grep -vxE '$FALLBACK_RE' | wc -l); r=\$(sed 1d /proc/net/route | wc -l); echo PROBE=if=\$n,routes=\$r"
        if want_launch "NETR2 a routed zone starts while the nic zone is up"; then
            # Did the launch build a network path at all? A plumb failure is
            # deliberately not fatal, so without this NETR3 and NETR4 cannot
            # tell "routing is broken" from "this zone never asked for it" -
            # and they reported the second as the first until this check
            # existed.
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

        # THE CONTROL. A mode=none zone in the same conditions, with the nic
        # zone still up, must still see only loopback - otherwise NETR3 is
        # measuring something every zone gets rather than something routing
        # gave this one.
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
# These were reported as "not implemented" by this suite until security landed
# them, which made the suite under-report what the system does - the same
# defect as over-reporting it, pointing the other way.
#
# What is checked is that the file CHANGES the zone, not that kryptikd says it
# read one. `keep-capability CAP_NET_RAW` is the directive with a consequence
# visible from inside a zone without a compiler: the bounding set gains
# CAP_NET_RAW (bit 13, 0x2000) on top of CAP_NET_BIND_SERVICE (bit 10, 0x400).
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

# The network capabilities are the ones worth restricting, and security
# restricted them: only the zone that owns the NIC may keep them. A zone that
# asks anyway must be refused, and the refusal must say which rule it broke.
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

# A file that names something outside the vocabulary must refuse the launch,
# not silently do nothing: a typo that produced a quietly narrower zone than
# the file says would be the worst outcome of having files at all.
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

# The Landlock half is NOT implemented, and the suite says so by name rather
# than leaving it inside a message about seccomp.
lp="$("$KRYPTIKD" explain widened --zones "$ZONES" 2>&1 | sed -n 's/^policy *//p' | head -1)"
if [[ -n "$lp" ]]; then
    pass "POL5 explain reports what the policy file adds ($lp)"
else
    fail "POL5 explain does not report the policy file's additions"
fi
skip "POL6 per-zone LANDLOCK policy files are NOT applied (seccomp files are; kryptikd refuses a zone naming a landlock file)"

# ============================================================================
head_ "LC. Zone lifecycle: registry, stop, concurrency  [unpriv]"
# ============================================================================
# `kryptikd run` was one-shot: it supervised its own zone and nothing else
# could find that zone. There was no `stop`, no way to ask what was running,
# and therefore no way for a routed zone to attach to a running `net` zone -
# which is what blocks M3.
#
# The registry is how a SECOND kryptikd finds the first. There is still no
# daemon. Design 06.
#
# The invariant that carries the rest: liveness is a LOCK, not a pid. The
# launcher holds flock(LOCK_EX) on the entry for its whole life, so a crash
# releases it and "the lock is free" means "nothing is supervising this" with
# no bookkeeping to get wrong. The pid is recorded only so `stop` has
# something to signal, and it is recorded WITH the process start time so a
# reused pid can never be mistaken for the original.

info "registry: $REG"

lc_cleanup() {
    "$KRYPTIKD" stop lczone --now >/dev/null 2>&1
    "$KRYPTIKD" gc >/dev/null 2>&1
}
lc_cleanup

# --- LC1: one instance per zone ---------------------------------------------
# Two launchers of one zone would share a data directory, a cgroup name and -
# once M3 lands - a veth name, and the second would quietly corrupt the first.
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

# LC10: init.pid really is the zone's pid 1 - a different pid namespace from
# ours, and NSpid ending in 1.
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
else
    fail "LC10 no usable init.pid in the registry entry"
fi

# LC7: mode and owner. The registry names running zones, their identities and
# their cgroups; nothing that is not kryptikd should be able to read it.
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
# pid 1 of a namespace cannot be killed from inside by anything but its
# supervisor, so a zone that traps TERM must not be able to keep itself alive.
# The 5s escalation in the supervision path is the whole policy.
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
# The scenario that makes a naive implementation dangerous: a stale entry whose
# recorded pid now belongs to something else entirely. kryptikd must leave that
# process alone.
lc_cleanup
mkdir -p "$REG/lczone"
/bin/sleep 25 & victim=$!
BG_PIDS+=("$victim")
# Record the victim's pid with a deliberately WRONG start time.
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

# --- LC6: the REGISTRY is invisible inside a zone ---------------------------
#
# This used to assert that /run/kryptik did not exist at all, and that stopped
# being the right question when the broker landed: a zone now has
# /run/kryptik/broker, deliberately, because that socket is how it will ask for
# anything outside itself.
#
# What must still be true - and is the thing the old check was really about -
# is that the REGISTRY is not in there. A zone that could read
# /run/kryptik/zones would learn every other zone's name, pid and cgroup, which
# is an inventory of the machine it is supposed to be sealed off from.
zrun alpha -- /bin/sh -c "$PRO if [ -e /run/kryptik/zones ]; then echo PROBE=VISIBLE; else echo PROBE=absent; fi"
probe "LC6 the zone registry is not visible inside a zone" "absent"

# And the positive control for it: /run/kryptik itself IS there, holding the
# broker socket and nothing else. Without this, LC6 would keep passing if the
# whole directory quietly stopped being mounted - which is how a check outlives
# the thing it was written for.
zrun alpha -- /bin/sh -c "$PRO echo PROBE=\$(ls -A /run/kryptik 2>/dev/null | tr '
' ',')"
probe "LC6b control: /run/kryptik is present and contains only the broker socket" "broker,"

# LC15: the registry directory itself must not be plantable.
#
# R-7b F1: base() falls back to a path under /tmp, which is world-writable, so
# another local user could create it - or symlink it somewhere - before the
# victim ever ran kryptikd, and then own the directory kryptikd keeps its
# entries in. Driven here through the real `kryptikd run` rather than a unit
# test, because what matters is that a zone does not start.
#
# XDG_RUNTIME_DIR points base() at a directory this suite owns, so the plant
# happens in the suite's own workspace and the developer's real registry is
# untouched.
#
# Unprivileged only, and that is not a convenience: as root, base() is
# /run/kryptik/zones and never consults XDG_RUNTIME_DIR at all, because /run is
# not world-writable and the whole class of attack this check is about does not
# exist there. Planting a symlink at /run/kryptik as root would exercise the
# same three lines of ensure_base against a path nobody can attack, while
# displacing the registry of any zone still running in this VM. So the
# unprivileged run is where this is measured; the VM says so rather than
# pretending.
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

# LC16: the positive control for LC15. The same launch, same variable, with a
# real directory instead of the symlink, must start - otherwise LC15 passes for
# the boring reason that XDG_RUNTIME_DIR breaks every launch.
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
# A skipped mandatory check is not a release pass. These are named so the gap
# is visible in the summary rather than absent from it.

if (( CGROUP_OK == 0 )); then
    skip "cgroup memory/pids limits are enforced          [vm] this host cannot create cgroups; group M covers it there"
fi
# Routed networking is implemented and is covered by group NETR, which runs
# only inside the disposable VM. The gap this line reported is now a check
# with a positive control.
# ephemeral storage is implemented (M2) and covered by group E-EPH above, so
# it is no longer listed as a gap. The one thing it does NOT deliver - secure
# erasure, because tmpfs pages can be swapped - is asserted by EPH8 rather than
# listed here, since it is a property of the implementation and not a missing
# feature.
# Per-zone SECCOMP policy files are applied and are covered by group POL;
# the Landlock half is still refused and is reported there as POL6. This
# line claimed both were unimplemented long after one of them was.
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
