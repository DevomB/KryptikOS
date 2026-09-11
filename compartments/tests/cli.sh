#!/usr/bin/env bash
# Tests for `kryptik`, the user-facing command.
#
# The wrapper's whole job is to be convenient, and convenience is exactly how a
# safety property gets lost - so most of what is checked here is that it did
# NOT become convenient in the wrong place: it must not start a zone whose
# guarantees are unmet without the person saying so, must not execute its own
# config file, and must not offer commands for things that do not work.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# In a checkout this is tools/kryptik next to the suite. In an image the suite
# lives under /usr/lib/kryptik and the command is installed on PATH, which is
# where a user would meet it - so look there too rather than reporting a
# missing file about a system where it is present.
KRYPTIK="${KRYPTIK:-}"
if [[ -z "$KRYPTIK" ]]; then
    if   [[ -x "$REPO/tools/kryptik" ]]; then KRYPTIK="$REPO/tools/kryptik"
    elif command -v kryptik >/dev/null 2>&1; then KRYPTIK="$(command -v kryptik)"
    else KRYPTIK="$REPO/tools/kryptik"   # for the error message below
    fi
fi
KRYPTIKD="${KRYPTIKD:-$REPO/compartments/kryptikd/target/debug/kryptikd}"
export KRYPTIKD

PASS=0; FAIL=0; SKIP=0
FAILED=()
C_GRN=""; C_RED=""; C_YEL=""; C_DIM=""; C_RST=""
if [[ -t 1 ]]; then
    C_GRN=$'\033[32m'; C_RED=$'\033[31m'; C_YEL=$'\033[33m'
    C_DIM=$'\033[2m'; C_RST=$'\033[0m'
fi
pass() { printf '%s  PASS%s  %s\n' "$C_GRN" "$C_RST" "$1"; PASS=$((PASS+1)); }
fail() { printf '%s  FAIL%s  %s\n' "$C_RED" "$C_RST" "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
skip() { printf '%s  SKIP%s  %s\n' "$C_YEL" "$C_RST" "$1"; SKIP=$((SKIP+1)); }
info() { printf '%s        %s%s\n' "$C_DIM" "$1" "$C_RST"; }

[[ -x "$KRYPTIK"  ]] || { echo "no kryptik at $KRYPTIK"; exit 2; }
[[ -x "$KRYPTIKD" ]] || { echo "no kryptikd at $KRYPTIKD — run cargo build"; exit 2; }

WORK="$(mktemp -d)"
cleanup() {
    "$KRYPTIKD" gc >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

ZONES="$WORK/zones"; ROOTFS="$WORK/data"; mkdir -p "$ZONES" "$ROOTFS"
CONF="$WORK/kryptik.conf"
export KRYPTIK_CONF="$CONF"
cat > "$CONF" <<CONF
# written by cli.sh
zones_dir = $ZONES
rootfs    = $ROOTFS
CONF

mkzone() { # name storage-mode colour [network-mode]
    local net="${4:-none}"
    {
        printf '[zone]\nname = "%s"\ndescription = "cli.sh fixture %s"\n' "$1" "$1"
        printf '[network]\nmode = "%s"\n' "$net"
        [[ "$net" == "nic" ]] && printf 'bridge = "kryptik0"\n'
        printf '[storage]\nmode = "%s"\n' "$2"
        [[ "$2" == "ephemeral" ]] && printf 'size = "32M"\n'
        [[ "$2" == "encrypted" ]] && printf 'volume = "/dev/kryptik/%s"\n' "$1"
        printf '[ui]\nborder_color = "%s"\n' "$3"
    } > "$ZONES/$1.toml"
}
# The valid storage modes are `ephemeral` and `encrypted`, and only those -
# there is no "persistent", which the first version of this file assumed and
# which made kryptikd reject the whole directory.
#
# `carrier` is not decoration: kryptikd validates the zone SET, and refuses one
# in which no zone holds the physical NIC, because a routed zone would then
# have no path out. Every fixture directory needs one.
mkzone plain     ephemeral "#101010"
mkzone sealed    encrypted "#202020"
mkzone carrier   ephemeral "#303030" nic

K() { "$KRYPTIK" "$@"; }

echo "=== kryptik, the user-facing command ==="

# --- it works at all --------------------------------------------------------
out="$(K --help 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == *"run and manage Kryptik zones"* ]]; then
    pass "A1  --help works and exits 0"
else
    fail "A1  --help exited $rc"
fi

out="$(K list 2>&1)"
# The DESCRIPTION column too, not just the names. It was empty for every zone
# for a while - the wrapper matched "description:" against output that says
# "description  text" - and a list of names beside a blank column reads as
# zones that have no description rather than a wrapper that cannot read them.
if [[ "$out" == *"cli.sh fixture plain"* ]]; then
    pass "A2b list shows each zone's description, not just its name"
else
    fail "A2b list printed no description for 'plain'"
    info "output: $(printf '%s' "$out" | tr '
' '|' | cut -c1-200)"
fi
if [[ "$out" == *plain* && "$out" == *sealed* && "$out" == *carrier* ]]; then
    pass "A2  list shows the configured zones, read from the config file"
else
    fail "A2  list did not show all three zones"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

# The config file must be DATA. If it were sourced, this line would run.
CANARY="$WORK/config-was-executed"
printf 'evil = $(touch "%s")\n' "$CANARY" >> "$CONF"
K list >/dev/null 2>&1
if [[ -e "$CANARY" ]]; then
    fail "A3  the config file was EXECUTED — a line in it ran a command"
else
    pass "A3  the config file is data, not code: a \$(...) in it did not run"
fi
# Put the config back the way the rest of the run expects.
sed -i '/^evil =/d' "$CONF"

# --- a wrong zone name is answered with the right ones -----------------------
out="$(K status nosuchzone 2>&1)"; rc=$?
if (( rc != 0 )) && [[ "$out" == *nosuchzone* && "$out" == *plain* ]]; then
    pass "B1  an unknown zone is refused, and the message lists the known ones"
else
    fail "B1  unknown zone: exit $rc, and the message did not list the real zones"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

# --- a guarantee this build cannot deliver is refused, with no way past it ---
# The check that matters most. A zone declaring encrypted storage would run on
# a plain directory, so kryptikd refuses it. This command must not offer any
# flag that turns that refusal into a warning: "encrypted, except not really"
# is the one claim that must never reach a user.
out="$(K run sealed -- /bin/sh -c 'echo CLI_STARTED' 2>&1)"; rc=$?
if [[ "$out" == *CLI_STARTED* ]]; then
    fail "C1  a zone claiming ENCRYPTED storage ran on a plain directory"
elif (( rc != 0 )) && [[ "$out" == *"NOT IMPLEMENTED"* ]]; then
    pass "C1  a zone claiming encrypted storage is refused, saying encryption is not implemented"
else
    fail "C1  refused (exit $rc) without explaining that encryption is unimplemented"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-240)"
fi

# And there must be no documented way to override it from here.
if "$KRYPTIK" --help 2>&1 | grep -qi 'accept-incomplete\|experimental'; then
    fail "C2  the help text offers a way past the refusal"
else
    pass "C2  no flag is offered for starting a zone whose guarantees are unmet"
fi

# The caveat on ephemeral storage must reach the person, not be summarised away.
out="$(K run plain -- /bin/sh -c 'echo CLI_STARTED' 2>&1)"
if [[ "$out" == *"not secure erasure"* ]]; then
    pass "C3  the ephemeral swap caveat is passed through verbatim on every start"
else
    fail "C3  the ephemeral caveat did not reach the user"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-240)"
fi

# --- running a command -------------------------------------------------------
out="$(K run plain -- /bin/sh -c 'echo CLI_RAN_INSIDE; id -u' 2>&1)"; rc=$?
if [[ "$out" == *CLI_RAN_INSIDE* ]]; then
    pass "D1  run executes a command inside the zone"
else
    fail "D1  run did not execute the command (exit $rc)"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-240)"
fi

# It must be a ZONE, not a shell on the host. The zone's hostname is its own
# name, and the host's is not.
#
# Read from a SENTINEL LINE rather than by searching the whole output for the
# zone's name: the first version of this check looked for "plain" anywhere in
# the output, and passed on the error message "no zone named plain" - reporting
# that a command had run in a zone that did not exist.
out="$(K run plain -- /bin/sh -c 'echo "D2HOST=$(hostname)"' 2>&1)"
got="$(printf '%s' "$out" | sed -n 's/^D2HOST=//p' | head -1)"
if [[ "$got" == "plain" ]]; then
    pass "D2  the command really ran in the zone (it reported hostname 'plain')"
elif [[ -z "$got" ]]; then
    fail "D2  no hostname line came back at all — the command did not run"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
else
    fail "D2  the command ran somewhere else: hostname was '$got', not 'plain'"
fi
if [[ "$got" == "$(hostname)" ]]; then
    fail "D2b it ran on the HOST: the zone reported the host's own hostname"
else
    pass "D2b positive control: the host's hostname is '$(hostname)', which is not the zone's"
fi

# --- state is a word, not a colour -------------------------------------------
out="$(K list 2>&1 | cat)"
if [[ "$out" == *stopped* ]]; then
    pass "E1  state is reported as a word, and survives being piped into a file"
else
    fail "E1  no state word in piped output"
fi
if printf '%s' "$out" | grep -q $'\033'; then
    fail "E2  escape sequences in non-terminal output"
else
    pass "E2  no escape sequences when the output is not a terminal"
fi

# --- stop --------------------------------------------------------------------
out="$(K stop plain 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == *"not running"* ]]; then
    pass "F1  stopping a zone that is not running says so and succeeds"
else
    fail "F1  stop on a stopped zone: exit $rc"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

# --- commands that do not exist, do not exist --------------------------------
for c in transfer clipboard; do
    out="$(K "$c" 2>&1)"; rc=$?
    if (( rc != 0 )) && [[ "$out" == *"does not exist yet"* ]]; then
        pass "G1  \`$c\` is refused with a reason rather than half-working"
    else
        fail "G1  \`$c\` exited $rc without explaining itself"
    fi
done

# --- doctor ------------------------------------------------------------------
out="$(K doctor 2>&1)"; rc=$?
if [[ "$out" == *"$ZONES"* ]]; then
    pass "H1  doctor reports the paths it would use"
else
    fail "H1  doctor did not report its configuration"
fi

printf '\n  %s%d passed, %d failed, %d not run%s\n' \
    "$( ((FAIL)) && printf '%s' "$C_RED" || printf '%s' "$C_GRN")" \
    "$PASS" "$FAIL" "$SKIP" "$C_RST"
if (( FAIL )); then
    printf '\nfailed:\n'
    for f in "${FAILED[@]}"; do printf '  - %s\n' "$f"; done
    exit 1
fi
exit 0
