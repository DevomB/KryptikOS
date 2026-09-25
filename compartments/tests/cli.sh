#!/usr/bin/env bash
# Tests for `kryptik`, the user-facing command: mostly that convenience has not
# cost safety. No zone starts with its guarantees unmet, the config file is
# never executed, and nothing is offered that does not work.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# tools/kryptik in a checkout; on PATH in an image, where this suite lives
# under /usr/lib/kryptik.
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
DAEMON=""
cleanup() {
    [[ -n "$DAEMON" ]] && kill -9 "$DAEMON" 2>/dev/null
    "$KRYPTIKD" gc >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

ZONES="$WORK/zones"; ROOTFS="$WORK/data"; mkdir -p "$ZONES" "$ROOTFS"

# As root a zone maps to host uid 100000 and must traverse into its data
# directory, which `mktemp -d` makes 0700 and root-owned. Otherwise every
# launch fails with a misleading "mount(root tmpfs)...: Permission denied".
if [[ "$(id -u)" -eq 0 ]]; then
    chmod 0755 "$WORK" "$ZONES" "$ROOTFS"
    chown -R 100000:100000 "$ROOTFS"
fi
CONF="$WORK/kryptik.conf"
export KRYPTIK_CONF="$CONF"
cat > "$CONF" <<CONF
# written by cli.sh
zones_dir = $ZONES
rootfs    = $ROOTFS
wifi_dir  = $WORK/wifi
CONF

mkzone() { # name storage-mode colour [network-mode]
    local net="${4:-none}"
    {
        printf '[zone]\nname = "%s"\ndescription = "cli.sh fixture %s"\n' "$1" "$1"
        printf '[network]\nmode = "%s"\n' "$net"
        printf '[storage]\nmode = "%s"\n' "$2"
        [[ "$2" == "ephemeral" ]] && printf 'size = "32M"\n'
        [[ "$2" == "encrypted" ]] && printf 'volume = "/dev/kryptik/%s"\n' "$1"
        printf '[ui]\nborder_color = "%s"\n' "$3"
    } > "$ZONES/$1.toml"
}
# kryptikd refuses a zone set in which no zone holds the physical NIC, hence
# `carrier`.
mkzone plain     ephemeral "#101010"
mkzone sealed    encrypted "#202020"
mkzone carrier   ephemeral "#303030" nic

K() { "$KRYPTIK" "$@"; }

echo "=== kryptik, the user-facing command ==="

# --- it works at all --------------------------------------------------------
out="$(K --help 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == *"run and manage Kryptik zones"* ]]; then
    pass "--help works and exits 0"
else
    fail "--help exited $rc"
fi

out="$(K list 2>&1)"
if [[ "$out" == *"cli.sh fixture plain"* ]]; then
    pass "list shows each zone's description, not just its name"
else
    fail "list printed no description for 'plain'"
    info "output: $(printf '%s' "$out" | tr '
' '|' | cut -c1-200)"
fi
if [[ "$out" == *plain* && "$out" == *sealed* && "$out" == *carrier* ]]; then
    pass "list shows the configured zones, read from the config file"
else
    fail "list did not show all three zones"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

# The config file is data; if it were sourced, this line would run.
CANARY="$WORK/config-was-executed"
printf 'evil = $(touch "%s")\n' "$CANARY" >> "$CONF"
K list >/dev/null 2>&1
if [[ -e "$CANARY" ]]; then
    fail "the config file was EXECUTED — a line in it ran a command"
else
    pass "the config file is data, not code: a \$(...) in it did not run"
fi
sed -i '/^evil =/d' "$CONF"

# --- a wrong zone name is answered with the right ones -----------------------
out="$(K status nosuchzone 2>&1)"; rc=$?
if (( rc != 0 )) && [[ "$out" == *nosuchzone* && "$out" == *plain* ]]; then
    pass "an unknown zone is refused, and the message lists the known ones"
else
    fail "unknown zone: exit $rc, and the message did not list the real zones"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

# --- an encrypted zone needs its passphrase; there is no way to skip that ----
# It starts only with its passphrase (a descriptor from the launch daemon, or a
# root-owned file). Without one the command never runs, and no flag may fall
# back to a plain directory.
out="$(K run sealed -- /bin/sh -c 'echo CLI_STARTED' 2>&1)"; rc=$?
if [[ "$out" == *CLI_STARTED* ]]; then
    fail "a zone claiming ENCRYPTED storage ran without its passphrase"
elif (( rc != 0 )) && [[ "$out" == *"encrypted"* && ( "$out" == *"passphrase"* || "$out" == *"root"* ) ]]; then
    pass "an encrypted zone without its passphrase is refused, saying what it needs"
else
    fail "refused (exit $rc) without saying that the zone is encrypted and needs a passphrase"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-240)"
fi

# The help must offer no way around the refusal.
if "$KRYPTIK" --help 2>&1 | grep -qi 'accept-incomplete\|experimental'; then
    fail "the help text offers a way past the refusal"
else
    pass "no flag is offered for starting a zone whose guarantees are unmet"
fi

# The ephemeral storage caveat must reach the user verbatim.
out="$(K run plain -- /bin/sh -c 'echo CLI_STARTED' 2>&1)"
if [[ "$out" == *"not secure erasure"* ]]; then
    pass "the ephemeral swap caveat is passed through verbatim on every start"
else
    fail "the ephemeral caveat did not reach the user"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-240)"
fi

# --- running a command -------------------------------------------------------
out="$(K run plain -- /bin/sh -c 'echo CLI_RAN_INSIDE; id -u' 2>&1)"; rc=$?
if [[ "$out" == *CLI_RAN_INSIDE* ]]; then
    pass "run executes a command inside the zone"
else
    fail "run did not execute the command (exit $rc)"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-240)"
fi

# It must run in the zone, not on the host: the zone's hostname is its name.
# Read from a sentinel line, since an error such as "no zone named plain" also
# contains the name.
out="$(K run plain -- /bin/sh -c 'echo "D2HOST=$(hostname)"' 2>&1)"
got="$(printf '%s' "$out" | sed -n 's/^D2HOST=//p' | head -1)"
if [[ "$got" == "plain" ]]; then
    pass "the command really ran in the zone (it reported hostname 'plain')"
elif [[ -z "$got" ]]; then
    fail "no hostname line came back at all — the command did not run"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
else
    fail "the command ran somewhere else: hostname was '$got', not 'plain'"
fi
if [[ "$got" == "$(hostname)" ]]; then
    fail "it ran on the HOST: the zone reported the host's own hostname"
else
    pass "positive control: the host's hostname is '$(hostname)', which is not the zone's"
fi

# --- state is a word, not a colour -------------------------------------------
out="$(K list 2>&1 | cat)"
if [[ "$out" == *stopped* ]]; then
    pass "state is reported as a word, and survives being piped into a file"
else
    fail "no state word in piped output"
fi
if printf '%s' "$out" | grep -q $'\033'; then
    fail "escape sequences in non-terminal output"
else
    pass "no escape sequences when the output is not a terminal"
fi

# --- stop --------------------------------------------------------------------
out="$(K stop plain 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == *"not running"* ]]; then
    pass "stopping a zone that is not running says so and succeeds"
else
    fail "stop on a stopped zone: exit $rc"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

# --- no transfer or clipboard commands ---------------------------------------
# Files cross zones only through the sending zone's broker after the user's yes,
# and the clipboard only by the chrome's gesture. From zone 0 either command
# would go around the user, so both are refused, naming the real path.
for c in transfer clipboard; do
    out="$(K "$c" 2>&1)"; rc=$?
    if (( rc != 0 )) && [[ "$out" == *"not a"*"command"* && "$out" == *"broker"* && "$out" == *"chrome"* ]]; then
        pass "\`$c\` is refused, and the refusal names the broker and the chrome"
    else
        fail "\`$c\` exited $rc without explaining itself"
        info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
    fi
done

# --- doctor ------------------------------------------------------------------
out="$(K doctor 2>&1)"; rc=$?
if [[ "$out" == *"$ZONES"* ]]; then
    pass "doctor reports the paths it would use"
else
    fail "doctor did not report its configuration"
fi

# --- wifi: the net zone's credentials ----------------------------------------
# A passphrase never goes on a command line, where any process could read it:
# `kryptik wifi add` reads it (terminal with echo off, or a pipe) and passes it
# on stdin to kryptik-launch or, as here, to kryptikd.
out="$(K wifi 2>&1)"; rc=$?
if (( rc != 0 )) && [[ "$out" == *"list, add SSID or forget SSID"* ]]; then
    pass "wifi without a subcommand fails and names the subcommands"
else
    fail "wifi without a subcommand: exit $rc"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
fi

WCONF="$WORK/wifi/wpa_supplicant.conf"
out="$(K wifi list 2>&1)"; rc=$?
if (( rc == 0 )) && [[ -z "$out" ]]; then
    pass "wifi list with nothing configured prints nothing and succeeds"
else
    fail "wifi list on an empty configuration: exit $rc, output '$out'"
fi

out="$(printf 'correct horse battery\n' | K wifi add Home 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == *"added network \"Home\""* && -f "$WCONF" ]]; then
    pass "wifi add takes the passphrase on standard input and writes the net zone's file"
else
    fail "wifi add: exit $rc"
    info "output: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-240)"
fi
if [[ "$(stat -c %a "$WCONF" 2>/dev/null)" == 400 ]] && grep -qxF $'\tssid="Home"' "$WCONF" && grep -qxF $'\tpsk="correct horse battery"' "$WCONF"; then
    pass "the file is 0400 and holds the ssid= and psk= lines kryptikd writes"
else
    fail "the file is not as kryptikd writes it (mode $(stat -c %a "$WCONF" 2>&1))"
fi
out="$(K wifi list 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == "Home" ]]; then
    pass "wifi list prints the SSID, one per line, and nothing else"
else
    fail "wifi list after add: exit $rc, output '$out'"
fi
if [[ "$out" != *"correct horse"* ]]; then
    pass "wifi list never prints a passphrase"
else
    fail "the passphrase is in the listing"
fi
out="$(K wifi forget Home 2>&1)"; rc=$?
if (( rc == 0 )) && [[ "$out" == *"forgot network \"Home\""* && "$(K wifi list 2>&1)" == "" ]]; then
    pass "wifi forget removes the network"
else
    fail "wifi forget: exit $rc, output '$out'"
fi

# Through the launch service, as a user in a session gets there. Its socket
# path is fixed, so a stand-in for kryptik-launch with the same command line
# forwards to this suite's daemon; under test is the wrapper's side.
if [[ "$(id -u)" -eq 0 ]]; then
    skip "the launch-service path: as root the wrapper drives kryptikd directly, so there is nothing to stand in for"
elif ! command -v python3 >/dev/null 2>&1; then
    skip "the launch-service path needs python3 for the stand-in's socket client"
else
    SOCK="$WORK/launch.sock"; WDAEMON="$WORK/wifi-daemon"
    "$KRYPTIKD" serve --zones "$ZONES" --rootfs "$ROOTFS" --socket "$SOCK" --wifi-dir "$WDAEMON" > "$WORK/serve.log" 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 100); do [[ -S "$SOCK" ]] && break; sleep 0.05; done
    cat > "$WORK/client.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(30); s.connect(sys.argv[1])
s.sendall(sys.stdin.buffer.read()); s.shutdown(socket.SHUT_WR)
out = b""
while True:
    b = s.recv(4096)
    if not b: break
    out += b
sys.stdout.write(out.decode("utf-8", "replace"))
PY
    cat > "$WORK/launch-shim" <<SHIM
#!/usr/bin/env bash
# Stands in for kryptik-launch: the same command line, the same requests,
# to this suite's daemon. The request is piped to the client, so the
# passphrase is on no command line here either.
client() { python3 "$WORK/client.py" "$SOCK"; }
case "\${1:-}" in
    --runtime-dir) exit 0 ;;
    --wifi-list)   printf 'wifi-list\n' | client | sed -n 's/^network //p' ;;
    --wifi-add)    IFS= read -r pass
                   r="\$(printf 'wifi-add\nssid %s\npsk %s\nend\n' "\$2" "\$pass" | client)"
                   printf '%s\n' "\$r"; [[ "\$r" == ok* ]] ;;
    --wifi-forget) r="\$(printf 'wifi-forget\nssid %s\nend\n' "\$2" | client)"
                   printf '%s\n' "\$r"; [[ "\$r" == ok* ]] ;;
    *) exit 2 ;;
esac
SHIM
    chmod +x "$WORK/launch-shim"
    # The daemon's file as kryptikd writes it: the header and one block.
    mkdir -p "$WDAEMON"
    printf 'ctrl_interface=/run/wpa_supplicant\nupdate_config=0\n\nnetwork={\n\tssid="Fixture"\n\tpsk="fixture passphrase"\n}\n' > "$WDAEMON/wpa_supplicant.conf"
    if [[ -S "$SOCK" ]] && kill -0 "$DAEMON" 2>/dev/null; then
        out="$(KRYPTIK_LAUNCH="$WORK/launch-shim" K wifi list 2>&1)"; rc=$?
        if (( rc == 0 )) && [[ "$out" == "Fixture" ]]; then
            pass "through the launch service, wifi list prints what the daemon's file holds"
        else
            fail "wifi list through the launch service: exit $rc, output '$out'"
        fi
        out="$(printf 'cafe passphrase\n' | KRYPTIK_LAUNCH="$WORK/launch-shim" K wifi add Cafe 2>&1)"; rc=$?
        if (( rc == 0 )) && [[ "$out" == "ok added network \"Cafe\";"* ]] && grep -qxF $'\tpsk="cafe passphrase"' "$WDAEMON/wpa_supplicant.conf"; then
            pass "through the launch service, wifi add sends the passphrase in the request and shows the daemon's reply"
        else
            fail "wifi add through the launch service: exit $rc, output '$out'"
            sed 's/^/        /' "$WORK/serve.log"
        fi
        out="$(printf 'short\n' | KRYPTIK_LAUNCH="$WORK/launch-shim" K wifi add Cafe 2>&1)"; rc=$?
        if (( rc != 0 )) && [[ "$out" == *"8 to 63"* ]]; then
            pass "a refusal comes back as the daemon's error line and a failing exit"
        else
            fail "a too-short passphrase through the launch service: exit $rc, output '$out'"
        fi
    else
        fail "the launch daemon did not start for the launch-service checks"
        sed 's/^/        /' "$WORK/serve.log"
    fi
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
