#!/usr/bin/env bash
# Tests for the launch daemon (`kryptikd serve`), driven over its socket as
# kryptik-launch drives it; launcher.sh covers `kryptikd run` itself. Runs as a
# user (a developer instance serving only this uid) or as root. Needs python3
# (exit 77 without it). Exits 0 only when every check ran and passed.
#
# A refusal only counts once the daemon is seen answering something else, and
# a launch only once the zone is seen doing what it was asked.

set -uo pipefail

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
[[ -t 1 ]] || { C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""; }

PASS=0; FAIL=0; SKIP=0
declare -a FAILED=() SKIPPED=()
pass()  { printf '%s  PASS%s  %s\n' "$C_GRN" "$C_RST" "$1"; PASS=$((PASS+1)); }
fail()  { printf '%s  FAIL%s  %s\n' "$C_RED" "$C_RST" "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }
skip()  { printf '%s  SKIP%s  %s\n' "$C_YEL" "$C_RST" "$1"; SKIP=$((SKIP+1)); SKIPPED+=("$1"); }
info()  { printf '%s        %s%s\n' "$C_DIM" "$1" "$C_RST"; }
head_() { printf '\n%s==>%s %s\n' "$C_BLU" "$C_RST" "$1"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TARGET="${CARGO_TARGET_DIR:-}"
KRYPTIKD="${KRYPTIKD:-${TARGET:+$TARGET/debug/kryptikd}}"
KRYPTIKD="${KRYPTIKD:-$REPO/compartments/kryptikd/target/debug/kryptikd}"
WLPROXY="${KRYPTIK_WLPROXY:-${TARGET:+$TARGET/debug/kryptik-wlproxy}}"
WLPROXY="${WLPROXY:-$REPO/compositor/target/debug/kryptik-wlproxy}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'serve.sh: python3 is required for the client side and is not installed\n'
    exit 77
fi
if [[ ! -x "$KRYPTIKD" ]]; then
    printf '%sBUILD REQUIRED%s: %s is not executable.\n' "$C_RED" "$C_RST" "$KRYPTIKD"
    printf 'Run: (cd %s/compartments/kryptikd && cargo build)\n' "$REPO"
    exit 2
fi
if [[ ! -x "$WLPROXY" ]] && command -v cargo >/dev/null 2>&1; then
    info "building kryptik-wlproxy for the proxy-socket checks"
    ( cd "$REPO/compositor" && cargo build --quiet -p wlproxy ) || true
    [[ -x "$WLPROXY" ]] || WLPROXY="$REPO/compositor/target/debug/kryptik-wlproxy"
fi

WORK="$(mktemp -d)"
ZONES="$WORK/zones"; ROOTFS="$WORK/rootfs"; SOCK="$WORK/launch.sock"
mkdir -p "$ZONES" "$ROOTFS"
# mktemp -d makes 0700, but a privileged zone's setup runs as the zone's own
# identity and must reach its data directory.
chmod 0755 "$WORK" "$ROOTFS"
declare -a BG_PIDS=()
cleanup() {
    for p in "${BG_PIDS[@]:-}"; do [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null; done
    [[ -n "${RT_DIR:-}" && -d "$RT_DIR" ]] && rm -rf "$RT_DIR/alpha" "$RT_DIR/beta" 2>/dev/null
    rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

if (( EUID == 0 )); then PRIVILEGED=1; info "running as root: zones map to their own identity ranges"; else PRIVILEGED=0; info "running unprivileged as uid $EUID"; fi
# A root daemon writes zone logs under /var/log/kryptik, a developer one in $WORK.
if (( PRIVILEGED == 1 )); then ZLOG=/var/log/kryptik/zone-alpha.log; else ZLOG="$WORK/zone-alpha.log"; fi
MARK="LAUNCH_OK_$$"

# --- fixtures ----------------------------------------------------------------

# uid_base (65536-aligned, >= 131072) is used by root launches only; an
# unprivileged launch maps to the caller.
mkzone() { # name mode extra-lines uid_base
    local name="$1" mode="$2" extra="${3:-}" base="$4"
    {
        printf '[zone]\nname = "%s"\ndescription = "serve-suite fixture"\n' "$name"
        printf '[network]\nmode = "%s"\n' "$mode"
        [[ "$mode" == nic ]] && printf 'bridge = "kryptik0"\n'
        printf '[storage]\nmode = "ephemeral"\nsize = "64M"\n'
        [[ -n "$extra" ]] && printf '%s\n' "$extra"
        printf '[identity]\nuid_base = %s\n' "$base"
        printf '[ui]\nborder_color = "#%06x"\n' "$base"
    } > "$ZONES/$name.toml"
}
mkzone alpha   none ''                                            131072
mkzone beta    none ''                                            196608
mkzone carrier nic  ''                                            262144
mkzone broken  none $'[policy]\nseccomp = "policy/does-not-exist.seccomp"' 327680
# An encrypted zone, for `info`; never launched here (that is the volume suite).
{
    printf '[zone]\nname = "sealed"\ndescription = "serve-suite fixture"\n[network]\nmode = "none"\n'
    printf '[storage]\nmode = "encrypted"\nvolume = "/dev/kryptik/sealed"\n[identity]\nuid_base = 393216\n[ui]\nborder_color = "#060000"\n'
} > "$ZONES/sealed.toml"

# --- the client ----------------------------------------------------------------

cat > "$WORK/client.py" <<'PY'
import os, socket, sys, time
sock = sys.argv[1]; mode = sys.argv[2]; text = sys.argv[3].encode().decode("unicode_escape").encode()
def connect():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(45); s.connect(sock); return s
def read_all(s):
    out = b""
    while True:
        try:
            b = s.recv(4096)
        except socket.timeout:
            out += b"<client timeout>"; break
        if not b: break
        out += b
    return out
s = connect()
if mode == "send":
    fds = [os.open(p, os.O_RDONLY) for p in sys.argv[4:]]
    if fds:
        s.sendmsg([text], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, b"".join(fd.to_bytes(4, sys.byteorder) for fd in fds))])
    else:
        s.sendall(text)
    s.shutdown(socket.SHUT_WR)
elif mode == "hold":         # send a partial request and stall
    s.sendall(text); time.sleep(float(sys.argv[4]))
elif mode == "latefd":       # bytes first, then a descriptor with more bytes
    s.sendall(text)
    time.sleep(0.5)          # let the daemon read the first bytes on their own
    fd = os.open(sys.argv[4], os.O_RDONLY)
    s.sendmsg([b"end\n"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fd.to_bytes(4, sys.byteorder))])
    s.shutdown(socket.SHUT_WR)
sys.stdout.write(read_all(s).decode("utf-8", "replace"))
PY
ask()  { python3 "$WORK/client.py" "$SOCK" send "$@"; }

# A fake upstream compositor socket the proxy can connect to.
cat > "$WORK/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(sys.argv[1]); s.listen(8)
while True:
    c, _ = s.accept()
PY

# --- the daemon --------------------------------------------------------------------

head_ "daemon"
# --group: the suite's own; root is authorised anyway and a developer instance
# ignores it. --wifi-dir keeps the credentials file in $WORK, so no installed
# one is touched and no real net zone is restarted.
"$KRYPTIKD" serve --zones "$ZONES" --rootfs "$ROOTFS" --socket "$SOCK" --proxy-exe "$WLPROXY" --group "$(id -gn)" --wifi-dir "$WORK/wifi" > "$WORK/serve.log" 2>&1 &
DAEMON=$!; BG_PIDS+=("$DAEMON")
for _ in $(seq 1 100); do [[ -S "$SOCK" ]] && break; sleep 0.05; done
if [[ -S "$SOCK" ]] && kill -0 "$DAEMON" 2>/dev/null; then
    pass "S0 the daemon listens on --socket"
else
    fail "S0 the daemon did not start"; sed 's/^/        /' "$WORK/serve.log"; exit 1
fi

# --- requests -----------------------------------------------------------------------

head_ "requests"
r="$(ask 'status\n')"
if [[ "$r" == "end" ]]; then pass "S1 status answers (positive control)"; else fail "S1 status: $r"; fi

r="$(ask 'info alpha\n')"
if [[ "$r" == *"encrypted no"* && "$r" == *"running no"* && "$r" == *end ]]; then pass "S2a info alpha: not encrypted, not running"; else fail "S2a info alpha: $r"; fi
r="$(ask 'info sealed\n')"
if [[ "$r" == *"encrypted yes"* ]]; then pass "S2b info sealed: encrypted"; else fail "S2b info sealed: $r"; fi
r="$(ask 'info nosuch\n')"
if [[ "$r" == "error: no zone named"* ]]; then pass "S2c info of an unknown zone is an error"; else fail "S2c: $r"; fi
r="$(ask 'info ../x\n')"
if [[ "$r" == "error:"* ]]; then pass "S2d info with a bad name is refused"; else fail "S2d: $r"; fi

r="$(ask 'bogus\n')"
if [[ "$r" == "error: unknown request"* ]]; then pass "S3a an unknown verb is refused"; else fail "S3a: $r"; fi
r="$(ask 'run alpha\narg x\nend\nmore\n')"
# The request ends at `end`; what follows is never read as part of it.
if [[ "$r" == "error:"* || "$r" == ok* ]]; then pass "S3b trailing bytes after end do not confuse the reader"; else fail "S3b: $r"; fi
r="$(ask 'run alpha\nend\n')"
if [[ "$r" == "error: run: no command"* ]]; then pass "S3c run without a command is refused"; else fail "S3c: $r"; fi
r="$(ask 'run nosuch\narg /bin/true\nend\n')"
if [[ "$r" == "error: no zone named"* ]]; then pass "S3d run of an unknown zone is refused before anything is forked"; else fail "S3d: $r"; fi
r="$(ask 'clipboard-move alpha alpha\n')"
if [[ "$r" == "error: clipboard-move needs two different zone names"* ]]; then pass "S3f clipboard-move refuses the same zone twice"; else fail "S3f: $r"; fi
r="$(ask 'clipboard-move alpha beta\n')"
if [[ "$r" == "error:"* && "$r" == *"not running"* ]]; then pass "S3g clipboard-move of zones that are not running is refused: ${r%$'\n'}"; else fail "S3g: $r"; fi
r="$(ask 'runtime\n')"
if [[ "$r" == ok\ /* ]]; then
    d="${r#ok }"; d="${d%$'\n'}"
    if [[ -d "$d" && "$(stat -c %a "$d")" == 700 ]]; then pass "S3e runtime creates a private runtime directory ($d)"; else fail "S3e runtime dir $d missing or not 0700"; fi
else fail "S3e runtime: $r"; fi

# --- the deadline -----------------------------------------------------------------------

head_ "a stalled client"
python3 "$WORK/client.py" "$SOCK" hold 'run alpha\narg x\n' 12 > "$WORK/hold.out" 2>&1 &
HOLD=$!; BG_PIDS+=("$HOLD")
sleep 0.5
t0=$(date +%s%N)
r="$(ask 'status\n')"
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
if [[ "$r" == "end" && "$ms" -lt 8000 ]]; then
    pass "S4a a second client is answered while the first stalls (after ${ms} ms; deadline 5 s)"
else
    fail "S4a second client: reply '$r' after ${ms} ms"
fi
wait "$HOLD" 2>/dev/null
if grep -q "not completed within" "$WORK/hold.out"; then pass "S4b the stalled client is told its request timed out"; else fail "S4b stalled client got: $(cat "$WORK/hold.out")"; fi

# --- descriptors --------------------------------------------------------------------------

head_ "descriptors"
printf 'x' > "$WORK/f1"; printf 'y' > "$WORK/f2"
r="$(ask 'run alpha pass=fd\narg /bin/true\nend\n' "$WORK/f1" "$WORK/f2")"
if [[ "$r" == "error: at most one descriptor"* ]]; then pass "S5a two descriptors are refused"; else fail "S5a: $r"; fi
r="$(ask 'run alpha\narg /bin/true\nend\n' "$WORK/f1")"
if [[ "$r" == "error: a descriptor was sent without pass=fd"* ]]; then pass "S5b a descriptor without pass=fd is refused"; else fail "S5b: $r"; fi
r="$(ask 'run alpha pass=fd\narg /bin/true\nend\n')"
if [[ "$r" == "error: pass=fd needs exactly one descriptor, got 0"* ]]; then pass "S5c pass=fd without a descriptor is refused"; else fail "S5c: $r"; fi
r="$(python3 "$WORK/client.py" "$SOCK" latefd 'run alpha pass=fd\narg /bin/true\n' "$WORK/f1")"
if [[ "$r" == "error: a descriptor must accompany the first bytes"* ]]; then pass "S5d a descriptor arriving after the first bytes is refused"; else fail "S5d: $r"; fi
if [[ "$(ask 'status\n')" == "end" ]]; then pass "S5e the daemon still answers after the refusals"; else fail "S5e daemon wedged"; fi

# --- launches -------------------------------------------------------------------------------

head_ "launches"
# The command truncates its stdout between its two lines. O_APPEND does not
# stop ftruncate, so that stdout must not be the log file itself.
r="$(ask "run alpha\narg /bin/sh\narg -c\narg echo $MARK; python3 -c 'import os; os.ftruncate(1, 0)' 2>/dev/null; echo after-$MARK; sleep 15\nend\n")"
if [[ "$r" == ok\ [0-9]* ]]; then
    pass "S6a run alpha replies ok <pid> once the zone is up"
    s="$(ask 'status\n')"
    if [[ "$s" == *"running alpha"* ]]; then pass "S6b status shows alpha running after ok"; else fail "S6b status after ok: $s"; fi
    ok=0; for _ in $(seq 1 40); do grep -q "$MARK" "$ZLOG" 2>/dev/null && { ok=1; break; }; sleep 0.1; done
    if [[ "$ok" -eq 1 ]]; then pass "S6c the zone ran the command (its log shows $MARK)"; else fail "S6c no $MARK in $ZLOG"; fi
    for _ in $(seq 1 40); do grep -q "after-$MARK" "$ZLOG" 2>/dev/null && break; sleep 0.1; done
    if grep -q "^zone alpha| $MARK\$" "$ZLOG" && grep -q "^zone alpha| after-$MARK\$" "$ZLOG"; then
        pass "S6c2 what the zone printed is in the log under its mark, and its attempt to empty the log emptied nothing"
    else fail "S6c2 the log after the zone tried to empty it:"; sed 's/^/        /' "$ZLOG" | tail -6; fi
    r2="$(ask 'run alpha\narg /bin/true\nend\n')"
    if [[ "$r2" == "error:"* ]]; then pass "S6d a second launch of a running zone is refused: ${r2%$'\n'}"; else fail "S6d second launch: $r2"; fi
    r3="$(ask 'stop alpha\n')"
    if [[ "$r3" == "ok" ]]; then pass "S6e stop alpha"; else fail "S6e stop: $r3"; fi
    for _ in $(seq 1 60); do [[ "$(ask 'status\n')" == "end" ]] && break; sleep 0.1; done
    if [[ "$(ask 'status\n')" == "end" ]]; then pass "S6f status is empty once the zone is gone"; else fail "S6f alpha still listed"; fi
else
    fail "S6a run alpha: $r"; sed 's/^/        /' "$ZLOG" 2>/dev/null | tail -5
fi

# A zone that ignores SIGTERM is only gone at stop's SIGKILL, seconds later.
# Another client's status, asked meanwhile, must be answered at once.
ms() { date +%s%3N; }
r="$(ask "run alpha\narg /bin/sh\narg -c\narg trap '' TERM; while :; do sleep 1; done\nend\n")"
if [[ "$r" == ok\ [0-9]* ]]; then
    t0="$(ms)"; ( ask 'stop alpha\n' > "$WORK/slow-stop.out"; ms > "$WORK/slow-stop.end" ) &
    stopper=$!
    sleep 0.5
    s0="$(ms)"; s="$(ask 'status\n')"; s1="$(ms)"
    wait "$stopper"
    took=$(( $(cat "$WORK/slow-stop.end") - t0 )); asked=$(( s1 - s0 ))
    if [[ "$took" -lt 2000 ]]; then
        fail "S6g the stop took ${took} ms, too quick to show anything (the zone did not ignore SIGTERM)"
    elif [[ "$asked" -lt 1000 && "$s" == *"alpha"* ]]; then
        pass "S6g status was answered in ${asked} ms while a ${took} ms stop was under way"
    else
        fail "S6g status took ${asked} ms during a ${took} ms stop (answer: ${s%$'\n'})"
    fi
    [[ "$(cat "$WORK/slow-stop.out")" == "ok" ]] && pass "S6h the slow stop still replies ok when it ends" || fail "S6h slow stop: $(cat "$WORK/slow-stop.out")"
else
    fail "S6g run alpha (ignoring SIGTERM): $r"
fi

r="$(ask 'run broken\narg /bin/true\nend\n')"
if [[ "$r" == "error: zone \"broken\" did not start: launcher exited"* ]]; then
    pass "S7a a zone that cannot start is reported with the launcher's exit"
    if [[ "$r" == *"policy"* || "$r" == *"seccomp"* ]]; then pass "S7b ... and the last line it logged names the cause"; else fail "S7b no cause in: $r"; fi
else
    fail "S7a broken zone: $r"
fi

r="$(ask 'run alpha\narg /does/not/exist\nend\n')"
if [[ "$r" == "error: zone \"alpha\" started but its command ended at once"* ]]; then
    pass "S7c a command that cannot exec is not reported as ok"
elif [[ "$r" == ok* ]]; then
    fail "S7c exec failure reported as ok: $r"
else
    fail "S7c: $r"
fi
for _ in $(seq 1 60); do [[ "$(ask 'status\n')" == "end" ]] && break; sleep 0.1; done

# A command that ends at once with 0 is ok, and its end is in the log however
# quickly it came: a zone terminal whose shell died unseen was a silent "ok".
r="$(ask 'run alpha\narg /bin/true\nend\n')"
for _ in $(seq 1 60); do [[ "$(ask 'status\n')" == "end" ]] && break; sleep 0.1; done
if [[ "$r" == ok\ [0-9]* ]] && grep -q "launcher ${r#ok } exited 0" "$WORK/serve.log"; then
    pass "S7d a command that ends at once is ok, and the log says it ended"
else
    fail "S7d ${r%$'\n'}: $(grep -F "${r#ok }" "$WORK/serve.log" | tr '\n' '|')"
fi

# --- the proxy socket ------------------------------------------------------------------------

head_ "the proxy socket"
r="$(ask 'run alpha wayland=/tmp/wayland-0\narg /bin/true\nend\n')"
if [[ "$r" == "error: wayland socket must be /run/user/$EUID/kryptik/alpha/wayland-0"* ]]; then pass "S8a a socket outside the session's runtime directory is refused"; else fail "S8a: $r"; fi
r="$(ask "run alpha wayland=/run/user/$EUID/kryptik/beta/wayland-0\narg /bin/true\nend\n")"
if [[ "$r" == "error: wayland socket must be"* ]]; then pass "S8b another zone's socket is refused"; else fail "S8b: $r"; fi

RT_DIR=""
if [[ -d "/run/user/$EUID" && -w "/run/user/$EUID" ]]; then
    RT_DIR="/run/user/$EUID/kryptik"
elif (( PRIVILEGED == 1 )) && mkdir -p "/run/user/$EUID" 2>/dev/null; then
    chmod 700 "/run/user/$EUID"; RT_DIR="/run/user/$EUID/kryptik"
fi
if [[ -z "$RT_DIR" ]]; then
    skip "S8c-S8h need a writable /run/user/$EUID (none here)"
elif [[ ! -x "$WLPROXY" ]]; then
    skip "S8c-S8h need kryptik-wlproxy at $WLPROXY (build compositor/ first)"
else
    mkdir -p "$RT_DIR/alpha" "$RT_DIR/beta"; chmod 700 "$RT_DIR" "$RT_DIR/alpha" "$RT_DIR/beta"
    UP="$WORK/upstream.sock"
    python3 "$WORK/upstream.py" "$UP" & BG_PIDS+=("$!")
    for _ in $(seq 1 50); do [[ -S "$UP" ]] && break; sleep 0.05; done
    WL="$RT_DIR/alpha/wayland-0"
    r="$(ask "run alpha wayland=$WL\narg /bin/true\nend\n")"
    if [[ "$r" == "error: wayland socket: wayland-0:"* ]]; then pass "S8c a socket that does not exist is refused"; else fail "S8c: $r"; fi

    # Something that is not the proxy, listening at the right path.
    python3 "$WORK/upstream.py" "$WL" & IMP=$!; BG_PIDS+=("$IMP")
    for _ in $(seq 1 50); do [[ -S "$WL" ]] && break; sleep 0.05; done
    r="$(ask "run alpha wayland=$WL\narg /bin/true\nend\n")"
    if [[ "$r" == "error: wayland socket is not served by kryptik-wlproxy"* ]]; then pass "S8d a listener that is not the proxy is refused"; else fail "S8d: $r"; fi
    kill "$IMP" 2>/dev/null; wait "$IMP" 2>/dev/null; rm -f "$WL"

    # The proxy, but for another zone.
    "$WLPROXY" --zone beta --listen "$WL" --upstream "$UP" > "$WORK/proxy-beta.log" 2>&1 & PB=$!; BG_PIDS+=("$PB")
    for _ in $(seq 1 50); do [[ -S "$WL" ]] && break; sleep 0.05; done
    r="$(ask "run alpha wayland=$WL\narg /bin/true\nend\n")"
    if [[ "$r" == "error: wayland socket is served by a proxy for another zone"* ]]; then pass "S8e a proxy for another zone is refused"; else fail "S8e: $r"; fi
    kill "$PB" 2>/dev/null; wait "$PB" 2>/dev/null; rm -f "$WL"

    # The zone's own proxy; the zone sees it at /run/kryptik/wayland-0.
    "$WLPROXY" --zone alpha --listen "$WL" --upstream "$UP" > "$WORK/proxy-alpha.log" 2>&1 & PA=$!; BG_PIDS+=("$PA")
    for _ in $(seq 1 50); do [[ -S "$WL" ]] && break; sleep 0.05; done
    r="$(ask "run alpha wayland=$WL\narg /bin/sh\narg -c\narg test -S /run/kryptik/wayland-0 && echo WL_$MARK; sleep 1\nend\n")"
    if [[ "$r" == ok\ [0-9]* ]]; then
        ok=0; for _ in $(seq 1 40); do grep -q "WL_$MARK" "$ZLOG" 2>/dev/null && { ok=1; break; }; sleep 0.1; done
        if [[ "$ok" -eq 1 ]]; then pass "S8f the session's own proxy socket is accepted and reaches the zone"; else fail "S8f zone did not see /run/kryptik/wayland-0"; fi
        if grep -q "client #1 connected" "$WORK/proxy-alpha.log"; then pass "S8g the daemon identified the listener by connecting to it"; else fail "S8g no probe connection in the proxy log"; fi
    else
        fail "S8f run with the real proxy: $r"
    fi
    for _ in $(seq 1 60); do [[ "$(ask 'status\n')" == "end" ]] && break; sleep 0.1; done

    # A symlinked zone directory leading to that valid socket: the path is
    # walked without following links.
    mv "$RT_DIR/alpha" "$RT_DIR/alpha.real"; ln -s "$RT_DIR/alpha.real" "$RT_DIR/alpha"
    r="$(ask "run alpha wayland=$WL\narg /bin/true\nend\n")"
    if [[ "$r" == "error: wayland socket path:"* ]]; then pass "S8h a symlink on the way to the socket is refused"; else fail "S8h: $r"; fi
    rm -f "$RT_DIR/alpha"; mv "$RT_DIR/alpha.real" "$RT_DIR/alpha"
    kill "$PA" 2>/dev/null; wait "$PA" 2>/dev/null
fi

# --- the net zone's Wi-Fi credentials --------------------------------------------------
# One file for the net zone (kryptikd's wifi.rs). The passphrase only travels
# in a request body and never comes back out; a refusal leaves the file as it was.

head_ "wi-fi credentials"
WIFI="$WORK/wifi"; WCONF="$WIFI/wpa_supplicant.conf"
r="$(ask 'wifi-list\n')"
if [[ "$r" == "end" ]]; then pass "S9a wifi-list with no file is an empty list"; else fail "S9a: $r"; fi
r="$(ask 'wifi-add\nssid Home\npsk correct horse battery\nend\n')"
if [[ "$r" == "ok added network \"Home\"; the net zone was not restarted"* && -f "$WCONF" ]]; then
    pass "S9b wifi-add writes the file and says why the net zone was not restarted here"
else
    fail "S9b wifi-add: $r"
fi
if [[ "$(stat -c %a "$WCONF" 2>/dev/null)" == 400 ]]; then pass "S9c the file is mode 0400"; else fail "S9c mode $(stat -c %a "$WCONF" 2>&1)"; fi
if grep -qxF $'\tssid="Home"' "$WCONF" && grep -qxF $'\tpsk="correct horse battery"' "$WCONF"; then
    pass "S9d ... holding the ssid= and psk= lines, quoted and tab-indented"
else
    fail "S9d file:"; sed 's/^/        /' "$WCONF"
fi
if [[ "$(stat -c %a "$WIFI")" == 711 ]]; then pass "S9e the directory is 0711: traversable, not listable"; else fail "S9e directory mode $(stat -c %a "$WIFI")"; fi
if (( PRIVILEGED == 1 )); then
    # carrier is the nic zone, the only reader of the file.
    if [[ "$(stat -c %u:%g "$WCONF")" == "262144:262144" ]]; then pass "S9f the file is owned by the nic zone's identity (carrier, uid_base 262144)"; else fail "S9f owned by $(stat -c %u:%g "$WCONF"), not 262144:262144"; fi
else
    if [[ "$(stat -c %u "$WCONF")" == "$EUID" ]]; then pass "S9f an unprivileged daemon leaves the file owned by its writer"; else fail "S9f owned by $(stat -c %u "$WCONF")"; fi
fi
r="$(ask 'wifi-list\n')"
if [[ "$r" == $'network Home\nend' ]]; then pass "S9g wifi-list names the network and nothing else"; else fail "S9g: $r"; fi
if [[ "$r" != *"correct horse"* ]]; then pass "S9h ... and never the passphrase"; else fail "S9h the passphrase is in the listing"; fi
ino1="$(stat -c %i "$WCONF")"
r="$(ask 'wifi-add\nssid Cafe Wifi\npsk 0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef\nend\n')"
if [[ "$r" == "ok added network \"Cafe Wifi\";"* && "$(grep -c '^network={' "$WCONF")" == 2 ]]; then pass "S9i a second add appends a second block"; else fail "S9i: $r"; fi
if grep -qxF $'\tpsk=0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef' "$WCONF"; then pass "S9j 64 hex digits are written unquoted: the raw PSK, underived"; else fail "S9j no unquoted psk line"; fi
ino2="$(stat -c %i "$WCONF")"
if [[ "$ino1" != "$ino2" && ! -e "$WCONF.tmp" ]]; then
    pass "S9k the write is a rename: a new inode, and no .tmp left behind"
else
    fail "S9k inode $ino1 -> $ino2, .tmp $([[ -e "$WCONF.tmp" ]] && echo present || echo absent)"
fi
r="$(ask 'wifi-add\nssid Home\npsk a different one\nend\n')"
if [[ "$r" == "ok replaced the passphrase of network \"Home\";"* && "$(grep -c '^network={' "$WCONF")" == 2 ]] && grep -qxF $'\tpsk="a different one"' "$WCONF" && ! grep -qF "correct horse" "$WCONF"; then
    pass "S9l adding an SSID again replaces its block and says so"
else
    fail "S9l: $r"
fi
r="$(ask 'wifi-forget\nssid Home\nend\n')"
if [[ "$r" == "ok forgot network \"Home\";"* ]] && ! grep -qF Home "$WCONF" && grep -qxF $'\tssid="Cafe Wifi"' "$WCONF" \
   && grep -qxF 'ctrl_interface=/run/wpa_supplicant' "$WCONF" && grep -qxF 'update_config=0' "$WCONF"; then
    pass "S9m wifi-forget removes only its block; the header and the other network stay"
else
    fail "S9m: $r"; sed 's/^/        /' "$WCONF"
fi
r="$(ask 'wifi-forget\nssid Home\nend\n')"
if [[ "$r" == "error: no network named \"Home\""* ]]; then pass "S9n forgetting a network that is not there is an error"; else fail "S9n: $r"; fi

# Refusals: each names its rule, and the file is byte-identical afterwards.
cp "$WCONF" "$WORK/wifi-before"
long33="$(printf 'x%.0s' $(seq 1 33))"
nothex="$(printf 'g%.0s' $(seq 1 64))"
while IFS='|' read -r id label req rule; do
    r="$(ask "$req")"
    if [[ "$r" == "error: "*"$rule"* ]] && cmp -s "$WCONF" "$WORK/wifi-before"; then
        pass "$id $label is refused naming the rule, and the file is untouched"
    else
        fail "$id $label: $r"
    fi
done <<REFUSALS
S9o|an SSID with a double quote|wifi-add\nssid say "hi"\npsk long enough\nend\n|printable ASCII
S9p|an SSID of 33 bytes|wifi-add\nssid $long33\npsk long enough\nend\n|1 to 32 bytes
S9q|a passphrase of 7 characters|wifi-add\nssid Home\npsk seven c\nend\n|8 to 63
S9r|64 characters that are not all hex|wifi-add\nssid Home\npsk $nothex\nend\n|8 to 63
S9s|a passphrase holding a newline|wifi-add\nssid Home\npsk long\nenough\nend\n|newline
REFUSALS
if ! grep -qF -e "correct horse" -e "a different one" -e "0123456789abcdef" "$WORK/serve.log"; then
    pass "S9t no passphrase reached the daemon's log"
else
    fail "S9t a passphrase is in $WORK/serve.log"
fi
if [[ "$(ask 'status\n')" == "end" ]]; then pass "S9u the daemon still answers"; else fail "S9u daemon wedged"; fi

# --- summary ---------------------------------------------------------------------------

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
if (( FAIL > 0 )); then printf 'FAILED:\n'; printf '  %s\n' "${FAILED[@]}"; fi
if (( SKIP > 0 )); then printf 'NOT RUN (not a pass):\n'; printf '  %s\n' "${SKIPPED[@]}"; fi
if (( FAIL > 0 )); then printf '\ndaemon log:\n'; sed 's/^/  /' "$WORK/serve.log"; fi
(( FAIL == 0 && SKIP == 0 )) || exit 1
exit 0
