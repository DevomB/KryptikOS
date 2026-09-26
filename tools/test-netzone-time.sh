#!/usr/bin/env bash
# Test the net zone's clock query (docs/design/time.md): ask_time from
# netzone-init.sh and sntp-offset.py, against loopback time servers and a
# stand-in broker, under each POSIX shell here (the image's /bin/sh may be any).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/tools/net/netzone-init.sh"
SNTP="${ROOT}/tools/net/sntp-offset.py"
PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }

command -v python3 >/dev/null 2>&1 || { echo "no python3: the query and its stand-in servers need it"; exit 77; }
[[ -r "$SCRIPT" && -r "$SNTP" ]] || { echo "missing ${SCRIPT} or ${SNTP}"; exit 1; }
T="$(mktemp -d)"
PIDS=()
# Only the main shell cleans up: every $(...) subshell inherits this trap.
MAIN=$BASHPID
cleanup() { [[ "$BASHPID" == "$MAIN" ]] || return 0; for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT

# The block under test: from TIME_CONF= up to, not including, its first call.
sed -n '/^TIME_CONF=/,/^ask_time "\$@"$/p' "$SCRIPT" | sed '$d' > "$T/block.sh"
grep -q '^ask_time()' "$T/block.sh" || { echo "could not find the time block in ${SCRIPT#"$ROOT"/} (did its markers move?)"; exit 1; }

# A loopback time server: its clock is ours plus SKEW; MODE picks how it misbehaves.
cat > "$T/ntpd.py" <<'PY'
import socket, struct, sys, time
mode, skew, portfile = sys.argv[1], float(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0))
open(portfile, "w").write(str(s.getsockname()[1]))
def ts(t): return struct.pack("!II", (int(t) + 2208988800) % 2**32, int((t - int(t)) * 2**32) % 2**32)
while True:
    data, addr = s.recvfrom(512)
    if mode == "silent": continue
    now = time.time() + skew
    first = ((3 if mode == "unsync" else 0) << 6) | (4 << 3) | 4
    stratum = 0 if mode == "kod" else 2
    origin = bytes(8) if mode == "badorigin" else data[40:48]
    s.sendto(bytes([first, stratum, 0, 0xEC]) + bytes(12) + ts(now) + origin + ts(now) + ts(now), addr)
PY
# A stand-in broker: logs each request and answers as zone 0 does.
cat > "$T/broker.py" <<'PY'
import os, socket, sys
path, log = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(path); s.listen(4)
open(path + ".ready", "w").close()
while True:
    c, _ = s.accept(); data = b""
    while True:
        b = c.recv(4096)
        if not b: break
        data += b
    open(log, "ab").write(data); c.sendall(b"ok stepped\n"); c.close()
PY
# The query, logging its arguments first; NOQUERY=1 stops there.
cat > "$T/sntp-logged.py" <<PY
import os, runpy, sys
open(os.environ["ARGLOG"], "a").write(" ".join(sys.argv[1:]) + "\n")
if os.environ.get("NOQUERY") == "1": sys.exit(1)
sys.argv[0] = "$SNTP"; runpy.run_path("$SNTP", run_name="__main__")
PY
cat > "$T/harness.sh" <<EOF
say() { echo "SAY: \$*"; }
uplink_addr() { echo "\$FAKE_ADDR"; }
. "$T/block.sh"
TIME_CONF="\$FAKE_CONF"
set -- eth0 wlan0
ask_time "\$@"
echo "STATE=\$TIME_STATE"
echo "UPLINKS=\$*"
EOF

# serve VAR MODE SKEW: start a server and put its port in VAR. Not via $(...),
# whose subshell would lose the pid.
NSERVED=0
serve() {
    NSERVED=$((NSERVED + 1))
    local pf="$T/port.$NSERVED"; : > "$pf"
    python3 "$T/ntpd.py" "$2" "$3" "$pf" & PIDS+=("$!")
    for _ in $(seq 1 50); do [[ -s "$pf" ]] && break; sleep 0.1; done
    [[ -s "$pf" ]] || { echo "a stand-in time server did not start"; exit 1; }
    printf -v "$1" '%s' "$(< "$pf")"
}
python3 "$T/broker.py" "$T/broker.sock" "$T/told" & PIDS+=("$!")
for _ in $(seq 1 50); do [[ -e "$T/broker.sock.ready" ]] && break; sleep 0.1; done
[[ -S "$T/broker.sock" ]] || { echo "the stand-in broker did not start"; exit 1; }

serve P_BEHIND ok 300; serve P_AHEAD ok -300; serve P_AHEAD2 ok -300; serve P_LIAR ok 90000
serve P_KOD kod 0; serve P_UNSYNC unsync 0; serve P_BADORIGIN badorigin 0; serve P_SILENT silent 0
# conf LINE...: write a source list; its path goes in CONF.
NCONF=0
conf() { NCONF=$((NCONF + 1)); CONF="$T/conf.$NCONF"; printf '%s\n' "$@" > "$CONF"; }
has() { [[ "$1" == *"$2"* ]]; }
near() { python3 -c "import sys; sys.exit(0 if abs(float(sys.argv[1]) - float(sys.argv[2])) < 2 else 1)" "$1" "$2" 2>/dev/null; }

SHELLS=()
for s in dash bash busybox; do command -v "$s" >/dev/null 2>&1 && SHELLS+=("$s"); done
[[ ${#SHELLS[@]} -gt 0 ]] || { echo "no shell to run it under"; exit 77; }

for s in "${SHELLS[@]}"; do
    sh_cmd="$s"; [[ "$s" == busybox ]] && sh_cmd="busybox sh"
    echo "under ${sh_cmd}:"
    # shellcheck disable=SC2086  # "busybox sh" is two words on purpose
    r() {   # r ADDR CONF [NOQUERY] -> OUT, ARGS (what reached the query), TOLD (what reached the broker)
        : > "$T/args"; : > "$T/told"
        OUT="$(ARGLOG="$T/args" NOQUERY="${3:-0}" KRYPTIK_SNTP="$T/sntp-logged.py" KRYPTIK_SNTP_TIMEOUT=2 KRYPTIK_BROKER="$T/broker.sock" \
               FAKE_ADDR="$1" FAKE_CONF="$2" $sh_cmd "$T/harness.sh" 2>&1)"
        ARGS="$(cat "$T/args")"; TOLD="$(cat "$T/told")"
        STATE="$(sed -n 's/^STATE=//p' <<<"$OUT")"
    }

    conf 'server time.example.org' '# a comment' 'pool   pool.example.net  ' 'server bad host' 'server evil;rm' 'server' 'peer other.example' '  server  spaced.example  '
    r 10.0.2.15/24 "$CONF" 1
    if [[ "$ARGS" == "--timeout 2 --server time.example.org --pool pool.example.net --server spaced.example" ]]; then
        green "zone 0's source list reaches the query as a flag and a name each; spaces, ';' and other directives do not"
    else red "the source list was not passed on as written" "$ARGS"; fi
    if has "$OUT" "UPLINKS=eth0 wlan0"; then green "the script's list of uplinks survives the function's own set --"
    else red "ask_time clobbered the script's positional parameters" "$OUT"; fi

    conf "server 127.0.0.1:${P_BEHIND}"
    r 10.0.2.15/24 "$CONF"
    off="${TOLD#time-offset }"; off="${off%% *}"
    if near "$STATE" 300 && has "$TOLD" "time-offset +" && [[ "$TOLD" == *" 1" ]] && near "$off" 300; then
        green "a clock five minutes behind the server: zone 0 is told about +300 s, from 1 server (${TOLD})"
    else red "wrong claim for a clock that is behind" "state=${STATE} told=${TOLD}"; fi

    conf "server 127.0.0.1:${P_AHEAD}"
    r 10.0.2.15/24 "$CONF"
    if near "$STATE" -300 && has "$TOLD" "time-offset -"; then green "a clock five minutes ahead: about -300 s (${TOLD})"
    else red "wrong claim for a clock that is ahead" "state=${STATE} told=${TOLD}"; fi

    conf "server 127.0.0.1:${P_AHEAD}" "server 127.0.0.1:${P_LIAR}" "server 127.0.0.1:${P_AHEAD2}"
    r 10.0.2.15/24 "$CONF"
    if near "$STATE" -300 && [[ "$TOLD" == *" 3" ]]; then green "one server a day out among three is outvoted: the median, from 3 servers (${TOLD})"
    else red "a lying server moved the answer" "state=${STATE} told=${TOLD}"; fi

    for bad in "kod:${P_KOD}:a kiss-of-death" "unsync:${P_UNSYNC}:an unsynchronised server" "badorigin:${P_BADORIGIN}:a reply that does not echo what was sent" "silent:${P_SILENT}:a server that does not answer"; do
        IFS=: read -r _ port what <<<"$bad"
        conf "server 127.0.0.1:${port}"
        r 10.0.2.15/24 "$CONF"
        if [[ "$STATE" == no-answer && -z "$TOLD" ]]; then green "${what} is 'no-answer': not a pass, not a zero, and zone 0 is told nothing"
        else red "${what} was not reported as no answer" "state=${STATE} told=${TOLD}"; fi
    done

    conf "server 127.0.0.1:${P_SILENT}" "server 127.0.0.1:${P_BEHIND}"
    r 10.0.2.15/24 "$CONF"
    if near "$STATE" 300 && [[ "$TOLD" == *" 1" ]]; then green "a silent server beside a good one costs nothing but the count (${TOLD})"
    else red "a silent server spoiled a good answer" "state=${STATE} told=${TOLD}"; fi

    conf "server 127.0.0.1:${P_BEHIND}"
    r "" "$CONF"
    if [[ "$STATE" == no-uplink && -z "$ARGS" && -z "$TOLD" ]]; then green "with no uplink address nothing is asked at all"
    else red "asked the network with no uplink" "state=${STATE} args=${ARGS}"; fi

    r 10.0.2.15/24 /nonexistent 1
    if [[ "$ARGS" == "--timeout 2 --pool pool.ntp.org" ]]; then green "without zone 0's source list the public pool is what is asked"
    else red "the default source is wrong" "$ARGS"; fi

    conf '# nothing here'
    r 10.0.2.15/24 "$CONF"
    if [[ "$STATE" == unconfigured && -z "$ARGS" ]]; then green "a source list that names nothing asks nothing and says so"
    else red "an empty source list was not reported" "state=${STATE} args=${ARGS}"; fi
done

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
