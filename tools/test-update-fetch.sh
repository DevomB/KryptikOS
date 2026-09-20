#!/usr/bin/env bash
# The net zone's half of the update channel, tools/net/update-fetch.py, against
# a real HTTP server on loopback and a stand-in for zone 0's broker on a unix
# socket (docs/design/update-channel.md).
#
# The fetcher decides nothing, so what is checked is that it is a faithful
# pipe: the bytes that arrive are the bytes that were served, in the order
# and from the offsets zone 0 asked for, in pieces zone 0 will take, and that
# it stops when zone 0 says no. The stand-in keeps zone 0's side of the
# conversation honest enough for that: it answers a poll from what it holds,
# and refuses a piece that is not at the offset it holds.
#
# Needs bash and python3; no root, no network beyond loopback. Exit 0 when
# every row passes, 77 when python3 is missing.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FETCH="$ROOT/tools/net/update-fetch.py"
command -v python3 >/dev/null 2>&1 || { echo "python3 not found; cannot run"; exit 77; }

PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT

# --- a release to serve --------------------------------------------------------
REL="$T/www/chan/1.0.3"
mkdir -p "$REL" "$T/stage"
head -c 2621445 /dev/urandom > "$REL/kryptik-root.img"      # 2.5 MiB and five bytes: three pieces
head -c 70000 /dev/urandom > "$REL/kryptik-a.efi"
printf '{ "fixture": true }\n' > "$REL/root.json"
printf 'KRYPTIK-MANIFEST-1\nfixture\n' > "$REL/manifest"
printf 'a signature, as far as this suite cares\n' > "$REL/manifest.sig"
printf 'KRYPTIK-LATEST-1\nversion: 1.0.3\n' > "$T/www/chan/latest"
printf 'and its signature\n' > "$T/www/chan/latest.sig"
# What the stand-in "verified manifest" lists: name and size.
for f in kryptik-root.img kryptik-a.efi root.json; do printf '%s %s\n' "$f" "$(stat -c %s "$REL/$f")"; done > "$T/listed"

# --- the HTTP server: Range honoured unless $T/norange exists ---------------------
cat > "$T/httpd.py" <<'EOF'
import http.server, os, sys
root, portfile, flag, log = sys.argv[1:5]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        path = os.path.normpath(os.path.join(root, self.path.lstrip("/")))
        if not path.startswith(root) or not os.path.isfile(path):
            self.send_error(404); return
        data = open(path, "rb").read()
        rng = self.headers.get("Range")
        open(log, "a").write("%s %s\n" % (self.path, rng or "-"))
        if rng and not os.path.exists(flag):
            start = int(rng.split("=")[1].split("-")[0])
            body = data[start:]
            self.send_response(206)
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, len(data) - 1, len(data)))
        else:
            body = data
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
EOF

# --- zone 0's broker, as far as the fetcher can tell ------------------------------
cat > "$T/broker.py" <<'EOF'
import os, socket, sys
sock, work, base = sys.argv[1:4]
stage = os.path.join(work, "stage")
def held(n):
    p = os.path.join(stage, n)
    return os.path.getsize(p) if os.path.exists(p) else 0
def poll():
    if not os.path.exists(os.path.join(work, "wanted")):
        return "idle"
    need = [(n, 0) for n in ("manifest", "manifest.sig") if held(n) == 0]
    if not need:
        for line in open(os.path.join(work, "listed")):
            n, size = line.split()
            if held(n) < int(size):
                need.append((n, held(n)))
    return "fetch 1.0.3 %s need %s" % (base, " ".join("%s %d" % x for x in need)) if need else "idle"
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock); srv.listen(8)
while True:
    c, _ = srv.accept()
    data = b""
    while True:
        chunk = c.recv(1 << 16)
        if not chunk:
            break
        data += chunk
    header, _, payload = data.partition(b"\n")
    words = header.decode().split()
    open(os.path.join(work, "requests.log"), "a").write("%s payload=%d\n" % (header.decode(), len(payload)))
    if words[0] == "update-latest":
        plen, slen = int(words[1]), int(words[2])
        open(os.path.join(work, "got-latest"), "wb").write(payload[:plen])
        open(os.path.join(work, "got-latest.sig"), "wb").write(payload[plen:plen + slen])
        reply = "ok available 1.0.3" if len(payload) == plen + slen else "error: payload short"
    elif words[0] == "update-poll":
        reply = poll()
    elif words[0] == "update-put":
        name, offset, length = words[1], int(words[2]), int(words[3])
        refused = os.path.join(work, "refuse")
        if os.path.exists(refused) and open(refused).read().strip() == name:
            reply = "error: %s: zone 0 says no" % name
        elif offset != held(name) or length != len(payload):
            reply = "error: %s: %d bytes are held; the next byte wanted is %d, not %d" % (name, held(name), held(name), offset)
        else:
            open(os.path.join(stage, name), "ab").write(payload)
            reply = "ok %s %d" % (name, held(name))
    else:
        reply = "error: unknown verb"
    c.sendall((reply + "\n").encode()); c.close()
EOF

python3 "$T/httpd.py" "$T/www" "$T/port" "$T/norange" "$T/http.log" & PIDS+=($!)
for _ in $(seq 50); do [[ -s "$T/port" ]] && break; sleep 0.1; done
PORT="$(cat "$T/port" 2>/dev/null)"
[[ -n "$PORT" ]] || { echo "the HTTP server did not start"; exit 1; }
BASE="http://127.0.0.1:$PORT/chan"
python3 "$T/broker.py" "$T/broker.sock" "$T" "$BASE/1.0.3/" & PIDS+=($!)
for _ in $(seq 50); do [[ -S "$T/broker.sock" ]] && break; sleep 0.1; done
[[ -S "$T/broker.sock" ]] || { echo "the broker stand-in did not start"; exit 1; }
printf '# where releases are\nchannel = %s\n' "$BASE" > "$T/update.conf"

run() { python3 "$FETCH" "$@" --conf "$T/update.conf" --broker "$T/broker.sock" --ca /nonexistent; }
identical() { cmp -s "$REL/$1" "$T/stage/$1"; }

# --- the statement of what is current ---------------------------------------------
out="$(run latest 2>&1)"; rc=$?
if [[ "$rc" = 0 && "$out" == "ok available 1.0.3" ]] && cmp -s "$T/www/chan/latest" "$T/got-latest" && cmp -s "$T/www/chan/latest.sig" "$T/got-latest.sig"; then
    ok "latest: the statement and its signature reach zone 0 byte for byte, and its answer is passed on"
else
    bad "latest: rc=$rc out=$out"
fi

cp "$T/www/chan/latest" "$T/latest.keep"
head -c 9000 /dev/zero > "$T/www/chan/latest"
: > "$T/requests.log"
out="$(run latest 2>&1)"; rc=$?
if [[ "$rc" = 1 && "$out" == *"larger than 8192"* && ! -s "$T/requests.log" ]]; then
    ok "latest: a statement larger than zone 0 will take is not sent at all"
else
    bad "latest, oversized: rc=$rc out=$out"
fi
cp "$T/latest.keep" "$T/www/chan/latest"

# --- nothing asked for --------------------------------------------------------------
out="$(run poll 2>&1)"; rc=$?
[[ "$rc" = 0 && "$out" == "idle" && -z "$(ls -A "$T/stage")" ]] \
    && ok "poll: told idle, it fetches nothing" || bad "poll, idle: rc=$rc out=$out"

# --- a release, whole -----------------------------------------------------------------
: > "$T/wanted"; : > "$T/requests.log"
out="$(run poll 2>&1)"; rc=$?
if [[ "$rc" = 0 && "$out" == "idle" ]] && identical manifest && identical manifest.sig && identical kryptik-root.img && identical kryptik-a.efi && identical root.json; then
    ok "poll: every file of the release arrives byte for byte, and the run ends when zone 0 says idle"
else
    bad "poll, whole release: rc=$rc out=$out"
fi
first_two="$(grep '^update-put' "$T/requests.log" | head -2 | awk '{print $2}' | tr '\n' ' ')"
[[ "$first_two" == "manifest manifest.sig " ]] \
    && ok "poll: the manifest and its signature cross before anything else, because that is what zone 0 asked for" \
    || bad "poll: the first two pieces were: $first_two"
biggest="$(grep '^update-put' "$T/requests.log" | awk '{print $4}' | sort -n | tail -1)"
pieces="$(grep -c '^update-put kryptik-root.img' "$T/requests.log")"
[[ "$biggest" = 1048576 && "$pieces" = 3 ]] \
    && ok "poll: no piece is larger than 1 MiB (the root image crossed in $pieces)" \
    || bad "poll: biggest piece $biggest, root image pieces $pieces"

# --- a download cut short resumes from the byte zone 0 names -------------------------
truncate -s 1048581 "$T/stage/kryptik-root.img"; : > "$T/http.log"
out="$(run poll 2>&1)"; rc=$?
if [[ "$rc" = 0 ]] && identical kryptik-root.img && grep -q '^/chan/1.0.3/kryptik-root.img bytes=1048581-$' "$T/http.log"; then
    ok "poll: a file cut at byte 1048581 is asked for from that byte, and ends up identical"
else
    bad "poll, resume: rc=$rc out=$out http: $(cat "$T/http.log" | tr '\n' ' ')"
fi
truncate -s 1048581 "$T/stage/kryptik-root.img"; : > "$T/norange"
out="$(run poll 2>&1)"; rc=$?
rm -f "$T/norange"
[[ "$rc" = 0 ]] && identical kryptik-root.img \
    && ok "poll: a server that ignores Range sends the whole file; the bytes before the offset are dropped, not sent to zone 0" \
    || bad "poll, resume without Range: rc=$rc out=$out"

# --- zone 0 has the last word ----------------------------------------------------------
rm -f "$T/stage/kryptik-root.img"; echo kryptik-root.img > "$T/refuse"; : > "$T/requests.log"
out="$(run poll 2>&1)"; rc=$?
tries="$(grep -c '^update-put kryptik-root.img' "$T/requests.log")"
if [[ "$rc" = 1 && "$out" == *"zone 0 says no"* && "$tries" = 1 && ! -e "$T/stage/kryptik-root.img" ]]; then
    ok "poll: a piece zone 0 refuses ends the run; it is not sent again"
else
    bad "poll, refusal: rc=$rc tries=$tries out=$out"
fi
rm -f "$T/refuse"

# --- what it cannot do without -----------------------------------------------------------
printf '# nothing here\n' > "$T/empty.conf"
out="$(python3 "$FETCH" latest --conf "$T/empty.conf" --broker "$T/broker.sock" 2>&1)"; rc=$?
[[ "$rc" = 1 && "$out" == *"names no channel"* ]] \
    && ok "without a channel address from zone 0 it asks nobody" || bad "no channel: rc=$rc out=$out"
printf 'channel = http://127.0.0.1:1/chan\n' > "$T/dead.conf"
out="$(python3 "$FETCH" latest --conf "$T/dead.conf" --broker "$T/broker.sock" 2>&1)"; rc=$?
[[ "$rc" = 1 && "$out" == update-fetch:* ]] \
    && ok "a host that does not answer is one line and exit 1, not a traceback" || bad "dead host: rc=$rc out=$out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
