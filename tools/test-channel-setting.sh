#!/usr/bin/env bash
# Stage 06's KRYPTIK_CHANNEL: which addresses it takes for which role, and
# that every address it takes is one the net zone's fetcher can use: the
# update.conf stage 06 writes reads back as a request with a host, no query or
# fragment, and a path that ends in the name asked for. Runs stage 06's own
# check, role reader and writer, and the real fetcher.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S06="$ROOT/build/stages/06-iso.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed -n '/^check_channel() {/,/^}/p; /^channel_conf() {/,/^}/p' "$S06" > "$T/fns.sh"
for fn in check_channel channel_conf; do
    grep -q "^${fn}() " "$T/fns.sh" || { echo "could not extract ${fn} from $S06"; exit 1; }
done
# shellcheck source=/dev/null
. "$T/fns.sh"

long="https://updates.example/$(printf 'a%.0s' {1..488})"   # 512 bytes
# address, then its verdict for a production and for a development image
TABLE=(
    "https://updates.example/stable"                take  take
    "https://updates.example:8443/stable/"          take  take
    "https://[::1]:8443/stable"                     take  take
    "https://[2001:db8::1]/"                        take  take
    'https://acct.blob.core.windows.net/$web/stable/' take take
    "$long"                                         take  take
    "${long}a"                                      refuse refuse
    "http://10.0.2.2:8080/"                         refuse take
    "http://updates.example/stable"                 refuse take
    "https://user:pw@updates.example/s"             refuse refuse
    "https://user@updates.example/s"                refuse refuse
    "https://updates.example:notaport/"             refuse refuse
    "https://updates.example:65535/"                take  take
    "https://updates.example:99999/"                refuse refuse
    "https://updates.example:0/"                    refuse refuse
    'https://updates.example/a"b'                   refuse refuse
    'https://updates.example/a\b'                   refuse refuse
    'https://updates.example/a`b'                   refuse refuse
    'https://updates.example/a|b'                   refuse refuse
    'https://updates.example/<b>'                   refuse refuse
    'https://updates.example/{b}^'                  refuse refuse
    "https://updates.example/stable#x"              refuse refuse
    "https://updates.example/stable?token=1"        refuse refuse
    "https://?x"                                    refuse refuse
    "https://#x"                                    refuse refuse
    "https://:443/"                                 refuse refuse
    "https://"                                      refuse refuse
    "https:///path"                                 refuse refuse
    "https:/updates.example/"                       refuse refuse
    "HTTPS://updates.example/"                      refuse refuse
    "ftp://updates.example/"                        refuse refuse
    "file:///var/lib/"                              refuse refuse
    "updates.example/stable"                        refuse refuse
    "https://updates.example/a b"                   refuse refuse
    $'https://updates.example/\tx'                  refuse refuse
    $'https://updates.example/x\n'                  refuse refuse
    "https://updates.example/é"                     refuse refuse
    ""                                              refuse refuse
)
taken=()
for ((i = 0; i < ${#TABLE[@]}; i += 3)); do
    a="${TABLE[i]}"
    for role in production development; do
        if [[ "$role" == production ]]; then want="${TABLE[i+1]}"; else want="${TABLE[i+2]}"; fi
        why="$(check_channel "$a" "$role")"
        if [[ -z "$why" ]]; then got=take; else got=refuse; fi
        label="$(printf '%q' "${a:0:60}")"
        [[ "$got" == "$want" ]] && ok "${role}: ${want} ${label}${why:+ ($why)}" || bad "${role}: wanted ${want}, got ${got}: ${label}"
    done
    [[ "${TABLE[i+2]}" == take ]] && taken+=("$a")
done

# Every address stage 06 takes, written as it writes it and read by the
# fetcher, makes requests the fetcher can send.
n=0
for a in "${taken[@]}"; do channel_conf "$a" > "$T/update-$n.conf"; n=$((n + 1)); done
out="$(python3 - "$ROOT/tools/net/update-fetch.py" "$T"/update-*.conf <<'EOF' 2>&1
import importlib.util, sys, urllib.parse, urllib.request
spec = importlib.util.spec_from_file_location("fetch", sys.argv[1])
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)
for conf in sys.argv[2:]:
    ch = fetch.channel(conf)
    for name in ("latest", "latest.sig"):
        r = urllib.request.Request(ch + name)
        u = urllib.parse.urlsplit(r.full_url)
        u.port  # raises on a port that is not a number
        good = r.host and u.hostname and not u.query and not u.fragment and not u.username and u.path.endswith("/" + name)
        print(("ok " if good else "BAD ") + r.full_url[:80])
EOF
)"
bads="$(grep -c '^BAD\|Error' <<<"$out")"
oks="$(grep -c '^ok ' <<<"$out")"
[[ "$bads" -eq 0 && "$oks" -eq $((2 * ${#taken[@]})) ]] \
    && ok "the fetcher makes a usable request from every address taken (${oks} requests)" || bad "the fetcher on the addresses taken: ${out}"

channel_conf https://updates.example/stable > "$T/update.conf"
[[ "$(grep -c '=' "$T/update.conf")" -eq 1 ]] && ok "only the channel line has an '=' for a reader to take" || bad "update.conf has more than one '=' line"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
