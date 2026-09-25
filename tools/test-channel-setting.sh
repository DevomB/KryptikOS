#!/usr/bin/env bash
# Stage 06's KRYPTIK_CHANNEL: which addresses it takes for which image, by
# zone 0's rules, and that the update.conf it writes is read back as that
# address by the net zone's fetcher. Runs stage 06's own functions.
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
takes() { [[ -z "$(check_channel "$1" "$2")" ]]; }

takes https://updates.example/stable production && ok "an https address is taken for a production image" || bad "https refused: $(check_channel https://updates.example/stable production)"
takes http://updates.example/stable production && bad "plain http was taken for a production image" || ok "plain http is refused for a production image"
takes http://10.0.2.2:8080/ development && ok "and taken for a development image" || bad "http refused for development: $(check_channel http://10.0.2.2:8080/ development)"
for a in "https://updates.example/a b" $'https://updates.example/\tx' $'https://updates.example/x\n' "https://updates.example/é" \
         "ftp://updates.example/" "file:///var/lib/" "https://" "https:///path" "updates.example/stable" ""; do
    takes "$a" development && bad "taken: '${a}'" || ok "refused: '${a}' ($(check_channel "$a" development))"
done
takes "https://updates.example/$(printf 'a%.0s' {1..488})" production && ok "512 bytes is taken" || bad "512 bytes refused"
takes "https://updates.example/$(printf 'a%.0s' {1..489})" production && bad "513 bytes was taken" || ok "513 bytes is refused"

channel_conf https://updates.example/stable > "$T/update.conf"
got="$(python3 - "$ROOT/tools/net/update-fetch.py" "$T/update.conf" <<'EOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("fetch", sys.argv[1])
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)
print(fetch.channel(sys.argv[2]))
EOF
)"
[[ "$got" == https://updates.example/stable/ ]] && ok "the net zone's fetcher reads the address stage 06 wrote" || bad "the fetcher read '${got}'"
[[ "$(grep -c '=' "$T/update.conf")" -eq 1 ]] && ok "only the channel line has an '=' for a reader to take" || bad "update.conf has more than one '=' line"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
