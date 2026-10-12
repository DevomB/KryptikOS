#!/usr/bin/env bash
# Test the menu's Wi-Fi window taking a network by its number in a scan (heard_list, heard_name
# and heard_pick in tools/desktop/kryptik-chrome): the networks are numbered and the radio lines
# are not, a number gives back the name the daemon quoted, a name quoted with a backslash (a
# byte quoted so no terminal acts on it) is not passed on, and a takes only a network with a
# passphrase and o only an open one. Under each POSIX shell here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHROME="$ROOT/tools/desktop/kryptik-chrome"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1: got '$(tr '\n' '|' <<<"$2")', want '$(tr '\n' '|' <<<"$3")'"; fi; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -n '/^heard_list() {/,/^}/p; /^heard_name() {/,/^}/p; /^heard_pick() {/,/^}/p' "$CHROME" > "$T/fn.sh"
for fn in heard_list heard_name heard_pick; do
    grep -q "^${fn}() {" "$T/fn.sh" || { echo "could not extract ${fn} from $CHROME"; exit 1; }
done

# An answer as kryptikd wifi scan words one: a radio switched off first, then the networks.
cat > "$T/scan" <<'EOF'
radio nic1 is switched off, by its switch or an airplane-mode key
"Home Net"  WPA2/WPA3  -40 dBm  saved
"café"  open  -55 dBm
"x\u{1b}[2Jy"  open  -60 dBm
" spaced "  WPA2  -61 dBm
"q\"uote"  WPA2  -70 dBm
"old"  WEP, which Kryptik does not join  -80 dBm
EOF

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    echo "-- ${sh}"
    run() { "$sh" -c '. "$1"; shift; "$@"' sh "$T/fn.sh" "$@" 2>/dev/null; }
    scan="$(cat "$T/scan")"
    same "the networks are numbered, the radio's line is not" "$(run heard_list "$scan")" \
"   radio nic1 is switched off, by its switch or an airplane-mode key
 1 \"Home Net\"  WPA2/WPA3  -40 dBm  saved
 2 \"café\"  open  -55 dBm
 3 \"x\\u{1b}[2Jy\"  open  -60 dBm
 4 \" spaced \"  WPA2  -61 dBm
 5 \"q\\\"uote\"  WPA2  -70 dBm
 6 \"old\"  WEP, which Kryptik does not join  -80 dBm"
    same "a number gives the name the daemon quoted, and its security" "$(run heard_name "$scan" 1)" "$(printf 'Home Net\nWPA2/WPA3')"
    same "a UTF-8 name comes back whole" "$(run heard_name "$scan" 2)" "$(printf 'café\nopen')"
    same "spaces at either end are kept" "$(run heard_name "$scan" 4)" "$(printf ' spaced \nWPA2')"
    for n in 3 5 7 0; do
        if run heard_name "$scan" "$n" >/dev/null; then
            bad "number $n is refused (an escaped byte, or no such network)"
        else
            ok "number $n is refused (an escaped byte, or no such network)"
        fi
    done
    # a saves a network with a passphrase and o an open one, as each line says it is.
    same "a takes a WPA2/WPA3 network" "$(run heard_pick a "$scan" 1)" "Home Net"
    same "o takes an open network" "$(run heard_pick o "$scan" 2)" "café"
    same "o refuses a WPA2 network" "$(run heard_pick o "$scan" 4; echo "rc=$?")" \
        "$(printf 'network  spaced  is WPA2: a saves it, with its passphrase\nrc=1')"
    same "a refuses an open network" "$(run heard_pick a "$scan" 2; echo "rc=$?")" \
        "$(printf 'network café is open: o saves it\nrc=1')"
    same "neither takes one Kryptik does not join" "$(run heard_pick a "$scan" 6; echo "rc=$?")" \
        "$(printf 'network old is WEP, which Kryptik does not join\nrc=1')"
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
