#!/usr/bin/env bash
# Test the chrome's reading of dwl's status stream (status_to_focus in
# tools/desktop/kryptik-chrome): the focus record is the selected output's
# window, wherever that output comes in the stream.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHROME="$ROOT/tools/desktop/kryptik-chrome"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -n '/^zone_field() {/,/^}/p; /^status_to_focus() {/,/^}/p' "$CHROME" > "$T/fn.sh"
for fn in zone_field status_to_focus; do
    grep -q "^${fn}() {" "$T/fn.sh" || { echo "could not extract ${fn} from $CHROME"; exit 1; }
done
mkdir -p "$T/zones" "$T/kryptik"
printf '[ui]\nlabel = "UNTRUSTED"\nglyph = "^"\n' > "$T/zones/untrusted.toml"

# One output's lines, in the order dwl writes them; an output with no window
# has an empty title, app_id and fullscreen.
block() {   # block OUTPUT SELECTED [TITLE APPID FULLSCREEN]
    printf '%s title %s\n%s appid %s\n%s fullscreen %s\n%s floating 0\n%s selmon %s\n%s tags 1 1 0 0\n%s layout []=\n' \
        "$1" "${3:-}" "$1" "${4:-}" "$1" "${5:-}" "$1" "$1" "$2" "$1" "$1"
}
# Under sh, as the chrome runs.
feed() {
    ZONES="$T/zones" FOCUS="$T/kryptik/focus" FOCUS_ZONE="$T/kryptik/focus.zone" \
        sh -c '. "$1"; status_to_focus' sh "$T/fn.sh" 2>/dev/null
}
holds() {   # holds FILE WHAT LINE...: the record holds every LINE
    local f="$T/kryptik/$1" what="$2" w; shift 2
    for w in "$@"; do
        grep -qxF -- "$w" "$f" 2>/dev/null || { bad "${what}: no '${w}' in: $(tr '\n' ' ' < "$f" 2>/dev/null)"; return; }
    done
    ok "$what"
}
ZWIN=(kryptik.untrusted.havoc 0)   # a zone's window: the app_id the proxy stamps, not fullscreen

block Virtual-1 1 havoc havoc 0 | feed
holds focus "one output: the record is its window" output=Virtual-1 zone=0 'label=ZONE 0 (trusted)' title=havoc fullscreen=0

# dwl lists the newest output first, so a second monitor in use is written
# before the first.
{ block Virtual-2 1 '[untrusted] havoc' "${ZWIN[@]}"; block Virtual-1 0 havoc havoc 0; } | feed
holds focus "two outputs, the selected one written first: the record is the selected output's window" \
    output=Virtual-2 zone=untrusted label=UNTRUSTED 'glyph=^' 'title=[untrusted] havoc' fullscreen=0
holds focus.zone "and it is the last zone window on record" output=Virtual-2 zone=untrusted

{ block Virtual-2 0 havoc havoc 0; block Virtual-1 1 '[untrusted] havoc' "${ZWIN[@]}"; } | feed
holds focus "two outputs, the selected one written last: the same" output=Virtual-1 zone=untrusted label=UNTRUSTED

{ block Virtual-2 1; block Virtual-1 0 '[untrusted] havoc' "${ZWIN[@]}"; } | feed
holds focus "a selected output with no window is recorded as that, not as the other output's window" \
    output=Virtual-2 zone=- 'label=(no window)' title=

block Virtual-1 1 havoc havoc 0 | feed
holds focus "zone 0 takes the focus" output=Virtual-1 zone=0
holds focus.zone "and the last zone window's record stays" zone=untrusted label=UNTRUSTED

block Virtual-1 1 ghost kryptik.ghost.term 0 | feed
holds focus "a zone with no file is named as unknown, never as trusted" zone=ghost 'label=UNKNOWN ZONE ghost'

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
