#!/usr/bin/env bash
# keyboard.sh against a stand-in variable, run file and loadkeys: which names
# the table takes, what a variable may hold, what a load records and what a
# store writes. The shipped table is checked for form.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/build/service-scripts/keyboard.sh"
TABLE="$ROOT/build/config/keyboard-layouts"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for f in "$LIB" "$TABLE"; do [[ -f "$f" ]] || { echo "missing: $f"; exit 1; }; done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/vars"
# loadkeys records the keymap it was given, and fails when told to.
cat > "$T/bin/loadkeys" <<'EOF'
#!/bin/sh
[ ! -e "$KB_TEST/loadkeys-fails" ] || exit 1
for a in "$@"; do last="$a"; done
printf '%s\n' "$last" > "$KB_TEST/loaded"
EOF
chmod +x "$T/bin/loadkeys"
export KB_TEST="$T" KB_TABLE="$TABLE" KB_VAR="$T/vars/KryptikKeyboard" KB_RUN="$T/run-keyboard" KB_KEYMAPS=/keymaps
export PATH="$T/bin:$PATH"
# Each call in a fresh sh, as the callers source it; stdout, then the status.
kb() { sh -c '. "$1"; shift; "$@"' sh "$LIB" "$@"; }
var() { rm -f "$KB_VAR"; printf '\007\000\000\000%s' "$1" > "$KB_VAR"; }

echo "-- the shipped table"
names="$(kb kb_names)"
[[ "$(head -1 <<<"$names")" == us ]] && ok "us is the first layout" || bad "the first layout is '$(head -1 <<<"$names")'"
[[ "$(sort <<<"$names" | uniq -d | wc -l)" -eq 0 ]] && ok "no name is listed twice" || bad "a name is listed twice: $(sort <<<"$names" | uniq -d | tr '\n' ' ')"
odd="$(awk '!/^#/ && NF && (NF != 4 || $1 !~ /^[a-z0-9-]+$/ || length($1) > 32 || $2 !~ /^[A-Za-z0-9_.\/-]+\.map\.gz$/ || $2 ~ /\.\./ || $3 !~ /^[a-z0-9_]+$/ || $4 !~ /^(-|[a-z0-9_-]+)$/) { print $1 }' "$TABLE")"
[[ -z "$odd" ]] && ok "every row is a name, a keymap path, an xkb layout and a variant" || bad "malformed rows: ${odd}"

echo "-- names"
[[ "$(kb kb_row de)" == "de i386/qwertz/de-latin1.map.gz de -" ]] && ok "a name gives its row" || bad "de gave '$(kb kb_row de)'"
for n in '' DE 'de;reboot' '../de' 'de us' nosuchlayout "$(printf 'a%.0s' $(seq 33))"; do
    if kb kb_row "$n" > /dev/null 2>&1; then bad "'${n}' was taken as a layout"; else ok "'${n:0:20}' is not a layout"; fi
done

echo "-- what the variable may hold"
rm -f "$KB_VAR"
[[ -z "$(kb kb_stored)" ]] && ok "no variable is no name" || bad "no variable gave '$(kb kb_stored)'"
var de;            [[ "$(kb kb_stored)" == de ]] && ok "a name is read past the four bytes of attributes" || bad "de read as '$(kb kb_stored)'"
var 'de;reboot';   [[ -z "$(kb kb_stored)" ]] && ok "a value with other characters is no name" || bad "took '$(kb kb_stored)'"
var "$(printf 'a%.0s' $(seq 40))"; [[ -z "$(kb kb_stored)" ]] && ok "a value longer than a name is no name" || bad "took a 40-byte value"
printf '\007\000\000\000' > "$KB_VAR"; [[ -z "$(kb kb_stored)" ]] && ok "an empty value is no name" || bad "took an empty value"
printf 'de' > "$KB_VAR"; [[ -z "$(kb kb_stored)" ]] && ok "a file shorter than its attributes is no name" || bad "took a two-byte file"

echo "-- loading"
rm -f "$T/loaded" "$KB_RUN"
kb kb_load ch-fr; rc=$?
[[ "$rc" -eq 0 && "$(cat "$T/loaded")" == /keymaps/i386/qwertz/fr_CH.map.gz ]] && ok "the row's console keymap is what loadkeys is given" || bad "ch-fr: rc=${rc}, loadkeys got '$(cat "$T/loaded" 2>/dev/null)'"
[[ "$(cat "$KB_RUN")" == $'layout=ch-fr\nxkb_layout=ch\nxkb_variant=fr' ]] && ok "and the row is recorded for the session" || bad "recorded: $(tr '\n' '|' < "$KB_RUN")"
[[ "$(stat -c %a "$KB_RUN")" == 644 ]] && ok "where a session's user can read it" || bad "mode $(stat -c %a "$KB_RUN")"
[[ "$(kb kb_current)" == ch-fr ]] && ok "it is the layout in force" || bad "in force: $(kb kb_current)"
got="$(sh -c '. "$1"; kb_export_xkb; echo "$XKB_DEFAULT_LAYOUT/$XKB_DEFAULT_VARIANT"' sh "$LIB")"
[[ "$got" == ch/fr ]] && ok "the session exports its xkb layout and variant" || bad "exported '${got}'"
kb kb_load de; got="$(sh -c '. "$1"; kb_export_xkb; echo "$XKB_DEFAULT_LAYOUT/${XKB_DEFAULT_VARIANT:-}"' sh "$LIB")"
[[ "$got" == de/ ]] && ok "a layout without a variant exports none" || bad "exported '${got}'"
rm -f "$T/loaded"; kb kb_load nosuchlayout 2>/dev/null; rc=$?
[[ "$rc" -ne 0 && ! -e "$T/loaded" ]] && ok "a name the table lacks loads nothing" || bad "nosuchlayout: rc=${rc}"
touch "$T/loadkeys-fails"; kb kb_load fr 2>/dev/null; rc=$?; rm -f "$T/loadkeys-fails"
[[ "$rc" -ne 0 && "$(kb kb_current)" == de ]] && ok "a keymap that does not load leaves the record as it was" || bad "a failed load: rc=${rc}, in force $(kb kb_current)"
rm -f "$KB_RUN"; [[ "$(kb kb_current)" == us ]] && ok "with nothing loaded the layout in force is us" || bad "in force with no record: $(kb kb_current)"
printf 'xkb_layout=de;reboot\n' > "$KB_RUN"
got="$(sh -c '. "$1"; unset XKB_DEFAULT_LAYOUT; kb_export_xkb; echo "${XKB_DEFAULT_LAYOUT:-none}"' sh "$LIB")"
[[ "$got" == none ]] && ok "a record that is not a layout's exports nothing" || bad "exported '${got}'"

echo "-- storing"
rm -f "$KB_VAR"
kb kb_store us; rc=$?
[[ "$rc" -eq 0 && ! -e "$KB_VAR" ]] && ok "us with no variable writes nothing: none means us" || bad "us: rc=${rc}"
kb kb_store de; rc=$?
[[ "$rc" -eq 0 && "$(od -An -tx1 "$KB_VAR" | tr -d ' \n')" == 070000006465 ]] && ok "a name is written behind the attributes, and nothing after it" || bad "de: rc=${rc}, wrote $(od -An -tx1 "$KB_VAR" 2>/dev/null | tr -d ' \n')"
[[ "$(kb kb_stored)" == de ]] && ok "and reads back" || bad "read back '$(kb kb_stored)'"
kb kb_store us; [[ "$(kb kb_stored)" == us ]] && ok "us replaces another name" || bad "after us: '$(kb kb_stored)'"
kb kb_store nosuchlayout 2>/dev/null; rc=$?
[[ "$rc" -ne 0 && "$(kb kb_stored)" == us ]] && ok "a name the table lacks is not written" || bad "nosuchlayout stored: rc=${rc}"
KB_VAR="$T/no-such-directory/KryptikKeyboard" kb kb_store de 2>/dev/null; rc=$?
[[ "$rc" -ne 0 ]] && ok "without firmware variables a store fails" || bad "a store with no efivars succeeded"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
