#!/usr/bin/env bash
# `kryptik timezone` against a stand-in zoneinfo tree: the link it makes, the names it lists, and
# the names it refuses, none of which may leave the link changed or a stray file beside it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLI="$ROOT/tools/kryptik"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
[[ -f "$CLI" ]] || { echo "missing: $CLI"; exit 1; }

T="$(mktemp -d)"; trap 'chmod -R u+w "$T"; rm -rf "$T"' EXIT
DB="$T/zoneinfo"; mkdir -p "$DB/Europe" "$DB/America/Argentina" "$DB/Etc" "$T/etc"
for z in UTC Europe/Berlin Europe/Busingen America/New_York America/Argentina/Buenos_Aires Etc/GMT+5; do
    printf 'TZif2\0\0\0' > "$DB/$z"
done
echo "not a zone" > "$DB/Europe/Notes"
printf '#code\tcoordinates\tTZ\tcomments\nDE\t+5230+01322\tEurope/Berlin\tmost of Germany\nDE\t+4742+00841\tEurope/Busingen\tBusingen\nUS\t+404251-0740023\tAmerica/New_York\tEastern (most areas)\n' > "$DB/zone.tab"
printf '#codes\tcoordinates\tTZ\tcomments\nDE,DK\t+5230+01322\tEurope/Berlin\nUS\t+404251-0740023\tAmerica/New_York\tEastern (most areas)\nAR\t-3436-05827\tAmerica/Argentina/Buenos_Aires\tBuenos Aires (BA, CF)\n' > "$DB/zone1970.tab"
export KRYPTIK_ZONEINFO="$DB" KRYPTIK_LOCALTIME="$T/etc/localtime" KRYPTIK_CONF=/nonexistent
run() { bash "$CLI" timezone "$@" > "$T/out" 2>&1; }
out() { cat "$T/out"; }
link() { readlink "$T/etc/localtime" 2>/dev/null; }

echo "-- the zone in force"
run && [[ "$(out)" == "UTC (no time zone chosen)" ]] && ok "with no link it says UTC, none chosen" || bad "no link: $(out)"
if run Europe/Berlin && [[ "$(link)" == "$DB/Europe/Berlin" && "$(out)" == "time zone Europe/Berlin:"* ]]; then
    ok "a zone's name links /etc/localtime to its file"
else
    bad "Europe/Berlin: link '$(link)', said '$(out)'"
fi
run && [[ "$(out)" == Europe/Berlin ]] && ok "the zone in force is named" || bad "after Europe/Berlin: $(out)"
run America/Argentina/Buenos_Aires && [[ "$(link)" == "$DB/America/Argentina/Buenos_Aires" ]] \
    && ok "a name of three parts is taken" || bad "Buenos_Aires: link '$(link)', said '$(out)'"
run Etc/GMT+5 && [[ "$(link)" == "$DB/Etc/GMT+5" ]] && ok "a name with + is taken" || bad "Etc/GMT+5: $(out)"
run Europe/Berlin
[[ -L "$T/etc/localtime" && ! -e "$T/etc/localtime.new" ]] && ok "the link is replaced whole, nothing left beside it" \
    || bad "after a change: $(ls -la "$T/etc")"

echo "-- names refused"
for n in ../etc/passwd Europe/../UTC /etc/passwd Europe Europe/Notes zone.tab -x Nowhere/Here \
         'Europe/Berlin x' 'Europe/Berlin;id' a/b/c/d '' .; do
    if run "$n"; then bad "'${n}' was taken"
    elif [[ "$(link)" != "$DB/Europe/Berlin" || -e "$T/etc/localtime.new" ]]; then bad "'${n}' changed the link to '$(link)'"
    else ok "'${n}' is refused"; fi
done
if run Europe/Berlin UTC; then bad "two names were taken"; else ok "two names are refused"; fi

echo "-- listing"
run list && [[ "$(out)" == $'America/Argentina/Buenos_Aires\nAmerica/New_York\nEurope/Berlin\nUTC' ]] \
    && ok "list gives the zones apart since 1970 and UTC, sorted" || bad "list: $(out | tr '\n' ' ')"
run list berlin && [[ "$(out)" == Europe/Berlin ]] && ok "a word lists the names holding it, in any case" || bad "list berlin: $(out)"
run list de && [[ "$(out)" == $'Europe/Berlin                    most of Germany\nEurope/Busingen                  Busingen' ]] \
    && ok "two letters list that country's zones" || bad "list de: $(out | tr '\n' '|')"
if run list zz; then bad "an unknown country listed '$(out)'"; else ok "an unknown country is said to have none"; fi
if run list nowhere; then bad "a word no name holds listed '$(out)'"; else ok "a word no name holds is said to match none"; fi
if run list a b; then bad "list took two words"; else ok "list takes one word"; fi

echo "-- refusals of the place"
if [[ "$(id -u)" -ne 0 ]]; then
    chmod a-w "$T/etc"
    if run UTC; then bad "a link in a directory it cannot write was claimed"
    elif [[ "$(out)" == *"root's to change"* && "$(link)" == "$DB/Europe/Berlin" ]]; then ok "without the right to change it, it says whose it is"
    else bad "unwritable: $(out)"; fi
    chmod u+w "$T/etc"
fi
if KRYPTIK_ZONEINFO="$T/none" bash "$CLI" timezone UTC > "$T/out" 2>&1; then bad "no database, yet UTC was taken"
elif [[ "$(out)" == *"no time zone database"* ]]; then ok "with no database it says so"
else bad "no database: $(out)"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
