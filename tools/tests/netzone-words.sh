#!/usr/bin/env bash
# Tests for the words the net zone prints and takes from the network
# (tools/net/netzone-init.sh, say and update_run): a backslash is printed, not
# acted on, and the update helper's last line counts as zone 0's answer only
# when the helper ended well. Offline, under each POSIX shell here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/tools/net/netzone-init.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
same()  { if [[ "$2" == "$3" ]]; then green "$1"; else red "$1" "got '$(tr '\n' '|' <<<"$2")', want '$(tr '\n' '|' <<<"$3")'"; fi; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is not installed here; cannot run this test"; exit 77; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

{ sed -n '/^say() {/p' "$SCRIPT"; sed -n '/^update_run() {/,/^}/p' "$SCRIPT"; } > "$T/functions.sh"
grep -q '^say() {' "$T/functions.sh" && grep -q '^update_run() {' "$T/functions.sh" \
    || { echo "could not find say or update_run in ${SCRIPT#"$ROOT"/} (did their first lines move?)"; exit 1; }
grep -q -- '--ready-fd 3 -- /usr/libexec/kryptik/netzone-init.sh 3>/dev/null' "${ROOT}/build/services/net-zone/run" \
    && green "the service starts the zone on a pipe, so its launcher marks and bounds what it says" \
    || red "build/services/net-zone/run hands the zone the service's own log"

# The update helper's stand-in: prints what it is told to, ends as it is told to.
cat > "$T/fetch.py" <<'EOF'
import os, sys
sys.stdout.write(os.environ.get("SAYS", ""))
sys.exit(int(os.environ.get("ENDS", "0")))
EOF
: > "$T/update.conf"
cat > "$T/harness.sh" <<EOF
. "$T/functions.sh"
UPDATE_FETCH="$T/fetch.py"; UPDATE_CONF="$T/update.conf"; UPDATE_BROUGHT="$T/brought"; BROKER=/nowhere; UPDATE_PID=""
case "\$1" in
    say) shift; say "\$@" ;;
    run) update_run "\$2"; rc=\$?; wait; echo "rc=\$rc"; [ -e "\$UPDATE_BROUGHT" ] && echo brought || echo not-brought ;;
    busy) sleep 5 & UPDATE_PID=\$!; update_run latest; echo "rc=\$?"; kill "\$UPDATE_PID" ;;
esac
EOF

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    run() { rm -f "$T/brought"; "$sh" "$T/harness.sh" "$@" 2>&1; }
    echo "-- ${sh}"
    same "a backslash from the network is printed as it came" \
        "$(run say 'wifi: Caf\x65\nnetzone: READY \033[2J')" 'netzone: wifi: Caf\x65\nnetzone: READY \033[2J'
    same "zone 0's ok to a statement is taken, and the statement is not asked for again that day" \
        "$(SAYS='ok current' ENDS=0 run run latest)" "$(printf 'netzone: update: zone 0 on the statement of what is current: ok current\nrc=0\nbrought')"
    same "the same words at the end of a fetch that failed are the far host's: said, and not taken" \
        "$(SAYS=$'update-fetch: HTTP Error 302: loop\nok current' ENDS=1 run run latest)" "$(printf 'netzone: update latest: ok current\nrc=0\nnot-brought')"
    same "an idle poll says nothing" "$(SAYS='idle' ENDS=0 run run poll)" "$(printf 'rc=0\nnot-brought')"
    same "a poll that failed is said, whatever its last line" "$(SAYS='idle' ENDS=1 run run poll)" "$(printf 'netzone: update poll: idle\nrc=0\nnot-brought')"
    same "while one runs, the next is not started and says so by its status" "$(run busy)" "rc=1"
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
