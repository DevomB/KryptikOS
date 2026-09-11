#!/usr/bin/env bash
# Regression test: a build recipe that fails partway must NOT be recorded as
# successful.
#
# This bug has now shipped twice, in two different disguises:
#
#   1.  if "$@" > "$logfile" 2>&1; then ...
#       bash suppresses errexit for any command in a condition, and the
#       suppression propagates into functions called from there.
#
#   2.  ( set -Eeuo pipefail; "$@" ) > "$logfile" 2>&1 || rc=$?
#       written specifically to fix (1), and broken the same way: the trailing
#       || is itself a condition context, and it overrides the explicit set -e
#       inside the subshell.
#
# Both looked correct. Only running them shows the difference, which is what
# this test is for. It extracts the real step() from each stage file and runs a
# recipe that fails in the middle and then succeeds.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

# A recipe that fails in the middle and then succeeds. If errexit is working,
# `false` aborts it. If not, the function runs to the end and returns 0 - which
# is exactly how a package that never compiled gets stamped as built.
make_probe() {
    cat <<'PROBE'
probe_recipe() {
    echo "recipe: step 1"
    false
    echo "recipe: step 2 - errexit did NOT fire"
    true
}
PROBE
}

# Pull the step() body out of a real stage file so the test cannot drift away
# from the code it is testing.
extract_step() {
    local file="$1"
    sed -n '/^step() {/,/^}/p' "$file"
}

check_stage() {
    local file="$1" name="$2"
    local work; work="$(mktemp -d)"

    {
        echo 'set -Eeuo pipefail'
        # Minimal stand-ins for what step() expects from common.sh.
        echo "STAMPS='${work}/stamps'"
        echo "LOGS='${work}/logs'"
        echo 'REDO=""'
        echo 'mkdir -p "$STAMPS" "$LOGS"'
        echo 'log()  { :; }'
        echo 'dim()  { :; }'
        echo 'ok()   { :; }'
        echo 'warn() { :; }'
        echo 'err()  { :; }'
        echo 'die()  { exit 1; }'
        echo 'set_flags_for() { :; }'
        echo 'SECONDS=0'
        make_probe
        extract_step "$file"
        # Called BARE, exactly as the stage files call it. Adding `|| true`
        # here would create the very condition context under test and make a
        # correct step() look broken - the first version of this test did
        # exactly that and reported all four stages as failing.
        echo 'step probe probe_recipe'
    } > "${work}/harness.sh"

    # step() calls die() on failure, so a nonzero exit here is the CORRECT
    # outcome. What matters is whether a stamp was left behind.
    bash "${work}/harness.sh" >/dev/null 2>&1

    local stamped
    stamped="$(ls "${work}/stamps" 2>/dev/null | head -1)"
    rm -rf "$work"

    if [[ -z "$stamped" ]]; then
        green "${name}: a failing recipe left no success stamp"
    else
        red "${name}: FAILING RECIPE WAS STAMPED SUCCESSFUL (${stamped})"
    fi
}

echo "Regression test: failed builds must not be stamped successful"
echo

for f in 01-toolchain 02-temp-tools 04-base-system 05-kernel; do
    path="${ROOT}/build/stages/${f}.sh"
    [[ -f "$path" ]] || { red "${f}: file missing"; continue; }
    check_stage "$path" "$f"
done

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} stage(s) will record a failed build as successful."
    echo "Stamps from such a run prove nothing; clear them and rebuild."
    exit 1
fi
echo "All ${PASS} stage(s) correctly propagate recipe failure."
