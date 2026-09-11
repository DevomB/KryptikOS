#!/usr/bin/env bash
# Regression test: a build recipe that fails partway must NOT be recorded as
# successful, and a stamp must not outlive the inputs it was built from.
#
# The errexit bug has shipped twice, in two different disguises:
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
# this test is for.
#
# WHAT CHANGED, AND WHY IT MATTERS
#
# The old version of this test reconstructed a fake stage: it sed-extracted the
# step() body out of each stage file and ran it against stub log/ok/err/die
# functions and a stubbed-out ERR trap. That tested a copy of the code with the
# error handling removed - the one part most worth testing.
#
# It also only ever asserted one thing: that no stamp appeared. A step() that
# refused to run anything at all would have passed every check.
#
# This version sources the REAL build/lib/common.sh, with the REAL ERR trap
# installed, and calls the REAL step(). It asserts, separately:
#
#   * a successful recipe runs to completion, exits 0, and IS stamped
#   * a failing recipe actually executed (the log proves the recipe ran)
#   * the failure produced a non-zero exit from step()'s caller
#   * no command after the failing one ran
#   * no stamp was written
#   * the ERR trap from common.sh fired and named the failure
#   * a stamp whose inputs have changed is refused, not trusted
#   * a fingerprint-less stamp from the old harness is archived, not trusted

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

check() {
    local desc="$1" cond="$2"
    if [[ "$cond" == "ok" ]]; then green "$desc"; else red "$desc"; fi
}

# --------------------------------------------------------------------------
# A harness that drives the real step() from the real common.sh.
#
# STAGE_FILE is a throwaway copy inside the work dir, so the staleness tests
# can mutate "the recipe" without touching the repository.
# --------------------------------------------------------------------------
make_harness() {
    local work="$1"
    mkdir -p "$work/.stamps" "$work/logs"
    cat > "$work/stage-under-test.sh" <<'STAGE'
# stand-in stage file; its hash is a fingerprint input
STAGE
    cat > "$work/harness.sh" <<HARNESS
#!/usr/bin/env bash
export KRYPTIK_ROOT="${ROOT}"
export KRYPTIK_WORK="${work}"
export NO_COLOR=1
source "${ROOT}/build/lib/common.sh"

STAMPS="${work}/.stamps"
LOGS="${work}/logs"
STAGE_FILE="${work}/stage-under-test.sh"
STAMP_PREFIX="t-"
STAMP_CC="gcc"
REDO=""

# A recipe that succeeds all the way through.
recipe_ok() {
    echo "recipe: step 1"
    true
    echo "recipe: step 2 reached"
}

# A recipe that fails in the middle and then tries to continue. If errexit is
# working, \`false\` aborts it. If not, the function runs to the end and returns
# 0 - which is exactly how a package that never compiled gets stamped as built.
recipe_fail() {
    echo "recipe: step 1"
    false
    echo "recipe: step 2 reached"
}

# Called BARE, exactly as the stage files call it. Adding \`|| true\` here would
# create the very condition context under test and make a correct step() look
# broken - the first version of this test did exactly that and reported all
# four stages as failing.
step "\$1" "\$2"
HARNESS
    chmod +x "$work/harness.sh"
}

# --------------------------------------------------------------------------
# 1. A recipe that succeeds must be recorded as succeeding.
#
# Without this, a step() that refuses to run anything passes every other check
# in this file.
# --------------------------------------------------------------------------
test_positive() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc
    out="$(bash "$work/harness.sh" good recipe_ok 2>&1)"; rc=$?
    local log="$work/logs/t-good.log"
    local stamp="$work/.stamps/t-good"

    [[ "$rc" -eq 0 ]] && check "successful recipe: step() exits 0" ok \
                      || check "successful recipe: step() exits 0 (got ${rc})" no
    [[ -f "$stamp" ]] && check "successful recipe: stamp written" ok \
                      || check "successful recipe: stamp written" no
    grep -q "^fingerprint: [0-9a-f]\{64\}$" "$stamp" 2>/dev/null \
        && check "successful recipe: stamp carries a fingerprint" ok \
        || check "successful recipe: stamp carries a fingerprint" no
    grep -q "recipe: step 2 reached" "$log" 2>/dev/null \
        && check "successful recipe: ran to the end" ok \
        || check "successful recipe: ran to the end" no

    # Re-running must skip, not rebuild.
    out="$(bash "$work/harness.sh" good recipe_ok 2>&1)"; rc=$?
    { [[ "$rc" -eq 0 ]] && [[ "$out" == *"skip good"* ]]; } \
        && check "unchanged inputs: second run skips the step" ok \
        || check "unchanged inputs: second run skips the step" no

    rm -rf "$work"
}

# --------------------------------------------------------------------------
# 2. The failure case, asserted in five separate ways.
# --------------------------------------------------------------------------
test_negative() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc
    out="$(bash "$work/harness.sh" bad recipe_fail 2>&1)"; rc=$?
    local log="$work/logs/t-bad.log"
    local stamp="$work/.stamps/t-bad"

    [[ "$rc" -ne 0 ]] && check "failing recipe: step() propagates a non-zero exit" ok \
                      || check "failing recipe: step() propagates a non-zero exit (got 0)" no

    # The recipe must have actually EXECUTED. A step() that fails to invoke the
    # recipe at all also leaves no stamp, and would sail through the old test.
    grep -q "recipe: step 1" "$log" 2>/dev/null \
        && check "failing recipe: the recipe really ran" ok \
        || check "failing recipe: the recipe really ran" no

    grep -q "recipe: step 2 reached" "$log" 2>/dev/null \
        && check "failing recipe: no command after the failure ran" no \
        || check "failing recipe: no command after the failure ran" ok

    [[ -f "$stamp" ]] \
        && check "failing recipe: FAILING RECIPE WAS STAMPED SUCCESSFUL" no \
        || check "failing recipe: left no success stamp" ok

    # The ERR trap installed by common.sh must have fired inside the recipe
    # subshell and said where. Stubbing it out, as the old test did, hides the
    # single most useful piece of diagnostic the build has.
    grep -q "aborted at" "$log" 2>/dev/null \
        && check "failing recipe: common.sh ERR trap fired and named the line" ok \
        || check "failing recipe: common.sh ERR trap fired and named the line" no

    rm -rf "$work"
}

# --------------------------------------------------------------------------
# 3. Stamps must not outlive the inputs they were built from.
# --------------------------------------------------------------------------
test_staleness() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    bash "$work/harness.sh" pkg recipe_ok >/dev/null 2>&1
    [[ -f "$work/.stamps/t-pkg" ]] || { red "staleness: setup build did not stamp"; rm -rf "$work"; return; }

    # Change the recipe. The stamp now describes something that no longer
    # exists.
    echo "# recipe changed" >> "$work/stage-under-test.sh"

    local out rc
    out="$(bash "$work/harness.sh" pkg recipe_ok 2>&1)"; rc=$?
    { [[ "$rc" -ne 0 ]] && [[ "$out" == *"Refusing to resume onto changed inputs"* ]]; } \
        && check "changed inputs: resume is refused by default" ok \
        || check "changed inputs: resume is refused by default" no

    out="$(KRYPTIK_STALE=rebuild bash "$work/harness.sh" pkg recipe_ok 2>&1)"; rc=$?
    { [[ "$rc" -eq 0 ]] && [[ "$out" == *"rebuilding this step"* ]]; } \
        && check "changed inputs: KRYPTIK_STALE=rebuild rebuilds" ok \
        || check "changed inputs: KRYPTIK_STALE=rebuild rebuilds" no

    rm -rf "$work"
}

# --------------------------------------------------------------------------
# 4. Stamps from the old harness prove nothing.
#
# Every stamp written before the errexit bug was found came from a step() that
# recorded FAILED builds as successful. Such a stamp is an empty file with no
# fingerprint, and must be treated as absent - but preserved, because it is
# still the only record of what that run did.
# --------------------------------------------------------------------------
test_legacy_stamp() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    # Exactly what the old harness left behind: `touch`.
    : > "$work/.stamps/t-ancient"

    local out rc
    out="$(bash "$work/harness.sh" ancient recipe_ok 2>&1)"; rc=$?

    [[ "$rc" -eq 0 ]] && check "legacy stamp: the step is rebuilt" ok \
                      || check "legacy stamp: the step is rebuilt" no
    [[ "$out" == *"proves nothing"* ]] \
        && check "legacy stamp: refused as evidence, with a reason" ok \
        || check "legacy stamp: refused as evidence, with a reason" no
    [[ -f "$work/.stamps/legacy/t-ancient" ]] \
        && check "legacy stamp: archived rather than deleted" ok \
        || check "legacy stamp: archived rather than deleted" no
    grep -q "^fingerprint: " "$work/.stamps/t-ancient" 2>/dev/null \
        && check "legacy stamp: replaced by a fingerprinted one" ok \
        || check "legacy stamp: replaced by a fingerprinted one" no

    rm -rf "$work"
}

# --------------------------------------------------------------------------
# 5. There must be exactly one step().
#
# Four copies is how the same bug shipped twice: a fix landed in one file and
# not the others, and this test had to re-derive the code under test from each
# stage in turn.
# --------------------------------------------------------------------------
test_single_implementation() {
    local strays
    strays="$(grep -l '^step() {' "$ROOT"/build/stages/*.sh 2>/dev/null || true)"
    if [[ -z "$strays" ]]; then
        green "single implementation: no stage defines its own step()"
    else
        red "single implementation: these stages define their own step():"
        printf '          %s\n' $strays
    fi

    if grep -q '^step() {' "$ROOT/build/lib/common.sh"; then
        green "single implementation: build/lib/common.sh provides step()"
    else
        red "single implementation: build/lib/common.sh provides step()"
    fi

    # Every stage that runs steps must declare what its stamps are
    # fingerprinted against, or the fingerprint silently degrades to a
    # constant.
    local f base
    for f in "$ROOT"/build/stages/0{1,2,4,5}-*.sh; do
        base="$(basename "$f")"
        if grep -q '^STAGE_FILE=' "$f" && grep -q '^STAMP_CC=' "$f" \
        && grep -q '^STAMP_PREFIX=' "$f"; then
            green "stamp contract: ${base} declares STAGE_FILE/STAMP_PREFIX/STAMP_CC"
        else
            red "stamp contract: ${base} is missing part of the stamp contract"
        fi
    done
}

echo "Regression test: the build step runner"
echo

echo "-- a successful recipe is recorded as successful"
test_positive
echo
echo "-- a failing recipe is not"
test_negative
echo
echo "-- stamps do not outlive their inputs"
test_staleness
echo
echo "-- stamps from the pre-fix harness are not evidence"
test_legacy_stamp
echo
echo "-- there is one step(), and the stages declare their inputs"
test_single_implementation

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed."
    echo "A build run under this harness cannot be trusted to have built what"
    echo "its stamps claim. Fix the harness before reading anything into a"
    echo "green build."
    exit 1
fi
echo "All ${PASS} checks passed."
