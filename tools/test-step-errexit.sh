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
# It also asserted exactly one thing: that no stamp appeared. A step() that
# refused to run anything at all would have passed every check in the file.
#
# This version sources the REAL build/lib/common.sh, with the REAL ERR trap
# installed, and calls the REAL step().

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

yes_() { green "$1"; }
no_()  { red "$1"; }
check() { if [[ "$2" == ok ]]; then green "$1"; else red "$1"; fi; }

# ---------------------------------------------------------------------------
# A harness that drives the real step() from the real common.sh.
#
# $2 is injected into the body of recipe_ok, so a test can change what the
# recipe IS - which is what the fingerprint is supposed to notice.
# ---------------------------------------------------------------------------
make_harness() {
    local work="$1" extra="${2:-}"
    mkdir -p "$work/.stamps" "$work/logs" "$work/src"
    : > "$work/stage-under-test.sh"
    [[ -f "$work/src/probe-1.0.tar.gz" ]] || echo "original tarball" > "$work/src/probe-1.0.tar.gz"

    cat > "$work/harness.sh" <<HARNESS
#!/usr/bin/env bash
export KRYPTIK_ROOT="${ROOT}"
export KRYPTIK_WORK="${work}"
export KRYPTIK_SOURCES="${work}/src"
export NO_COLOR=1
source "${ROOT}/build/lib/common.sh"

STAMPS="${work}/.stamps"
LOGS="${work}/logs"
stage_contract "${work}/stage-under-test.sh" "t-" gcc
REDO=""
V_PROBE=1.0

# A recipe that succeeds all the way through.
recipe_ok() {
    echo "recipe: step 1"
    true
    ${extra}
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

# A recipe whose input is a tarball named in its arguments.
recipe_src() {
    echo "recipe: consuming \$1"
}

# step() calls this after printing the tail of a failed log. Its output is
# how the test tells that step() survived the failure far enough to report
# it, rather than being killed on the subshell line by the ERR trap.
step_failure_hint() {
    echo "HINT-RAN:\$1"
}

# step() calls this after printing the tail of a failed log. Its output is
# how the test tells that step() survived the failure far enough to report
# it, rather than being killed on the subshell line by the ERR trap.
step_failure_hint() {
    echo "HINT-RAN:\$1"
}

# A recipe that names its tarball from a version variable instead, the way
# s_glibc and the stage 05 steps do.
recipe_ver() {
    echo "recipe: building probe-\${V_PROBE}"
}

# Called BARE, exactly as the stage files call it. Adding \`|| true\` here would
# create the very condition context under test and make a correct step() look
# broken - the first version of this test did exactly that and reported all
# four stages as failing.
step "\$@"
HARNESS
    chmod +x "$work/harness.sh"
}

run_harness() { bash "$1/harness.sh" "${@:2}" 2>&1; }

# ---------------------------------------------------------------------------
# 1. A recipe that succeeds must be recorded as succeeding.
#
# Without this, a step() that refuses to run anything passes every other check
# in this file.
# ---------------------------------------------------------------------------
test_positive() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc
    out="$(run_harness "$work" good recipe_ok)"; rc=$?
    local log="$work/logs/t-good.log" stamp="$work/.stamps/t-good"

    check "successful recipe: step() exits 0" "$([[ $rc -eq 0 ]] && echo ok)"
    check "successful recipe: stamp written" "$([[ -f $stamp ]] && echo ok)"
    check "successful recipe: stamp carries a fingerprint" \
          "$(grep -qE '^fingerprint: [0-9a-f]{64}$' "$stamp" 2>/dev/null && echo ok)"
    check "successful recipe: ran to the end" \
          "$(grep -q 'recipe: step 2 reached' "$log" 2>/dev/null && echo ok)"

    out="$(run_harness "$work" good recipe_ok)"; rc=$?
    check "unchanged inputs: second run skips the step" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip good"* ]]; } && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 2. The failure case, asserted in five separate ways.
# ---------------------------------------------------------------------------
test_negative() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc
    out="$(run_harness "$work" bad recipe_fail)"; rc=$?
    local log="$work/logs/t-bad.log" stamp="$work/.stamps/t-bad"

    check "failing recipe: step() propagates a non-zero exit" \
          "$([[ $rc -ne 0 ]] && echo ok)"

    # The recipe must have actually EXECUTED. A step() that fails to invoke the
    # recipe at all also leaves no stamp, and would sail through the old test.
    check "failing recipe: the recipe really ran" \
          "$(grep -q 'recipe: step 1' "$log" 2>/dev/null && echo ok)"

    check "failing recipe: no command after the failure ran" \
          "$(grep -q 'recipe: step 2 reached' "$log" 2>/dev/null || echo ok)"

    check "failing recipe: left no success stamp" \
          "$([[ ! -f $stamp ]] && echo ok)"

    # The ERR trap installed by common.sh must have fired inside the recipe
    # subshell and said where. Stubbing it out, as the old test did, hides the
    # single most useful diagnostic the build has.
    check "failing recipe: common.sh ERR trap fired and named the line" \
          "$(grep -q 'aborted at' "$log" 2>/dev/null && echo ok)"

    # Everything above passes whether or not step() SURVIVED the failure.
    #
    # `set +e` does not disable an ERR trap, and common.sh's trap exits, so
    # step() used to die on the subshell line: no stamp, non-zero exit, and
    # the recipe's own abort line in the log - every assertion above still
    # satisfied - while the log tail, the hint and die() never ran. A python
    # failure buried at line 1659 of 6060 then had to be found by hand.
    #
    # These two assertions are the difference.
    check "failing recipe: step() reports which step failed and where" \
          "$(grep -q 'bad failed. Last .* lines of' <<<"$out" && echo ok)"
    check "failing recipe: step_failure_hint ran" \
          "$(grep -q 'HINT-RAN:bad' <<<"$out" && echo ok)"
    check "failing recipe: the log tail reached the caller" \
          "$(grep -q 'recipe: step 1' <<<"$out" && echo ok)"

    # Everything above passes whether or not step() SURVIVED the failure.
    #
    # `set +e` does not disable an ERR trap, and common.sh's trap exits, so
    # step() used to die on the subshell line: no stamp, non-zero exit, and
    # the recipe's own abort line in the log - every assertion above still
    # satisfied - while the log tail, the hint and die() never ran. A python
    # failure buried at line 1659 of 6060 then had to be found by hand.
    #
    # These two assertions are the difference.
    check "failing recipe: step() reports which step failed and where" \
          "$(grep -q 'bad failed. Last .* lines of' <<<"$out" && echo ok)"
    check "failing recipe: step_failure_hint ran" \
          "$(grep -q 'HINT-RAN:bad' <<<"$out" && echo ok)"
    check "failing recipe: the log tail reached the caller" \
          "$(grep -q 'recipe: step 1' <<<"$out" && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 3. Stamps must not outlive the inputs they were built from - and must not
#    be invalidated by inputs that are not theirs.
#
# The second half matters as much as the first. A fingerprint over the whole
# stage file would pass every "did it notice" check here and still be useless,
# because one recipe fix would invalidate all fifty-eight stamps in stage 04.
# ---------------------------------------------------------------------------
test_staleness() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    run_harness "$work" untouched recipe_ver >/dev/null
    run_harness "$work" pkg recipe_ok >/dev/null
    if [[ ! -f "$work/.stamps/t-pkg" || ! -f "$work/.stamps/t-untouched" ]]; then
        red "staleness: setup build did not stamp"; rm -rf "$work"; return
    fi

    # Change what the recipe IS.
    make_harness "$work" 'echo "recipe: an extra command"'

    local out rc
    out="$(run_harness "$work" pkg recipe_ok)"; rc=$?
    check "changed recipe: resume is refused by default" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume onto changed inputs"* ]]; } && echo ok)"

    out="$(KRYPTIK_STALE=rebuild run_harness "$work" pkg recipe_ok)"; rc=$?
    check "changed recipe: KRYPTIK_STALE=rebuild rebuilds" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"rebuilding this step"* ]]; } && echo ok)"

    # A different step, whose own recipe did not change, must still be valid.
    out="$(run_harness "$work" untouched recipe_ver)"; rc=$?
    check "changed recipe: an unrelated step is NOT invalidated" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip untouched"* ]]; } && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 4. The sources a step names are part of its inputs.
# ---------------------------------------------------------------------------
test_source_inputs() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    run_harness "$work" tar recipe_src probe-1.0.tar.gz >/dev/null
    run_harness "$work" ver recipe_ver >/dev/null
    if [[ ! -f "$work/.stamps/t-tar" || ! -f "$work/.stamps/t-ver" ]]; then
        red "source inputs: setup build did not stamp"; rm -rf "$work"; return
    fi

    # Same name, different bytes: a re-fetched or tampered tarball.
    echo "different tarball" > "$work/src/probe-1.0.tar.gz"

    local out rc
    out="$(run_harness "$work" tar recipe_src probe-1.0.tar.gz)"; rc=$?
    check "changed tarball: the step that names it is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"

    out="$(run_harness "$work" ver recipe_ver)"; rc=$?
    check "changed tarball: a step that does not name it is untouched" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip ver"* ]]; } && echo ok)"

    # A version bump reaches recipes that build the filename internally, which
    # is how s_glibc and every stage 05 step name their sources.
    out="$(sed -i 's/^V_PROBE=1.0/V_PROBE=1.1/' "$work/harness.sh"; run_harness "$work" ver recipe_ver)"; rc=$?
    check "version bump: a recipe that interpolates V_* is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 5. Stamps from the old harness prove nothing.
#
# Every stamp written before the errexit bug was found came from a step() that
# recorded FAILED builds as successful. Such a stamp is an empty file with no
# fingerprint, and must be treated as absent - but preserved, because it is
# still the only record of what that run did.
# ---------------------------------------------------------------------------
test_legacy_stamp() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    # Exactly what the old harness left behind: `touch`.
    : > "$work/.stamps/t-ancient"

    local out rc
    out="$(run_harness "$work" ancient recipe_ok)"; rc=$?

    check "legacy stamp: the step is rebuilt" "$([[ $rc -eq 0 ]] && echo ok)"
    check "legacy stamp: refused as evidence, with a reason" \
          "$([[ $out == *"proves nothing"* ]] && echo ok)"
    check "legacy stamp: archived rather than deleted" \
          "$([[ -f "$work/.stamps/legacy/t-ancient" ]] && echo ok)"
    check "legacy stamp: replaced by a fingerprinted one" \
          "$(grep -q '^fingerprint: ' "$work/.stamps/t-ancient" 2>/dev/null && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 6. There must be exactly one step().
#
# Four copies is how the same bug shipped twice: a fix landed in one file and
# not the others, and this test had to re-derive the code under test from each
# stage in turn.
# ---------------------------------------------------------------------------
test_single_implementation() {
    local strays
    strays="$(grep -l '^step() {' "$ROOT"/build/stages/*.sh 2>/dev/null || true)"
    if [[ -z "$strays" ]]; then
        green "single implementation: no stage defines its own step()"
    else
        red "single implementation: these stages define their own step():"
        printf '          %s\n' "$strays"
    fi

    check "single implementation: build/lib/common.sh provides step()" \
          "$(grep -q '^step() {' "$ROOT/build/lib/common.sh" && echo ok)"
    check "stamp contract: common.sh defines stage_contract()" \
          "$(grep -q '^stage_contract() {' "$ROOT/build/lib/common.sh" && echo ok)"

    # Every stage that runs steps must declare what its stamps are
    # fingerprinted against, or the fingerprint silently degrades to something
    # that distinguishes nothing.
    local f base
    for f in "$ROOT"/build/stages/0{1,2,4,5}-*.sh; do
        base="$(basename "$f")"
        check "stamp contract: ${base} calls stage_contract()" \
              "$(grep -q '^stage_contract "' "$f" && echo ok)"
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
echo "-- stamps track their own inputs, and only their own"
test_staleness
echo
echo "-- the sources a step names are part of its inputs"
test_source_inputs
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
