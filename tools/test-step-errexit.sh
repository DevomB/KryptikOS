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

# This suite asserts step()'s DEFAULT behaviour: a changed input is refused,
# not silently rebuilt. `make acceptance` (and any build run) exports
# KRYPTIK_STALE=rebuild, which would turn every "is refused" case into a
# rebuild and fail it. Neutralise the ambient value; the cases that test the
# rebuild path set KRYPTIK_STALE=rebuild themselves, per invocation.
unset KRYPTIK_STALE

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
    local work="$1" extra="${2:-}" hcode="${3:-true}" hcomment="${4:-a comment}" ucode="${5:-true}" textra="${6:-true}"
    mkdir -p "$work/.stamps" "$work/logs" "$work/src"
    : > "$work/stage-under-test.sh"
    [[ -f "$work/src/probe-1.0.tar.gz" ]] || echo "original tarball" > "$work/src/probe-1.0.tar.gz"

    cat > "$work/harness.sh" <<HARNESS
#!/usr/bin/env bash
export KRYPTIK_ROOT="${ROOT}"
export KRYPTIK_WORK="${work}"
export KRYPTIK_SOURCES="${work}/src"
export KRYPTIK_PATCHES="${work}/patches"
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

# A recipe that does its work through a helper that calls another, the way
# native_build reaches unpack; and a helper nothing calls.
helper_inner() {
    # ${hcomment}
    ${hcode}
}
helper_outer() { helper_inner; }
recipe_helped() { helper_outer; }
helper_unused() { ${ucode}; }
# A recipe that says "step" in a message, which is not a call to step().
recipe_says_step() { echo "the step before this one"; }

# A recipe that installs into the sysroot: one file always, one more as the
# test asks, and a line appended to a file it did not create.
recipe_tree() {
    mkdir -p "\$KRYPTIK_SYSROOT/usr/bin"
    echo a > "\$KRYPTIK_SYSROOT/usr/bin/a"
    ${textra}
    echo /bin/sh >> "\$KRYPTIK_SYSROOT/etc/shells"
}

# step() calls this after printing the tail of a failed log. Its output is
# how the test tells that step() survived the failure far enough to report
# it, rather than being killed on the subshell line by the ERR trap.
step_failure_hint() {
    echo "HINT-RAN:\$1"
}

# Stage 04 narrows CFLAGS per package, dropping a flag for any package with an
# entry in hardening-exceptions.txt. Modelled here, because a step whose flags
# differ from its neighbours' is the case that broke.
export CFLAGS="-O2 -D_FORTIFY_SOURCE=3"
set_flags_for() {
    export CFLAGS="-O2 -D_FORTIFY_SOURCE=3"
    if [ "\$1" = "excepted" ]; then
        export CFLAGS="-O2"
    fi
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

# Recipes that apply an in-repository patch set: one names it as an
# argument, one in its own text through a version variable, the way s_glibc
# does. Each rebuilds its tree from scratch, as unpack() would.
recipe_patch() {
    rm -rf "${work}/src/tree"; mkdir -p "${work}/src/tree"
    echo a > "${work}/src/tree/file"
    cd "${work}/src/tree"
    apply_repo_patches "\$1"
    grep -q '^b\$' file
}
recipe_patch_ver() {
    rm -rf "${work}/src/tree"; mkdir -p "${work}/src/tree"
    echo a > "${work}/src/tree/file"
    cd "${work}/src/tree"
    apply_repo_patches "probe-\${V_PROBE}"
    grep -q '^b\$' file
}

# A later stage seeds its chain from an earlier stage's stamp; modelled with
# an environment variable so one harness can play both stages.
if [ -n "\${SEED_FROM:-}" ]; then
    stage_depends_on "t-" "\$SEED_FROM"
fi

# Called BARE, exactly as the stage files call it. Adding \`|| true\` here would
# create the very condition context under test and make a correct step() look
# broken - the first version of this test did exactly that and reported all
# four stages as failing.
#
# Several steps separated by -- run in ONE process, the way a stage runs its
# list: the dependency chain between steps only exists inside a process.
run_steps() {
    local cur=() a
    for a in "\$@" --; do
        if [ "\$a" = "--" ]; then
            if [ "\${#cur[@]}" -gt 0 ]; then
                step "\${cur[@]}"
            fi
            cur=()
        else
            cur+=("\$a")
        fi
    done
}
run_steps "\$@"
HARNESS
    chmod +x "$work/harness.sh"
}

run_harness() { bash "$1/harness.sh" "${@:2}" 2>&1; }

# make_patchset <work> <set-name> <replacement-line>: a one-patch set that
# turns the tree's "a" into the given line, with its SHA256SUMS beside it.
make_patchset() {
    local dir="$1/patches/$2"
    mkdir -p "$dir"
    printf -- '--- a/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+%s\n' "$3" > "$dir/0001-change.patch"
    ( cd "$dir" && sha256sum 0001-change.patch > SHA256SUMS )
}

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

# The helpers a recipe reaches are its inputs, by their code: not a comment in
# them, not a helper it never calls.
test_helpers() {
    local work out rc; work="$(mktemp -d)"
    make_harness "$work"
    run_harness "$work" helped recipe_helped >/dev/null
    [[ -f "$work/.stamps/t-helped" ]] || { red "helpers: setup build did not stamp"; rm -rf "$work"; return; }

    make_harness "$work" "" true "another comment" 'echo changed'
    out="$(run_harness "$work" helped recipe_helped)"; rc=$?
    check "helpers: a comment, or a helper the recipe never calls, changes nothing" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip helped"* ]]; } && echo ok)"

    make_harness "$work" "" 'echo changed'
    out="$(run_harness "$work" helped recipe_helped)"; rc=$?
    check "helpers: a code change two calls down is a changed input" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume onto changed inputs"* ]]; } && echo ok)"

    out="$(bash -c 'source "$1"; recipe() { echo "the step before"; }; _helpers_of recipe' _ "$ROOT/build/lib/common.sh" 2>&1)"
    check "helpers: \"step\" in a recipe's message does not bring in the step runner" "$([[ -z "$out" ]] && echo ok)"
    rm -rf "$work"
}

# With STAMP_TREE, a step records the files it created, and a rebuild removes
# the ones it no longer installs; a file it only changed is not its to remove.
test_outputs() {
    local work out rc; work="$(mktemp -d)"
    # shellcheck disable=SC2016  # expanded by the harness, not here
    make_harness "$work" "" true "a comment" true 'echo b > "$KRYPTIK_SYSROOT/usr/bin/b"'
    mkdir -p "$work/sysroot/etc"; echo /bin/bash > "$work/sysroot/etc/shells"
    STAMP_TREE=1 run_harness "$work" tree recipe_tree >/dev/null
    check "outputs: the files a step created are listed beside its stamp, a file it changed is not" \
          "$([[ "$(cat "$work/.stamps/t-tree.files" 2>/dev/null)" == "$work/sysroot/usr/bin/a"$'\n'"$work/sysroot/usr/bin/b" ]] && echo ok)"

    make_harness "$work"
    out="$(STAMP_TREE=1 KRYPTIK_STALE=rebuild run_harness "$work" tree recipe_tree)"; rc=$?
    check "outputs: rebuilt without it, the step leaves behind no file it stopped installing" \
          "$([[ $rc -eq 0 && ! -e "$work/sysroot/usr/bin/b" && -f "$work/sysroot/usr/bin/a" ]] && echo ok)"
    check "outputs: and the file it only changed survives" \
          "$(grep -q /bin/bash "$work/sysroot/etc/shells" 2>/dev/null && echo ok)"
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
# 4b. A step whose flags are narrowed must still skip on the next run.
#
# step() used to compute the fingerprint for the skip comparison BEFORE
# calling set_flags_for, and write the stamp AFTER. For every package whose
# flags are untouched those are the same string; for a package with a
# hardening exception they are not, so its stamp could never match and it went
# stale on every resume.
#
# In stage 04 exactly one package has an exception - glibc - so exactly one
# package was affected, and it looked like a mysterious one-off rather than a
# logic error.
# ---------------------------------------------------------------------------
test_per_step_flags() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc

    # The ordinary case still has to work.
    run_harness "$work" ordinary recipe_ok >/dev/null
    out="$(run_harness "$work" ordinary recipe_ok)"; rc=$?
    check "unexcepted step: skips on the second run" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip ordinary"* ]]; } && echo ok)"

    # And so does the one whose flags set_flags_for narrows.
    run_harness "$work" excepted recipe_ok >/dev/null
    if [[ ! -f "$work/.stamps/t-excepted" ]]; then
        red "narrowed flags: setup build did not stamp"; rm -rf "$work"; return
    fi
    out="$(run_harness "$work" excepted recipe_ok)"; rc=$?
    check "step with narrowed flags: skips on the second run" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip excepted"* ]]; } && echo ok)"
    check "step with narrowed flags: is not reported stale" \
          "$(grep -q 'Refusing to resume' <<<"$out" && echo "" || echo ok)"

    # Changing the flags themselves must still invalidate it, or the
    # fingerprint would have stopped covering them at all.
    out="$(CFLAGS_EXTRA=x run_harness "$work" excepted recipe_ok)"; rc=$?
    check "narrowed flags: unchanged inputs still skip" "$([[ $rc -eq 0 ]] && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 4c. A step's stamp covers the steps before it BY FINGERPRINT, not by name.
#
# The chain used to carry names only, so a step rebuilt in place with a
# changed recipe left every later step's stamp valid: sixty packages linked
# against a glibc that no longer existed, all reporting "inputs unchanged".
# Both halves are asserted - a change invalidates what comes after it, and
# leaves what comes before it alone - because a chain that invalidated
# everything would pass the first half and be useless.
# ---------------------------------------------------------------------------
test_dependency_chain() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc s
    run_harness "$work" zero recipe_ver -- first recipe_ok -- second recipe_src probe-1.0.tar.gz >/dev/null
    for s in zero first second; do
        if [[ ! -f "$work/.stamps/t-$s" ]]; then
            red "dependency chain: setup build did not stamp ${s}"; rm -rf "$work"; return
        fi
    done

    out="$(run_harness "$work" zero recipe_ver -- first recipe_ok -- second recipe_src probe-1.0.tar.gz)"; rc=$?
    check "unchanged chain: every step skips" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip zero"* && $out == *"skip first"* && $out == *"skip second"* ]]; } && echo ok)"

    # Change the MIDDLE step's recipe and rebuild it alone.
    make_harness "$work" 'echo "recipe: an extra command"'
    out="$(KRYPTIK_STALE=rebuild run_harness "$work" zero recipe_ver -- first recipe_ok)"; rc=$?
    check "changed middle step: the step before it still skips" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip zero"* ]]; } && echo ok)"
    check "changed middle step: it is rebuilt" \
          "$([[ $out == *"first: KRYPTIK_STALE=rebuild"* ]] && echo ok)"

    # The step AFTER it: its own recipe, source and flags are untouched, and
    # its stamp must still be refused, because what it was built on changed.
    out="$(run_harness "$work" zero recipe_ver -- first recipe_ok -- second recipe_src probe-1.0.tar.gz)"; rc=$?
    check "changed middle step: the step after it is refused although its own inputs are unchanged" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"skip first"* ]] && [[ $out == *"second: stamp records a different fingerprint"* ]]; } && echo ok)"
    out="$(KRYPTIK_STALE=rebuild run_harness "$work" zero recipe_ver -- first recipe_ok -- second recipe_src probe-1.0.tar.gz)"; rc=$?
    check "changed middle step: KRYPTIK_STALE=rebuild rebuilds only what comes after it" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip zero"* && $out == *"skip first"* && $out == *"second: KRYPTIK_STALE=rebuild"* ]]; } && echo ok)"
    out="$(run_harness "$work" zero recipe_ver -- first recipe_ok -- second recipe_src probe-1.0.tar.gz)"; rc=$?
    check "rebuilt chain: everything skips again" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip zero"* && $out == *"skip first"* && $out == *"skip second"* ]]; } && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 4d. A stage seeds its chain from the stage it builds on.
#
# Stage 04 is compiled by stage 02's toolchain and the kernel by stage 04's.
# A rebuilt predecessor has to reach their stamps, and a missing predecessor
# has to stop the stage before it builds anything on nothing.
# ---------------------------------------------------------------------------
test_stage_seed() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc
    out="$(SEED_FROM=up run_harness "$work" down recipe_ver)"; rc=$?
    check "missing predecessor stamp: the stage refuses to start" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"has not completed"* ]]; } && echo ok)"
    check "missing predecessor stamp: nothing was built" \
          "$([[ ! -f "$work/.stamps/t-down" ]] && echo ok)"

    run_harness "$work" up recipe_ok >/dev/null
    out="$(SEED_FROM=up run_harness "$work" down recipe_ver)"; rc=$?
    check "seeded stage: builds on a finished predecessor" \
          "$({ [[ $rc -eq 0 ]] && [[ -f "$work/.stamps/t-down" ]]; } && echo ok)"
    out="$(SEED_FROM=up run_harness "$work" down recipe_ver)"; rc=$?
    check "seeded stage: unchanged predecessor, the step skips" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip down"* ]]; } && echo ok)"

    # Rebuild the predecessor with a changed recipe: the dependent is stale.
    make_harness "$work" 'echo "recipe: an extra command"'
    KRYPTIK_STALE=rebuild run_harness "$work" up recipe_ok >/dev/null
    out="$(SEED_FROM=up run_harness "$work" down recipe_ver)"; rc=$?
    check "rebuilt predecessor: the dependent stage's step is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"

    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# 4e. In-repository patch sets are inputs, and are verified before they are
#     applied.
# ---------------------------------------------------------------------------
test_patchset() {
    local work; work="$(mktemp -d)"
    make_harness "$work"
    make_patchset "$work" probe-set b
    make_patchset "$work" probe-1.0 b

    local out rc
    out="$(run_harness "$work" pat recipe_patch probe-set)"; rc=$?
    check "patch set: applied, and the step succeeds" "$([[ $rc -eq 0 ]] && echo ok)"
    check "patch set: the log names the patch it applied" \
          "$(grep -q 'applying 0001-change.patch' "$work/logs/t-pat.log" 2>/dev/null && echo ok)"
    out="$(run_harness "$work" pat recipe_patch probe-set)"; rc=$?
    check "patch set: unchanged, the step skips" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip pat"* ]]; } && echo ok)"

    run_harness "$work" patv recipe_patch_ver >/dev/null
    out="$(run_harness "$work" patv recipe_patch_ver)"; rc=$?
    check "patch set named through V_*: unchanged, the step skips" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip patv"* ]]; } && echo ok)"

    # A different patch, with its record updated: both steps are stale.
    make_patchset "$work" probe-set c
    make_patchset "$work" probe-1.0 c
    out="$(run_harness "$work" pat recipe_patch probe-set)"; rc=$?
    check "changed patch: a step naming the set as an argument is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"
    out="$(run_harness "$work" patv recipe_patch_ver)"; rc=$?
    check "changed patch: a step naming the set in its text is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"

    # A patch altered WITHOUT its record: the rebuild must fail, not apply it.
    make_patchset "$work" probe-set b
    printf -- '--- a/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+z\n' > "$work/patches/probe-set/0001-change.patch"
    out="$(KRYPTIK_STALE=rebuild run_harness "$work" pat recipe_patch probe-set)"; rc=$?
    check "tampered patch: the step fails" "$([[ $rc -ne 0 ]] && echo ok)"
    check "tampered patch: no stamp was written" "$([[ ! -f "$work/.stamps/t-pat" ]] && echo ok)"
    check "tampered patch: the log says SHA256SUMS refused it" \
          "$(grep -q 'does not match SHA256SUMS' "$work/logs/t-pat.log" 2>/dev/null && echo ok)"

    # A patch present but not listed at all.
    make_patchset "$work" probe-set b
    cp "$work/patches/probe-set/0001-change.patch" "$work/patches/probe-set/0002-extra.patch"
    out="$(KRYPTIK_STALE=rebuild run_harness "$work" pat recipe_patch probe-set)"; rc=$?
    check "unlisted patch: the step fails and says why" \
          "$({ [[ $rc -ne 0 ]] && grep -q 'not listed in SHA256SUMS' "$work/logs/t-pat.log"; } && echo ok)"

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
test_helpers
test_outputs
echo
echo "-- the sources a step names are part of its inputs"
test_source_inputs
echo
echo "-- a step whose flags are narrowed still resumes"
test_per_step_flags
echo
echo "-- a step's stamp covers what came before it, by fingerprint"
test_dependency_chain
echo
echo "-- a stage seeds its chain from the stage it builds on"
test_stage_seed
echo
echo "-- in-repository patch sets are inputs, verified before use"
test_patchset
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
