#!/usr/bin/env bash
# Tests for step() in build/lib/common.sh, run for real with its ERR trap: a
# recipe that fails partway is never stamped, and a stamp is refused once its
# inputs change.
#
# bash suppresses errexit in any condition context (`if cmd`, `cmd || x`) and
# in functions called from one, even under `set -e` inside a subshell.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0

# Test the default (refuse changed inputs): builds export KRYPTIK_STALE=rebuild,
# and the rebuild cases set it per invocation.
unset KRYPTIK_STALE

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

yes_() { green "$1"; }
no_()  { red "$1"; }
check() { if [[ "$2" == ok ]]; then green "$1"; else red "$1"; fi; }

# make_harness WORK [EXTRA]: a script that runs the real step() on its
# arguments. EXTRA goes into recipe_ok's body, to change the recipe.
make_harness() {
    local work="$1" extra="${2:-}" hcode="${3:-true}" hcomment="${4:-a comment}" ucode="${5:-true}"
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

# make_patchset WORK SET LINE: one patch turning the tree's "a" into LINE,
# with its SHA256SUMS.
make_patchset() {
    local dir="$1/patches/$2"
    mkdir -p "$dir"
    printf -- '--- a/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+%s\n' "$3" > "$dir/0001-change.patch"
    ( cd "$dir" && sha256sum 0001-change.patch > SHA256SUMS )
}

# Positive control: a step() that ran nothing would pass every other test.
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

test_negative() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc
    out="$(run_harness "$work" bad recipe_fail)"; rc=$?
    local log="$work/logs/t-bad.log" stamp="$work/.stamps/t-bad"

    check "failing recipe: step() propagates a non-zero exit" \
          "$([[ $rc -ne 0 ]] && echo ok)"

    # A step() that never ran the recipe would leave no stamp either.
    check "failing recipe: the recipe really ran" \
          "$(grep -q 'recipe: step 1' "$log" 2>/dev/null && echo ok)"

    check "failing recipe: no command after the failure ran" \
          "$(grep -q 'recipe: step 2 reached' "$log" 2>/dev/null || echo ok)"

    check "failing recipe: left no success stamp" \
          "$([[ ! -f $stamp ]] && echo ok)"

    check "failing recipe: common.sh ERR trap fired and named the line" \
          "$(grep -q 'aborted at' "$log" 2>/dev/null && echo ok)"

    # The checks above also pass if step() died with the recipe: `set +e` does
    # not disable common.sh's exiting ERR trap. These show it lived to report.
    check "failing recipe: step() reports which step failed and where" \
          "$(grep -q 'bad failed. Last .* lines of' <<<"$out" && echo ok)"
    check "failing recipe: step_failure_hint ran" \
          "$(grep -q 'HINT-RAN:bad' <<<"$out" && echo ok)"
    check "failing recipe: the log tail reached the caller" \
          "$(grep -q 'recipe: step 1' <<<"$out" && echo ok)"

    rm -rf "$work"
}

# A changed recipe invalidates its own stamp and no other (a fingerprint of the
# whole stage file would rebuild everything on any change).
test_staleness() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    run_harness "$work" untouched recipe_ver >/dev/null
    run_harness "$work" pkg recipe_ok >/dev/null
    if [[ ! -f "$work/.stamps/t-pkg" || ! -f "$work/.stamps/t-untouched" ]]; then
        red "staleness: setup build did not stamp"; rm -rf "$work"; return
    fi

    # Change the recipe.
    make_harness "$work" 'echo "recipe: an extra command"'

    local out rc
    out="$(run_harness "$work" pkg recipe_ok)"; rc=$?
    check "changed recipe: resume is refused by default" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume onto changed inputs"* ]]; } && echo ok)"

    out="$(KRYPTIK_STALE=rebuild run_harness "$work" pkg recipe_ok)"; rc=$?
    check "changed recipe: KRYPTIK_STALE=rebuild rebuilds" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"rebuilding this step"* ]]; } && echo ok)"

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

    # The runner is in no fingerprint, so the line every recipe runs under
    # changes only with a stamp format bump, and this test with it. A whole
    # line, so a comment quoting the old one cannot stand in for it.
    check "helpers: the line every recipe runs under changes only with the stamp format" \
          "$(grep -qxF '    ( set -Eeuo pipefail; trap _kryptik_trap ERR; "$@" ) > "$logfile" 2>&1' "$ROOT/build/lib/common.sh" \
             && grep -qx 'KRYPTIK_STAMP_FORMAT=4' "$ROOT/build/lib/common.sh" && echo ok)"
    rm -rf "$work"
}

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

    # A version bump must reach recipes that build the filename from V_*, as
    # s_glibc and the stage 05 steps do.
    out="$(sed -i 's/^V_PROBE=1.0/V_PROBE=1.1/' "$work/harness.sh"; run_harness "$work" ver recipe_ver)"; rc=$?
    check "version bump: a recipe that interpolates V_* is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"

    rm -rf "$work"
}

# The skip check must fingerprint the flags after set_flags_for, as the stamp
# does, or a package with a hardening exception (glibc) never skips.
test_per_step_flags() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

    local out rc

    run_harness "$work" ordinary recipe_ok >/dev/null
    out="$(run_harness "$work" ordinary recipe_ok)"; rc=$?
    check "unexcepted step: skips on the second run" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip ordinary"* ]]; } && echo ok)"

    run_harness "$work" excepted recipe_ok >/dev/null
    if [[ ! -f "$work/.stamps/t-excepted" ]]; then
        red "narrowed flags: setup build did not stamp"; rm -rf "$work"; return
    fi
    out="$(run_harness "$work" excepted recipe_ok)"; rc=$?
    check "step with narrowed flags: skips on the second run" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip excepted"* ]]; } && echo ok)"
    check "step with narrowed flags: is not reported stale" \
          "$(grep -q 'Refusing to resume' <<<"$out" && echo "" || echo ok)"

    # CFLAGS_EXTRA is not a fingerprint input, so the step is not refused.
    out="$(CFLAGS_EXTRA=x run_harness "$work" excepted recipe_ok)"; rc=$?
    check "narrowed flags: unchanged inputs still skip" "$([[ $rc -eq 0 ]] && echo ok)"

    rm -rf "$work"
}

# A stamp covers the fingerprints of the steps before it: a change invalidates
# the steps after it and leaves the ones before alone.
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

    # Change the middle step's recipe and rebuild it alone.
    make_harness "$work" 'echo "recipe: an extra command"'
    out="$(KRYPTIK_STALE=rebuild run_harness "$work" zero recipe_ver -- first recipe_ok)"; rc=$?
    check "changed middle step: the step before it still skips" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip zero"* ]]; } && echo ok)"
    check "changed middle step: it is rebuilt" \
          "$([[ $out == *"first: KRYPTIK_STALE=rebuild"* ]] && echo ok)"

    # The step after it: its own inputs are unchanged, but what it was built
    # on is not, so its stamp is refused.
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

# A stage's chain starts from its predecessor's stamp (stage 04 builds with
# stage 02's toolchain): a rebuilt predecessor invalidates it, and a missing
# one stops the stage.
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

    # Documentation beside the patches is not something the step applies.
    echo "what these patches are for" > "$work/patches/probe-set/README.md"
    out="$(run_harness "$work" pat recipe_patch probe-set)"; rc=$?
    check "patch set: a README beside the patches changes nothing" \
          "$({ [[ $rc -eq 0 ]] && [[ $out == *"skip pat"* ]]; } && echo ok)"

    # A different patch, with its record updated: both steps are stale.
    make_patchset "$work" probe-set c
    make_patchset "$work" probe-1.0 c
    out="$(run_harness "$work" pat recipe_patch probe-set)"; rc=$?
    check "changed patch: a step naming the set as an argument is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"
    out="$(run_harness "$work" patv recipe_patch_ver)"; rc=$?
    check "changed patch: a step naming the set in its text is refused" \
          "$({ [[ $rc -ne 0 ]] && [[ $out == *"Refusing to resume"* ]]; } && echo ok)"

    # A patch altered without its record: the rebuild must fail, not apply it.
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

# A stamp with no fingerprint may record a failed build: rebuild the step, and
# keep the old stamp under .stamps/legacy/.
test_legacy_stamp() {
    local work; work="$(mktemp -d)"
    make_harness "$work"

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

# One step(), in common.sh, so a fix cannot land in one stage and miss another.
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

    # Without stage_contract a stage's fingerprints distinguish nothing.
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
