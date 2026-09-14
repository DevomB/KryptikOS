#!/usr/bin/env bash
# End-to-end update, rollback and recovery — for the SYSTEM, not the files.
#
#   ./compartments/tests/update.sh
#
# WHY THIS EXISTS ALONGSIDE tools/test-apply-update.sh, AND WHY THEY MUST NOT
# BE MERGED.
#
# That suite is thorough about the property an update tool must have: a target
# is never a mixture of two releases, and every refusal is checked twice - that
# it refused, and that the target is byte-identical afterwards. It proves those
# over a synthetic payload: a `bin/hello` shell script and an `etc/release`
# file. That is the right payload for what it is testing, because the question
# is about bytes and renames.
#
# It leaves one question unasked, and it is the only one a person actually
# cares about: after the update, does the system DO something different? An
# update mechanism that moves the right bytes into place and leaves the
# machine behaving exactly as before has failed, and no hash comparison can
# tell you so.
#
# So this suite updates a REAL Kryptik tree - the built kryptikd, the `kryptik`
# command, real zone files - and asserts on BEHAVIOUR observed by running the
# INSTALLED binary against the INSTALLED configuration:
#
#   v1 installed  ->  `kryptikd explain gamma` fails: no such zone
#   v2 installed  ->  `kryptikd explain gamma` succeeds
#   rolled back   ->  it fails again
#
# Every refusal below is checked the same way: not "the bytes did not change"
# but "the system still does what it did before".
#
# Nothing here needs root and nothing leaves the temporary directory.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT
unset KRYPTIK_RELEASE_SIGNERS

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/tools/apply-update.sh"
RM="${ROOT}/tools/release-manifest.sh"
# KRYPTIKD, else whichever build exists - release first, then the debug build
# the other suites (and tools/run-tests.sh) produce.
KD="${KRYPTIKD:-}"
if [[ -z "$KD" ]]; then
    for _p in release debug; do
        [[ -x "${ROOT}/compartments/kryptikd/target/${_p}/kryptikd" ]] && { KD="${ROOT}/compartments/kryptikd/target/${_p}/kryptikd"; break; }
    done
fi
KD="${KD:-${ROOT}/compartments/kryptikd/target/release/kryptikd}"

PASS=0; FAIL=0; SKIP=0
C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_0=$'\033[0m'
pass() { printf '%s  PASS%s  %s\n' "$C_G" "$C_0" "$1"; PASS=$((PASS + 1)); }
fail() { printf '%s  FAIL%s  %s\n' "$C_R" "$C_0" "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '%s  SKIP%s  %s\n' "$C_Y" "$C_0" "$1"; SKIP=$((SKIP + 1)); }
info() { printf '        %s\n' "$1"; }
head_() { printf '\n%s==> %s%s\n' $'\033[1m' "$1" "$C_0"; }

# A missing dependency is reported as a skip and an exit code CI understands,
# never as a pass and never as a failure of the thing being tested.
for t in ssh-keygen sha256sum; do
    command -v "$t" >/dev/null 2>&1 || {
        printf 'update.sh: %s is required and is not installed\n' "$t"
        exit 77
    }
done
[[ -x "$KD" ]] || {
    printf 'update.sh: no kryptikd at %s - build it first:\n' "$KD"
    printf '    (cd compartments/kryptikd && cargo build --release)\n'
    exit 77
}

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
OUT="${W}/out"
TARGET="${W}/install"
show() { sed 's/^/        /' "$OUT" | head -12; }

# --- a development signing key, made here and thrown away -------------------
mkdir -p "${W}/keys"
ssh-keygen -q -t ed25519 -N '' -C release -f "${W}/keys/rel" </dev/null
SIGNERS="${W}/keys/allowed_signers"
printf 'release@kryptik.test %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/rel.pub")" > "$SIGNERS"
PRINCIPAL=release@kryptik.test

# --- payloads made of the real thing ----------------------------------------
#
# check_invariants refuses a zone set without exactly one NIC-holding zone, and
# refuses two zones sharing a border colour. Both payloads therefore carry a
# complete, valid zone set rather than a fragment - which is the point: what is
# being installed is a configuration the system would actually start from.
zone() { # name mode colour [extra]
    printf '[zone]\nname = "%s"\ndescription = "update-suite zone"\n' "$1"
    printf '[network]\nmode = "%s"\n' "$2"
    [[ -n "${4:-}" ]] && printf '%s\n' "$4"
    printf '[storage]\nmode = "ephemeral"\nsize = "64M"\n'
    printf '[ui]\nborder_color = "%s"\n' "$3"
}

make_payload() { # dir version with_gamma
    local d="$1" ver="$2" gamma="$3"
    rm -rf "$d"; mkdir -p "${d}/bin" "${d}/etc/kryptik/zones"
    cp "$KD" "${d}/bin/kryptikd"
    [[ -f "${ROOT}/tools/kryptik" ]] && cp "${ROOT}/tools/kryptik" "${d}/bin/kryptik"
    chmod 755 "${d}/bin/"*
    zone alpha   none "#111111" > "${d}/etc/kryptik/zones/alpha.toml"
    zone beta    none "#222222" > "${d}/etc/kryptik/zones/beta.toml"
    zone carrier nic  "#333333" 'bridge = "kryptik0"' > "${d}/etc/kryptik/zones/carrier.toml"
    (( gamma )) && zone gamma none "#444444" > "${d}/etc/kryptik/zones/gamma.toml"
    printf 'VERSION=%s\n' "$ver" > "${d}/etc/kryptik/release"
    return 0
}

sign_payload() { # dir version [role] -> manifest path on stdout
    local d="$1" ver="$2" role="${3:-development}" m="${1}.manifest"
    rm -f "$m" "${m}.sig"
    bash "$RM" create --out "$m" --root "$d" --name kryptik \
        --version "$ver" --role "$role" . >/dev/null 2>&1 || return 1
    bash "$RM" sign --key "${W}/keys/rel" "$m" >/dev/null 2>&1 || return 1
    printf '%s' "$m"
}

# THE behavioural probe. Runs the INSTALLED kryptikd against the INSTALLED
# zone directory, so a wrong answer means the system changed - not that a file
# somewhere has a different hash.
has_gamma() {
    "${TARGET}/bin/kryptikd" explain gamma --zones "${TARGET}/etc/kryptik/zones" \
        >/dev/null 2>&1
}
installed_runs() {
    "${TARGET}/bin/kryptikd" check --zones "${TARGET}/etc/kryptik/zones" >/dev/null 2>&1
}

apply() { # manifest payload [extra args...]
    local m="$1" p="$2"; shift 2
    bash "$TOOL" --manifest="$m" --signers="$SIGNERS" --payload="$p" \
        --target="$TARGET" --principal="$PRINCIPAL" "$@" >"$OUT" 2>&1
}

# Back to a known state: v1 installed, nothing left over.
#
# Not "install v1 over whatever is there" - that is refused, correctly, because
# apply-update will not install a release older than the one already present.
# An earlier version of this file reset by doing exactly that, swallowed the
# refusal, and then reported that ROLLBACK was broken. It was not; the reset
# was. A helper that hides a failure is worse than no helper.
reset_target() {
    rm -rf "$TARGET" "${TARGET}.previous" "${TARGET}.staged"
    apply "$M1" "${W}/v1" && return 0
    fail "could not reset the target to v1 - every check after this is unreliable"
    show
    return 1
}

make_payload "${W}/v1" 1.0.0 0
make_payload "${W}/v2" 2.0.0 1
M1="$(sign_payload "${W}/v1" 1.0.0)" || { echo "could not sign v1"; exit 1; }
M2="$(sign_payload "${W}/v2" 2.0.0)" || { echo "could not sign v2"; exit 1; }

# A third payload, for the interruption section only, padded so that verifying
# and staging it take long enough to be interrupted at all. Without the pad the
# whole update finishes inside a millisecond and every kill lands after it -
# which the suite reports rather than quietly counting as a success.
make_payload "${W}/vbig" 3.0.0 1
dd if=/dev/zero of="${W}/vbig/bin/pad" bs=1M count=64 status=none 2>/dev/null \
    || head -c 67108864 /dev/zero > "${W}/vbig/bin/pad"
MBIG="$(sign_payload "${W}/vbig" 3.0.0)" || { echo "could not sign vbig"; exit 1; }
rm -rf "$TARGET" "${TARGET}.previous" "${TARGET}.staged"

# ============================================================================
head_ "A. The first install produces a system that works"
# ============================================================================
if apply "$M1" "${W}/v1"; then
    pass "A1 v1 installs"
else
    fail "A1 v1 did not install"; show
fi

if installed_runs; then
    pass "A2 the INSTALLED kryptikd validates the INSTALLED zone set"
else
    fail "A2 the installed tree does not work: kryptikd check failed"
    info "$("${TARGET}/bin/kryptikd" check --zones "${TARGET}/etc/kryptik/zones" 2>&1 | head -3)"
fi

# The discriminator every later check depends on. If this passed, nothing below
# could tell v1 from v2.
if has_gamma; then
    fail "A3 v1 already knows the zone only v2 adds - the suite cannot discriminate"
else
    pass "A3 v1 does not know zone 'gamma' (the discriminator works)"
fi

# ============================================================================
head_ "B. An update changes what the system does"
# ============================================================================
if apply "$M2" "${W}/v2"; then
    pass "B1 v2 installs over v1"
else
    fail "B1 v2 did not install"; show
fi

if has_gamma; then
    pass "B2 the installed system now knows zone 'gamma' - the update took effect"
else
    fail "B2 the update installed but the system behaves exactly as before"
    info "this is the failure no hash comparison can detect"
fi

if installed_runs; then
    pass "B3 the updated tree still validates its own zone set"
else
    fail "B3 the update left a tree that does not work"
fi

if bash "$RM" verify --signers "$SIGNERS" --principal "$PRINCIPAL" \
        --root "$TARGET" --exact "$M2" >"$OUT" 2>&1; then
    pass "B4 the installed tree verifies against its own signed manifest, --exact"
else
    fail "B4 the tree that was just installed does not match the manifest it came from"
    show
fi

# ============================================================================
head_ "C. A refusal leaves a system that still works"
# ============================================================================
# Not "the bytes are unchanged" - that is tools/test-apply-update.sh's
# question, and it answers it well. The question here is whether the machine
# still runs, which is what someone whose update failed actually needs.

cp -a "${W}/v2" "${W}/tampered"
printf 'tampered\n' >> "${W}/tampered/etc/kryptik/release"
if apply "$M2" "${W}/tampered"; then
    fail "C1 a payload that does not match its manifest was INSTALLED"
else
    pass "C1 a payload that does not match its signed manifest is refused"
fi
if has_gamma && installed_runs; then
    pass "C2 after the refusal the system still works and is still v2"
else
    fail "C2 a refused update damaged the running system"
fi

if apply "$M2" "${W}/v2" --require-role=production; then
    fail "C3 a development-signed manifest satisfied --require-role=production"
else
    pass "C3 a development-signed manifest is refused for a production role"
fi
if has_gamma && installed_runs; then
    pass "C4 after the role refusal the system still works"
else
    fail "C4 the role refusal damaged the running system"
fi

# ============================================================================
head_ "D. Interruption, and recovery to a COMPLETE release"
# ============================================================================
# Killed at a random point, repeatedly. The two-rename design says the only
# states it can leave are "staged directory present" and "target missing,
# previous present"; this does not assume that, it kills the process and looks.
#
# The bar for recovery is deliberately high: not "a target exists" but "the
# target verifies --exact against the signed manifest of one of the two
# releases, AND the installed kryptikd still validates the installed zones".
# Verifying --exact is the only way to tell a complete release from a partial
# one, and until 06fd2b5 it could not pass on an installed tree at all.
# How long does an uninterrupted one take HERE? Guessing a sleep gets a suite
# that interrupts nothing on a fast machine and times out on a slow one; the
# first attempt at this caught 1 run in 8. Measure once, then kill at fractions
# of the measured time, so the same file works on both.
reset_target
t0=$(date +%s%N)
apply "$MBIG" "${W}/vbig" >/dev/null 2>&1
full_ms=$(( ($(date +%s%N) - t0) / 1000000 ))
(( full_ms > 0 )) || full_ms=1
info "one uninterrupted update of the padded payload takes ${full_ms}ms here"

# A kill lands in one of three observable states, and each is a different
# claim. Lumping them together and calling the ones with nothing left over
# "already finished" - which this file did at first - hides the most common
# outcome and the most reassuring one.
#
#   untouched  killed before anything in the target moved. Nothing to recover;
#              the target must still be the OLD release and still work.
#   staged     killed during the copy into TARGET.staged. The target has still
#              not moved; --status must SAY an interrupted install is there,
#              and clearing it must not touch the target.
#   done       the two renames completed before the kill landed.
#
# There is a fourth state - between the two renames - and this never caught it
# in dozens of attempts. That is the design's central claim ("that window is
# one rename wide"), and not catching it is weak evidence for it, so it is
# reported as not observed rather than as a pass.
untouched=0; staged=0; done_=0; safe=0; attempts=0; status_named=0
window=0; staged_untouched=0
HAVE_SETSID=0
command -v setsid >/dev/null 2>&1 && HAVE_SETSID=1
(( HAVE_SETSID )) || info "no setsid here: the kill cannot reach orphaned children, so these results are weaker"
for i in 1 2 3 4 5 6 7 8 9 10; do
    reset_target || break
    attempts=$((attempts + 1))
    # In its own process group, and the GROUP is killed - not the shell.
    #
    # SIGKILL to apply-update.sh alone leaves its `cp -a` running as an orphan.
    # The copy then finishes after the kill, and a staging directory appears
    # milliseconds after this loop has already decided nothing was staged. Two
    # iterations in ten failed that way, and the failure was entirely this
    # file's: a machine that loses power does not keep copying.
    if (( HAVE_SETSID )); then
        setsid bash "$TOOL" --manifest="$MBIG" --signers="$SIGNERS" --payload="${W}/vbig" \
            --target="$TARGET" --principal="$PRINCIPAL" >"$OUT" 2>&1 &
    else
        bash "$TOOL" --manifest="$MBIG" --signers="$SIGNERS" --payload="${W}/vbig" \
            --target="$TARGET" --principal="$PRINCIPAL" >"$OUT" 2>&1 &
    fi
    victim=$!
    # i/11 of a full run: spread across verification, staging and the swap.
    sleep "$(awk -v m="$full_ms" -v i="$i" 'BEGIN{printf "%.3f", m*i/11/1000}')"
    if (( HAVE_SETSID )); then
        kill -9 -- "-${victim}" 2>/dev/null || kill -9 "$victim" 2>/dev/null
    else
        kill -9 "$victim" 2>/dev/null
    fi
    wait "$victim" 2>/dev/null
    # Nothing of that update may still be running when the state is read.
    while pgrep -g "$victim" >/dev/null 2>&1; do kill -9 -- "-${victim}" 2>/dev/null; done

    # Each state gets the recovery the tool itself documents for it - not
    # --rollback for everything, which is what this did at first. After an
    # interrupted STAGING there is nothing to roll back to and nothing that
    # needs rolling back: the target was never replaced. `--status` says so and
    # exits non-zero, and re-running the same update completes it.
    want="$M1"                      # what the target SHOULD still be
    if [[ ! -d "$TARGET" ]]; then
        # The one-rename window: target already moved aside, staged not yet in
        # place. --rollback is exactly the command for this.
        window=$((window + 1)); want=""
        bash "$TOOL" --target="$TARGET" --rollback >>"$OUT" 2>&1
    elif [[ -d "${TARGET}.staged" ]]; then
        staged=$((staged + 1))
        bash "$TOOL" --target="$TARGET" --status >"$OUT" 2>&1
        sra=$?
        grep -qi 'interrupted' "$OUT" && (( sra != 0 )) && status_named=$((status_named + 1))
        # The target must be untouched RIGHT NOW, before any recovery runs.
        bash "$RM" verify --signers "$SIGNERS" --principal "$PRINCIPAL" \
            --root "$TARGET" --exact "$M1" >/dev/null 2>&1 \
            && staged_untouched=$((staged_untouched + 1))
        # The documented recovery: run the same update again.
        apply "$MBIG" "${W}/vbig" && want="$MBIG"
    elif bash "$RM" verify --signers "$SIGNERS" --principal "$PRINCIPAL" \
            --root "$TARGET" --exact "$MBIG" >/dev/null 2>&1; then
        done_=$((done_ + 1)); want="$MBIG"
    else
        untouched=$((untouched + 1))
    fi

    ok=0
    for m in ${want:-"$M1" "$MBIG"}; do
        if bash "$RM" verify --signers "$SIGNERS" --principal "$PRINCIPAL" \
                --root "$TARGET" --exact "$m" >/dev/null 2>&1; then ok=1; break; fi
    done
    if (( ok )) && installed_runs && [[ ! -d "${TARGET}.staged" ]]; then
        safe=$((safe + 1))
    else
        info "iteration $i: target does not verify --exact, does not run, or left a staging dir"
        left=""; for d in "${TARGET}"*; do [[ -e "$d" ]] && left+="${d##*/} "; done
        info "${left:-nothing}"
    fi
done
if (( safe == attempts )); then
    pass "D1 all $attempts killed updates ended at a complete, working, signed release"
    info "before anything moved: $untouched; mid-staging: $staged; already committed: $done_; between the two renames: $window"
else
    fail "D1 only $safe of $attempts killed updates ended at a complete working release"
fi
if (( staged == 0 )); then
    skip "D2 no kill landed during staging, so --status on an interrupted install is untested here"
else
    if (( status_named == staged )); then
        pass "D2 all $staged interrupted installs were named as interrupted by --status, which exited non-zero"
        info "a script can detect this state, not only a person reading the output"
    else
        fail "D2 $status_named of $staged interrupted installs were reported as interrupted"
        info "an interrupted install that --status does not report is one nobody will recover"
    fi
    if (( staged_untouched == staged )); then
        pass "D3 in all $staged cases the target was still the OLD release, untouched, before any recovery"
        info "which is the whole claim of verify-then-swap: the running system is not at risk while an update is being staged"
    else
        fail "D3 $staged_untouched of $staged interrupted stagings left the target intact"
    fi
fi
if (( untouched > 0 )); then
    pass "D4 $untouched kills landed before the target moved and left it untouched and working"
    info "the largest window in an update is the one in which nothing has happened yet"
else
    skip "D4 no kill landed before the target moved"
fi
if (( window == 0 )); then
    skip "D5 no kill landed between the two renames - the window the design calls one rename wide"
    info "not catching it in $attempts tries is weak evidence for that claim, and is reported as such rather than as a pass"
else
    pass "D5 $window kill(s) landed between the two renames and --rollback recovered every one"
fi

# ============================================================================
head_ "E. Rollback returns the system, not just the files"
# ============================================================================
reset_target
if apply "$M2" "${W}/v2"; then
    if bash "$TOOL" --target="$TARGET" --rollback >"$OUT" 2>&1; then
        pass "E1 rollback reports success"
    else
        fail "E1 rollback failed"; show
    fi
    if has_gamma; then
        fail "E2 after rollback the system still behaves like v2"
    else
        pass "E2 after rollback the system behaves like v1 again"
    fi
    if installed_runs; then
        pass "E3 the rolled-back tree still validates its own zone set"
    else
        fail "E3 rollback left a tree that does not work"
    fi
    if bash "$RM" verify --signers "$SIGNERS" --principal "$PRINCIPAL" \
            --root "$TARGET" --exact "$M1" >"$OUT" 2>&1; then
        pass "E4 the rolled-back tree verifies --exact against v1's signed manifest"
        info "which is what distinguishes a complete rollback from a partial one"
    else
        fail "E4 the rolled-back tree does not match v1's manifest"; show
    fi
else
    fail "E1 could not install v2 to roll it back"
fi


# ============================================================================
head_ "F. An older release is not installed just because it is signed"
# ============================================================================
# This suite learned this one the hard way: an earlier version of it reset
# state by installing v1 over v2, had that refused, swallowed the message, and
# then reported that rollback was broken. The refusal is the feature - a
# correctly signed OLD release is exactly what an attacker who can replay
# traffic has - so it gets a check of its own rather than being something the
# suite works around.
reset_target
if apply "$M2" "${W}/v2"; then
    if apply "$M1" "${W}/v1"; then
        fail "F1 an older signed release was installed over a newer one"
    else
        pass "F1 an older signed release is refused over a newer one"
        if grep -qi 'downgrade' "$OUT"; then
            pass "F2 the refusal says it is a downgrade, not just that it failed"
        else
            fail "F2 the refusal did not name the reason"
            show
        fi
    fi
    if has_gamma && installed_runs; then
        pass "F3 after the downgrade refusal the system is still the newer release, and works"
    else
        fail "F3 the downgrade refusal damaged the running system"
    fi
else
    fail "F1 could not install v2 to try downgrading from it"
fi

printf '\n%s%d passed, %d failed, %d not run%s\n' $'\033[1m' "$PASS" "$FAIL" "$SKIP" "$C_0"
(( FAIL == 0 )) || exit 1
exit 0
