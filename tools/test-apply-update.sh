#!/usr/bin/env bash
# Focused tests for tools/apply-update.sh — the M6 update and recovery
# acceptance checks.
#
#   ./tools/test-apply-update.sh
#
# Deterministic and offline, with real OpenSSH signatures over real files.
#
# The property under test is the one that matters for an update tool: a target
# is never a mixture of two releases. Every refusal is therefore checked twice
# — that it refused, and that the target is byte-identical to what it was
# before — because "refused" and "refused without damage" are different
# claims and only the second one is useful.
#
# The interrupted-install states are tested by their observable form rather
# than by racing a copy: a staging directory left behind (interrupted before
# the swap) and a target missing with a previous release present (interrupted
# between the two renames). Those are the only two states the two-rename
# design can leave, which is the point of using it.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT
unset KRYPTIK_RELEASE_SIGNERS

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/apply-update.sh"
RM="${ROOT}/tools/release-manifest.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in ssh-keygen sha256sum; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }

FAKE="${W}/root"
mkdir -p "${FAKE}/build/config"
: > "${FAKE}/build/config/versions.env"

# --- keys -------------------------------------------------------------------

mkdir -p "${W}/keys"
ssh-keygen -q -t ed25519 -N '' -C release  -f "${W}/keys/rel" </dev/null
ssh-keygen -q -t ed25519 -N '' -C outsider -f "${W}/keys/out" </dev/null
SIGNERS="${W}/keys/allowed_signers"
printf 'release@kryptik.test %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/rel.pub")" \
    > "$SIGNERS"

TARGET="${W}/install"
PREV="${TARGET}.previous"
STAGED="${TARGET}.staged"

# --- payload builders -------------------------------------------------------

# make_payload <dir> <version> <marker-text>
make_payload() {
    local d="$1" ver="$2" marker="$3"
    rm -rf "$d"
    mkdir -p "${d}/bin" "${d}/etc"
    printf '#!/bin/sh\necho %s\n' "$marker" > "${d}/bin/hello"
    chmod 755 "${d}/bin/hello"
    printf 'VERSION=%s\nMARKER=%s\n' "$ver" "$marker" > "${d}/etc/release"
}

# sign_payload <dir> <version> [role] -> manifest path
sign_payload() {
    local d="$1" ver="$2" role="${3:-development}"
    local m="${d}.manifest"
    rm -f "$m" "${m}.sig"
    bash "$RM" create --out "$m" --root "$d" --name kryptik \
        --version "$ver" --role "$role" . > /dev/null 2>&1
    bash "$RM" sign --key "${W}/keys/rel" "$m" > /dev/null 2>&1
    printf '%s' "$m"
}

# A hash of the whole target tree, so "untouched" can be asserted rather than
# eyeballed.
tree_hash() {
    [[ -d "$1" ]] || { printf 'ABSENT'; return; }
    ( cd "$1" && find . -type f ! -name '.kryptik-update' -print0 \
        | LC_ALL=C sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum ) \
        | cut -d' ' -f1
}

run() {
    KRYPTIK_ROOT="$FAKE" NO_COLOR=1 bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

expect_pass() {
    local name="$1" want="$2"
    if [[ "$RC" -ne 0 ]]; then red "${name}: expected exit 0, got ${RC}"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: exit 0 but output lacks [${want}]"; show
    else green "$name"; fi
}

expect_fail() {
    local name="$1" want="$2"
    if [[ "$RC" -eq 0 ]]; then red "${name}: PASSED when it should have failed"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: failed, but not for the stated reason [${want}]"; show
    else green "$name"; fi
}

untouched() {   # untouched <name> <hash-before>
    if [[ "$(tree_hash "$TARGET")" == "$2" ]]; then
        green "$1"
    else
        red "$1: the target changed despite the refusal"
    fi
}

echo "tools/apply-update.sh"
echo

# ---------------------------------------------------------------------------
# positive control: a verified update installs
# ---------------------------------------------------------------------------

rm -rf "$TARGET" "$PREV" "$STAGED"
make_payload "${W}/p1" 1.0 first
M1="$(sign_payload "${W}/p1" 1.0)"
run --manifest="$M1" --signers="$SIGNERS" --payload="${W}/p1" \
    --target="$TARGET" --principal=release@kryptik.test
expect_pass "a verified update installs" "installed version 1.0"

if [[ -f "${TARGET}/bin/hello" ]] && grep -q first "${TARGET}/etc/release"; then
    green "the target holds the new payload"
else
    red "the target does not hold the payload"
fi
if [[ "$(tree_hash "$TARGET")" == "$(tree_hash "${W}/p1")" ]]; then
    green "the installed tree is identical to the verified payload"
else
    red "the installed tree differs from the payload"
fi
run --target="$TARGET" --status
expect_pass "status reports the installed version" "version 1.0"

# ---------------------------------------------------------------------------
# a second update keeps the previous release
# ---------------------------------------------------------------------------

make_payload "${W}/p2" 2.0 second
M2="$(sign_payload "${W}/p2" 2.0)"
run --manifest="$M2" --signers="$SIGNERS" --payload="${W}/p2" \
    --target="$TARGET" --principal=release@kryptik.test
expect_pass "a second update installs" "installed version 2.0"
if [[ -d "$PREV" ]] && grep -q first "${PREV}/etc/release"; then
    green "the previous release is kept for rollback"
else
    red "the previous release was not kept"
fi

# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------

run --target="$TARGET" --rollback
expect_pass "rollback restores the previous release" "rolled back to 1.0"
if grep -q first "${TARGET}/etc/release"; then
    green "the restored tree is the earlier payload"
else
    red "rollback did not restore the earlier contents"
fi

run --target="$TARGET" --rollback
expect_fail "rollback with nothing kept is refused" "nothing kept"

# ---------------------------------------------------------------------------
# every refusal leaves the target alone
# ---------------------------------------------------------------------------

# Reinstall 2.0 as the baseline for the refusal cases.
make_payload "${W}/p2" 2.0 second
M2="$(sign_payload "${W}/p2" 2.0)"
run --manifest="$M2" --signers="$SIGNERS" --payload="${W}/p2" \
    --target="$TARGET" --principal=release@kryptik.test
BASE="$(tree_hash "$TARGET")"

# Signed by a key that is not enrolled.
make_payload "${W}/p3" 3.0 third
M3="${W}/p3.manifest"
bash "$RM" create --out "$M3" --root "${W}/p3" --version 3.0 \
    --role development . > /dev/null 2>&1
bash "$RM" sign --key "${W}/keys/out" "$M3" > /dev/null 2>&1
run --manifest="$M3" --signers="$SIGNERS" --payload="${W}/p3" --target="$TARGET"
expect_fail "an update signed by an unenrolled key is refused" \
    "does not match its signed manifest"
untouched "and the target is untouched after that refusal" "$BASE"

# A payload altered after signing.
make_payload "${W}/p4" 4.0 fourth
M4="$(sign_payload "${W}/p4" 4.0)"
printf 'backdoor\n' >> "${W}/p4/bin/hello"
run --manifest="$M4" --signers="$SIGNERS" --payload="${W}/p4" --target="$TARGET"
expect_fail "an altered payload is refused" "does not match its signed manifest"
untouched "and the target is untouched after that refusal" "$BASE"

# An extra file the manifest does not list.
make_payload "${W}/p5" 5.0 fifth
M5="$(sign_payload "${W}/p5" 5.0)"
printf 'extra\n' > "${W}/p5/bin/stowaway"
run --manifest="$M5" --signers="$SIGNERS" --payload="${W}/p5" --target="$TARGET"
expect_fail "a payload carrying an unlisted file is refused" \
    "does not match its signed manifest"
untouched "and the target is untouched after that refusal" "$BASE"

# A replayed older release.
make_payload "${W}/p0" 0.9 ancient
M0="$(sign_payload "${W}/p0" 0.9)"
run --manifest="$M0" --signers="$SIGNERS" --payload="${W}/p0" --target="$TARGET"
expect_fail "a replayed older release is refused" "does not match its signed manifest"
untouched "and the target is untouched after that refusal" "$BASE"
if grep -qF "older than the installed" "$OUT"; then
    green "the downgrade refusal names the reason"
else
    red "the downgrade was refused for the wrong reason"; show
fi

# A development manifest where production was required.
make_payload "${W}/p6" 6.0 sixth
M6="$(sign_payload "${W}/p6" 6.0 development)"
run --manifest="$M6" --signers="$SIGNERS" --payload="${W}/p6" \
    --target="$TARGET" --require-role=production
expect_fail "a development update is refused where production is required" \
    "does not match its signed manifest"
untouched "and the target is untouched after that refusal" "$BASE"

# ---------------------------------------------------------------------------
# compatibility
# ---------------------------------------------------------------------------

make_payload "${W}/p7" 7.0 seventh
M7="$(sign_payload "${W}/p7" 7.0)"
run --manifest="$M7" --signers="$SIGNERS" --payload="${W}/p7" \
    --target="$TARGET" --expect-current=1.0
expect_fail "an update for a different installed version is refused" \
    "expects the installed version to be 1.0"
untouched "and the target is untouched after that refusal" "$BASE"

run --manifest="$M7" --signers="$SIGNERS" --payload="${W}/p7" \
    --target="$TARGET" --expect-current=2.0 --principal=release@kryptik.test
expect_pass "an update for the installed version proceeds" "installed version 7.0"

# ---------------------------------------------------------------------------
# --dry-run verifies and installs nothing
# ---------------------------------------------------------------------------

BASE="$(tree_hash "$TARGET")"
make_payload "${W}/p8" 8.0 eighth
M8="$(sign_payload "${W}/p8" 8.0)"
run --manifest="$M8" --signers="$SIGNERS" --payload="${W}/p8" \
    --target="$TARGET" --dry-run
expect_pass "--dry-run verifies without installing" "verified only"
untouched "and --dry-run leaves the target untouched" "$BASE"

# ---------------------------------------------------------------------------
# interrupted installs: the only two states the design can leave
# ---------------------------------------------------------------------------

# (a) Interrupted BEFORE the swap: a staging directory survives and the target
#     is still the old release.
rm -rf "$STAGED"
cp -a "${W}/p8" "$STAGED"
run --target="$TARGET" --status
if [[ "$RC" -eq 2 ]] && grep -qF "INTERRUPTED install" "$OUT"; then
    green "status detects an interrupted install and exits 2"
else
    red "an interrupted install was not detected (exit ${RC})"; show
fi
if grep -qF "target was not replaced" "$OUT"; then
    green "and says the target was not replaced"
else
    red "status did not say the target survived"; show
fi

BASE="$(tree_hash "$TARGET")"
run --manifest="$M8" --signers="$SIGNERS" --payload="${W}/p8" \
    --target="$TARGET" --principal=release@kryptik.test
expect_pass "re-running the update discards the stale staging directory" \
    "discarding a staging directory"
if [[ ! -d "$STAGED" ]]; then
    green "no staging directory survives a completed install"
else
    red "a staging directory was left behind"
fi

# (b) Interrupted BETWEEN the two renames: the target is gone and the previous
#     release is present. This is the one-rename-wide window, and it must be
#     recoverable rather than terminal.
rm -rf "$PREV"
mv "$TARGET" "$PREV"
run --target="$TARGET" --status
if [[ "$RC" -eq 0 ]] && grep -qF "no target at" "$OUT" \
   && grep -qF "previous release kept" "$OUT"; then
    green "status reports a missing target with a recoverable previous release"
else
    red "the mid-rename state was not reported usefully (exit ${RC})"; show
fi
run --target="$TARGET" --rollback
expect_pass "rollback recovers from an interruption between the renames" \
    "rolled back to"
if [[ -f "${TARGET}/bin/hello" ]]; then
    green "and the recovered target is a complete tree"
else
    red "the recovered target is incomplete"
fi

# ---------------------------------------------------------------------------
# a verifier that cannot run has not produced a verification result
# ---------------------------------------------------------------------------
#
# The = form of --signers once made release-manifest.sh die with "unknown
# option", which apply-update.sh reported as "does not match its signed
# manifest" - a verification failure nobody had established. A tool that
# cannot tell those apart will eventually blame a good payload.

make_payload "${W}/pv" 20.0 twentieth
MV="$(sign_payload "${W}/pv" 20.0)"
BASE="$(tree_hash "$TARGET")"
# A signers path that does not exist makes the verifier refuse to start.
run --manifest="$MV" --signers="${W}/no-such-signers" --payload="${W}/pv"     --target="$TARGET"
expect_fail "a verifier that cannot run is reported as a tooling fault"     "tooling fault, not a"
if grep -qF "has NOT been shown to be bad" "$OUT"; then
    green "and it says the payload was not shown to be bad"
else
    red "the tooling fault was reported as a bad payload"; show
fi
untouched "and the target is untouched" "$BASE"

# ---------------------------------------------------------------------------
# no default trust anchor, and nothing installs without a manifest
# ---------------------------------------------------------------------------

make_payload "${W}/p9" 9.0 ninth
M9="$(sign_payload "${W}/p9" 9.0)"
BASE="$(tree_hash "$TARGET")"
run --manifest="$M9" --payload="${W}/p9" --target="$TARGET"
expect_fail "installing without --signers is refused" "no default trust anchor"
untouched "and the target is untouched" "$BASE"

run --payload="${W}/p9" --signers="$SIGNERS" --target="$TARGET"
expect_fail "installing without a manifest is refused" "--manifest"
untouched "and the target is untouched" "$BASE"

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
