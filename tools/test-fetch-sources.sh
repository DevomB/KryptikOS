#!/usr/bin/env bash
# Focused tests for tools/fetch-sources.sh.
#
#   ./tools/test-fetch-sources.sh
#
# Deterministic and offline: a small substituted manifest of file:// URLs, so
# the download path, the hashing and the refusal all run exactly as they do in
# production against a real curl and a real sha256.
#
# WHY THIS EXISTS.
#
# fetch-sources.sh is the tool that gives sources.lock its force. The claim in
# docs/supply-chain.md is that it "refuses to proceed on a mismatch — it does
# not warn and continue", and until now that claim had no regression check
# anywhere. Every other assertion in this tree got one tonight; the one that
# stops a tampered tarball from being built should not be the exception.
#
# The cases are the ones where "continue anyway" would be a plausible bug:
# a hash that does not match, a file with no lock entry at all, and a download
# that failed. Each must exit non-zero, and each must say which file.

set -uo pipefail

# See the same note in the other suites: common.sh prefers these over anything
# derived from KRYPTIK_ROOT.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/fetch-sources.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in curl sha256sum sort; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }

UPSTREAM="${W}/upstream"      # what the "mirror" serves
FAKE="${W}/root"              # KRYPTIK_ROOT for the run
mkdir -p "$UPSTREAM"

# 4KB each, deliberately. A "same length, wrong bytes" partial needs a file
# long enough for a prefix to exist; a 30-byte payload made every partial
# longer than the file it was supposedly a partial of, which is a different
# case entirely.
for f in alpha-1.0 beta-2.0 gamma-3.0; do
    { printf 'upstream payload for %s\n' "$f"
      head -c 4096 /dev/urandom | base64 | head -c 4000
      printf '\n'; } > "${UPSTREAM}/${f}.tar.gz"
done

MANIFEST="${W}/manifest"
{
    printf 'alpha|1.0|file://%s/alpha-1.0.tar.gz\n' "$UPSTREAM"
    printf 'beta|2.0|file://%s/beta-2.0.tar.gz\n'   "$UPSTREAM"
    printf 'gamma|3.0|file://%s/gamma-3.0.tar.gz\n' "$UPSTREAM"
} > "$MANIFEST"

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

# build_root <lock-spec>...
#   each spec is name-ver:good|bad|absent  (absent = no lock entry)
build_root() {
    rm -rf "$FAKE"
    mkdir -p "${FAKE}/build/config" "${FAKE}/sources"
    : > "${FAKE}/build/config/versions.env"
    : > "${FAKE}/sources.lock"
    local spec f kind
    for spec in "$@"; do
        f="${spec%%:*}"; kind="${spec##*:}"
        case "$kind" in
            good) printf '%s  %s.tar.gz\n' "$(sha_of "${UPSTREAM}/${f}.tar.gz")" "$f" \
                      >> "${FAKE}/sources.lock" ;;
            bad)  printf '%s  %s.tar.gz\n' \
                      0000000000000000000000000000000000000000000000000000000000000000 \
                      "$f" >> "${FAKE}/sources.lock" ;;
            absent) : ;;
        esac
    done
}

# Pre-place a downloaded copy in sources/, optionally tampered.
place() {  # place <name-ver> [tampered]
    cp "${UPSTREAM}/$1.tar.gz" "${FAKE}/sources/$1.tar.gz"
    [[ "${2:-}" == tampered ]] && printf 'tampered\n' >> "${FAKE}/sources/$1.tar.gz"
    return 0
}

run() {
    KRYPTIK_ROOT="$FAKE" \
    KRYPTIK_FETCH_SELFTEST=1 \
    KRYPTIK_FETCH_MANIFEST="$MANIFEST" \
    NO_COLOR=1 \
    bash "$TOOL" "$@" > "$OUT" 2>&1
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

echo "tools/fetch-sources.sh"
echo

# ---------------------------------------------------------------------------
# positive controls
# ---------------------------------------------------------------------------

build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place alpha-1.0; place beta-2.0; place gamma-3.0
run
expect_pass "an already-downloaded, matching set verifies" "3 package(s) verified"

# Nothing on disk: it must fetch, then verify what it fetched.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
run
expect_pass "an empty sources/ is downloaded and then verified" "3 downloaded"
if [[ -f "${FAKE}/sources/alpha-1.0.tar.gz" ]]; then
    green "the downloaded file is left in sources/"
else
    red "the download did not land in sources/"
fi

run
expect_pass "a second run uses the cached copies" "3 cached"

# ---------------------------------------------------------------------------
# the refusal that sources.lock exists for
# ---------------------------------------------------------------------------

build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place alpha-1.0; place beta-2.0 tampered; place gamma-3.0
run
expect_fail "a tampered download is refused" "CHECKSUM MISMATCH for beta-2.0.tar.gz"
if grep -qF "CHANGED after it was locked" "$OUT" && grep -qF "Do not" "$OUT"; then
    green "the refusal says it is refusing, and which kind of mismatch it is"
else
    red "the mismatch did not produce a refusal message"; show
fi
if grep -qF "3 package(s) verified" "$OUT"; then
    red "it reported a verified count despite the mismatch"; show
else
    green "no verified summary is printed after a mismatch"
fi

# The mismatching file must still be there for a human to look at, and the
# message must name it.
if [[ -f "${FAKE}/sources/beta-2.0.tar.gz" ]] && grep -qF "beta-2.0.tar.gz" "$OUT"; then
    green "the offending file is named and left in place for inspection"
else
    red "the offending file was removed or not named"; show
fi

# A lock entry that does not exist at all is not a pass either.
build_root alpha-1.0:good beta-2.0:absent gamma-3.0:good
place alpha-1.0; place beta-2.0; place gamma-3.0
run
expect_fail "a file with no lock entry is refused" \
    "no entry for beta-2.0.tar.gz in sources.lock"

# An entirely missing lock file must not read as "nothing to check".
build_root alpha-1.0:absent beta-2.0:absent gamma-3.0:absent
rm -f "${FAKE}/sources.lock"
place alpha-1.0
run
expect_fail "a missing sources.lock is refused" "no entry for"

# A download that cannot happen is a failure, not an empty success.
cat > "${W}/dead-manifest" <<EOF
alpha|1.0|file://${UPSTREAM}/alpha-1.0.tar.gz
missing|9.9|file://${UPSTREAM}/does-not-exist.tar.gz
EOF
build_root alpha-1.0:good
printf '%s  missing-9.9.tar.gz\n' \
    0000000000000000000000000000000000000000000000000000000000000000 \
    >> "${FAKE}/sources.lock"
KRYPTIK_ROOT="$FAKE" KRYPTIK_FETCH_SELFTEST=1 \
    KRYPTIK_FETCH_MANIFEST="${W}/dead-manifest" NO_COLOR=1 \
    bash "$TOOL" > "$OUT" 2>&1
RC=$?
expect_fail "an unfetchable source is refused" "download failed"

# ---------------------------------------------------------------------------
# interrupted downloads
# ---------------------------------------------------------------------------
#
# `-C -` asks the server to continue from the size of the local .part. Three
# states of that file behave differently and all three used to be untested.

part() { printf '%s' "${FAKE}/sources/$1.tar.gz.part"; }

# A genuine interruption: a prefix of the real file. Resuming is the point of
# keeping it, so this must complete and verify.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place beta-2.0; place gamma-3.0
head -c 1500 "${UPSTREAM}/alpha-1.0.tar.gz" > "$(part alpha-1.0)"
run
expect_pass "a truncated partial file is resumed and verifies" "3 package(s) verified"
if [[ ! -e "$(part alpha-1.0)" ]]; then
    green "the partial file is consumed, not left behind"
else
    red "a .part survived a successful download"
fi

# A partial LONGER than the upstream file makes the range unsatisfiable: curl
# exits 36 on file:// and 33/416 over HTTP. This used to be reported as a dead
# mirror and then reproduced itself on every retry, because the file keeping it
# broken was the one the error message promised to keep.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place beta-2.0; place gamma-3.0
head -c 100000 /dev/zero > "$(part alpha-1.0)"
run
expect_pass "an over-long stale partial is discarded and the fetch restarts" \
    "3 package(s) verified"
if grep -qF "discarding the partial file" "$OUT"; then
    green "the restart says why it happened rather than blaming the mirror"
else
    red "the over-long partial was handled without explanation"; show
fi
if [[ "$(sha_of "${FAKE}/sources/alpha-1.0.tar.gz")" == "$(sha_of "${UPSTREAM}/alpha-1.0.tar.gz")" ]]; then
    green "the restarted download produced the correct bytes"
else
    red "the restarted download produced wrong bytes"
fi

# A partial that is the right length but the wrong bytes cannot be detected by
# resuming - the range is satisfiable and the result is a corrupt file. The
# checksum is what catches it, and the message must say the DOWNLOAD is wrong
# rather than implying the disk changed under them.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place beta-2.0; place gamma-3.0
# Shorter than upstream, so the range IS satisfiable and the resume succeeds
# into a corrupt file. Only the checksum can catch this one.
head -c 1500 /dev/zero > "$(part alpha-1.0)"
run
expect_fail "a poisoned partial is caught by the checksum, not by the resume" \
    "CHECKSUM MISMATCH for alpha-1.0.tar.gz"
if grep -qF "downloaded just now" "$OUT" && grep -qF ".part" "$OUT"; then
    green "a fresh download's mismatch blames the download and names the .part"
else
    red "the fresh-download mismatch did not diagnose itself"; show
fi

# The same mismatch on a file that was ALREADY on disk is a different fact and
# must read differently: nothing was fetched, so the file changed after it was
# locked.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place alpha-1.0 tampered; place beta-2.0; place gamma-3.0
run
expect_fail "a cached mismatch is diagnosed as a change after locking" \
    "CHANGED after it was locked"
if grep -qF "Do not" "$OUT" && ! grep -qF "downloaded just now" "$OUT"; then
    green "the cached mismatch does not tell them to delete it first"
else
    red "the cached mismatch used the fresh-download wording"; show
fi

# Neither diagnosis deletes anything: a hash that does not match is evidence.
if [[ -f "${FAKE}/sources/alpha-1.0.tar.gz" ]]; then
    green "the mismatching file is preserved for inspection"
else
    red "the mismatching file was deleted"
fi

# ---------------------------------------------------------------------------
# --lock
# ---------------------------------------------------------------------------

build_root alpha-1.0:absent
place alpha-1.0; place beta-2.0; place gamma-3.0
run --lock
expect_pass "--lock records what it downloaded" "wrote 3 entries"

if grep -qF "NOT YET AUDITED" "$OUT"; then
    green "--lock says the result is unaudited"
else
    red "--lock did not warn that the lock is unaudited"; show
fi

# The written lock must actually verify afterwards, and be sorted so a diff of
# two locks is readable.
run
expect_pass "the lock --lock wrote then verifies" "3 package(s) verified"

if [[ "$(cut -d' ' -f3 "${FAKE}/sources.lock")" == \
      "$(cut -d' ' -f3 "${FAKE}/sources.lock" | LC_ALL=C sort)" ]]; then
    green "the written lock is sorted by filename"
else
    red "the written lock is not sorted"
    sed 's/^/        /' "${FAKE}/sources.lock"
fi

# --lock records whatever is on disk, tampered or not. That is by design and
# documented; the test pins it so nobody mistakes --lock for verification.
build_root alpha-1.0:absent
place alpha-1.0 tampered; place beta-2.0; place gamma-3.0
run --lock
if [[ "$RC" -eq 0 ]] \
   && grep -qF "Lock mode: recording checksums of whatever downloads" "$OUT"; then
    green "KNOWN BY DESIGN: --lock records a tampered file and says so"
else
    red "--lock did not state that it records whatever is present"; show
fi

# ---------------------------------------------------------------------------
# arguments and the selftest gate
# ---------------------------------------------------------------------------

run --list
expect_pass "--list prints the manifest without downloading" "alpha"

run --nonsense
expect_fail "an unknown argument is refused" "unknown argument"

build_root alpha-1.0:good
KRYPTIK_ROOT="$FAKE" KRYPTIK_FETCH_MANIFEST="$MANIFEST" NO_COLOR=1 \
    bash "$TOOL" --list > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to fetch or lock" "$OUT"; then
    green "a substituted manifest is refused without the selftest flag"
else
    red "a substituted manifest was accepted without the flag (exit ${rc})"; show
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
