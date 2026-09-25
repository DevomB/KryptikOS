#!/usr/bin/env bash
# Tests for tools/fetch-sources.sh. Offline: a substituted manifest of file://
# URLs, fetched and hashed by the real curl and sha256sum.

set -uo pipefail

# common.sh prefers these over paths derived from KRYPTIK_ROOT, so an exported
# one would point the tool at the real tree.
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

# About 4KB each, so the 1500-byte partials below are shorter than the file.
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

# --- positive controls ------------------------------------------------------

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

# --- checksum refusal -------------------------------------------------------

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

if [[ -f "${FAKE}/sources/beta-2.0.tar.gz" ]] && grep -qF "beta-2.0.tar.gz" "$OUT"; then
    green "the offending file is named and left in place for inspection"
else
    red "the offending file was removed or not named"; show
fi

build_root alpha-1.0:good beta-2.0:absent gamma-3.0:good
place alpha-1.0; place beta-2.0; place gamma-3.0
run
expect_fail "a file with no lock entry is refused" \
    "no entry for beta-2.0.tar.gz in sources.lock"

build_root alpha-1.0:absent beta-2.0:absent gamma-3.0:absent
rm -f "${FAKE}/sources.lock"
place alpha-1.0
run
expect_fail "a missing sources.lock is refused" "no entry for"

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

# --- interrupted downloads --------------------------------------------------

# Three kinds of leftover .part, which `-C -` resumes from.
part() { printf '%s' "${FAKE}/sources/$1.tar.gz.part"; }

# A genuine interruption: a prefix of the real file.
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

# Longer than the upstream file, so the range is unsatisfiable (curl exits 36
# on file://, 33/416 over HTTP).
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

# Wrong bytes, shorter than upstream: the resume succeeds into a corrupt file
# that only the checksum catches, and the message must blame the download.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place beta-2.0; place gamma-3.0
head -c 1500 /dev/zero > "$(part alpha-1.0)"
run
expect_fail "a poisoned partial is caught by the checksum, not by the resume" \
    "CHECKSUM MISMATCH for alpha-1.0.tar.gz"
if grep -qF "downloaded just now" "$OUT" && grep -qF ".part" "$OUT"; then
    green "a fresh download's mismatch blames the download and names the .part"
else
    red "the fresh-download mismatch did not diagnose itself"; show
fi

# The same mismatch on a file already on disk: it changed after locking.
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

if [[ -f "${FAKE}/sources/alpha-1.0.tar.gz" ]]; then
    green "the mismatching file is preserved for inspection"
else
    red "the mismatching file was deleted"
fi

# --- --lock -----------------------------------------------------------------

build_root alpha-1.0:absent
place alpha-1.0; place beta-2.0; place gamma-3.0
run --lock
expect_pass "--lock records what it downloaded" "wrote 3 entries"

if grep -qF "NOT YET AUDITED" "$OUT"; then
    green "--lock says the result is unaudited"
else
    red "--lock did not warn that the lock is unaudited"; show
fi

# The written lock must verify, and be sorted so lock diffs are readable.
run
expect_pass "the lock --lock wrote then verifies" "3 package(s) verified"

if [[ "$(cut -d' ' -f3 "${FAKE}/sources.lock")" == \
      "$(cut -d' ' -f3 "${FAKE}/sources.lock" | LC_ALL=C sort)" ]]; then
    green "the written lock is sorted by filename"
else
    red "the written lock is not sorted"
    sed 's/^/        /' "${FAKE}/sources.lock"
fi

# By design, --lock records whatever is on disk, tampered or not.
build_root alpha-1.0:absent
place alpha-1.0 tampered; place beta-2.0; place gamma-3.0
run --lock
if [[ "$RC" -eq 0 ]] \
   && grep -qF "Lock mode: recording checksums of whatever downloads" "$OUT"; then
    green "KNOWN BY DESIGN: --lock records a tampered file and says so"
else
    red "--lock did not state that it records whatever is present"; show
fi

# --- arguments and the selftest gate ----------------------------------------

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

# --- the shipped manifest and the shipped lockfile must agree ---------------

# A row with no lock line is refused at fetch time; a lock line with no row is
# a hash nobody checks. --list expands version defaults (gdbm's) as well.
bash "$TOOL" --list > "${W}/live-manifest" 2>/dev/null
awk '{n = $3; sub(/.*\//, "", n); print n}' "${W}/live-manifest" | sort -u > "${W}/mf"
awk '{print $2}' "${ROOT}/sources.lock" | sort -u > "${W}/lk"

miss="$(comm -23 "${W}/mf" "${W}/lk" | tr '
' ' ')"
if [[ -z "${miss// /}" ]]; then
    green "every source in the manifest has a sources.lock entry"
else
    red "manifest rows with no lock entry: ${miss}"
fi

stale="$(comm -13 "${W}/mf" "${W}/lk" | tr '
' ' ')"
if [[ -z "${stale// /}" ]]; then
    green "every sources.lock entry corresponds to a manifest row"
else
    red "lock entries with no manifest row: ${stale}"
fi

# An unset version with no default gives a URL like gdbm-.tar.gz: a quiet 404.
blank="$(awk 'NF < 3 || $2 == "" {print $1}' "${W}/live-manifest" | tr '
' ' ')"
if [[ -z "${blank// /}" ]]; then
    green "no manifest row resolves to an empty version"
else
    red "manifest rows resolving to an empty version: ${blank}"
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
