#!/usr/bin/env bash
# Focused tests for tools/check-pin-reviews.sh.
#
#   ./tools/test-check-pin-reviews.sh
#
# Offline and deterministic: the tool reads a survey file and a reviews file,
# so both are written here and the date is fixed with --today.
#
# The cases that matter are the ones where a list quietly stops being a gate:
# a review of a version that is no longer the pin, a review that upstream has
# since released past, a review too old to trust, a row with no reason, and a
# row left behind for a pin that has caught up.

set -uo pipefail

# See the same note in the other suites.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/check-pin-reviews.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
OUT="${W}/out"
show() { sed 's/^/        /' "$OUT"; }

# survey NAME PINNED NEWEST STATUS ...: one row per five arguments.
survey() {
    : > "${W}/survey.tsv"
    while [[ $# -ge 4 ]]; do
        printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "https://example.invalid/$1/" >> "${W}/survey.tsv"
        shift 4
    done
}
reviews() { printf '%s\n' "$@" > "${W}/reviews.tsv"; }
run() { NO_COLOR=1 "$TOOL" --survey "${W}/survey.tsv" --reviews "${W}/reviews.tsv" --today 2026-09-19 "$@" > "$OUT" 2>&1; RC=$?; }

# expect NAME WANT_RC REGEX...: the exit status, and every regex present.
expect() {
    local name="$1" want="$2"; shift 2
    local good=1 rx
    [[ "$RC" -eq "$want" ]] || good=0
    for rx in "$@"; do grep -qE -- "$rx" "$OUT" || good=0; done
    if [[ "$good" -eq 1 ]]; then green "$name"; else red "${name} (exit ${RC}, wanted ${want})"; show; fi
}
# absent NAME REGEX: the regex must not appear.
absent() { if grep -qE -- "$2" "$OUT"; then red "$1"; show; else green "$1"; fi; }

echo "-- a behind pin needs a review"
survey zlib 1.3.1 1.3.2 BEHIND  bash 5.3 5.3 current
reviews "# nothing reviewed yet"
run
expect "a behind pin with no row fails" 1 'BEHIND AND NOT REVIEWED' 'zlib 1\.3\.1 -> 1\.3\.2' 'COUNTS not-reviewed=1 '

reviews "zlib 1.3.1 1.3.2 fine 2026-09-19 read ChangeLog 1.3.2: build fixes only, no memory-safety change"
run
expect "a current review of it passes" 0 'reviewed as fine' 'zlib 1\.3\.1 \(upstream 1\.3\.2\)' 'COUNTS not-reviewed=0 .* fine=1'
absent "a current pin is not mentioned at all" 'bash'

echo
echo "-- a review stops covering the pin"
survey zlib 1.3.1 1.3.3 BEHIND
run
expect "upstream released past the review" 1 'NEW UPSTREAM RELEASE SINCE THE REVIEW' 'reviewed up to 1\.3\.2, upstream is at 1\.3\.3'

survey zlib 1.3.2 1.3.3 BEHIND
run
expect "the pin moved and the review is of the old one" 1 'STALE' 'the review is of 1\.3\.1, the pin is 1\.3\.2'

survey zlib 1.3.2 1.3.2 current
run
expect "the pin caught up and the row was left behind" 1 'STALE' 'the survey says current; remove the row'

survey zlib 1.3.1 1.3.2 BEHIND
reviews "zlib 1.3.1 1.3.2 fine 2026-01-01 read ChangeLog 1.3.2"
run
expect "a review older than the limit has expired" 1 'EXPIRED' 'reviewed 2026-01-01, 261 days ago \(limit 180\)'
run --max-age 365
expect "a longer limit accepts it" 0 'fine=1'

echo
echo "-- version ordering is the survey's, not the alphabet's"
survey coreutils 9.5 9.12 BEHIND
reviews "coreutils 9.5 9.9 fine 2026-09-01 read NEWS through 9.9"
run
expect "9.12 is newer than a review up to 9.9" 1 'reviewed up to 9\.9, upstream is at 9\.12'
reviews "coreutils 9.5 9.12 fine 2026-09-01 read NEWS through 9.12"
run
expect "and covered by a review up to 9.12" 0 'fine=1'

echo
echo "-- a held pin is loud, and a release refuses it"
survey expat 2.6.2 2.8.4 BEHIND
reviews "expat 2.6.2 2.8.4 held 2026-09-19 CVE-2024-45490 fixed in 2.6.3; held until the rebuild in progress lands"
run
expect "held passes with the reason printed" 0 'HELD: known security fixes upstream' 'CVE-2024-45490 fixed in 2\.6\.3' 'held=1'
run --no-held
expect "--no-held makes it a failure" 1 'HELD' 'not covered by a current review'

echo
echo "-- a row that says nothing is not a review"
survey zlib 1.3.1 1.3.2 BEHIND
reviews "zlib 1.3.1 1.3.2 fine 2026-09-19"
run
expect "no note" 1 'MALFORMED' 'no note'
reviews "zlib 1.3.1 1.3.2 probably-ok 2026-09-19 looked fine"
run
expect "a verdict that is neither fine nor held" 1 'MALFORMED' "neither fine nor held"
reviews "zlib 1.3.1 1.3.2 fine last-week read it"
run
expect "a date that is not a date" 1 'MALFORMED' 'is not a date'
reviews "zlib 1.3.1 1.3.2 fine 2026-09-19 read it" "zlib 1.3.1 1.3.2 held 2026-09-19 or maybe not"
run
expect "two rows for one package" 1 'MALFORMED' 'a second row for the same package'
reviews "zlib 1.3.1 1.3.2 fine 2026-09-19 read it" "zlibb 1.0 1.1 fine 2026-09-19 a typo"
run
expect "a row for a source the survey does not have" 1 'STALE' 'zlibb: reviewed, but the survey has no such source'

echo
echo "-- what the survey could not determine"
survey less 661 "" UNKNOWN  zlib 1.3.2 1.3.2 current
reviews "# none"
run
expect "undetermined is reported and passes by default" 0 'NOT DETERMINED by the survey' 'less 661' 'undetermined=1'
run --strict
expect "--strict makes it a failure" 1 'not covered by a current review'

echo
echo "-- a gate with nothing to read has not passed"
: > "${W}/survey.tsv"
run
expect "an empty survey is refused" 1 'missing or empty'
rm -f "${W}/survey.tsv"
run
expect "a missing survey is refused" 1 'missing or empty'

echo
echo "-- the shipped reviews file"
if [[ -f "${ROOT}/tools/pin-reviews.tsv" ]]; then
    survey placeholder 1 1 current
    NO_COLOR=1 "$TOOL" --survey "${W}/survey.tsv" --today 2026-09-19 > "$OUT" 2>&1
    if grep -q 'MALFORMED' "$OUT"; then red "tools/pin-reviews.tsv has a malformed row"; show
    else green "tools/pin-reviews.tsv is well formed"; fi
else
    red "tools/pin-reviews.tsv does not exist"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
