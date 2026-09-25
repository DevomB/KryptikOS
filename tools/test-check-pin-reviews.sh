#!/usr/bin/env bash
# Tests for tools/check-pin-reviews.sh. Offline: it reads two files.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/check-pin-reviews.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
PASS=0; FAIL=0

survey()  { : > "$W/s"; while [[ $# -ge 4 ]]; do printf '%s\t%s\t%s\t%s\turl\n' "$1" "$2" "$3" "$4" >> "$W/s"; shift 4; done; }
reviews() { printf '%s\n' "$@" > "$W/r"; }
# expect NAME WANT_RC REGEX [extra tool args...]
expect() {
    local name="$1" want="$2" rx="$3"; shift 3
    local out rc; out="$("$TOOL" --survey "$W/s" --reviews "$W/r" "$@" 2>&1)"; rc=$?
    if [[ "$rc" -eq "$want" ]] && grep -qE -- "$rx" <<<"$out"; then PASS=$((PASS + 1)); echo "  PASS  $name"
    else FAIL=$((FAIL + 1)); echo "  FAIL  $name (exit $rc, wanted $want)"; sed 's/^/        /' <<<"$out"; fi
}
ROW="zlib 1.3.1 1.3.2 fine 2026-09-19 read the ChangeLog: build fixes only"

survey zlib 1.3.1 1.3.2 BEHIND  bash 5.3 5.3 current
reviews "# none";                expect "a behind pin with no row fails"            1 'NOT REVIEWED: zlib 1.3.1 -> 1.3.2'
reviews "$ROW";                  expect "a row that covers it passes"               0 '^ok:'
survey zlib 1.3.1 1.3.3 BEHIND;  expect "upstream released past the review"         1 'NEW RELEASE: zlib: reviewed up to 1.3.2, upstream is at 1.3.3'
survey zlib 1.3.2 1.3.3 BEHIND;  expect "the pin moved off the version reviewed"    1 'STALE: zlib: the row reviews 1.3.1, the pin is 1.3.2'
survey zlib 1.3.2 1.3.2 current; expect "the pin caught up and the row was left"    1 'STALE: zlib is current now'

survey coreutils 9.5 9.12 BEHIND
reviews "coreutils 9.5 9.9 fine 2026-09-19 read NEWS";  expect "9.12 sorts after 9.9, not before it"  1 'NEW RELEASE'
reviews "coreutils 9.5 9.12 fine 2026-09-19 read NEWS"; expect "and a review up to 9.12 covers it"    0 '^ok:'

survey zlib 1.3.1 1.3.2 BEHIND
reviews "zlib 1.3.1 1.3.2 held 2026-09-19 1.3.2 introduces a worse bug"
expect "a held pin passes, with its reason printed"  0 'HELD: zlib 1.3.1: 1.3.2 introduces'
expect "and a release refuses it"                    1 'FAIL: 1 pin' --no-held

reviews "zlib 1.3.1 1.3.2 fine 2026-09-19";          expect "a row with no note is not a review"  1 'MALFORMED: zlib'
reviews "zlib 1.3.1 1.3.2 maybe 2026-09-19 looked";  expect "nor is an unknown verdict"           1 'MALFORMED: zlib'
reviews "$ROW" "$ROW";                               expect "nor a second row for one package"    1 'MALFORMED: zlib'
reviews "$ROW" "zlibb 1 2 fine 2026-09-19 a typo";   expect "a row for no source is stale"        1 'STALE: zlibb is not a source'

# An empty "newest" column must not shift the fields after it.
survey less 661 "" UNKNOWN; reviews "# none"
expect "an undetermined pin is reported, not swallowed"  0 'not determined.*less 661'
reviews "less 661 668 fine 2026-09-19 read the changes"
expect "and a review is kept while its upstream does not answer"  0 'not determined.*less 661'

# Commit IDs have no order: a branch head that sorts before the one reviewed
# is as new as one that sorts after it.
survey glibc-branch cdaa5d6db08e 111111111111 BEHIND
reviews "glibc-branch cdaa5d6db08e aaaaaaaaaaaa fine 2026-09-25 read the branch log"
expect "a branch head that sorts first is still new"  1 'NEW RELEASE: glibc-branch: reviewed up to aaaaaaaaaaaa'
reviews "glibc-branch cdaa5d6db08e 111111111111bbbbbbbbbbbbbbbbbbbbbbbbbbbb fine 2026-09-25 read the branch log"
expect "and a review of that head, written in full, covers it"  0 '^ok:'

: > "$W/s"; expect "an empty survey has not passed"      1 'need a non-empty --survey'

printf 'x\t1\t1\tcurrent\turl\n' > "$W/s"
if "$TOOL" --survey "$W/s" 2>&1 | grep -q MALFORMED; then FAIL=$((FAIL + 1)); echo "  FAIL  tools/pin-reviews.tsv has a malformed row"
else PASS=$((PASS + 1)); echo "  PASS  tools/pin-reviews.tsv is well formed"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
