#!/usr/bin/env bash
# Tests for tools/check-support-status.sh, on fixture policies with a fixed
# --now, so they need no network and do not age.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/check-support-status.sh"
REAL_POLICY="${ROOT}/tools/support-policy.tsv"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

W="$(mktemp -d)"
OUT="${W}/out"
POL="${W}/policy.tsv"
V="${W}/versions.env"
RC=0
trap 'rm -rf "$W"' EXIT

show() { sed 's/^/        /' "$OUT"; }

run() {
    RC=0
    NO_COLOR=1 "$TOOL" "$@" > "$OUT" 2>&1 || RC=$?
}

# has PATTERN            output contains it
has()  { grep -qE -- "$1" "$OUT"; }

expect_rc() {   # expect_rc WANT NAME
    if [[ "$RC" -eq "$1" ]]; then green "$2"; else red "$2 (exit ${RC}, wanted ${1})"; show; fi
}
expect_has() {  # expect_has PATTERN NAME
    if has "$1"; then green "$2"; else red "$2 (no match for /${1}/)"; show; fi
}
expect_not() {
    if has "$1"; then red "$2 (unexpected /${1}/)"; show; else green "$2"; fi
}

# A well-formed policy covering the four statuses and both date precisions.
good_policy() {
    cat > "$POL" <<'EOF'
# fixture policy
openssl  V_OPENSSL  3.3   supported       2026-04-09  https://example.invalid/openssl  2026-09-01  -
openssl  V_OPENSSL  3.5   supported       2030-04-08  https://example.invalid/openssl  2026-09-01  LTS
python   V_PYTHON   3.12  security-only   2028-10     https://example.invalid/python   2026-09-01  PEP 693 branch
perl     V_PERL     5.40  security-only   -           https://example.invalid/perl     2026-09-01  security fixes only
expat    V_EXPAT    *     none-published  -           https://example.invalid/expat    2026-09-01  volunteer project, no window published
linux    V_LINUX    *     delegated       -           https://example.invalid/linux    2026-09-01  tools/check-kernel-eol.sh queries releases.json live
EOF
}

versions() {  # versions LINE...
    printf '%s\n' "$@" > "$V"
}

echo "=== positive controls ==="

good_policy
versions 'V_OPENSSL=3.5.8'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 0 "a supported series passes --strict"
expect_has 'openssl 3.5.8: series 3.5 supported until 2030-04-08' "it names the series and the end date"

versions 'V_OPENSSL=3.5.8' 'V_PYTHON=3.12.5' 'V_PERL=5.40.0' 'V_EXPAT=2.6.2' 'V_LINUX=6.18.50'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 0 "every status except EOL passes --strict together"
expect_has 'no pinned series is known to be out of support' "and says so plainly"

echo
echo "=== the shipped policy file parses, and the shipped pins are evaluated ==="

# The real data file: a bad row must break here, not in a release gate.
: > "${W}/empty.env"
run --policy="$REAL_POLICY" --versions="${W}/empty.env" --now=2026-09-11
expect_rc 0 "the shipped support-policy.tsv is well formed"
expect_not 'malformed' "no malformed rows in the shipped policy"

run --policy="$REAL_POLICY" --versions="${ROOT}/build/config/versions.env" --now=2026-09-11
# That there is a verdict for each package, not which, so pin bumps pass.
for pkg in openssl python perl expat linux; do
    if grep -qE "(^|[^a-z])${pkg} " "$OUT"; then
        green "the real tree is evaluated for ${pkg}"
    else
        red "the real tree is evaluated for ${pkg}"; show
    fi
done

echo
echo "=== end of life: a false claim of support, so it fails in both modes ==="

versions 'V_OPENSSL=3.3.1'
run --policy="$POL" --versions="$V" --now=2026-04-09 --strict
expect_rc 0 "the last supported day is still supported"

run --policy="$POL" --versions="$V" --now=2026-04-10 --strict
expect_rc 1 "the day after end of support fails"
expect_has 'END OF LIFE on 2026-04-10|END OF LIFE on 2026-04-09' "it names the date"

run --policy="$POL" --versions="$V" --now=2026-09-11
expect_rc 1 "an EOL series fails informational mode too"
expect_has 'false claim of support' "and explains why it is not mode dependent"
expect_has '155 days ago' "it counts the days since support ended"
expect_has 'do not edit a pin under a' "and points at coordination, not a unilateral bump"

# A fixed pin, openssl 3.3.1, against the real policy data.
versions 'V_OPENSSL=3.3.1'
run --policy="$REAL_POLICY" --versions="$V" --now=2026-09-11 --strict
expect_rc 1 "the shipped openssl 3.3.1 is unsupported per upstream's own policy"
expect_has 'openssl 3.3.1: series 3.3 went END OF LIFE on 2026-04-09' "with upstream's date"

echo
echo "=== month precision: 2028-10 means the end of October ==="

versions 'V_PYTHON=3.12.5'
run --policy="$POL" --versions="$V" --now=2028-10-15 --strict
expect_rc 0 "mid-month in the final month is still supported"
expect_has 'month precision: 2028-10' "and the imprecision is shown, not hidden"

run --policy="$POL" --versions="$V" --now=2028-10-31 --strict
expect_rc 0 "the last day of the final month is still supported"

run --policy="$POL" --versions="$V" --now=2028-11-01 --strict
expect_rc 1 "the day after the final month is end of life"

echo
echo "=== security-fixes-only is supported, and warns ==="

versions 'V_PERL=5.40.0'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 0 "a security-only series does not fail --strict"
expect_has 'SECURITY FIXES ONLY' "but it is called out"
expect_has 'last tier before EOL' "with what that means"

echo
echo "=== tier-based support, which publishes no date at all ==="

# perlpolicy supports the two newest stable series, with no dates.
versions 'V_PERL=5.42.3'
run --policy="$REAL_POLICY" --versions="$V" --now=2026-09-11 --strict
expect_rc 0 "a tier-based supported series passes --strict"
expect_has 'perl 5.42.3: series 5.42 supported - perlpolicy' "quoting the tier it was read from"
expect_has 'cannot expire by itself' "and admitting the row has no expiry"

echo
echo "=== off the policy map: untestable, so mode dependent ==="

versions 'V_OPENSSL=3.1.0'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 1 "a series with no row fails --strict"
expect_has 'OFF THE POLICY MAP' "and says which"
expect_has 'has rows for openssl but none for 3.1' "naming the gap"

run --policy="$POL" --versions="$V" --now=2026-09-11
expect_rc 0 "off the map does not fail informational mode"
expect_has 'strict would fail here' "but says that it would"

echo
echo "=== a * row matches any series; a specific row wins over it ==="

versions 'V_EXPAT=2.6.2'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 0 "a * row matches the pinned series"
expect_has 'upstream publishes no support window' "with the recorded status"
expect_has 'NOT a statement that 2.6.2 is current' "and the caveat that matters"

versions 'V_EXPAT=99.99.99'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 0 "a * row matches an unrelated series too"

cat > "$POL" <<'EOF'
openssl  V_OPENSSL  *    supported  2099-01-01  https://example.invalid/o  2026-09-01  catch-all
openssl  V_OPENSSL  3.3  supported  2026-04-09  https://example.invalid/o  2026-09-01  specific
EOF
versions 'V_OPENSSL=3.3.1'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 1 "a specific series row wins over a catch-all"

echo
echo "=== delegation: named tool must exist, or it is a skipped check ==="

good_policy
versions 'V_LINUX=6.18.50'
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 0 "a delegated row whose tool exists passes"
expect_has 'NOT' "and reports NOT CHECKED rather than ok"
expect_has 'established by tools/check-kernel-eol.sh' "naming the tool"
expect_not '  ok .*linux' "a delegated row is never reported as ok"

sed -i 's|tools/check-kernel-eol.sh|tools/check-nothing-at-all.sh|' "$POL"
run --policy="$POL" --versions="$V" --now=2026-09-11 --strict
expect_rc 1 "a delegation to a missing tool fails --strict"
expect_has 'skipped check is not a pass' "with the reason"

run --policy="$POL" --versions="$V" --now=2026-09-11
expect_rc 0 "a missing delegate does not fail informational mode"

echo
echo "=== malformed policy data is a tooling fault, not a support result ==="

bad_row() {  # bad_row ROW NAME
    printf '%s\n' "$1" > "$POL"
    versions 'V_OPENSSL=3.5.8'
    run --policy="$POL" --versions="$V" --now=2026-09-11
    if [[ "$RC" -ne 0 ]] && has 'malformed'; then green "$2"; else red "$2 (exit ${RC})"; show; fi
}

bad_row 'openssl V_OPENSSL 3.5 maintained  2030-04-08 https://e.invalid/o 2026-09-01 x' \
        "an unknown status is refused"
bad_row 'openssl V_OPENSSL 3.5 supported   08-04-2030 https://e.invalid/o 2026-09-01 x' \
        "a non-ISO support_ends is refused"
bad_row 'openssl V_OPENSSL 3.5 supported   -          https://e.invalid/o 2026-09-01 -' \
        "supported with neither an end date nor a recorded tier is refused"
bad_row 'openssl V_OPENSSL 3.5 supported   -          https://e.invalid/o 2026-09-01' \
        "and an empty note does not satisfy the tier requirement either"
bad_row 'linux   V_LINUX    *   delegated  -          https://e.invalid/l 2026-09-01 -' \
        "a delegated row whose note is a placeholder is refused"
bad_row 'openssl V_OPENSSL 3.5 supported   2030-04-08 http://e.invalid/o  2026-09-01 x' \
        "a non-https policy_url is refused"
bad_row 'openssl V_OPENSSL 3.5 supported   2030-04-08 https://e.invalid/o 2099-01-01 x' \
        "a retrieval date in the future is refused"
bad_row 'openssl V_OPENSSL 3.5 supported   2030-04-08 https://e.invalid/o notadate   x' \
        "a non-date retrieval field is refused"
bad_row 'openssl V_OPENSSL 3.5 supported   2030-04-08' \
        "a row with missing fields is refused"
bad_row 'linux   V_LINUX    *   delegated  -          https://e.invalid/l 2026-09-01' \
        "a delegated row naming no tool is refused"

printf 'openssl V_OPENSSL 3.5 maintained 2030-04-08 https://e.invalid/o 2026-09-01 x\n' > "$POL"
versions 'V_OPENSSL=3.5.8'
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_has 'nothing here has been checked' "a malformed file checks nothing at all"
expect_not '  ok ' "and reports no passing row"

printf '# comments only\n\n' > "$POL"
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_rc 1 "a policy file with no rows is refused"

run --policy="${W}/does-not-exist.tsv" --versions="$V" --now=2026-09-11
expect_rc 1 "a missing policy file is refused"
expect_has 'cannot establish anything without it' "rather than passing vacuously"

echo
echo "=== arguments, pins and the report ==="

good_policy
versions 'V_OPENSSL=3.5.8'
run --policy="$POL" --versions="$V" --now=2026-13-45
expect_rc 1 "an impossible --now is refused"

run --policy="$POL" --versions="$V" --wat
expect_rc 1 "an unknown argument is refused"

run --policy="$POL" --versions="${W}/no-such.env" --now=2026-09-11
expect_rc 1 "a missing versions file is refused"

versions 'V_OPENSSL=3.5.8   # the LTS line' 'V_PERL="5.40.0"'
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_has 'openssl 3.5.8: series 3.5 supported' "a trailing comment is stripped from a pin"
expect_has 'perl 5.40.0' "quotes are stripped from a pin"

versions 'V_LANDLOCK_HELPER=unset' 'V_OPENSSL=unset'
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_has 'openssl is not pinned' "an unset pin is reported as unpinned, not evaluated"

versions 'V_PERL=5.40.0'
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_has 'openssl is not pinned' "an absent pin is reported as unpinned"

versions 'V_PERL=5.40.0' 'V_A=1' 'V_B=2' 'V_C=3' 'V_D=4'
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_has 'COVERAGE FLOOR: 5 of 5' "the coverage floor counts policy packages against pins"
expect_has 'never as .Kryptik ships nothing unsupported' "and refuses to be read as more"
expect_has 'check-source-currency' "pointing at the tool for the question it does not answer"

run --policy="$POL" --versions="$V" --now=2026-09-11 --report="${W}/r.txt"
if [[ -s "${W}/r.txt" ]] && grep -q 'COVERAGE FLOOR' "${W}/r.txt"; then
    green "--report writes the findings to a file"
else
    red "--report writes the findings to a file"
fi
if grep -q 'evaluated as of 2026-09-11' "${W}/r.txt"; then
    green "the report records the date it was evaluated against"
else
    red "the report records the date it was evaluated against"
fi

run --policy="$POL" --versions="$V" --now=2026-09-11 --report="${W}/nodir/sub/r.txt"
expect_rc 0 "--report creates a missing directory"

run --policy="$POL" --versions="$V" --now=2026-09-11 --report=/proc/1/nope
expect_rc 1 "an unwritable report path is refused before any work"

echo
echo "=== the policy data can itself go stale ==="

sed -i 's/2026-09-01/2020-01-01/' "$POL"
versions 'V_OPENSSL=3.5.8'
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_has 'read more than 180 days before' "a long-unread policy row warns"

good_policy
run --policy="$POL" --versions="$V" --now=2026-09-11
expect_not 'read more than 180 days before' "a recently read row does not"

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
