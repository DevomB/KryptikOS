#!/usr/bin/env bash
# Regression test for tools/artifact-manifest.sh.
#
# The manifest's whole value is that `--verify` says no when something moved.
# So every case here is a positive control: change one property of one entry,
# and verification must fail. The negative control - an untouched tree
# verifying clean - is first, because without it a verifier that always fails
# would pass every other case.
#
# Determinism gets its own case. A manifest that is not byte-stable makes the
# digest meaningless and `diff` useless, and the usual cause is a timestamp or
# an absolute path that crept into the body.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAN="${ROOT}/tools/artifact-manifest.sh"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == ok ]]; then green "$1"; else red "$1"; fi; }

[[ -x "$MAN" ]] || { echo "missing or non-executable: $MAN"; exit 1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

export KRYPTIK_ROOT="$ROOT"
export KRYPTIK_WORK="$W/work"
export KRYPTIK_SOURCES="$W/src"
export NO_COLOR=1
mkdir -p "$KRYPTIK_WORK" "$KRYPTIK_SOURCES"

# A tree with one of everything the manifest claims to record.
TREE="$W/tree"
mkdir -p "$TREE/usr/bin" "$TREE/etc" "$TREE/a dir with spaces"
echo "hello" > "$TREE/usr/bin/prog"
chmod 755 "$TREE/usr/bin/prog"
echo "config" > "$TREE/etc/conf"
chmod 600 "$TREE/etc/conf"
echo "spaced" > "$TREE/a dir with spaces/file name.txt"
ln -s /usr/bin/prog "$TREE/usr/bin/link"
mkfifo "$TREE/etc/fifo" 2>/dev/null || true

gen()  { "$MAN" --root "$TREE" --out "$1" >/dev/null 2>&1; }
ver()  { "$MAN" --root "$TREE" --verify "$1" 2>&1; }

M1="$W/m1.txt"
gen "$M1" || { echo "manifest generation failed"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Negative control.
# ---------------------------------------------------------------------------
out="$(ver "$M1")"; rc=$?
check "untouched tree verifies clean" "$([[ $rc -eq 0 ]] && echo ok)"
check "verification reports the digest" "$(grep -q 'digest matches' <<<"$out" && echo ok)"

# ---------------------------------------------------------------------------
# 2. Determinism: a second manifest of the same tree is byte-identical below
#    the comment block, and carries the same digest.
# ---------------------------------------------------------------------------
M2="$W/m2.txt"
sleep 1                      # a different generation second, deliberately
touch "$TREE/usr/bin/prog"   # a different mtime, deliberately
gen "$M2"
d1="$(sed -n 's/^# digest: //p' "$M1")"
d2="$(sed -n 's/^# digest: //p' "$M2")"
check "digest is stable across runs" "$([[ "$d1" == "$d2" && -n "$d1" ]] && echo ok)"
check "body is byte-identical across runs" \
      "$(diff <(grep -v '^#' "$M1") <(grep -v '^#' "$M2") >/dev/null && echo ok)"
check "mtime is deliberately not part of identity" "$([[ "$d1" == "$d2" ]] && echo ok)"

# The body must not contain the tree's absolute path, or the manifest stops
# being comparable between machines.
check "body carries no absolute root path" \
      "$(grep -v '^#' "$M1" | grep -qF "$TREE" && echo "" || echo ok)"

# ---------------------------------------------------------------------------
# 3. Positive controls: one property at a time.
# ---------------------------------------------------------------------------
echo "tampered" > "$TREE/usr/bin/prog"
out="$(ver "$M1")"; rc=$?
check "changed file content: detected" "$([[ $rc -ne 0 ]] && echo ok)"
check "changed file content: names the path" "$(grep -q 'usr/bin/prog' <<<"$out" && echo ok)"
echo "hello" > "$TREE/usr/bin/prog"

chmod 777 "$TREE/etc/conf"
out="$(ver "$M1")"; rc=$?
check "changed mode: detected" "$([[ $rc -ne 0 ]] && echo ok)"
chmod 600 "$TREE/etc/conf"
check "restoring mode restores the digest" "$(ver "$M1" >/dev/null 2>&1 && echo ok)"

echo "new" > "$TREE/etc/extra"
out="$(ver "$M1")"; rc=$?
check "added file: detected" "$([[ $rc -ne 0 ]] && echo ok)"
check "added file: counted as present-now-only" \
      "$(grep -q 'present now and not in the manifest' <<<"$out" && echo ok)"
rm -f "$TREE/etc/extra"

rm -f "$TREE/etc/conf"
out="$(ver "$M1")"; rc=$?
check "removed file: detected" "$([[ $rc -ne 0 ]] && echo ok)"
check "removed file: counted as manifest-only" \
      "$(grep -q 'in the manifest and not present now' <<<"$out" && echo ok)"
echo "config" > "$TREE/etc/conf"; chmod 600 "$TREE/etc/conf"

ln -sfn /etc/passwd "$TREE/usr/bin/link"
out="$(ver "$M1")"; rc=$?
check "retargeted symlink: detected" "$([[ $rc -ne 0 ]] && echo ok)"
ln -sfn /usr/bin/prog "$TREE/usr/bin/link"

# Same content, different name: a swap that a naive content-only manifest
# would miss entirely.
mv "$TREE/etc/conf" "$TREE/etc/conf2"
out="$(ver "$M1")"; rc=$?
check "renamed file with identical content: detected" "$([[ $rc -ne 0 ]] && echo ok)"
mv "$TREE/etc/conf2" "$TREE/etc/conf"

check "tree restored: verifies clean again" "$(ver "$M1" >/dev/null 2>&1 && echo ok)"

# ---------------------------------------------------------------------------
# 4. Paths with spaces survive the round trip.
# ---------------------------------------------------------------------------
check "spaced path is recorded" \
      "$(grep -qF 'a dir with spaces/file name.txt' "$M1" && echo ok)"
echo "changed" > "$TREE/a dir with spaces/file name.txt"
out="$(ver "$M1")"; rc=$?
check "spaced path: change detected" "$([[ $rc -ne 0 ]] && echo ok)"
echo "spaced" > "$TREE/a dir with spaces/file name.txt"

# ---------------------------------------------------------------------------
# 5. Inputs are recorded, not just the tree.
# ---------------------------------------------------------------------------
echo "fake tarball" > "$KRYPTIK_SOURCES/thing-1.0.tar.gz"
mkdir -p "$KRYPTIK_WORK/.stamps"
printf '# kryptik build stamp v2\nfingerprint: %064d\nstep: thing\n' 7 \
    > "$KRYPTIK_WORK/.stamps/thing"
M3="$W/m3.txt"
gen "$M3"
# Tabs must be real tabs: GNU grep -E reads "\t" as a literal 't', so a
# pattern written that way silently matches nothing and reports a failure that
# is not there.
T=$'\t'
check "records source tarballs by content" \
      "$(grep -qE "^input${T}source${T}thing-1.0.tar.gz${T}[0-9a-f]{64}$" "$M3" && echo ok)"
check "records per-step build fingerprints" \
      "$(grep -qE "^input${T}step${T}thing${T}0{63}7$" "$M3" && echo ok)"
check "records the recipes by content" \
      "$(grep -qE "^input${T}recipe${T}build/lib/common\.sh${T}[0-9a-f]{64}$" "$M3" && echo ok)"
check "records the repository commit" \
      "$(grep -qE "^input${T}repo-commit${T}" "$M3" && echo ok)"

# Changing a recorded INPUT must change the digest, even with the tree untouched.
echo "different tarball" > "$KRYPTIK_SOURCES/thing-1.0.tar.gz"
out="$(ver "$M3")"; rc=$?
check "changed input tarball: digest differs though the tree did not" \
      "$([[ $rc -ne 0 ]] && echo ok)"

# ---------------------------------------------------------------------------
# 6. A manifest this tool did not write is refused, not misread.
# ---------------------------------------------------------------------------
echo "not a manifest" > "$W/junk.txt"
out="$("$MAN" --root "$TREE" --verify "$W/junk.txt" 2>&1)"; rc=$?
check "manifest with no digest line is refused" \
      "$({ [[ $rc -ne 0 ]] && grep -q 'no digest line' <<<"$out"; } && echo ok)"

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed."
    exit 1
fi
echo "All ${PASS} checks passed."
