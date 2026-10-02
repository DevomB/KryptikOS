#!/usr/bin/env bash
# tools/glibc-branch-patch.sh against a local stand-in for upstream: the branch's diff from the tag becomes 0001, without NEWS or advisories.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
command -v git > /dev/null || { echo "git required"; exit 77; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
g() { git -C "$U" -c user.name=t -c user.email=t@example.test -c core.autocrlf=false "$@"; }

# Upstream: the tag, then three commits on the release branch, one of them touching only NEWS and advisories.
U="$T/upstream"; git init -q "$U"
printf 'one\n' > "$U/a.c"; printf 'news\n' > "$U/NEWS"; mkdir "$U/advisories"; printf 'adv\n' > "$U/advisories/x"
g add -A && g commit -qm base && g tag glibc-2.40 && g checkout -qb release/2.40/master
printf 'two\n' > "$U/a.c"; g commit -qam fix1
printf 'news2\n' > "$U/NEWS"; printf 'adv2\n' > "$U/advisories/x"; g commit -qam notes
NOTES="$(g rev-parse HEAD)"
printf 'three\n' > "$U/a.c"; g commit -qam fix2
HEAD_="$(g rev-parse HEAD)"
OLD="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# A tree with the tool and a patch set cut at OLD.
tree() {
    R="$T/tree"; rm -rf "$R"; mkdir -p "$R/tools" "$R/build/lib" "$R/build/config"
    cp "$ROOT/tools/glibc-branch-patch.sh" "$R/tools/"; cp "$ROOT/build/lib/common.sh" "$R/build/lib/"
    printf 'V_GLIBC=2.40\n' > "$R/build/config/versions.env"
    P="$R/build/patches/glibc-2.40"; mkdir -p "$P"
    echo old > "$P/0001-release-2.40-master-${OLD:0:12}.patch"; echo keep > "$P/0004-other.patch"
    (cd "$P" && sha256sum 0001-*.patch 0004-*.patch > SHA256SUMS)
    { printf '# 0001: sha256 of `git diff --full-index --no-renames glibc-2.40..%s -- . ...`\n' "$OLD"
      printf '#       generated 2026-09-19 from a clone\n'
      grep 0001 "$P/SHA256SUMS"; grep 0004 "$P/SHA256SUMS"; } > "$P/UPSTREAM-SHA256SUMS"
    printf '| `0001-release-2.40-master-%s.patch` | everything up to commit `%s` (2026-09-10, 230 commits), as one diff |\n' "${OLD:0:12}" "$OLD" > "$P/README.md"
}
run() { GLIBC_GIT="file://$U" NO_COLOR=1 bash "$R/tools/glibc-branch-patch.sh" "$@" > "$T/out" 2>&1; }

tree; run; rc=$?
new="$P/0001-release-2.40-master-${HEAD_:0:12}.patch"
if [[ "$rc" -eq 0 && -f "$new" && ! -e "$P/0001-release-2.40-master-${OLD:0:12}.patch" && "$(cat "$P/0004-other.patch")" == keep ]] \
    && grep -qx '+three' "$new" && ! grep -q 'NEWS\|advisories' "$new"; then
    ok "the branch head's diff from the tag replaces 0001, without NEWS or advisories, and 0004 stays"
else
    bad "the new 0001 (exit ${rc})"; cat "$T/out"
fi
if (cd "$P" && sha256sum --quiet -c SHA256SUMS) && grep -q "  ${new##*/}\$" "$P/UPSTREAM-SHA256SUMS" && grep -qF "$HEAD_" "$P/UPSTREAM-SHA256SUMS" \
    && grep -qF "\`${HEAD_}\` (" "$P/README.md" && grep -qF ', 3 commits)' "$P/README.md"; then
    ok "the checksums, the provenance note and the README's row follow it"
else
    bad "the bookkeeping: $(cat "$P/SHA256SUMS" "$P/README.md")"
fi

tree; run "$NOTES"; rc=$?
[[ "$rc" -eq 0 && -f "$P/0001-release-2.40-master-${NOTES:0:12}.patch" ]] && grep -qF ', 2 commits)' "$P/README.md" \
    && ok "a commit before the head can be named" || { bad "naming an earlier commit (exit ${rc})"; cat "$T/out"; }

tree; run "$(g rev-parse glibc-2.40^{commit})"; rc=$?
[[ "$rc" -ne 0 ]] && grep -q "is not on release/2.40/master" "$T/out" \
    && ok "a commit not on the branch is refused" || { bad "the tag itself was taken (exit ${rc})"; cat "$T/out"; }

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
