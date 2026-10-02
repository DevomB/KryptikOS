#!/usr/bin/env bash
# glibc's maintained release branch as one patch over the release tarball, made as build/patches/glibc-<V>/README.md says.
#
#   tools/glibc-branch-patch.sh [COMMIT]   the branch's head by default
#
# Writes 0001-release-<V>-master-<commit>.patch in place of the old one, its lines in SHA256SUMS and
# UPSTREAM-SHA256SUMS, and README.md's row for it; the list of fixes in README.md stays the reviewer's.
# GLIBC_GIT names another upstream (the fixture suite uses a local one).
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

url="${GLIBC_GIT:-https://sourceware.org/git/glibc.git}"
branch="release/${V_GLIBC}/master"
tag="glibc-${V_GLIBC}"
dir="${KRYPTIK_ROOT}/build/patches/glibc-${V_GLIBC}"
[[ -d "$dir" ]] || die "no patch set at ${dir}"
old=("$dir"/0001-release-"${V_GLIBC}"-master-*.patch)
[[ -f "${old[0]}" ]] || die "no 0001 patch in ${dir} to replace"

g="$(mktemp -d)"
trap 'rm -rf "$g"' EXIT
git -C "$g" init -q
git -C "$g" fetch -q --depth=1 "$url" "refs/tags/${tag}:refs/tags/${tag}"
# The branch since the tag: the commits to count, and the trees to diff.
git -C "$g" fetch -q --shallow-exclude="refs/tags/${tag}" "$url" "refs/heads/${branch}:refs/remotes/upstream/branch"
commit="${1:-$(git -C "$g" rev-parse refs/remotes/upstream/branch)}"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "${commit}: give a full commit id"
git -C "$g" merge-base --is-ancestor "$commit" refs/remotes/upstream/branch 2>/dev/null \
    || die "${commit} is not on ${branch}"
count="$(git -C "$g" rev-list --count "$commit")"
date="$(git -C "$g" log -1 --format=%cs "$commit")"

name="0001-release-${V_GLIBC}-master-${commit:0:12}.patch"
git -C "$g" diff --full-index --no-renames "${tag}..${commit}" -- . ':!NEWS' ':!advisories' > "${dir}/${name}.new"
[[ -s "${dir}/${name}.new" ]] || { rm -f "${dir}/${name}.new"; die "the branch at ${commit:0:12} differs from ${tag} in nothing"; }
oldname="${old[0]##*/}"
oldcommit="$(sed -n "s/.*${tag}\.\.\([0-9a-f]\{40\}\).*/\1/p" "${dir}/UPSTREAM-SHA256SUMS" | head -1)"
rm -f "${old[0]}"
mv "${dir}/${name}.new" "${dir}/${name}"
sum="$(sha256_of "${dir}/${name}")"

# The checksum lines and the commit in the provenance note follow the new file.
for f in SHA256SUMS UPSTREAM-SHA256SUMS; do
    sed -i "s|^[0-9a-f]\{64\}  ${oldname}\$|${sum}  ${name}|" "${dir}/${f}"
    grep -q "^${sum}  ${name}\$" "${dir}/${f}" || die "${f} has no line for ${oldname} to replace"
done
if [[ -n "$oldcommit" && "$oldcommit" != "$commit" ]]; then
    sed -i "s|${oldcommit}|${commit}|g; s|generated [0-9-]\{10\} from|generated $(date -u +%F) from|" "${dir}/UPSTREAM-SHA256SUMS"
fi
# README.md's row: the file, the commit, its date and the count.
sed -i -e "s|\`${oldname}\`|\`${name}\`|" \
       -e "s|up to commit \`[0-9a-f]\{40\}\` ([0-9-]\{10\}, [0-9]* commits)|up to commit \`${commit}\` (${date}, ${count} commits)|" \
       "${dir}/README.md"
grep -qF "\`${commit}\` (${date}, ${count} commits)" "${dir}/README.md" || warn "README.md's row for 0001 did not take the new commit; edit it by hand"

ok "${name}: ${count} commits up to ${commit:0:12} (${date}), sha256 ${sum}"
if [[ "$name" == "$oldname" ]]; then
    echo "the same commit as before: the patch is the one upstream's branch gives, byte for byte, if git shows no change"
fi
