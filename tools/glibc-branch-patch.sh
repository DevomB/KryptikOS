#!/usr/bin/env bash
# glibc's maintained release branch as one patch over the release tarball, made as build/patches/glibc-<V>/README.md says.
#
#   tools/glibc-branch-patch.sh [COMMIT]   the newest commit both hosts hold by default
#
# Writes 0001-release-<V>-master-<commit>.patch in place of the old one, its lines in SHA256SUMS and
# UPSTREAM-SHA256SUMS, and README.md's row for it; the list of fixes in README.md stays the reviewer's.
# The patch is cut only at a commit two hosts hold on the branch: a commit id names its content, so
# the two then serve the same. GLIBC_GIT and GLIBC_GIT_SECOND name other hosts (the fixture suite's are local).
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

url="${GLIBC_GIT:-https://sourceware.org/git/glibc.git}"
second="${GLIBC_GIT_SECOND:-https://gitlab.com/gnutools/glibc}"
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
git -C "$g" fetch -q --shallow-exclude="refs/tags/${tag}" "$second" "refs/heads/${branch}:refs/remotes/second/branch" \
    || die "${second} did not give ${branch}: the patch is cut only at a commit two hosts hold"
on() { git -C "$g" merge-base --is-ancestor "$1" "$2" 2>/dev/null; }   # on COMMIT REF
a="$(git -C "$g" rev-parse refs/remotes/upstream/branch)"; b="$(git -C "$g" rev-parse refs/remotes/second/branch)"
# With none named, the newest both hold: one host's head, when the other is behind it.
if [[ $# -gt 0 ]]; then commit="$1"
elif on "$a" "$b"; then commit="$a"
elif on "$b" "$a"; then commit="$b"
else die "${branch} differs between the two hosts: ${a} at ${url}, ${b} at ${second}"
fi
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "${commit}: give a full commit id"
on "$commit" refs/remotes/upstream/branch || die "${commit} is not on ${branch}"
on "$commit" refs/remotes/second/branch || die "${commit} is not on ${branch} at ${second}: name a commit both hosts hold"
count="$(git -C "$g" rev-list --count "$commit")"
date="$(git -C "$g" log -1 --format=%cs "$commit")"

# README.md's command, whatever this user's git configuration says.
gd() {
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$g" -c core.abbrev=40 diff --no-ext-diff --no-color "$@" \
        "${tag}..${commit}" -- . ':!NEWS' ':!advisories'
}
# patch(1) carries neither a binary change nor a change of mode alone.
[[ -z "$(gd --numstat | awk '$1 == "-"')" ]] || die "the branch changes a binary file since ${tag}, which a patch cannot carry"
[[ -z "$(gd --raw --abbrev=40 | awk 'substr($1, 2) != $2 && $3 == $4')" ]] || die "the branch changes a file's mode alone since ${tag}, which a patch cannot carry"
name="0001-release-${V_GLIBC}-master-${commit:0:12}.patch"
gd --full-index --no-renames > "${dir}/${name}.new"
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

ok "${name}: ${count} commits up to ${commit:0:12} (${date}), on ${branch} at ${url} and at ${second}, sha256 ${sum}"
if [[ "$name" == "$oldname" ]]; then
    echo "the same commit as before: the patch is the one upstream's branch gives, byte for byte, if git shows no change"
fi
