#!/usr/bin/env bash
# Every source has its licence files under ROOT/usr/share/licenses/<source>/
# (stage 04's s_licences installs them), and Kryptik has its own. A source
# the image carries no licence file for needs a line, with its reason, in
# build/config/licence-exceptions.txt.
#
#   ./tools/check-image-licences.sh ROOT

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

ROOT="${1:?usage: check-image-licences.sh ROOT}"
LIC="${ROOT}/usr/share/licenses"
EXC="${KRYPTIK_ROOT}/build/config/licence-exceptions.txt"
[[ -d "$LIC" ]] || die "no ${LIC}"

declare -A EXCEPT=()
if [[ -f "$EXC" ]]; then
    while read -r name _ || [[ -n "${name:-}" ]]; do
        [[ -z "$name" || "$name" == \#* ]] || EXCEPT["$name"]=1
    done < "$EXC"
fi

# A directory with at least one file in it.
has_files() { [[ -d "$1" && -n "$(find "$1" -type f -print -quit)" ]]; }

missing=(); n=0
while read -r name _ _; do
    [[ -n "$name" ]] || continue
    n=$((n + 1))
    [[ -n "${EXCEPT[$name]:-}" ]] && continue
    has_files "${LIC}/${name}" || missing+=("$name")
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
[[ "$n" -gt 0 ]] || die "fetch-sources.sh --list named no sources"
[[ -f "${LIC}/kryptik/LICENSE" ]] || missing+=(kryptik)

if [[ "${#missing[@]}" -gt 0 ]]; then
    printf '  no licence files: %s\n' "${missing[@]}"
    die "${#missing[@]} without licence files: install them, or give each a line and its reason in ${EXC}"
fi
ok "all ${n} sources have their licence files, and Kryptik has its own"
