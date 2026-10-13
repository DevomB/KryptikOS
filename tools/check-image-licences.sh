#!/usr/bin/env bash
# Checks ROOT/usr/share/licenses/ holds Kryptik's licence and each source's, or its exception line.
#
#   ./tools/check-image-licences.sh ROOT                the root image: the root's sources
#   ./tools/check-image-licences.sh --image NAME TREE   software image NAME: the sources it is built from

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

LIST=(--list-root); OF="the root's"
if [[ "${1:-}" == --image ]]; then
    LIST=(--list-image "${2:?usage: check-image-licences.sh --image NAME TREE}"); OF="image ${2}'s"
    shift 2
fi
ROOT="${1:?usage: check-image-licences.sh ROOT, or --image NAME TREE}"
LIC="${ROOT}/usr/share/licenses"
EXC="${KRYPTIK_ROOT}/build/config/licence-exceptions.txt"
# An image built from no listed source (the probe) has nothing here to hold.
[[ -d "$LIC" || "${LIST[0]}" == --list-image ]] || die "no ${LIC}"

declare -A EXCEPT=()
if [[ -f "$EXC" ]]; then
    while read -r name _ || [[ -n "${name:-}" ]]; do
        [[ -z "$name" || "$name" == \#* ]] || EXCEPT["$name"]=1
    done < "$EXC"
fi

has_files() { [[ -d "$1" && -n "$(find "$1" -type f -print -quit)" ]]; }

missing=(); n=0
while read -r name _ _; do
    [[ -n "$name" ]] || continue
    n=$((n + 1))
    [[ -n "${EXCEPT[$name]:-}" ]] && continue
    has_files "${LIC}/${name}" || missing+=("$name")
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" "${LIST[@]}")
if [[ "$n" -eq 0 && "${LIST[0]}" == --list-image ]]; then
    ok "image ${LIST[1]} is built from no listed source"
    exit 0
fi
[[ "$n" -gt 0 ]] || die "fetch-sources.sh ${LIST[*]} named no sources"
# Kryptik's own licence is the root's; an image holds only its sources'.
[[ "${LIST[0]}" != --list-root || -f "${LIC}/kryptik/LICENSE" ]] || missing+=(kryptik)

if [[ "${#missing[@]}" -gt 0 ]]; then
    printf '  no licence files: %s\n' "${missing[@]}"
    die "${#missing[@]} without licence files: install them, or give each a line and its reason in ${EXC}"
fi
ok "all ${n} of ${OF} sources have their licence files"
