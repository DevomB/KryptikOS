#!/usr/bin/env bash
# Remove from the sources directory every file the manifest does not name.
#
#   ./tools/prune-sources.sh            remove them
#   ./tools/prune-sources.sh --dry-run  say what would go
#
# Keeps CI's source caches from growing by a tarball per version bump. images/, the software images'
# own, is pruned the same way, with the links naming its files; other subdirectories are left alone.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

DRY=0
case "${1:-}" in
    --dry-run) DRY=1 ;;
    "") ;;
    *) die "unknown argument: $1 (expected --dry-run or nothing)" ;;
esac

[[ -d "$KRYPTIK_SOURCES" ]] || { dim "no sources directory at ${KRYPTIK_SOURCES}; nothing to prune"; exit 0; }

declare -A keep=()
while read -r _ _ url _; do
    [[ -n "$url" ]] && keep["$(basename "$url")"]=1
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
[[ "${#keep[@]}" -gt 0 ]] || die "the manifest is empty; refusing to prune against it"

removed=0
for f in "${KRYPTIK_SOURCES}"/* "${KRYPTIK_SOURCES}"/images/*; do
    # A link stays while the manifest names it, whether or not the images' cache was restored.
    [[ -f "$f" || -L "$f" ]] || continue
    name="$(basename "$f")"
    [[ -n "${keep[$name]:-}" ]] && continue
    if [[ "$DRY" -eq 1 ]]; then
        echo "would remove ${name}"
    else
        rm -f -- "$f"
        echo "removed ${name}"
    fi
    removed=$((removed + 1))
done
ok "${#keep[@]} files named by the manifest; ${removed} not named $([[ "$DRY" -eq 1 ]] && echo "would be" || echo "were") removed"

# images/crates/ keeps what the current crates' own locks name; with a crate missing its lock cannot be
# read, and nothing there is removed.
[[ -d "${KRYPTIK_SOURCES}/images/crates" ]] || exit 0
declare -A wanted=()
while read -r _ _ url _; do
    f="${url##*/}"
    [[ "$f" == *.crate ]] || continue
    [[ -f "${KRYPTIK_SOURCES}/${f}" ]] || { dim "${f} is not downloaded: images/crates/ is left as it is"; exit 0; }
    while read -r cname cver _; do wanted["${cname}-${cver}.crate"]=1; done \
        < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --crates "${KRYPTIK_SOURCES}/${f}")
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
dropped=0
for f in "${KRYPTIK_SOURCES}"/images/crates/*.crate; do
    [[ -f "$f" ]] || continue
    [[ -n "${wanted[$(basename "$f")]:-}" ]] && continue
    if [[ "$DRY" -eq 1 ]]; then echo "would remove crates/$(basename "$f")"; else rm -f -- "$f"; echo "removed crates/$(basename "$f")"; fi
    dropped=$((dropped + 1))
done
ok "${#wanted[@]} crates named by the crates' locks; ${dropped} not named $([[ "$DRY" -eq 1 ]] && echo "would be" || echo "were") removed"
