#!/usr/bin/env bash
# Remove from the sources directory every file the manifest no longer names.
#
#   ./tools/prune-sources.sh            remove them
#   ./tools/prune-sources.sh --dry-run  say what would go
#
# Keeps CI's restored source cache from growing by a tarball per version bump.
# Only regular files directly under KRYPTIK_SOURCES are touched.

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
while read -r _ _ url; do
    [[ -n "$url" ]] && keep["$(basename "$url")"]=1
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
[[ "${#keep[@]}" -gt 0 ]] || die "the manifest is empty; refusing to prune against it"

removed=0
for f in "${KRYPTIK_SOURCES}"/*; do
    [[ -f "$f" ]] || continue
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
