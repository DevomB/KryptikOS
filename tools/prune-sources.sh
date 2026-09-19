#!/usr/bin/env bash
# Remove from the sources directory every file the manifest no longer names.
#
#   ./tools/prune-sources.sh            remove them
#   ./tools/prune-sources.sh --dry-run  say what would go
#
# The CI caches restore the most recent earlier set of tarballs when
# sources.lock changes, so that a version bump downloads one file instead of
# every file (and is not at the mercy of every upstream's rate limiter at
# once). Without this, that cache would grow by one superseded tarball per
# bump for ever. Only regular files directly under KRYPTIK_SOURCES are
# considered; the signatures directory and anything else below it is left
# alone. It removes nothing the manifest names, so it cannot cost a download.

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
