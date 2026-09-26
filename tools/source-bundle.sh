#!/usr/bin/env bash
# Gather the corresponding source of one build: every sources.lock tarball
# with the signatures fetched for it, the Rust crates the static binaries
# link, and the repository at the build commit (build/patches included), with
# a manifest of every file's sha256. The release job calls it; CI does not.
#
#   ./tools/source-bundle.sh [--out DIR]     default: $KRYPTIK_OUT/source-<commit>

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

commit="$(git -C "$KRYPTIK_ROOT" rev-parse HEAD 2>/dev/null)" || die "${KRYPTIK_ROOT} is not a git checkout"
# A bundle stands for one commit, so nothing outside it may be in the tree.
[[ -z "$(git -C "$KRYPTIK_ROOT" status --porcelain)" ]] || die "the tree has uncommitted changes; commit them first"
OUT="${OUT:-${KRYPTIK_OUT}/source-${commit:0:12}}"
[[ ! -e "$OUT" ]] || die "${OUT} already exists"
mkdir -p "$OUT/sources" "$OUT/signatures" "$OUT/crates"
LOCK="${KRYPTIK_ROOT}/sources.lock"

log "Source bundle for ${commit} in ${OUT}"
# Each tarball is checked against sources.lock as it is copied.
n=0
while read -r name _ver url; do
    [[ -n "$name" ]] || continue
    f="${url##*/}"
    want="$(awk -v f="$f" '$2 == f { print $1; exit }' "$LOCK")"
    [[ -n "$want" ]] || die "${name}: ${f} is not in sources.lock"
    [[ -f "${KRYPTIK_SOURCES}/${f}" ]] || die "${name}: ${f} is not downloaded; run make sources"
    [[ "$(sha256_of "${KRYPTIK_SOURCES}/${f}")" == "$want" ]] || die "${name}: ${f} does not match sources.lock"
    [[ -f "$OUT/sources/${f}" ]] || { cp "${KRYPTIK_SOURCES}/${f}" "$OUT/sources/"; n=$((n + 1)); }
    for s in "${KRYPTIK_SOURCES}/.signatures/${f}".* "${KRYPTIK_SOURCES}/.signatures/${f%.*}.sign"; do
        if [[ -f "$s" ]]; then cp -f "$s" "$OUT/signatures/"; fi
    done
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
# Every file the lock names, so a list that came back short cannot pass for
# a whole bundle.
missing=()
while read -r hash f; do
    [[ -z "$hash" || "$hash" == \#* ]] && continue
    [[ -f "$OUT/sources/${f}" ]] || missing+=("$f")
done < "$LOCK"
[[ "${#missing[@]}" -eq 0 ]] || die "sources.lock names what the bundle lacks: ${missing[*]}"
cp "$LOCK" "$OUT/"
ok "${n} tarballs, $(find "$OUT/signatures" -type f | wc -l) signatures"

git -C "$KRYPTIK_ROOT" archive --format=tar.gz --prefix="kryptik-${commit:0:12}/" \
    -o "$OUT/kryptik-${commit:0:12}.tar.gz" "$commit"
ok "the repository at ${commit:0:12}"

# kryptikd and kryptik-wlproxy link their crates statically: those sources
# are part of what the binaries were built from.
for ws in compartments/kryptikd compositor; do
    (cd "${KRYPTIK_ROOT}/${ws}" && cargo vendor --locked --versioned-dirs "$OUT/crates/${ws##*/}" > /dev/null) \
        || die "cargo vendor failed in ${ws}"
done
ok "the crates of both Rust workspaces"

(cd "$OUT" && {
    printf '# Kryptik corresponding source for commit %s\n' "$commit"
    find . -type f ! -name MANIFEST -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
} > MANIFEST)
tar -C "$(dirname "$OUT")" -cf "${OUT}.tar" "$(basename "$OUT")"
ok "${OUT}.tar, with MANIFEST"
