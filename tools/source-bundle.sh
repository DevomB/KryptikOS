#!/usr/bin/env bash
# Gather one build's corresponding source: tarballs, signatures, crates, repository, MANIFEST.
#
#   ./tools/source-bundle.sh [--out DIR]     default: $KRYPTIK_OUT/source-<commit>

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,4p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

commit="$(git -C "$KRYPTIK_ROOT" rev-parse HEAD 2>/dev/null)" || die "${KRYPTIK_ROOT} is not a git checkout"
# A bundle stands for one commit, so nothing outside it may be in the tree.
[[ -z "$(git -C "$KRYPTIK_ROOT" status --porcelain)" ]] || die "the tree has uncommitted changes; commit them first"
OUT="${OUT:-${KRYPTIK_OUT}/source-${commit:0:12}}"
[[ ! -e "$OUT" ]] || die "${OUT} already exists"
mkdir -p "$OUT/sources" "$OUT/signatures" "$OUT/crates"
# The root's and the software images' locks: the bundle is everything a release is built from.
LOCKS=("$KRYPTIK_LOCK")
[[ ! -f "$KRYPTIK_IMAGES_LOCK" ]] || LOCKS+=("$KRYPTIK_IMAGES_LOCK")

log "Source bundle for ${commit} in ${OUT}"
# Each tarball is checked against sources.lock as it is copied.
n=0
while read -r name _ver url sig _; do
    [[ -n "$name" ]] || continue
    f="${url##*/}"
    want="$(lock_entry "$f")" || die "${name}: ${f} is not in sources.lock or build/images/sources.lock"
    [[ -f "${KRYPTIK_SOURCES}/${f}" ]] || die "${name}: ${f} is not downloaded; run make sources"
    [[ "$(sha256_of "${KRYPTIK_SOURCES}/${f}")" == "$want" ]] || die "${name}: ${f} does not match sources.lock"
    [[ -f "$OUT/sources/${f}" ]] || { cp "${KRYPTIK_SOURCES}/${f}" "$OUT/sources/"; n=$((n + 1)); }
    # A signed checksum list is named by the manifest, not by the tarball.
    sums=""; [[ "$sig" == sums:* ]] && sums="${KRYPTIK_SOURCES}/.signatures/${sig#sums:}"
    for s in "${KRYPTIK_SOURCES}/.signatures/${f}".* "${KRYPTIK_SOURCES}/.signatures/${f%.*}.sign" \
             "${KRYPTIK_SOURCES}/.signatures/${f%.tar.*}.sig" ${sums:+"$sums" "${sums%.*}"}; do
        if [[ -f "$s" ]]; then cp -f "$s" "$OUT/signatures/"; fi
    done
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
# Every file the lock names, so a list that came back short cannot pass for a whole bundle.
missing=()
while read -r hash f; do
    [[ -z "$hash" || "$hash" == \#* ]] && continue
    [[ -f "$OUT/sources/${f}" ]] || missing+=("$f")
done < <(cat "${LOCKS[@]}")
[[ "${#missing[@]}" -eq 0 ]] || die "the locks name what the bundle lacks: ${missing[*]}"
cp "$KRYPTIK_LOCK" "$OUT/"
[[ ! -f "$KRYPTIK_IMAGES_LOCK" ]] || cp "$KRYPTIK_IMAGES_LOCK" "$OUT/images-sources.lock"
ok "${n} tarballs, $(find "$OUT/signatures" -type f | wc -l) signatures"

git -C "$KRYPTIK_ROOT" archive --format=tar.gz --prefix="kryptik-${commit:0:12}/" \
    -o "$OUT/kryptik-${commit:0:12}.tar.gz" "$commit"
ok "the repository at ${commit:0:12}"

# kryptikd, kryptik-wlproxy and kryptik-stick link their crates statically, so the crates are
# corresponding source.
for ws in compartments/kryptikd compositor tools/stick; do
    (cd "${KRYPTIK_ROOT}/${ws}" && cargo vendor --locked --versioned-dirs "$OUT/crates/${ws##*/}" > /dev/null) \
        || die "cargo vendor failed in ${ws}"
done
ok "the crates of the three Rust workspaces"

# A crate a software image is built with, cbindgen for the browser, comes with the crates its own lock
# names, which fetch-sources.sh fetched into sources/images/crates/: each, held to that lock's hash.
nc=0
while read -r _ _ url _; do
    f="${url##*/}"
    [[ "$f" == *.crate ]] || continue
    while read -r cname cver csum; do
        c="${KRYPTIK_SOURCES}/images/crates/${cname}-${cver}.crate"
        [[ -f "$c" ]] || die "crate ${cname} ${cver}, which ${f} is built from, is not downloaded; run make sources"
        [[ "$(sha256_of "$c")" == "$csum" ]] || die "crate ${cname} ${cver} does not match ${f}'s Cargo.lock"
        mkdir -p "$OUT/crates/images"
        [[ -f "$OUT/crates/images/${c##*/}" ]] || { cp "$c" "$OUT/crates/images/"; nc=$((nc + 1)); }
    done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --crates "${KRYPTIK_SOURCES}/${f}")
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
ok "${nc} crates the software images' crates are built from"

(cd "$OUT" && {
    printf '# Kryptik corresponding source for commit %s\n' "$commit"
    find . -type f ! -name MANIFEST -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
} > MANIFEST)
tar -C "$(dirname "$OUT")" -cf "${OUT}.tar" "$(basename "$OUT")"
ok "${OUT}.tar, with MANIFEST"
