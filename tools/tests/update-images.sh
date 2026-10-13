#!/usr/bin/env bash
# Tests for the image store (build/service-scripts/image-store.sh) and kryptik-update's staging of a
# payload's images, offline: images reach the store only for the root they come with and only as their
# list signs them, and the store keeps the lists of the roots in the two slots and the images they name.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UPD="${ROOT}/tools/update/kryptik-update"
LIB="${ROOT}/build/service-scripts/image-store.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in zstd sha256sum; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
STORE="${W}/store"

# The store's functions and apply's staging, lifted out as image-list.sh lifts check-images, with
# what apply has set by the time it calls them: the payload's path, its manifest's hashes and the copy.
{
    printf 'IMAGES=%q\n' "$STORE"
    echo 'say() { printf "%s\n" "$*"; }'
    echo 'die() { printf "REFUSED: %s\n" "$*"; exit 1; }'
    echo 'uncache() { :; }'
    echo 'payload_path() { echo "$dir/$1"; }'
    echo 'manifest_hash() { sed -n '"'"'/^--$/,$p'"'"' "$m" | sed 1d | awk -v r="$1" '"'"'$3==r {print $1; exit}'"'"'; }'
    sed -n '/^images_keep() {/,/^}/p' "$LIB"
    sed -n '/^_images_fail() {/,/^}/p' "$LIB"
    sed -n '/^images_prune() {/,/^}/p' "$LIB"
    sed -n '/^stage_images() {/,/^}/p' "$UPD"
    grep '^payload_image() ' "$UPD"
} > "${W}/lib.sh"
for fn in images_keep _images_fail images_prune stage_images payload_image; do
    grep -q "^${fn}() " "${W}/lib.sh" || { echo "FATAL: ${fn} is missing from ${LIB} or ${UPD}" >&2; exit 1; }
done

hex() { printf "%064d" 0 | tr 0 "$1"; }
R1="$(hex 1)"; R2="$(hex 2)"; R3="$(hex 3)"

# A payload in DIR carrying the root BASE (what its list says) and an image NAME of CONTENT, the
# release manifest listing every file; the image's root hash is HASH.
payload() {   # payload DIR BASE NAME CONTENT HASH
    rm -rf "$1"; mkdir -p "$1"
    printf '%s' "$4" > "${W}/raw"
    zstd -q -f "${W}/raw" -o "$1/$3.img.zst"
    printf 'KRYPTIK-IMAGES-1\nrelease: 1.2.0\nbase: %s\nimage: %s 1 bytes=%s sha256=%s data-blocks=1 root-hash=%s salt=%s\n' \
        "$2" "$3" "$(stat -c %s "${W}/raw")" "$(sha256sum "${W}/raw" | cut -c1-64)" "$5" "$(hex a)" > "$1/images.manifest"
    printf 'a signature\n' > "$1/images.manifest.sig"
    {
        printf 'KRYPTIK-MANIFEST-1\n--\n'
        for f in images.manifest images.manifest.sig "$3.img.zst"; do
            printf '%s %s %s\n' "$(sha256sum "$1/$f" | cut -c1-64)" "$(stat -c %s "$1/$f")" "$f"
        done
    } > "$1/manifest"
}
# stage DIR ROOT-HASH: stage_images for that payload, its output and exit in OUT and RC.
stage() {
    mkdir -p "${W}/snap"
    OUT="$(dir="$1" m="$1/manifest" ROOT_HASH="$2" VERSION=1.2.0 SNAP="${W}/snap" bash -c ". '${W}/lib.sh'; stage_images" 2>&1)"; RC=$?
}

payload "${W}/p1" "$R1" probe "the probe image" "$(hex b)"
stage "${W}/p1" "$R1"
if [[ "$RC" -eq 0 && "$(cat "${STORE}/probe/$(hex b).img")" == "the probe image" ]] \
   && cmp -s "${W}/p1/images.manifest" "${STORE}/${R1}.manifest" && [[ -f "${STORE}/${R1}.manifest.sig" ]]; then
    green "a payload's image and its list are kept in the store, by root hash"
else
    red "the payload's image was not kept as its list says (exit ${RC}): ${OUT}"
fi
stage "${W}/p1" "$R1"
[[ "$RC" -eq 0 && "$OUT" == *"image probe: already kept"* ]] && green "an image already kept is not written again" \
    || red "staging the same image twice did not find it kept: ${OUT}"

stage "${W}/p1" "$R2"
[[ "$RC" -ne 0 && "$OUT" == *"REFUSED: the image list is for another root than the one it comes with"* ]] \
    && green "a list for another root than the payload carries is refused" || red "a list for another root was not refused: ${OUT}"

payload "${W}/p2" "$R1" viewer "what the list signs" "$(hex c)"
printf 'something else' > "${W}/other"
zstd -q -f "${W}/other" -o "${W}/p2/viewer.img.zst"
# The release manifest still vouches for the file, as it would for a payload built wrong.
sed -i "s/^[0-9a-f]* [0-9]* viewer.img.zst\$/$(sha256sum "${W}/p2/viewer.img.zst" | cut -c1-64) $(stat -c %s "${W}/p2/viewer.img.zst") viewer.img.zst/" "${W}/p2/manifest"
stage "${W}/p2" "$R1"
if [[ "$RC" -ne 0 && "$OUT" == *"REFUSED: image viewer is not the bytes its list signs"* ]] \
   && [[ -z "$(find "$STORE" -name '*.new')" && ! -e "${STORE}/viewer/$(hex c).img" ]]; then
    green "an image that does not decompress to its signed bytes is refused, and nothing of it is left"
else
    red "a wrong image was kept or left behind (exit ${RC}): ${OUT}; $(find "$STORE" -name '*.new')"
fi

payload "${W}/p3" "$R1" viewer "an image" "$(hex c)"
rm "${W}/p3/viewer.img.zst"
sed -i '/ viewer.img.zst$/d' "${W}/p3/manifest"
stage "${W}/p3" "$R1"
[[ "$RC" -ne 0 && "$OUT" == *"REFUSED: the list names image viewer, and the payload does not carry viewer.img.zst"* ]] \
    && green "a list naming an image the payload does not carry is refused" || red "a missing image was not refused: ${OUT}"

payload "${W}/p4" "$R1" viewer "an image" "$(hex c)"
printf '\n' >> "${W}/p4/images.manifest"
stage "${W}/p4" "$R1"
[[ "$RC" -ne 0 && "$OUT" == *"REFUSED: the image list changed after the manifest was checked"* ]] \
    && green "a list that is not the one the release manifest hashed is refused" || red "a changed list was not refused: ${OUT}"

payload "${W}/p5" "$R1" "../x" "an image" "$(hex c)"
stage "${W}/p5" "$R1"
[[ "$RC" -ne 0 && "$OUT" == *"REFUSED: the image list names '../x'"* ]] \
    && green "an image name that is not a plain name is refused" || red "a name with a path was not refused: ${OUT}"

# The reader stops one byte past the signed size, so a file swapped after the manifest's check
# cannot decompress into the store without end.
head -c 300000 /dev/zero > "${W}/big"
zstd -q -f "${W}/big" -o "${W}/p1/huge.img.zst"
got="$(dir="${W}/p1" bash -c ". '${W}/lib.sh'; payload_image huge 1000" | wc -c)"
[[ "$got" -eq 1001 ]] && green "the payload's reader stops one byte past the size the list signs" \
    || red "the payload's reader gave ${got} bytes for an image signed as 1000"

# A refusal partway takes the copies already made with it.
rm -rf "${W}/p6"; mkdir -p "${W}/p6"
printf 'first' > "${W}/raw-a"; printf 'second' > "${W}/raw-z"
zstd -q -f "${W}/raw-a" -o "${W}/p6/alpha.img.zst"; zstd -q -f "${W}/raw-z" -o "${W}/p6/zeta.img.zst"
{
    printf 'KRYPTIK-IMAGES-1\nrelease: 1.2.0\nbase: %s\n' "$R1"
    printf 'image: alpha 1 bytes=5 sha256=%s data-blocks=1 root-hash=%s salt=%s\n' "$(sha256sum "${W}/raw-a" | cut -c1-64)" "$(hex 6)" "$(hex a)"
    printf 'image: zeta 1 bytes=6 sha256=%s data-blocks=1 root-hash=%s salt=%s\n' "$(hex 0)" "$(hex 7)" "$(hex a)"
} > "${W}/p6/images.manifest"
printf 'a signature\n' > "${W}/p6/images.manifest.sig"
{
    printf 'KRYPTIK-MANIFEST-1\n--\n'
    for f in images.manifest images.manifest.sig alpha.img.zst zeta.img.zst; do
        printf '%s %s %s\n' "$(sha256sum "${W}/p6/$f" | cut -c1-64)" "$(stat -c %s "${W}/p6/$f")" "$f"
    done
} > "${W}/p6/manifest"
stage "${W}/p6" "$R1"
if [[ "$RC" -ne 0 && "$OUT" == *"REFUSED: image zeta is not the bytes its list signs"* && "$OUT" == *"image alpha: kept and checked"* ]] \
   && [[ -z "$(find "$STORE" -name '*.new')" && ! -e "${STORE}/alpha/$(hex 6).img" ]]; then
    green "a refusal partway removes the copies already made, and keeps none of them"
else
    red "a refusal partway left copies behind (exit ${RC}): ${OUT}; $(find "$STORE" -name '*.new')"
fi

# prune: three roots' lists, an image shared by two of them, and a leftover .new.
payload "${W}/q2" "$R2" probe "the probe image" "$(hex b)"; stage "${W}/q2" "$R2"
payload "${W}/q3" "$R3" viewer "only the third root's" "$(hex d)"; stage "${W}/q3" "$R3"
: > "${STORE}/probe/$(hex e).img.new"
( . "${W}/lib.sh"; images_prune "$STORE" "$R1" "$R2" )
if [[ -f "${STORE}/${R1}.manifest" && -f "${STORE}/${R2}.manifest.sig" && ! -e "${STORE}/${R3}.manifest" && ! -e "${STORE}/${R3}.manifest.sig" ]] \
   && [[ -f "${STORE}/probe/$(hex b).img" && ! -e "${STORE}/viewer/$(hex d).img" && ! -e "${STORE}/probe/$(hex e).img.new" ]]; then
    green "pruning keeps the two roots' lists and the images they name, and nothing else"
else
    red "pruning kept or removed the wrong files: $(cd "$STORE" && find . -type f | sort | tr '\n' ' ')"
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
