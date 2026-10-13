#!/usr/bin/env bash
# Tests for kryptik-update's check-images, offline, with throwaway ed25519 keys: an image list
# passes in its own namespace, signed by the release key, and as a KRYPTIK-IMAGES-1 alone.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UPD="${ROOT}/tools/update/kryptik-update"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen required"; exit 1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

for k in rel latest; do
    ssh-keygen -q -t ed25519 -N '' -C "$k" -f "${W}/${k}" </dev/null
    [[ -s "${W}/${k}" ]] || { echo "FATAL: ssh-keygen did not make ${W}/${k}" >&2; exit 1; }
done
ANCHOR="${W}/anchor"
{
    printf 'kryptik-release namespaces="kryptik-release,kryptik-media,kryptik-image" %s\n' "$(cut -d' ' -f1,2 < "${W}/rel.pub")"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 < "${W}/latest.pub")"
} > "$ANCHOR"

# The updater's own check, lifted out of the tool as release-manifest.sh lifts check-pointer.
{
    echo 'IMAGE_NAMESPACE=kryptik-image'; echo 'IMAGES_MAGIC=KRYPTIK-IMAGES-1'
    echo "SIGNERS=${ANCHOR}"
    echo 'say() { printf "%s\n" "$*"; }'
    echo 'die() { printf "REFUSED: %s\n" "$*"; exit 1; }'
    sed -n '/^verify_signed() {/,/^}/p' "$UPD"
    sed -n '/^cmd_check_images() {/,/^}/p' "$UPD"
    printf 'SNAP=%q\n' "${W}/snap"; echo 'mkdir -p "$SNAP"'
    echo 'cmd_check_images "$1" && echo ACCEPTED'
} > "${W}/check-images.sh"
grep -q '^cmd_check_images() {' "${W}/check-images.sh" || { echo "FATAL: no cmd_check_images in ${UPD}" >&2; exit 1; }

# A list in DIR signed with KEY in NAMESPACE, its first line FIRST.
list() {   # list DIR KEY NAMESPACE [FIRST]
    mkdir -p "$1"
    printf '%s\nrelease: 1.2.0\nbase: %064d\nimage: probe 1 bytes=8192 sha256=%064d data-blocks=1 root-hash=%064d salt=%064d\n' \
        "${4:-KRYPTIK-IMAGES-1}" 0 0 0 0 > "$1/manifest"
    ssh-keygen -Y sign -f "$2" -n "$3" "$1/manifest" </dev/null >/dev/null 2>&1
    [[ -s "$1/manifest.sig" ]] || { echo "FATAL: could not sign $1/manifest" >&2; exit 1; }
}
# Captured whole: under pipefail a refusal's exit 1 would fail a pipe to grep.
said() { bash "${W}/check-images.sh" "$1" 2>&1; }

list "${W}/good" "${W}/rel" kryptik-image
out="$(said "${W}/good")"
[[ "$out" == *ACCEPTED* ]] && green "a list the release key signs in kryptik-image is accepted" \
    || red "a list signed as it should be was refused: ${out}"

list "${W}/as-release" "${W}/rel" kryptik-release
out="$(said "${W}/as-release")"
[[ "$out" == *"REFUSED:"*"does NOT verify"* && "$out" != *ACCEPTED* ]] \
    && green "a list signed in kryptik-release is refused: a release manifest's signature does not pass for a list's" \
    || red "a list signed in kryptik-release was not refused: ${out}"

list "${W}/by-latest" "${W}/latest" kryptik-image
out="$(said "${W}/by-latest")"
[[ "$out" == *"REFUSED:"*"does NOT verify"* && "$out" != *ACCEPTED* ]] \
    && green "a list the statement key signs is refused: the anchor gives kryptik-image to the release key alone" \
    || red "a list signed by the statement key was not refused: ${out}"

list "${W}/manifest" "${W}/rel" kryptik-image KRYPTIK-MANIFEST-1
out="$(said "${W}/manifest")"
[[ "$out" == *"REFUSED: the image list is not a KRYPTIK-IMAGES-1"* ]] \
    && green "a signed file that is not an image list is refused" \
    || red "a signed file of another kind was not refused as such: ${out}"

# The same good list, under an anchor that grants the release key the older namespaces only.
sed -i 's/,kryptik-image"/"/' "$ANCHOR"
out="$(said "${W}/good")"
[[ "$out" == *"REFUSED:"* && "$out" != *ACCEPTED* ]] \
    && green "under an anchor without kryptik-image, the same list is refused" \
    || red "a list passed under an anchor that does not grant its namespace: ${out}"

# kryptikd runs the verb as nobody; the tool refuses it as root, as it refuses the other checks.
if grep -q '^    check-manifest|check-pointer|check-release|check-images)$' "$UPD" \
   && grep -q '^    check-images)   shift; cmd_check_images "\$@" ;;$' "$UPD"; then
    green "check-images is one of the checks that never run as root, and the tool dispatches it"
else
    red "check-images is missing from kryptik-update's checks or its dispatcher"
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
