#!/usr/bin/env bash
# Publish a tested release on the repository's Releases page, from the
# directory `make acceptance EXPORT=DIR` wrote (docs/releases.md).
#
#   ./tools/release-publish.sh EXPORT [--source-bundle FILE] [--repo OWNER/NAME]
#                              [--publish] [--stage DIR]
#
# The export is checked as a download is: the media's checksums against their
# signature and the anchor the image carries, then every file against them and
# against the record's SHA256SUMS. Only a PASS verdict is published, and only
# with tag v<version> at the tested revision. The two images go up compressed
# (a release file is capped at 2 GiB), so the notes gain a table of the
# uploaded files' hashes; the signed checksums stay the authority for what
# zstd -d restores. A development release is marked a pre-release. The release
# is a draft until --publish. --stage DIR writes the assets and the notes there
# and calls GitHub not at all.
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

usage() { sed -n '2,16p' "${BASH_SOURCE[0]}"; }

EXPORT="" BUNDLE="" REPO="" PUBLISH=0 STAGE=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --source-bundle) BUNDLE="${2:?--source-bundle needs a file}"; shift 2 ;;
        --repo)          REPO="${2:?--repo needs OWNER/NAME}"; shift 2 ;;
        --publish)       PUBLISH=1; shift ;;
        --stage)         STAGE="${2:?--stage needs a directory}"; shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        -*)              die "unknown argument: $1" ;;
        *)               [[ -z "$EXPORT" ]] || die "one export directory, not two"; EXPORT="$1"; shift ;;
    esac
done
[[ -n "$EXPORT" ]] || { usage; exit 1; }
[[ -d "$EXPORT" ]] || die "${EXPORT} is not a directory"
for t in ssh-keygen sha256sum zstd git numfmt tar; do have "$t" || die "${t} is required"; done
[[ -n "$STAGE" ]] || have gh || die "gh (GitHub's command line) creates the release; --stage DIR does without it"
[[ -z "$BUNDLE" || -f "$BUNDLE" ]] || die "no source bundle at ${BUNDLE}"

# --- the release the export stands for -----------------------------------------
[[ -f "${EXPORT}/RELEASE.txt" ]] || die "no RELEASE.txt in ${EXPORT}: give the directory make acceptance exported"
VERSION="$(sed -n '1s/^Kryptik //p' "${EXPORT}/RELEASE.txt")"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}$ ]] \
    || die "the export is of ${VERSION:-no version}: a release on the page is numbered MAJOR.MINOR.PATCH (docs/release-keys.md), and a dated build is not one"
VERDICT="$(sed -n 's/^acceptance *: *\([A-Z]*\).*/\1/p' "${EXPORT}/RELEASE.txt")"
[[ "$VERDICT" == PASS ]] || die "the export's verdict is ${VERDICT:-missing}: only a release every suite passed goes on the page"
REV="$(sed -n 's/^revision *: *\([0-9a-f]\{40\}\).*/\1/p' "${EXPORT}/RELEASE.txt")"
[[ -n "$REV" ]] || die "RELEASE.txt names no revision"
USB="kryptik-${VERSION}-usb.img"; ISO="kryptik-${VERSION}.iso"; SUMS="kryptik-${VERSION}.SHA256SUMS"
MANIFEST="manifest-${VERSION}"
RECORD=("$SUMS" "${SUMS}.sig" release-signers kryptik-sb.crt kryptik-sb.der root.json "$MANIFEST" "${MANIFEST}.sig"
        RELEASE.txt REVISION.txt RELEASE-NOTES.md INSTRUCTIONS.md ACCEPTANCE-REPORT.md SHA256SUMS)
for f in "$USB" "$ISO" "${RECORD[@]}"; do [[ -f "${EXPORT}/${f}" ]] || die "no ${f} in ${EXPORT}"; done
ROLE="$(awk -F': ' '$1 == "role" { print $2; exit }' "${EXPORT}/${MANIFEST}")"
case "$ROLE" in
    production)  KIND=release ;;
    development) KIND=pre-release ;;
    *) die "${MANIFEST} names no role" ;;
esac
TAG="v${VERSION}"

# --- checked as a download is, and against the tag -----------------------------
log "Checking ${EXPORT} as a download is checked"
( cd "$EXPORT" \
  && ssh-keygen -Y verify -f release-signers -I kryptik-release -n kryptik-media -s "${SUMS}.sig" < "$SUMS" > /dev/null \
  && sha256sum --quiet -c "$SUMS" \
  && sha256sum --quiet -c SHA256SUMS ) || die "${EXPORT} does not check out; nothing of it is published"
ok "the media's checksums carry the release key's signature, and every file hashes as recorded"
TOP="$(cd "$KRYPTIK_ROOT" && pwd -P)"
g() { git -c safe.directory="$TOP" -C "$TOP" "$@"; }
at="$(g rev-parse "refs/tags/${TAG}^{commit}" 2>/dev/null)" \
    || die "no tag ${TAG} here: tag the tested revision ${REV:0:12} and push the tag first (docs/releases.md)"
[[ "$at" == "$REV" ]] || die "tag ${TAG} is at ${at:0:12}, and the run tested ${REV:0:12}: a release is of the revision its tag names"
ok "${TAG} is at the tested revision, ${REV:0:12}"

# --- the files as they go up ----------------------------------------------------
if [[ -n "$STAGE" ]]; then
    OUT="$STAGE"; mkdir -p "$OUT"
    [[ -z "$(ls -A "$OUT")" ]] || die "${OUT} is not empty"
else
    OUT="$(mktemp -d "${TMPDIR:-/tmp}/kryptik-release.XXXXXX")"
    trap 'rm -rf "$OUT"' EXIT
fi
ASSETS=()
log "Compressing the images"
for f in "$USB" "$ISO"; do
    zstd -q -T0 -19 --long "${EXPORT}/${f}" -o "${OUT}/${f}.zst"
    ASSETS+=("${f}.zst")
done
for f in "${RECORD[@]}"; do cp "${EXPORT}/${f}" "${OUT}/"; ASSETS+=("$f"); done
if [[ -n "$BUNDLE" ]]; then
    # Under the name the notes give it.
    ln "$BUNDLE" "${OUT}/source-${REV:0:12}.tar" 2>/dev/null || cp "$BUNDLE" "${OUT}/source-${REV:0:12}.tar"
    ASSETS+=("source-${REV:0:12}.tar")
fi
if [[ -d "${EXPORT}/acceptance-logs" ]]; then
    tar -C "$EXPORT" -I 'zstd -q -T0 -19' -cf "${OUT}/kryptik-${VERSION}-acceptance-logs.tar.zst" acceptance-logs
    ASSETS+=("kryptik-${VERSION}-acceptance-logs.tar.zst")
fi
{
    cat "${EXPORT}/RELEASE-NOTES.md"
    printf '\n## Downloads\n\n'
    printf 'The two images are compressed for the download: `zstd -d` restores the files the signed checksums above cover. The other files are as tested.\n\n'
    printf '| File | Size | SHA-256 as uploaded |\n| --- | --- | --- |\n'
    for f in "${ASSETS[@]}"; do
        printf '| `%s` | %s | `%s` |\n' "$f" "$(stat -c %s "${OUT}/${f}" | numfmt --to=iec-i --suffix=B)" "$(sha256_of "${OUT}/${f}")"
    done
    printf '\nAfter `zstd -d kryptik-%s-usb.img.zst`, check it as `INSTRUCTIONS.md` says:\n\n' "$VERSION"
    printf '```sh\nssh-keygen -Y verify -f release-signers -I kryptik-release -n kryptik-media \\\n    -s kryptik-%s.SHA256SUMS.sig < kryptik-%s.SHA256SUMS\nsha256sum -c kryptik-%s.SHA256SUMS\n```\n' "$VERSION" "$VERSION" "$VERSION"
} > "${OUT}/NOTES.md"
if [[ -n "$STAGE" ]]; then
    ok "staged ${TAG}, a ${KIND}, in ${OUT}: ${#ASSETS[@]} files and NOTES.md"
    exit 0
fi

# --- the page -------------------------------------------------------------------
# gh takes the repository from the git remotes where it runs unless --repo
# names one, and the staged files are outside the checkout.
repo=(); [[ -z "$REPO" ]] || repo=(--repo "$REPO")
ghr() { (cd "$TOP" && gh "$@" "${repo[@]}"); }
! ghr release view "$TAG" > /dev/null 2>&1 || die "${TAG} is already on the page; delete it there, or number the next release"
args=(--title "Kryptik ${VERSION}" --notes-file "${OUT}/NOTES.md" --verify-tag)
[[ "$KIND" != pre-release ]] || args+=(--prerelease)
[[ "$PUBLISH" -eq 1 ]] || args+=(--draft)
uploads=(); for f in "${ASSETS[@]}"; do uploads+=("${OUT}/${f}"); done
log "Creating ${TAG} on GitHub"
ghr release create "$TAG" "${args[@]}" "${uploads[@]}"
ok "${TAG}, a ${KIND}, $([[ "$PUBLISH" -eq 1 ]] && echo published || echo drafted): $(ghr release view "$TAG" --json url --jq .url)"
