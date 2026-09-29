#!/usr/bin/env bash
# The update channel on GitHub: the statement of what is current on the
# repository's Pages site, the payload among the release's files, the
# statement key in a repository secret (docs/design/update-channel.md).
#
#   tools/channel-host.sh publish --release TAG --key FILE --site DIR [--channel NAME] [--repo OWNER/NAME]
#   tools/channel-host.sh reissue --key FILE --site DIR [--channel NAME] [--repo OWNER/NAME]
#   tools/channel-host.sh dry-run --site DIR [--channel NAME]
#
# SITE is the directory Pages serves; a channel is SITE/NAME (stable unless
# --channel says). Every mode first mirrors the statements the site serves
# now, so a deployment of SITE keeps every channel and a date only moves
# forward. publish takes the release's payload and anchor from the page,
# verifies the payload as the image will, and writes a statement whose base
# is the release's download address. reissue signs the current statement
# again, against the manifest that release serves. dry-run makes throwaway
# keys and a stand-in release under SITE and runs publish and reissue on them:
# no gh, no network, the same code.
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

usage() { sed -n '2,18p' "${BASH_SOURCE[0]}"; }
CHANNEL_TOOL="${KRYPTIK_ROOT}/tools/release-channel.sh"
MANIFEST_TOOL="${KRYPTIK_ROOT}/tools/release-manifest.sh"
PAYLOAD_FILES=(kryptik-root.img kryptik-a.efi kryptik-b.efi root.json manifest manifest.sig)
CHANNELS=(stable test)

MODE="${1:-}"; shift || true
RELEASE="" KEY="" SITE="" CHANNEL=stable REPO=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --release) RELEASE="${2:?--release needs a tag}"; shift 2 ;;
        --key)     KEY="${2:?--key needs a file}"; shift 2 ;;
        --site)    SITE="${2:?--site needs a directory}"; shift 2 ;;
        --channel) CHANNEL="${2:?--channel needs a name}"; shift 2 ;;
        --repo)    REPO="${2:?--repo needs OWNER/NAME}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
case "$MODE" in
    publish|reissue|dry-run) ;;
    -h|--help|help) usage; exit 0 ;;
    "") usage; exit 1 ;;
    *) die "unknown mode '${MODE}' (publish, reissue or dry-run)" ;;
esac
[[ -n "$SITE" ]] || die "--site is required"
[[ "$CHANNEL" =~ ^[a-z][a-z0-9-]*$ ]] || die "a channel name is lowercase letters, digits and dashes: ${CHANNEL}"
for t in ssh-keygen sha256sum curl; do have "$t" || die "${t} is required"; done
mkdir -p "${SITE}/${CHANNEL}"
: > "${SITE}/.nojekyll"

# --- what the site serves now ------------------------------------------------------
# The page's address, for the statements the site serves and the release
# files. A dry run without gh or a repository is the offline test and mirrors
# nothing; one with them mirrors, so its deployment keeps the other channels.
SITE_URL=""; DOWNLOAD=""
if [[ "$MODE" != dry-run ]] || { [[ -n "$REPO" ]] && have gh; }; then
    have gh || die "gh (GitHub's command line) fetches the release; dry-run does without it"
    [[ -n "$REPO" ]] || REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)" || die "no repository: give --repo"
    SITE_URL="$(gh api "repos/${REPO}/pages" --jq .html_url 2>/dev/null)" || die "${REPO} has no Pages site; enable it with deployments from a workflow"
    SITE_URL="${SITE_URL%/}/"
    DOWNLOAD="https://github.com/${REPO}/releases/download"
fi

mirror() {   # mirror NAME: the statement the site serves for channel NAME, if any
    local c="$1" f
    [[ -n "$SITE_URL" ]] || return 0
    for f in latest latest.sig; do
        if curl -fsSL --retry 3 -o "${SITE}/${c}/${f}.now" "${SITE_URL}${c}/${f}" 2>/dev/null; then
            mv -f "${SITE}/${c}/${f}.now" "${SITE}/${c}/${f}"
        else
            rm -f "${SITE}/${c}/${f}.now"
        fi
    done
    if [[ -f "${SITE}/${c}/latest" && ! -f "${SITE}/${c}/latest.sig" ]]; then
        die "${SITE_URL}${c}/latest is served without its signature; the site is broken, not to be built on"
    fi
}
for c in "${CHANNELS[@]}"; do mkdir -p "${SITE}/${c}"; mirror "$c"; done
# A channel left empty is not deployed as an empty directory.
for c in "${CHANNELS[@]}"; do [[ -f "${SITE}/${c}/latest" || "$c" == "$CHANNEL" ]] || rmdir "${SITE}/${c}"; done

field() { awk -F': ' -v k="$2" '$1 == k { print $2; exit }' "$1"; }

fetch_release() {   # fetch_release TAG DIR NAME...: the release's files, from the page
    local tag="$1" dir="$2"; shift 2
    mkdir -p "$dir"
    local n
    for n in "$@"; do
        gh release download "$tag" --repo "$REPO" --pattern "$n" --dir "$dir" --clobber \
            || die "release ${tag} has no ${n}; publish it with tools/release-publish.sh first"
    done
}

# --- the modes ---------------------------------------------------------------------
publish() {   # publish TAG PAYLOAD SIGNERS BASE: the statement, from a verified payload served at BASE
    local tag="$1" payload="$2" signers="$3" base="$4"
    local version; version="$(field "${payload}/manifest" version)"
    [[ "$tag" == "v${version}" ]] || die "release ${tag} carries a manifest of ${version}"
    "$CHANNEL_TOOL" publish --key "$KEY" --signers "$signers" --payload "$payload" \
        --out "${SITE}/${CHANNEL}" --base "$base"
}

reissue() {   # reissue SIGNERS MANIFEST: the current statement, signed again
    "$CHANNEL_TOOL" reissue --key "$KEY" --signers "$1" --manifest "$2" "${SITE}/${CHANNEL}"
}

case "$MODE" in
    publish)
        [[ -n "$RELEASE" && -f "$KEY" ]] || die "publish: --release and --key are required"
        dl="$(mktemp -d)"; trap 'rm -rf "$dl"' EXIT
        fetch_release "$RELEASE" "$dl" "${PAYLOAD_FILES[@]}" release-signers
        publish "$RELEASE" "$dl" "${dl}/release-signers" "${DOWNLOAD}/${RELEASE}/"
        ;;
    reissue)
        [[ -f "$KEY" ]] || die "reissue: --key is required"
        [[ -f "${SITE}/${CHANNEL}/latest" ]] || die "reissue: ${SITE_URL}${CHANNEL}/ serves no statement to sign again"
        version="$(field "${SITE}/${CHANNEL}/latest" version)"
        dl="$(mktemp -d)"; trap 'rm -rf "$dl"' EXIT
        fetch_release "v${version}" "$dl" manifest release-signers
        reissue "${dl}/release-signers" "${dl}/manifest"
        ;;
    dry-run)
        # Throwaway keys and a stand-in release, all under the site, so the
        # only thing left afterwards is the channel's statement.
        [[ "$CHANNEL" != stable ]] || die "dry-run: not on stable; give --channel test"
        w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
        ssh-keygen -q -t ed25519 -N '' -C kryptik-release -f "${w}/release" < /dev/null
        ssh-keygen -q -t ed25519 -N '' -C kryptik-latest -f "${w}/latest" < /dev/null
        {
            printf 'kryptik-release namespaces="kryptik-release,kryptik-media" %s\n' "$(cut -d' ' -f1,2 "${w}/release.pub")"
            printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 "${w}/latest.pub")"
        } > "${w}/release-signers"
        KEY="${w}/latest"
        p="${w}/payload"; mkdir -p "$p"
        printf 'a stand-in root image\n' > "${p}/kryptik-root.img"
        printf 'a stand-in kernel, slot a\n' > "${p}/kryptik-a.efi"
        printf 'a stand-in kernel, slot b\n' > "${p}/kryptik-b.efi"
        printf '{"root_hash": "00"}\n' > "${p}/root.json"
        "$MANIFEST_TOOL" create --out "${p}/manifest" --name kryptik --version 0.0.1 --role production \
            --root "$p" kryptik-root.img kryptik-a.efi kryptik-b.efi root.json > /dev/null
        "$MANIFEST_TOOL" sign --key "${w}/release" "${p}/manifest" > /dev/null
        base="https://example.invalid/releases/download/v0.0.1/"
        publish v0.0.1 "$p" "${w}/release-signers" "$base"
        reissue "${w}/release-signers" "${p}/manifest"
        ok "dry run: ${SITE}/${CHANNEL}/latest names $(field "${SITE}/${CHANNEL}/latest" version) at ${base}, signed by a throwaway key and signed again"
        ;;
esac
