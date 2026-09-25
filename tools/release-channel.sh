#!/usr/bin/env bash
# Publish a release into an update channel's directory, and sign the channel's
# statement of what is current again (docs/design/update-channel.md).
#
#   ./tools/release-channel.sh publish --key KEY --signers FILE --payload DIR
#                                      --out CHANNEL [--issued DATE]
#   ./tools/release-channel.sh reissue --key KEY --signers FILE
#                                      [--issued DATE] CHANNEL
#
# CHANNEL is served as it stands: latest, latest.sig, and one directory per
# version, which the statement's base names. KEY is the kryptik-latest key,
# passed to ssh-keygen by path and never read here; SIGNERS is the anchor the
# image carries, and every statement is checked against it as a client would.
# DATE defaults to now, as YYYY-MM-DDTHH:MM:SS+00:00. The payload's files are
# hard-linked where the filesystem allows, so a file in DIR must never be
# rewritten in place afterwards; replace DIR whole, as stage 06 does.
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

MANIFEST_TOOL="$(dirname "${BASH_SOURCE[0]}")/release-manifest.sh"
POINTER_NAMESPACE="kryptik-latest"

usage() { sed -n '2,16p' "${BASH_SOURCE[0]}"; }
[[ "$#" -gt 0 ]] || { usage; exit 1; }
MODE="$1"; shift
for t in ssh-keygen flock sha256sum; do have "$t" || die "${t} not found"; done

field() {   # field FILE KEY: the value of a "KEY: value" line
    awk -F': ' -v k="$2" '$1 == k { print $2; exit }' "$1"
}

statement_ok() {   # statement_ok FILE SIGNERS: does FILE.sig verify as a client checks it?
    ssh-keygen -Y verify -f "$2" -I "$POINTER_NAMESPACE" -n "$POINTER_NAMESPACE" \
        -s "$1.sig" < "$1" > /dev/null 2>&1
}

# One run at a time per channel, from reading its statement to replacing it:
# a reissue finishing after a publish would name the older release again.
lock_channel() {
    exec 9< "$1"
    flock -n 9 || die "another publish or reissue is running on $1"
}

# Sign a statement for MANIFEST under BASE, check it as a client would, and
# only then rename it into place. Anything that fails leaves the old pair.
install_statement() {   # install_statement CHANNEL MANIFEST BASE KEY SIGNERS ISSUED
    local chan="$1" manifest="$2" base="$3" key="$4" signers="$5" issued="$6"
    issued="${issued:-$(date -u +%Y-%m-%dT%H:%M:%S+00:00)}"
    # The forms zone 0 reads (parse_iso8601 in kryptikd's time.rs).
    local form='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$'
    [[ "$issued" =~ $form ]] || die "--issued ${issued} is not YYYY-MM-DDTHH:MM:SS with Z or +HH:MM"
    local now was
    now="$(date -u -d "$issued" +%s 2>/dev/null)" || die "--issued ${issued} is not a date"
    # Clients refuse a statement dated more than a day ahead of their clock,
    # and one issued before the newest they accepted.
    (( now <= $(date -u +%s) + 86400 )) || die "${issued} is more than a day ahead; clients would refuse it"
    if [[ -f "${chan}/latest" ]]; then
        was="$(date -u -d "$(field "${chan}/latest" issued)" +%s 2>/dev/null)" \
            || die "${chan}/latest carries no date"
        (( now >= was )) || die "${issued} is before the current statement's; clients would refuse it as a replay"
    fi
    local new="${chan}/.latest.new"
    rm -f "$new" "${new}.sig"
    "$MANIFEST_TOOL" pointer --key "$key" --manifest "$manifest" --signers "$signers" \
        --base "$base" --out "$new" --issued "$issued" > /dev/null \
        || { rm -f "$new" "${new}.sig"; die "no statement was made; ${chan}/latest is unchanged"; }
    if ! statement_ok "$new" "$signers"; then
        rm -f "$new" "${new}.sig"
        die "the new statement does not verify against ${signers}; ${chan}/latest is unchanged"
    fi
    # Two renames: a client reading between them gets a pair that does not
    # verify, refuses it, and asks again at its next poll.
    mv -f "${new}.sig" "${chan}/latest.sig"
    mv -f "$new" "${chan}/latest"
    ok "${chan}/latest names $(field "${chan}/latest" version), issued ${issued}"
}

do_publish() {
    local key="" signers="" payload="" out="" issued=""
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --key)     key="${2:?--key needs a file}"; shift 2 ;;
            --signers) signers="${2:?--signers needs a file}"; shift 2 ;;
            --payload) payload="${2:?--payload needs a directory}"; shift 2 ;;
            --out)     out="${2:?--out needs a directory}"; shift 2 ;;
            --issued)  issued="${2:?--issued needs a date}"; shift 2 ;;
            *) die "publish: unknown argument: $1" ;;
        esac
    done
    [[ -f "$key" && -f "$signers" ]] || die "publish: --key and --signers are required and must exist"
    [[ -f "${payload}/manifest" && -f "${payload}/manifest.sig" ]] \
        || die "publish: ${payload} holds no signed manifest"
    [[ -n "$out" ]] || die "publish: --out is required"
    mkdir -p "$out"
    lock_channel "$out"

    local cur=""
    if [[ -f "${out}/latest" ]]; then
        statement_ok "${out}/latest" "$signers" || die "publish: ${out}/latest does not verify against ${signers}"
        cur="$(field "${out}/latest" version)"
    fi
    # Verified as the image verifies it, and refused if older than what the
    # channel names (sort -V order, which zone 0's version_cmp mirrors).
    "$MANIFEST_TOOL" verify --signers "$signers" --principal kryptik-release \
        --root "$payload" --exact --strict ${cur:+--no-downgrade "$cur"} "${payload}/manifest" \
        || die "publish: ${payload} does not verify; nothing was published"
    local version
    version="$(field "${payload}/manifest" version)"
    [[ -n "$version" && "$version" != */* && "$version" != .* ]] || die "publish: the manifest names no usable version"

    local dir="${out}/${version}"
    if [[ -e "$dir" ]]; then
        # A published version never changes: a client may be part way through it.
        cmp -s "${payload}/manifest" "${dir}/manifest" \
            || die "publish: ${version} is already published with another manifest"
    else
        local tmp="${out}/.${version}.new" f
        rm -rf "$tmp"; mkdir -p "$tmp"
        while IFS= read -r f; do
            mkdir -p "${tmp}/$(dirname "$f")"
            # A link where the filesystem allows one: the images are gigabytes.
            ln "${payload}/${f}" "${tmp}/${f}" 2>/dev/null || cp --sparse=always "${payload}/${f}" "${tmp}/${f}"
        done < <(cd "$payload" && find . -type f -printf '%P\n')
        mv "$tmp" "$dir"
    fi
    install_statement "$out" "${dir}/manifest" "${version}/" "$key" "$signers" "$issued"
}

do_reissue() {
    local key="" signers="" issued="" chan=""
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --key)     key="${2:?--key needs a file}"; shift 2 ;;
            --signers) signers="${2:?--signers needs a file}"; shift 2 ;;
            --issued)  issued="${2:?--issued needs a date}"; shift 2 ;;
            -*) die "reissue: unknown argument: $1" ;;
            *)  chan="$1"; shift ;;
        esac
    done
    [[ -f "$key" && -f "$signers" ]] || die "reissue: --key and --signers are required and must exist"
    [[ -f "${chan}/latest" ]] || die "reissue: ${chan:-CHANNEL} has no statement to sign again"
    lock_channel "$chan"
    # Only what already verifies is signed again, so a tampered channel stays refused.
    statement_ok "${chan}/latest" "$signers" || die "reissue: ${chan}/latest does not verify against ${signers}"
    local base; base="$(field "${chan}/latest" base)"
    [[ "$base" != *://* ]] || die "reissue: ${chan}/latest names an absolute base (${base}); only a relative one can be checked here"
    # The same manifest, so the new statement differs from the old only in its date.
    [[ -f "${chan}/${base}manifest" \
        && "$(sha256sum "${chan}/${base}manifest" | cut -c1-64)" == "$(field "${chan}/latest" manifest-sha256)" ]] \
        || die "reissue: ${chan}/${base}manifest is not the manifest the statement names"
    install_statement "$chan" "${chan}/${base}manifest" "$base" "$key" "$signers" "$issued"
}

case "$MODE" in
    publish) do_publish "$@" ;;
    reissue) do_reissue "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown mode '${MODE}' (expected publish or reissue)" ;;
esac
