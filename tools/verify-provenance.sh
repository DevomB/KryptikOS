#!/usr/bin/env bash
# Verify sources that publish no detached GPG signature, by other means.
#
#   ./tools/verify-provenance.sh
#
# tools/verify-signatures.sh handles anything with a .sig/.asc/.sign. This
# handles the rest — and "the rest" happens to include the two most
# security-critical components in the tree, which is why it exists:
#
#   hardened_malloc  the system allocator (ADR-005)
#   the s6 stack     PID 1 and the service supervisor (ADR-006)
#
# Two independent mechanisms:
#
#   1. Signed git tags. GrapheneOS GPG-signs hardened_malloc release tags. The
#      GitHub source ARCHIVE is unsigned, but the tag it is generated from is
#      not, so the signature on the tag covers the tree the archive contains.
#
#   2. Publisher-published checksums. skarnet ships a .tar.gz.sha256 next to
#      each release. Comparing that against sources.lock is a genuinely
#      independent confirmation of the bytes: the lock records what Kryptik
#      downloaded, the .sha256 records what the publisher intended.
#
# Neither replaces a GPG signature over the artifact. Both are materially
# better than trust-on-first-use, and both are stated for what they are.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

VERIFIED=0
FAILED=0
SKIPPED=0
declare -a FAILED_LIST=()

lock_hash_for() {
    [[ -f "$KRYPTIK_LOCK" ]] || return 1
    awk -v f="$1" '$2 == f { print $1; found=1 } END { exit !found }' "$KRYPTIK_LOCK"
}

# --- 1. signed git tags -----------------------------------------------------

verify_signed_tag() {
    local repo="$1" tag="$2" label="$3"

    if ! have gh; then
        warn "${label}: gh CLI not available; cannot check the tag signature"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    local sha
    sha="$(gh api "repos/${repo}/git/ref/tags/${tag}" --jq '.object.sha' 2>/dev/null)" || {
        warn "${label}: could not resolve tag ${tag}"
        SKIPPED=$((SKIPPED + 1))
        return
    }

    # A lightweight tag points straight at a commit and cannot carry a
    # signature of its own. Only an annotated tag object can be signed.
    local objtype
    objtype="$(gh api "repos/${repo}/git/ref/tags/${tag}" --jq '.object.type' 2>/dev/null)"
    if [[ "$objtype" != "tag" ]]; then
        err "${label}: tag ${tag} is lightweight, so it carries no signature"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("${label} (unsigned tag)")
        return
    fi

    local verified reason tagger
    verified="$(gh api "repos/${repo}/git/tags/${sha}" --jq '.verification.verified' 2>/dev/null)"
    reason="$(gh api "repos/${repo}/git/tags/${sha}" --jq '.verification.reason' 2>/dev/null)"
    tagger="$(gh api "repos/${repo}/git/tags/${sha}" --jq '.tagger.name' 2>/dev/null)"

    if [[ "$verified" == "true" ]]; then
        ok "${label}: tag ${tag} GPG-signed by ${tagger} (${reason})"
        VERIFIED=$((VERIFIED + 1))
    else
        err "${label}: tag ${tag} signature NOT verified (${reason:-unknown})"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("${label} (bad tag signature)")
    fi
}

# --- 2. publisher-published checksums ---------------------------------------

verify_published_sha256() {
    local url="$1" label="$2"
    local file; file="$(basename "$url")"

    local expected
    expected="$(curl -fsSL --max-time 30 "${url}.sha256" 2>/dev/null | awk '{print $1}' | head -1)" || true
    if [[ -z "$expected" ]]; then
        warn "${label}: publisher does not publish a .sha256 for this version"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    local locked
    if ! locked="$(lock_hash_for "$file")"; then
        warn "${label}: not in sources.lock"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    if [[ "$expected" == "$locked" ]]; then
        ok "${label}: publisher sha256 matches sources.lock"
        VERIFIED=$((VERIFIED + 1))
    else
        err "${label}: CHECKSUM MISMATCH"
        err "  publisher says ${expected}"
        err "  sources.lock   ${locked}"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("${label} (checksum mismatch)")
    fi
}

# --- run --------------------------------------------------------------------

log "Verifying provenance of sources without detached signatures"
echo

log "Signed git tags"
verify_signed_tag "GrapheneOS/hardened_malloc" "${V_HARDENED_MALLOC}" \
    "hardened_malloc (system allocator)"

echo
log "Publisher-published checksums"
verify_published_sha256 \
    "https://skarnet.org/software/skalibs/skalibs-${V_SKALIBS}.tar.gz" "skalibs"
verify_published_sha256 \
    "https://skarnet.org/software/execline/execline-${V_EXECLINE}.tar.gz" "execline"
verify_published_sha256 \
    "https://skarnet.org/software/s6/s6-${V_S6}.tar.gz" "s6 (PID 1)"
verify_published_sha256 \
    "https://skarnet.org/software/s6-rc/s6-rc-${V_S6_RC}.tar.gz" "s6-rc"
verify_published_sha256 \
    "https://skarnet.org/software/s6-linux-init/s6-linux-init-${V_S6_LINUX_INIT}.tar.gz" \
    "s6-linux-init"

echo
log "Summary"
ok "verified: ${VERIFIED}"
[[ "$SKIPPED" -gt 0 ]] && warn "skipped:  ${SKIPPED}"
if [[ "$FAILED" -gt 0 ]]; then
    err "FAILED:   ${FAILED}"
    echo
    printf '  - %s\n' "${FAILED_LIST[@]}" >&2
    die "Provenance check failed. Do not build from these sources."
fi

echo
dim "Note: a signed tag covers the tree a GitHub archive is generated from,"
dim "and a publisher checksum confirms the bytes independently of the lock."
dim "Neither is a GPG signature over the artifact itself. Both beat TOFU."
