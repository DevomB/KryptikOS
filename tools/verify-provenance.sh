#!/usr/bin/env bash
# Verify sources that publish no detached GPG signature, by other means.
#
#   ./tools/verify-provenance.sh            informational
#   ./tools/verify-provenance.sh --strict   release gate
#   ./tools/verify-provenance.sh --offline  do no network work at all
#
# tools/verify-signatures.sh handles anything with a .sig/.asc/.sign. This
# handles the rest - and "the rest" happens to include the two most
# security-critical components in the tree, which is why it exists:
#
#   hardened_malloc  the system allocator (ADR-005)
#   the s6 stack     PID 1 and the service supervisor (ADR-006)
#
# ============================================================================
# FIVE DIFFERENT ASSERTIONS, KEPT APART ON PURPOSE
# ============================================================================
#
# These are not interchangeable, and averaging them into one green tick is how
# a supply chain gets described as verified when it is not. Each check below
# is labelled with which of these it establishes:
#
#   [lock]    LOCKFILE INTEGRITY. The bytes in sources/ hash to what
#             sources.lock records. Proves nothing about authenticity: --lock
#             recorded whatever downloaded. It detects later tampering with a
#             file Kryptik already has, and nothing else.
#
#   [pub]     PUBLISHER CHECKSUM. The publisher's own .sha256 agrees with
#             those bytes. Independent of the lock - the lock says what
#             Kryptik downloaded, the .sha256 says what the publisher
#             intended - but it arrives over the same TLS connection from the
#             same host, so it is not independent of a compromise of that
#             host. It is not a signature: nothing about it is unforgeable by
#             whoever controls the web server.
#
#   [sig]     SIGNED ARTIFACT / SIGNED TAG. A cryptographic signature that
#             verifies. On its own this says only "signed by whoever signed
#             it".
#
#   [id]      SIGNER IDENTITY. That signature was made by the key the
#             publisher names as its own, pinned in this file. A tagger
#             display name proves nothing - it is a free-text field in the
#             tag object - and importing the key that the signature itself
#             names is circular.
#
#   [tree]    AUTHENTICATED SOURCE TREE. The bytes that will actually be
#             built reproduce, object for object, the tree the verified tag
#             points at. This is the assertion that binds a signature
#             somewhere upstream to the tarball on this disk.
#
# The strongest class - a detached GPG signature over the artifact itself by a
# pinned maintainer key - is what tools/verify-signatures.sh does, and neither
# mechanism here is a substitute for it.
#
# ============================================================================
# WHAT THIS SCRIPT USED TO DO, AND WHY THAT WAS NOT ENOUGH
# ============================================================================
#
# It asked the GitHub API whether the hardened_malloc tag was signed, printed
# the tagger's display name, and called that verified. Three problems, each
# fatal on its own:
#
#   1. NOTHING CONNECTED THE TAG TO THE TARBALL. A valid tag somewhere upstream
#      does not authenticate the archive in sources/. GitHub generates that
#      archive on request; the check never compared the two. Any substituted
#      tarball whose hash was in sources.lock passed.
#
#   2. THE SIGNER WAS NEVER ESTABLISHED. `.verification.verified` is GitHub
#      asserting that it matched the signature against some key uploaded to
#      the account, and `.tagger.name` is free text inside the tag. Neither
#      names a key Kryptik decided to trust in advance.
#
#      That field is not merely weak in theory. hardened_malloc tags 12, 13
#      and 14 are all signed by ONE key - the one pinned below - and the old
#      check would have reported the signer of 12 and 13 as "Daniel Micay"
#      and of 14 as "GrapheneOS", because the display name changed and the
#      key did not. A name that varies while the key is constant is not an
#      identity; it is a label.
#
#   3. IT PASSED WHEN IT COULD NOT CHECK. A missing gh CLI, an unresolvable
#      tag, an unreachable API - each incremented a "skipped" counter and
#      exited 0.
#
#      The bundled CI step took that path on every run, and the reason is
#      worth getting right: gh IS pre-installed on GitHub's Ubuntu runner
#      images (GitHub CLI 2.100.0 on both Ubuntu 24.04, which is what
#      `ubuntu-latest` resolves to, and 26.04 - see actions/runner-images).
#      What it is not is authenticated. GITHUB_TOKEN is a secret, not an
#      exported environment variable, and .github/workflows/ci.yml sets no
#      GH_TOKEN for that step. An unauthenticated `gh api` fails even against
#      a public repository - measured with gh 2.97.0 and an empty config
#      directory: exit 4, "please run gh auth login". So `gh api` failed, the
#      script warned and skipped, and the one assertion
#      docs/supply-chain.md describes as verified passed without being made.
#
# It also described the tag as GPG-signed. It is not: GrapheneOS signs these
# tags with an SSH key (ssh-ed25519), which is why the trust anchor below is
# an allowed-signers entry rather than a GPG fingerprint.
#
# What happens now: the tag object is fetched with git, its signature verified
# locally against a pinned allowed-signers entry, and the downloaded archive
# re-hashed into a git tree that must equal the tree the verified tag points
# at. Nothing is taken on GitHub's word, and nothing that could not be checked
# is reported as checked.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

STRICT=0
OFFLINE=0
for a in "$@"; do
    case "$a" in
        --strict)  STRICT=1 ;;
        --offline) OFFLINE=1 ;;
        -h|--help) sed -n '2,6p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a (expected --strict, --offline, or nothing)" ;;
    esac
done

# ============================================================================
# TRUST ANCHOR
# ============================================================================
#
# GrapheneOS publishes its release-signing key as an OpenSSH allowed-signers
# entry at https://grapheneos.org/allowed_signers, on its own domain, for
# exactly this purpose. Retrieved 2026-09-11:
#
#   contact@grapheneos.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIUg/m5CoP83b0rfSCzYSVA4cw4ir49io5GPoxbgxdJE
#
#   $ ssh-keygen -lf -
#   256 SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM (ED25519)
#
# Pinned HERE, in the repository, rather than fetched at check time. A key
# fetched when the check runs is only as trustworthy as that fetch; a key in
# the tree changes visibly, in review, as a diff.
#
# How far one pinned key reaches: tags 12, 13 and 14 are all signed by this
# key, confirmed by decoding the SSHSIG blob of each tag and comparing the
# embedded public key byte-for-byte with the published one. So a pin bump
# across that range does not need a new anchor. If upstream ever rotates or
# adds a key, this check fails closed - it reports the wrong signer rather
# than accepting the new one - which is the intended direction, and means a
# rotation is a deliberate, reviewable edit here.
#
# WHAT THIS ANCHOR IS WORTH. It establishes that a tag was signed by the key
# GrapheneOS publishes at its own HTTPS origin - the same class of anchor as
# the kernel.org fingerprints pinned in tools/verify-signatures.sh, and a
# different thing entirely from trusting the key a signature names. It is not
# a web-of-trust path, and it has NOT been confirmed out-of-band: TLS to
# grapheneos.org, and the CA system behind it, is the trust root. Confirming
# this fingerprint through a second channel remains a manual step, and until
# someone does it that is the weakest link in this particular check.
HM_REPO="GrapheneOS/hardened_malloc"
HM_SIGNER_PRINCIPAL="contact@grapheneos.org"
HM_SIGNER_ENTRY="contact@grapheneos.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIUg/m5CoP83b0rfSCzYSVA4cw4ir49io5GPoxbgxdJE"
HM_SIGNER_FPR="SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM"

SKARNET_BASE="${MIRROR_SKARNET:-https://skarnet.org/software}"
HM_REMOTE="https://github.com/${HM_REPO}"

# Self-test hooks. tools/test-verify-provenance.sh drives every branch below
# from local fixtures - a git repository with a real SSH-signed tag, and an
# http.server on 127.0.0.1 - so the production code path is what gets tested.
# Gated together behind one flag: silently redirecting a release gate at a
# substituted trust anchor is the exact failure this script exists to prevent.
if [[ -n "${KRYPTIK_HM_REMOTE:-}${KRYPTIK_HM_SIGNERS:-}${KRYPTIK_HM_FPR:-}${KRYPTIK_SKARNET_BASE:-}" ]]; then
    [[ "${KRYPTIK_PROVENANCE_SELFTEST:-0}" == "1" ]] || die \
"A provenance override is set (KRYPTIK_HM_REMOTE / KRYPTIK_HM_SIGNERS /
KRYPTIK_HM_FPR / KRYPTIK_SKARNET_BASE) but KRYPTIK_PROVENANCE_SELFTEST is not.
Refusing to verify provenance against substituted inputs."
    warn "SELF-TEST MODE: provenance inputs are substituted, not upstream"
    [[ -n "${KRYPTIK_HM_REMOTE:-}" ]]   && HM_REMOTE="$KRYPTIK_HM_REMOTE"
    [[ -n "${KRYPTIK_SKARNET_BASE:-}" ]] && SKARNET_BASE="$KRYPTIK_SKARNET_BASE"
fi

WORK="${KRYPTIK_WORK}/provenance"
rm -rf "$WORK"
mkdir -p "$WORK"

SIGNERS="${WORK}/allowed_signers"
if [[ -n "${KRYPTIK_HM_SIGNERS:-}" ]]; then
    cp "$KRYPTIK_HM_SIGNERS" "$SIGNERS"
    HM_SIGNER_PRINCIPAL="$(awk 'NF{print $1; exit}' "$SIGNERS")"
    # Fixture keys are generated per run, so there is no fingerprint to pin
    # unless the test supplies one in order to exercise that branch.
    HM_SIGNER_FPR="${KRYPTIK_HM_FPR:-}"
else
    printf '%s\n' "$HM_SIGNER_ENTRY" > "$SIGNERS"
fi

# ============================================================================
# result accounting
# ============================================================================
#
# Four outcomes, three of which are not a pass:
#
#   PASS      the assertion was established
#   FAIL      the assertion was tested and is false. Always fatal.
#   UNAVAIL   it could not be tested - no network, nothing downloaded, a
#             deliberately offline run. Fatal under --strict.
#   PREREQ    a tool needed to test it is not installed. Fatal under --strict.
#
# UNAVAIL and PREREQ are the two the previous script spent as "skipped" and
# exited 0 on. They are counted separately from PASS so that no summary line
# can add them together.

PASS_N=0; FAIL_N=0; UNAVAIL_N=0; PREREQ_N=0
declare -a PASS_LIST=() FAIL_LIST=() UNAVAIL_LIST=() PREREQ_LIST=()

pass()    { ok   "[$1] $2";           PASS_N=$((PASS_N+1));       PASS_LIST+=("[$1] $2"); }
fail()    { err  "[$1] $2";           FAIL_N=$((FAIL_N+1));       FAIL_LIST+=("[$1] $2"); }
unavail() { warn "[$1] UNVERIFIED: $2"; UNAVAIL_N=$((UNAVAIL_N+1)); UNAVAIL_LIST+=("[$1] $2"); }
prereq()  { warn "[$1] CANNOT CHECK: $2"; PREREQ_N=$((PREREQ_N+1)); PREREQ_LIST+=("[$1] $2"); }

lock_hash_for() {
    [[ -f "$KRYPTIK_LOCK" ]] || return 1
    awk -v f="$1" '$2 == f { print $1; found=1 } END { exit !found }' "$KRYPTIK_LOCK"
}

# GET a URL. Sets HTTP_CODE; returns curl's exit status.
#
# Exit status is the primary signal and HTTP_CODE only distinguishes "the
# server answered, with 404" from "there was no answer". %{http_code} reports
# the LAST hop of a redirect chain, which is why it is not parsed for success.
http_get() {
    local url="$1" dest="$2" rc=0
    HTTP_CODE="$(curl -fsSL --max-time 30 --retry 2 --retry-delay 2 \
                      -o "$dest" -w '%{http_code}' "$url" 2>/dev/null)" || rc=$?
    return "$rc"
}

# ============================================================================
# 1. hardened_malloc: an authenticated source tree
# ============================================================================

HM_TAG="${V_HARDENED_MALLOC:-}"
# GitHub names a tag archive after the tag, so the manifest entry in
# tools/fetch-sources.sh downloads .../archive/refs/tags/14.tar.gz as the
# bare filename "14.tar.gz". If that manifest row changes shape, the lock
# lookup below changes with it.
HM_ARCHIVE="${HM_TAG}.tar.gz"
HM_LABEL="hardened_malloc (system allocator)"

# [lock] the bytes on disk are the bytes sources.lock records.
verify_hm_lock() {
    local path="${KRYPTIK_SOURCES}/${HM_ARCHIVE}"
    local locked actual

    if ! locked="$(lock_hash_for "$HM_ARCHIVE")"; then
        fail lock "${HM_LABEL}: ${HM_ARCHIVE} has no entry in sources.lock"
        return 1
    fi
    if [[ ! -f "$path" ]]; then
        unavail lock "${HM_LABEL}: ${HM_ARCHIVE} is not downloaded, so the
       bytes that would be built cannot be checked at all. Run 'make sources'."
        return 1
    fi
    actual="$(sha256_of "$path")"
    if [[ "$actual" != "$locked" ]]; then
        fail lock "${HM_LABEL}: ${HM_ARCHIVE} does not match sources.lock"
        err  "       sources.lock ${locked}"
        err  "       on disk      ${actual}"
        return 1
    fi
    pass lock "${HM_LABEL}: ${HM_ARCHIVE} matches sources.lock"
    return 0
}

# [sig] + [id] + [tree]
verify_hm_tree() {
    local repo="${WORK}/hm.git"
    local extract="${WORK}/hm-extract"
    local archive="${KRYPTIK_SOURCES}/${HM_ARCHIVE}"

    if [[ -z "$HM_TAG" ]]; then
        fail id "${HM_LABEL}: V_HARDENED_MALLOC is unset, so there is no tag to
       authenticate against"
        return
    fi

    local missing=""
    have git       || missing="${missing} git"
    have ssh-keygen|| missing="${missing} ssh-keygen (openssh-client)"
    have tar       || missing="${missing} tar"
    if [[ -n "$missing" ]]; then
        prereq tree "${HM_LABEL}: missing${missing}; the allocator source cannot
       be bound to its signed tag"
        return
    fi

    if [[ "$OFFLINE" -eq 1 ]]; then
        unavail tree "${HM_LABEL}: --offline, so the signed tag was not fetched"
        return
    fi

    # A shallow fetch of the tag ref brings the tag object, its commit and the
    # tree. The blobs are not needed: re-deriving the tree writes them locally.
    git init -q --bare "$repo"
    local ferr="${WORK}/fetch.err"
    if ! git --git-dir="$repo" fetch -q --depth=1 "$HM_REMOTE" \
             "refs/tags/${HM_TAG}:refs/tags/${HM_TAG}" 2>"$ferr"; then
        unavail tree "${HM_LABEL}: could not fetch refs/tags/${HM_TAG} from
       ${HM_REMOTE}: $(tr -d '\n' < "$ferr" | cut -c1-160)"
        return
    fi

    # Only an annotated tag object can carry a signature. A lightweight tag is
    # a bare pointer at a commit, and reporting one as "signed" would be the
    # same mistake in a new place.
    local objtype
    objtype="$(git --git-dir="$repo" cat-file -t "refs/tags/${HM_TAG}" 2>/dev/null || true)"
    if [[ "$objtype" != "tag" ]]; then
        fail sig "${HM_LABEL}: ${HM_TAG} is not an annotated tag object
       (git reports it as a ${objtype:-missing} ref), so it cannot be signed"
        return
    fi

    local tagobj="${WORK}/tag.txt"
    git --git-dir="$repo" cat-file tag "refs/tags/${HM_TAG}" > "$tagobj"
    if grep -q 'BEGIN PGP SIGNATURE' "$tagobj"; then
        SIGKIND="PGP"
    elif grep -q 'BEGIN SSH SIGNATURE' "$tagobj"; then
        SIGKIND="SSH"
    else
        fail sig "${HM_LABEL}: tag ${HM_TAG} carries no signature at all"
        return
    fi

    # git verify-tag against a pinned allowed-signers file. The subtlety that
    # makes a naive check useless: for a signature by a key that is NOT in the
    # file, git still prints 'Good "git" signature' - it means the signature is
    # cryptographically sound - and then 'No principal matched.' with a
    # non-zero exit. Grepping for "Good" therefore accepts any signer. The exit
    # status, the principal and the key fingerprint are all required to match.
    local vout="${WORK}/verify.txt" vrc=0
    git --git-dir="$repo" -c gpg.ssh.allowedSignersFile="$SIGNERS" \
        verify-tag --raw "refs/tags/${HM_TAG}" > "$vout" 2>&1 || vrc=$?

    if [[ "$vrc" -ne 0 ]]; then
        fail id "${HM_LABEL}: tag ${HM_TAG} is not signed by the pinned
       ${HM_SIGNER_PRINCIPAL} key: $(tr '\n' ' ' < "$vout" | cut -c1-200)"
        return
    fi
    if ! grep -qF "signature for ${HM_SIGNER_PRINCIPAL}" "$vout"; then
        fail id "${HM_LABEL}: tag ${HM_TAG} verified, but not for principal
       ${HM_SIGNER_PRINCIPAL}: $(tr '\n' ' ' < "$vout" | cut -c1-200)"
        return
    fi
    if [[ -n "$HM_SIGNER_FPR" ]] && ! grep -qF "$HM_SIGNER_FPR" "$vout"; then
        fail id "${HM_LABEL}: tag ${HM_TAG} verified for the right principal
       with the WRONG key. Expected ${HM_SIGNER_FPR}, got:
       $(tr '\n' ' ' < "$vout" | cut -c1-200)"
        return
    fi

    local signed_by
    signed_by="$(sed -n 's/.*with \([A-Z0-9]*\) key \(SHA256:[^ ]*\).*/\1 \2/p' "$vout" | head -1)"
    pass sig "${HM_LABEL}: tag ${HM_TAG} carries a valid ${SIGKIND} signature"
    pass id  "${HM_LABEL}: signed by the pinned ${HM_SIGNER_PRINCIPAL} key
       (${signed_by:-$HM_SIGNER_FPR})"

    # ---- the binding ------------------------------------------------------
    #
    # Re-derive a git tree from the extracted archive and require it to equal
    # the tree the verified tag points at. This is the step that makes the
    # signature mean something about the bytes in sources/: it is not a
    # comparison of tarball hashes (GitHub regenerates archives and their
    # compression is not stable) but of content, object for object.
    if [[ ! -f "$archive" ]]; then
        unavail tree "${HM_LABEL}: ${HM_ARCHIVE} is not downloaded, so there is
       nothing to bind to the authenticated tree"
        return
    fi

    mkdir -p "$extract"
    if ! tar xzf "$archive" -C "$extract" 2>"${WORK}/tar.err"; then
        fail tree "${HM_LABEL}: ${HM_ARCHIVE} did not extract:
       $(tr -d '\n' < "${WORK}/tar.err" | cut -c1-160)"
        return
    fi

    local -a tops=()
    while IFS= read -r d; do tops+=("$d"); done < <(cd "$extract" && ls -A)
    if [[ "${#tops[@]}" -ne 1 || ! -d "${extract}/${tops[0]}" ]]; then
        fail tree "${HM_LABEL}: ${HM_ARCHIVE} does not contain exactly one
       top-level directory (found ${#tops[@]}: ${tops[*]:-none})"
        return
    fi
    local top="${extract}/${tops[0]}"

    if [[ -e "${top}/.gitattributes" ]]; then
        warn "[tree] ${HM_LABEL}: the archive contains .gitattributes; text"
        warn "       normalisation attributes can make this re-derivation"
        warn "       inexact. Read a mismatch below with that in mind."
    fi

    # core.attributesFile / core.excludesFile are neutralised so that the
    # operator's own git configuration cannot change which files are hashed or
    # how; add -f for the same reason.
    local derived tagtree
    derived="$(GIT_INDEX_FILE="${WORK}/hm.index" \
        git --git-dir="$repo" --work-tree="$top" \
            -c core.autocrlf=false -c core.safecrlf=false -c core.eol=lf \
            -c core.fileMode=true -c core.symlinks=true \
            -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
            add -A -f -- . >/dev/null 2>&1 && \
        GIT_INDEX_FILE="${WORK}/hm.index" git --git-dir="$repo" write-tree)" || {
        fail tree "${HM_LABEL}: could not re-derive a tree from ${HM_ARCHIVE}"
        return
    }
    tagtree="$(git --git-dir="$repo" rev-parse "refs/tags/${HM_TAG}^{tree}")"

    if [[ "$derived" == "$tagtree" ]]; then
        pass tree "${HM_LABEL}: ${HM_ARCHIVE} reproduces the tree of the
       verified tag (${tagtree})"
    else
        fail tree "${HM_LABEL}: ${HM_ARCHIVE} IS NOT THE SIGNED TREE"
        err  "       signed tag ${HM_TAG} points at tree ${tagtree}"
        err  "       the downloaded archive contains tree ${derived}"
        err  "       The tag signature is valid and the lock hash may match,"
        err  "       and the contents are still not what was signed."
    fi
}

# ============================================================================
# 2. skarnet: publisher-published checksums
# ============================================================================
#
# skarnet ships a .tar.gz.sha256 next to each release. That is a real, separate
# statement - sources.lock records what Kryptik downloaded, the .sha256 records
# what the publisher intended - but see [pub] above for what it is not.
#
# skarnet keeps a checksum only for the CURRENT release, so a missing .sha256
# means the pin has fallen behind and has become unverifiable by this
# mechanism. versions.env requires current versions for the s6 stack for
# exactly this reason, which is why absence is a strict-gate failure and not a
# shrug.

verify_published_sha256() {
    local url="$1" label="$2"
    local file; file="$(basename "$url")"
    local body="${WORK}/${file}.sha256"
    local path="${KRYPTIK_SOURCES}/${file}"

    local locked
    if ! locked="$(lock_hash_for "$file")"; then
        fail lock "${label}: ${file} has no entry in sources.lock"
        return
    fi

    # [lock] the bytes on disk against the lock, independently of the publisher.
    if [[ -f "$path" ]]; then
        local actual; actual="$(sha256_of "$path")"
        if [[ "$actual" == "$locked" ]]; then
            pass lock "${label}: ${file} matches sources.lock"
        else
            fail lock "${label}: ${file} does not match sources.lock"
            err  "       sources.lock ${locked}"
            err  "       on disk      ${actual}"
        fi
    else
        unavail lock "${label}: ${file} is not downloaded. Run 'make sources'."
    fi

    # [pub] the publisher's statement about those bytes.
    if [[ "$OFFLINE" -eq 1 ]]; then
        unavail pub "${label}: --offline, so the publisher checksum was not fetched"
        return
    fi
    have curl || { prereq pub "${label}: curl is not installed"; return; }

    local rc=0
    http_get "${url}.sha256" "$body" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        if [[ "${HTTP_CODE:-000}" == "404" ]]; then
            unavail pub "${label}: the publisher no longer publishes a .sha256
       for this version. skarnet keeps one only for the current release, so
       this pin is stale AND unverifiable by publisher checksum."
        else
            unavail pub "${label}: could not fetch ${url}.sha256
       (curl exit ${rc}, HTTP ${HTTP_CODE:-none})"
        fi
        return
    fi

    local expected
    expected="$(awk 'NF{print $1; exit}' "$body" 2>/dev/null || true)"
    if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
        fail pub "${label}: ${url}.sha256 is not a sha256 digest
       (got $(head -c 80 "$body" | tr -d '\n' || true))"
        return
    fi
    expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"

    if [[ "$expected" == "$locked" ]]; then
        pass pub "${label}: publisher sha256 agrees with sources.lock"
    else
        fail pub "${label}: PUBLISHER CHECKSUM MISMATCH"
        err  "       publisher says ${expected}"
        err  "       sources.lock   ${locked}"
    fi
}

# ============================================================================
# run
# ============================================================================

if [[ "$STRICT" -eq 1 ]]; then
    log "Verifying provenance of sources without detached signatures (strict)"
else
    log "Verifying provenance of sources without detached signatures"
fi
[[ "$OFFLINE" -eq 1 ]] && warn "--offline: no network check will be performed"
echo

log "hardened_malloc: authenticated source tree"
verify_hm_lock || true
verify_hm_tree

echo
log "skarnet: publisher-published checksums"
verify_published_sha256 "${SKARNET_BASE}/skalibs/skalibs-${V_SKALIBS}.tar.gz" "skalibs"
verify_published_sha256 "${SKARNET_BASE}/execline/execline-${V_EXECLINE}.tar.gz" "execline"
verify_published_sha256 "${SKARNET_BASE}/s6/s6-${V_S6}.tar.gz" "s6 (PID 1)"
verify_published_sha256 "${SKARNET_BASE}/s6-rc/s6-rc-${V_S6_RC}.tar.gz" "s6-rc"
verify_published_sha256 "${SKARNET_BASE}/s6-linux-init/s6-linux-init-${V_S6_LINUX_INIT}.tar.gz" \
    "s6-linux-init"

echo
log "Summary"
ok "established:  ${PASS_N}"
[[ "$UNAVAIL_N" -gt 0 ]] && warn "unverified:   ${UNAVAIL_N}"
[[ "$PREREQ_N"  -gt 0 ]] && warn "uncheckable:  ${PREREQ_N}"
[[ "$FAIL_N"    -gt 0 ]] && err  "FAILED:       ${FAIL_N}"

if [[ "$FAIL_N" -gt 0 ]]; then
    echo
    printf '  - %s\n' "${FAIL_LIST[@]}" >&2
fi
if [[ "$UNAVAIL_N" -gt 0 ]]; then
    echo
    dim "Not established (not evidence of tampering, and not a pass either):"
    printf '  - %s\n' "${UNAVAIL_LIST[@]}"
fi
if [[ "$PREREQ_N" -gt 0 ]]; then
    echo
    dim "Could not be checked for want of a tool:"
    printf '  - %s\n' "${PREREQ_LIST[@]}"
fi

echo
if [[ "$FAIL_N" -gt 0 ]]; then
    die "Provenance check FAILED. Do not build from these sources."
fi

# An unverified assertion is not a verified one. Under --strict that ends the
# run: a release gate that passes because it could not look is not a gate, and
# that is precisely how the previous version of this script reported
# hardened_malloc as covered while skipping it on every CI run.
if [[ "$STRICT" -eq 1 ]] && [[ "$((UNAVAIL_N + PREREQ_N))" -gt 0 ]]; then
    err "${UNAVAIL_N} assertion(s) unverified and ${PREREQ_N} uncheckable"
    die "--strict will not pass provenance that was not established.
Install the missing tools, download the sources, restore network access, or
update the pins - but do not ship on the strength of a check that did not run."
fi
if [[ "$((UNAVAIL_N + PREREQ_N))" -gt 0 ]]; then
    warn "$((UNAVAIL_N + PREREQ_N)) assertion(s) were NOT established."
    warn "This run is informational. --strict fails here."
fi

ok "No provenance failures (${PASS_N} assertion(s) established)."
echo
dim "What this run did and did not establish:"
dim "  [lock] bytes on disk match sources.lock - detects later tampering only"
dim "  [pub]  the publisher's own checksum agrees - not a signature"
dim "  [sig]  a tag signature verifies cryptographically"
dim "  [id]   that signature is by the key pinned in this script"
dim "  [tree] the archive reproduces the tree the verified tag points at"
dim "A detached GPG signature over the artifact by a pinned maintainer key is"
dim "stronger than any of these; see tools/verify-signatures.sh."
