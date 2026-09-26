#!/usr/bin/env bash
# Verify sources that publish no detached GPG signature, by other means.
#
#   ./tools/verify-provenance.sh                informational
#   ./tools/verify-provenance.sh --strict       release gate
#   ./tools/verify-provenance.sh --offline      do no network work at all
#   ./tools/verify-provenance.sh --report=FILE  per-assertion results to FILE

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

STRICT=0
OFFLINE=0
REPORT=""
for a in "$@"; do
    case "$a" in
        --strict)  STRICT=1 ;;
        --offline) OFFLINE=1 ;;
        --report=*) REPORT="${a#--report=}" ;;
        -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a (expected --strict, --offline, --report=FILE, or nothing)" ;;
    esac
done
[[ -n "$REPORT" ]] && : > "$REPORT"

# GrapheneOS's release key, pinned from https://grapheneos.org/allowed_signers
# (2026-09-11; it signs tags 12-14). Its only trust root is TLS to that site:
# the fingerprint has not been confirmed out of band.
HM_REPO="GrapheneOS/hardened_malloc"
HM_SIGNER_PRINCIPAL="contact@grapheneos.org"
HM_SIGNER_ENTRY="contact@grapheneos.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIUg/m5CoP83b0rfSCzYSVA4cw4ir49io5GPoxbgxdJE"
HM_SIGNER_FPR="SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM"

SKARNET_BASE="${MIRROR_SKARNET:-https://skarnet.org/software}"
HM_REMOTE="https://github.com/${HM_REPO}"

# Overrides for tools/test-verify-provenance.sh. They substitute the trust
# anchor, so they are refused without KRYPTIK_PROVENANCE_SELFTEST=1.
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
    # Fixture keys are made per run: no fingerprint unless the test sets one.
    HM_SIGNER_FPR="${KRYPTIK_HM_FPR:-}"
else
    printf '%s\n' "$HM_SIGNER_ENTRY" > "$SIGNERS"
fi

# A fail is always fatal. unavail (could not be tested: offline, not
# downloaded) and prereq (a needed tool is missing) are fatal under --strict.
PASS_N=0; FAIL_N=0; UNAVAIL_N=0; PREREQ_N=0
declare -a PASS_LIST=() FAIL_LIST=() UNAVAIL_LIST=() PREREQ_LIST=()

# The source the current checks belong to, for --report lines.
RSRC="-"

# report <assertion> <result> <detail>
# Appends "source<TAB>assertion:result<TAB>detail" for provenance-inventory.sh.
report() {
    [[ -n "$REPORT" ]] || return 0
    local detail="${3//$'\n'/ }"
    printf '%s\t%s:%s\t%s\n' "$RSRC" "$1" "$2" "${detail//$'\t'/ }" >> "$REPORT"
}

pass()    { ok   "[$1] $2";           PASS_N=$((PASS_N+1));       PASS_LIST+=("[$1] $2");    report "$1" established  "$2"; }
fail()    { err  "[$1] $2";           FAIL_N=$((FAIL_N+1));       FAIL_LIST+=("[$1] $2");    report "$1" failed       "$2"; }
unavail() { warn "[$1] UNVERIFIED: $2"; UNAVAIL_N=$((UNAVAIL_N+1)); UNAVAIL_LIST+=("[$1] $2"); report "$1" unverified   "$2"; }
prereq()  { warn "[$1] CANNOT CHECK: $2"; PREREQ_N=$((PREREQ_N+1)); PREREQ_LIST+=("[$1] $2"); report "$1" uncheckable  "$2"; }

lock_hash_for() {
    [[ -f "$KRYPTIK_LOCK" ]] || return 1
    awk -v f="$1" '$2 == f { print $1; found=1 } END { exit !found }' "$KRYPTIK_LOCK"
}

# http_get <url> <dest>: curl's exit status decides success. HTTP_CODE (the
# last redirect hop's) only tells a 404 from no answer.
http_get() {
    local url="$1" dest="$2" rc=0
    HTTP_CODE="$(curl -fsSL --max-time 30 --retry 2 --retry-delay 2 \
                      -o "$dest" -w '%{http_code}' "$url" 2>/dev/null)" || rc=$?
    return "$rc"
}

# hardened_malloc: fetch the tag with git, verify its signature against the
# pinned key, and require the downloaded archive to reproduce the tag's tree.

HM_TAG="${V_HARDENED_MALLOC:-}"
# The name fetch-sources.sh saves GitHub's tag archive under.
HM_ARCHIVE="${HM_TAG}.tar.gz"
HM_LABEL="hardened_malloc (system allocator)"

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

    git init -q --bare "$repo"
    local ferr="${WORK}/fetch.err"
    if ! git --git-dir="$repo" fetch -q --depth=1 "$HM_REMOTE" \
             "refs/tags/${HM_TAG}:refs/tags/${HM_TAG}" 2>"$ferr"; then
        unavail tree "${HM_LABEL}: could not fetch refs/tags/${HM_TAG} from
       ${HM_REMOTE}: $(tr -d '\n' < "$ferr" | cut -c1-160)"
        return
    fi

    # Only an annotated tag object can carry a signature.
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

    # A key missing from the allowed-signers file still gets 'Good "git"
    # signature' (then "No principal matched." and a non-zero exit), so the
    # exit status, the principal and the fingerprint must all match.
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

    # Bind the signature to the bytes in sources/: the archive must reproduce
    # the tag's tree. Tarball hashes cannot be compared, since GitHub
    # regenerates archives and their compression is not stable.
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

    # The -c settings and add -f keep the user's git config out of the hashing.
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

# Publisher checksums: a .sha256 beside the release. It comes from the same
# host over the same TLS as the tarball, so it is not a signature. skarnet keeps
# one only for its current release; versions.env keeps the s6 stack current.

# verify_published_sha256 <url> <label> <manifest-name>
# Reports are keyed by the name fetch-sources.sh --list uses, not the label.
verify_published_sha256() {
    local url="$1" label="$2" name="$3"
    RSRC="$name"
    local file; file="$(basename "$url")"
    local body="${WORK}/${file}.sha256"
    local path="${KRYPTIK_SOURCES}/${file}"

    local locked
    if ! locked="$(lock_hash_for "$file")"; then
        fail lock "${label}: ${file} has no entry in sources.lock"
        return
    fi

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

if [[ "$STRICT" -eq 1 ]]; then
    log "Verifying provenance of sources without detached signatures (strict)"
else
    log "Verifying provenance of sources without detached signatures"
fi
[[ "$OFFLINE" -eq 1 ]] && warn "--offline: no network check will be performed"
echo

log "hardened_malloc: authenticated source tree"
RSRC="hardened-malloc"
verify_hm_lock || true
verify_hm_tree

echo
log "skarnet: publisher-published checksums"
verify_published_sha256 "${SKARNET_BASE}/skalibs/skalibs-${V_SKALIBS}.tar.gz" "skalibs" "skalibs"
verify_published_sha256 "${SKARNET_BASE}/execline/execline-${V_EXECLINE}.tar.gz" "execline" "execline"
verify_published_sha256 "${SKARNET_BASE}/s6/s6-${V_S6}.tar.gz" "s6 (PID 1)" "s6"
verify_published_sha256 "${SKARNET_BASE}/s6-rc/s6-rc-${V_S6_RC}.tar.gz" "s6-rc" "s6-rc"
verify_published_sha256 "${SKARNET_BASE}/s6-linux-init/s6-linux-init-${V_S6_LINUX_INIT}.tar.gz" \
    "s6-linux-init" "s6-linux-init"

# The CA bundle is unsigned; curl.se publishes a .sha256 beside it. Test
# fixtures pin none.
if [[ -n "${V_CA_BUNDLE:-}" ]]; then
    echo
    log "curl.se: publisher-published checksum"
    verify_published_sha256 "${MIRROR_CURL_CA:-https://curl.se/ca}/cacert-${V_CA_BUNDLE}.pem" \
        "CA bundle (Mozilla's set, as curl.se publishes it)" "ca-bundle"
fi

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
