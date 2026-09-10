#!/usr/bin/env bash
# Verify upstream GPG signatures for fetched source tarballs.
#
#   ./tools/verify-signatures.sh            verify
#   ./tools/verify-signatures.sh --refresh  discard cached keys and re-import
#
# This is the check that gives sources.lock its meaning. A SHA-256 recorded by
# fetch-sources.sh only proves the file has not changed since Kryptik first saw
# it; it says nothing about whether the file was authentic to begin with.
# Signature verification is what turns trust-on-first-use into trust in an
# upstream maintainer's key.
#
# Coverage, stated honestly:
#   GNU packages  - detached .sig verified against the GNU keyring
#   Linux kernel  - .sign verified against kernel.org maintainer keys, over
#                   the UNCOMPRESSED tar (which is what kernel.org signs)
#   LFS patches   - NOT individually signed upstream. Reported as unverifiable
#                   rather than silently passed.
#
# Residual limitation no script removes: the GNU keyring is itself fetched over
# the network. If you have never verified these keys out-of-band, this
# establishes "signed by whoever the keyring says" rather than "signed by the
# person you believe maintains this package". See docs/supply-chain.md.
#
# IMPLEMENTATION NOTE - do not "simplify" this back to --keyring.
# GnuPG 2.4 with keyboxd enabled SILENTLY IGNORES --keyring, printing only a
# note, and verifies against the user's default store instead. Every signature
# then reports as "key not held" no matter what is in the file. This script
# therefore uses an isolated GNUPGHOME and imports keys into it.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

have gpg || die "gpg not found. Install gnupg."

KEYDIR="${KRYPTIK_ROOT}/build/work/keys"
SIGDIR="${KRYPTIK_SOURCES}/.signatures"
GNU_KEYRING="${KEYDIR}/gnu-keyring.gpg"

# Isolated keyring home - never touches the user's own GnuPG configuration.
export GNUPGHOME="${KEYDIR}/gnupg"

[[ "${1:-}" == "--refresh" ]] && rm -rf "$GNUPGHOME" "$GNU_KEYRING"

mkdir -p "$KEYDIR" "$SIGDIR" "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

IMPORTED_MARK="${GNUPGHOME}/.kryptik-imported"

quiet_fetch() {
    curl -fL --no-progress-meter --connect-timeout 20 \
         --retry 2 --retry-delay 2 -o "$2" "$1"
}

# --- keys ------------------------------------------------------------------

CANONICAL_GNU="https://ftp.gnu.org/gnu"

import_keys() {
    if [[ -f "$IMPORTED_MARK" ]]; then
        dim "  using cached keyring ($(cat "$IMPORTED_MARK") keys)"
        return 0
    fi

    log "fetching GNU keyring"
    if [[ ! -s "$GNU_KEYRING" ]]; then
        quiet_fetch "${CANONICAL_GNU}/gnu-keyring.gpg" "$GNU_KEYRING" \
            || { rm -f "$GNU_KEYRING"; warn "could not fetch GNU keyring"; }
    fi

    if [[ -s "$GNU_KEYRING" ]]; then
        log "importing GNU keyring (a few thousand keys, this takes a moment)"
        gpg --batch --quiet --import "$GNU_KEYRING" 2>/dev/null || true
    fi

    # kernel.org maintainer keys: Torvalds signs mainline, Kroah-Hartman stable.
    log "fetching kernel.org signing keys"
    local fpr
    for fpr in "ABAF11C65A2970B130ABE3C479BE3E4300411886" \
               "647F28654894E3BD457199BE38DBBDC86092693E"; do
        gpg --batch --quiet --keyserver hkps://keyserver.ubuntu.com \
            --recv-keys "$fpr" >/dev/null 2>&1 || true
    done

    local count
    count="$(gpg --batch --list-keys 2>/dev/null | grep -c '^pub' || echo 0)"
    printf '%s' "$count" > "$IMPORTED_MARK"

    if [[ "$count" -lt 2 ]]; then
        warn "only ${count} key(s) imported - verification will be mostly unverifiable"
    else
        ok "keyring ready (${count} public keys)"
    fi
}

# --- verification ----------------------------------------------------------

VERIFIED=0
FAILED=0
UNVERIFIABLE=0
EXPIRED=0
REVOKED=0
declare -a FAILED_LIST=()
declare -a UNVERIFIABLE_LIST=()
declare -a EXPIRED_LIST=()
declare -a REVOKED_LIST=()

mark_unverifiable() {
    UNVERIFIABLE=$((UNVERIFIABLE + 1))
    UNVERIFIABLE_LIST+=("$1")
}

# Run gpg --verify and classify from its machine-readable status output.
#
# The distinction that matters, and which a naive implementation gets wrong:
#
#   GOODSIG     signature valid, key currently valid            -> verified
#   EXPKEYSIG   signature CRYPTOGRAPHICALLY VALID, key expired  -> verified*
#   REVKEYSIG   signature valid, key REVOKED                    -> serious
#   BADSIG      signature does not match the data               -> tampering
#   NO_PUBKEY   cannot check, key not held                      -> unverifiable
#   ERRSIG      cannot check, other reason                      -> unverifiable
#
# EXPKEYSIG is NOT tampering and must not be reported as such. Upstream
# maintainers routinely extend key expiry, while the GNU keyring snapshot
# carries an older self-signature - so a 2024 release legitimately verifies
# against a key the keyring believes expired in 2020. The cryptography is
# sound; only the keyring's freshness is stale. Treating that as a build-
# stopping failure trains people to ignore the tool, which is worse than the
# risk it was guarding against.
#
# BADSIG is the one that means what people think all of these mean.
check_sig() {
    local name="$1" sigfile="$2" datafile="$3"
    local out signer keyid
    out="$(gpg --batch --status-fd 1 --verify "$sigfile" "$datafile" 2>/dev/null || true)"

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] GOODSIG"; then
        signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] GOODSIG [0-9A-F]* //p' | head -1)"
        ok "${name}: signature valid  [${signer:-unknown}]"
        VERIFIED=$((VERIFIED + 1))
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] EXPKEYSIG"; then
        signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] EXPKEYSIG [0-9A-F]* //p' | head -1)"
        ok "${name}: signature valid, signing key expired  [${signer:-unknown}]"
        VERIFIED=$((VERIFIED + 1))
        EXPIRED=$((EXPIRED + 1))
        EXPIRED_LIST+=("${name} - ${signer:-unknown}")
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] REVKEYSIG"; then
        signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] REVKEYSIG [0-9A-F]* //p' | head -1)"
        err "${name}: signature made with a REVOKED key [${signer:-unknown}]"
        REVOKED=$((REVOKED + 1))
        REVOKED_LIST+=("${name} - ${signer:-unknown}")
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] NO_PUBKEY"; then
        keyid="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] NO_PUBKEY //p' | head -1)"
        warn "${name}: signing key ${keyid} not held"
        mark_unverifiable "${name} (signing key ${keyid} not held)"
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] BADSIG"; then
        err "${name}: BAD SIGNATURE - the file does not match its signature"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("$name")
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] ERRSIG"; then
        warn "${name}: signature could not be checked"
        mark_unverifiable "${name} (ERRSIG - key unavailable or unsupported algorithm)"
        return 0
    fi

    warn "${name}: inconclusive gpg result"
    mark_unverifiable "${name} (inconclusive)"
    return 0
}

# GNU signature files live on the canonical host; mirrors often 403 on them.
verify_gnu() {
    local name="$1" url="$2" file="$3"
    local sig="${SIGDIR}/${file}.sig"
    local relpath="${url#"${MIRROR_GNU}/"}"

    if [[ ! -s "$sig" ]]; then
        if ! quiet_fetch "${CANONICAL_GNU}/${relpath}.sig" "$sig" \
        && ! quiet_fetch "${url}.sig" "$sig"; then
            rm -f "$sig"
            warn "${name}: no .sig published upstream"
            mark_unverifiable "${name} (no signature upstream)"
            return
        fi
    fi
    check_sig "$name" "$sig" "${KRYPTIK_SOURCES}/${file}" || true
}

# Detached .sig alongside the file, same URL plus .sig.
verify_detached() {
    local name="$1" url="$2" file="$3"
    local sig="${SIGDIR}/${file}.sig"

    if [[ ! -s "$sig" ]] && ! quiet_fetch "${url}.sig" "$sig"; then
        rm -f "$sig"
        warn "${name}: no .sig published upstream"
        mark_unverifiable "${name} (no signature upstream)"
        return
    fi
    check_sig "$name" "$sig" "${KRYPTIK_SOURCES}/${file}" || true
}

verify_kernel() {
    local name="$1" url="$2" file="$3"
    local sign="${SIGDIR}/${file%.xz}.sign"

    if [[ ! -s "$sign" ]] && ! quiet_fetch "${url%.tar.xz}.tar.sign" "$sign"; then
        rm -f "$sign"
        warn "${name}: could not fetch .sign"
        mark_unverifiable "${name} (.sign unavailable)"
        return
    fi

    # kernel.org signs the uncompressed tar, so decompress before verifying.
    local tmptar="${KRYPTIK_WORK}/verify-$(basename "${file%.xz}")"
    mkdir -p "$(dirname "$tmptar")"
    dim "  decompressing kernel tarball to verify (~1.5GB, takes a moment)"
    if ! xz -dc "${KRYPTIK_SOURCES}/${file}" > "$tmptar"; then
        rm -f "$tmptar"
        err "${name}: decompression failed"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("$name")
        return
    fi
    check_sig "$name" "$sign" "$tmptar" || true
    rm -f "$tmptar"
}

# --- run -------------------------------------------------------------------

log "Verifying upstream signatures"
import_keys
echo

while read -r name ver url; do
    [[ -z "$name" ]] && continue
    file="$(basename "$url")"
    [[ -f "${KRYPTIK_SOURCES}/${file}" ]] || { warn "${name}: not downloaded"; continue; }

    case "$url" in
        *gnu.org*|*mirrors.kernel.org/gnu*) verify_gnu    "$name" "$url" "$file" ;;
        *cdn.kernel.org*)                   verify_kernel "$name" "$url" "$file" ;;
        *github.com/anthraxx/linux-hardened*)
            verify_detached "$name" "$url" "$file"
            ;;
        *linuxfromscratch.org*)
            # LFS publishes md5sums for its patch set, not per-patch signatures.
            warn "${name}: LFS patches are not individually signed upstream"
            mark_unverifiable "${name} (upstream publishes no signature)"
            ;;
        *) mark_unverifiable "${name} (unknown source)" ;;
    esac
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)

echo
log "Summary"
ok "verified:     ${VERIFIED}$([[ "$EXPIRED" -gt 0 ]] && printf ' (%s with expired keys)' "$EXPIRED")"
[[ "$UNVERIFIABLE" -gt 0 ]] && warn "unverifiable: ${UNVERIFIABLE}"
[[ "$FAILED" -gt 0 ]]       && err  "FAILED:       ${FAILED}"

if [[ "${#UNVERIFIABLE_LIST[@]}" -gt 0 ]]; then
    echo
    dim "Unverifiable (not proof of tampering - upstream may publish no signature):"
    printf '  - %s\n' "${UNVERIFIABLE_LIST[@]}"
fi

if [[ "$FAILED" -gt 0 ]]; then
    echo
    err "Signature verification FAILED for: ${FAILED_LIST[*]}"
    die "Do not build from these sources. Delete them and re-fetch."
fi

echo
if [[ "$UNVERIFIABLE" -gt 0 ]]; then
    warn "${UNVERIFIABLE} source(s) unverified. sources.lock pins them by hash,
which protects against later tampering but not against a bad first fetch."
fi
ok "No signature verification failures (${VERIFIED} verified)."
