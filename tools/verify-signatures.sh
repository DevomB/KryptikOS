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

FETCH_UNKNOWN=0
for a in "$@"; do
    case "$a" in
        --refresh) rm -rf "$GNUPGHOME" "$GNU_KEYRING" ;;
        --fetch-unknown-keys) FETCH_UNKNOWN=1 ;;
    esac
done

# Records every key that verification relied on, for human audit.
KEYS_MANIFEST="${KRYPTIK_ROOT}/keys.manifest"

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
FETCHED=0
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

        # --fetch-unknown-keys pulls the key the signature NAMES and retries.
        #
        # Be clear about what this does and does not establish. Trusting a key
        # because the signature it is checking told you its id is circular: it
        # proves the file was signed by whoever signed it. It is still strictly
        # better than no check at all - it detects later tampering and pins the
        # signer - but the fingerprint must be confirmed out-of-band against
        # the project before it means "signed by the maintainer".
        #
        # Every key used this way is written to keys.manifest for that audit.
        if [[ "$FETCH_UNKNOWN" -eq 1 ]]; then
            if gpg --batch --quiet --keyserver hkps://keyserver.ubuntu.com                    --recv-keys "$keyid" >/dev/null 2>&1; then
                out="$(gpg --batch --status-fd 1 --verify "$sigfile" "$datafile" 2>/dev/null || true)"
                if printf '%s' "$out" | grep -qE "^\[GNUPG:\] (GOODSIG|EXPKEYSIG)"; then
                    signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) [0-9A-F]* //p' | head -1)"
                    local fpr
                    fpr="$(gpg --batch --with-colons --fingerprint "$keyid" 2>/dev/null                            | awk -F: '$1=="fpr"{print $10; exit}')"
                    ok "${name}: signature valid  [${signer:-unknown}] (key fetched, UNAUDITED)"
                    printf '%-18s %-42s %s
' "$name" "${fpr:-$keyid}" "${signer:-unknown}"                         >> "$KEYS_MANIFEST"
                    VERIFIED=$((VERIFIED + 1))
                    FETCHED=$((FETCHED + 1))
                    return 0
                fi
            fi
        fi

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

# Try each conventional detached-signature suffix in turn.
#
# There is no single convention: GNU and kernel.org use .sig, python.org and
# many others use .asc, some projects publish .sign. Trying all three turns a
# vague "unknown source" into either a real verification or a specific,
# actionable "signing key NNN not held".
verify_any() {
    local name="$1" url="$2" file="$3"
    local suffix sig
    for suffix in .sig .asc .sign; do
        sig="${SIGDIR}/${file}${suffix}"
        if [[ -s "$sig" ]] || quiet_fetch "${url}${suffix}" "$sig" 2>/dev/null; then
            check_sig "$name" "$sig" "${KRYPTIK_SOURCES}/${file}" || true
            return
        fi
        rm -f "$sig"
    done
    warn "${name}: no detached signature published (.sig/.asc/.sign)"
    mark_unverifiable "${name} (upstream publishes no signature)"
}

# Detached signature alongside the file, at the same URL plus a suffix.
verify_detached() {
    local name="$1" url="$2" file="$3" suffix="${4:-.sig}"
    local sig="${SIGDIR}/${file}${suffix}"

    if [[ ! -s "$sig" ]] && ! quiet_fetch "${url}${suffix}" "$sig"; then
        rm -f "$sig"
        warn "${name}: no .sig published upstream"
        mark_unverifiable "${name} (no signature upstream)"
        return
    fi
    check_sig "$name" "$sig" "${KRYPTIK_SOURCES}/${file}" || true
}

# kernel.org signs the UNCOMPRESSED tar, not the compressed tarball, and uses
# this convention for the kernel AND for util-linux, kbd, kmod, iproute2,
# libcap and e2fsprogs. Looking for "<file>.tar.xz.sig" finds nothing and
# reports these as unsigned when they are all properly signed.
verify_kernel() {
    local name="$1" url="$2" file="$3"
    local sign="${SIGDIR}/${file%.xz}.sign"

    # Handles .tar.xz and .tar.gz alike.
    local sign_url="${url%.tar.*}.tar.sign"
    if [[ ! -s "$sign" ]] && ! quiet_fetch "$sign_url" "$sign"; then
        rm -f "$sign"
        warn "${name}: could not fetch .sign"
        mark_unverifiable "${name} (.sign unavailable)"
        return
    fi

    # kernel.org signs the uncompressed tar, so decompress before verifying.
    local tmptar
    tmptar="${KRYPTIK_WORK}/verify-$(basename "${file%.*}")"
    mkdir -p "$(dirname "$tmptar")"
    dim "  decompressing ${name} to verify against its .tar.sign"
    local decomp="xz -dc"
    [[ "$file" == *.gz ]] && decomp="gzip -dc"
    if ! $decomp "${KRYPTIK_SOURCES}/${file}" > "$tmptar"; then
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
if [[ "$FETCH_UNKNOWN" -eq 1 ]]; then
    warn "--fetch-unknown-keys: will import keys named by the signatures themselves."
    warn "That proves a file was signed by whoever signed it, NOT that the signer"
    warn "is the real maintainer. Confirm keys.manifest out-of-band."
    : > "$KEYS_MANIFEST"
    printf '# Keys fetched by --fetch-unknown-keys. AUDIT THESE.
' >> "$KEYS_MANIFEST"
    printf '# package           fingerprint                                signer
' >> "$KEYS_MANIFEST"
fi
import_keys
echo

while read -r name _ver url; do
    [[ -z "$name" ]] && continue
    file="$(basename "$url")"
    [[ -f "${KRYPTIK_SOURCES}/${file}" ]] || { warn "${name}: not downloaded"; continue; }

    case "$url" in
        *gnu.org*|*mirrors.kernel.org/gnu*) verify_gnu    "$name" "$url" "$file" ;;
        *cdn.kernel.org*|*www.kernel.org/pub*) verify_kernel "$name" "$url" "$file" ;;
        *github.com/anthraxx/linux-hardened*|*github.com/tukaani-project/xz*)
            verify_detached "$name" "$url" "$file"
            ;;
        *astron.com*)
            verify_detached "$name" "$url" "$file" ".asc"
            ;;
        *linuxfromscratch.org*)
            # LFS publishes md5sums for its patch set, not per-patch signatures.
            warn "${name}: LFS patches are not individually signed upstream"
            mark_unverifiable "${name} (upstream publishes no signature)"
            ;;
        *)
            # Everything else: try the two conventional detached-signature
            # suffixes before giving up. Reporting "unknown source" for a
            # package that publishes a perfectly good .sig was hiding real
            # verifiable sources behind a vague label.
            verify_any "$name" "$url" "$file"
            ;;
    esac
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)

echo
log "Summary"
ok "verified:     ${VERIFIED}$([[ "$EXPIRED" -gt 0 ]] && printf ' (%s with expired keys)' "$EXPIRED")"
[[ "$FETCHED" -gt 0 ]] && warn "  of which ${FETCHED} used UNAUDITED fetched keys - see keys.manifest"
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
