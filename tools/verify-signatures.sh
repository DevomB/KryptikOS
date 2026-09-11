#!/usr/bin/env bash
# Verify upstream GPG signatures for fetched source tarballs.
#
#   ./tools/verify-signatures.sh            verify (informational)
#   ./tools/verify-signatures.sh --strict   release gate
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
# UNVERIFIED IS NOT VERIFIED, AND --strict IS WHERE THAT BITES.
# An unverifiable source is not a failure - upstream may publish no signature
# at all - but it is not a pass either, and this script used to exit 0 with any
# number of them. `--strict` is the release-gate invocation: it refuses to
# succeed while anything went unverified.
#
# Keys imported by --fetch-unknown-keys are counted separately from verified,
# not added to it. Trusting a key because the signature it checks named it is
# circular: it establishes that a file was signed by whoever signed it, and
# nothing about who that is. Counting those into the verified total is how a
# coverage number grows without any trust being established, so they now have
# their own bucket that --strict refuses to pass.
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
STRICT=0
REPORT=""
for a in "$@"; do
    case "$a" in
        --refresh) rm -rf "$GNUPGHOME" "$GNU_KEYRING" ;;
        --fetch-unknown-keys) FETCH_UNKNOWN=1 ;;
        --strict) STRICT=1 ;;
        # Machine-readable per-source outcome, for tools/provenance-inventory.sh.
        # `--report=FILE` rather than `--report FILE` so that the simple loop
        # over "$@" stays a simple loop over "$@".
        --report=*) REPORT="${a#--report=}" ;;
        -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done
[[ -n "$REPORT" ]] && : > "$REPORT"

# report <source> <class> <detail>
#
# One tab-separated line per source. The class is the ASSURANCE CLASS, not a
# pass/fail: the whole purpose of writing it out is that an inventory can show
# "verified against a key we pinned" and "verified against a key the signature
# named" as the different things they are, instead of adding them up.
report() {
    [[ -n "$REPORT" ]] || return 0
    printf '%s\t%s\t%s\n' "$1" "$2" "${3//$'\t'/ }" >> "$REPORT"
}

# The ledger of keys accepted WITHOUT audit, for human confirmation
# out-of-band. It is read on every run, not only when --fetch-unknown-keys is
# passed, and that is the whole point: see UNAUDITED_FPRS below.
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

# Self-test hooks, gated together below. tools/test-verify-signatures.sh needs
# three things substituted to run offline - which manifest is verified, where
# the keyring comes from, and where an "unknown" key is fetched from - and
# nothing else. The classification in check_sig(), which is what the tests are
# actually about, runs exactly as it does in production.
if [[ -n "${KRYPTIK_SIGCHECK_MANIFEST:-}${KRYPTIK_SIGCHECK_KEYRING:-}${KRYPTIK_SIGCHECK_KEYSOURCE:-}${KRYPTIK_SIGCHECK_PROVENANCE:-}" ]]; then
    [[ "${KRYPTIK_SIGCHECK_SELFTEST:-0}" == "1" ]] || die \
"A signature-check override is set (KRYPTIK_SIGCHECK_MANIFEST /
KRYPTIK_SIGCHECK_KEYRING / KRYPTIK_SIGCHECK_KEYSOURCE /
KRYPTIK_SIGCHECK_PROVENANCE) but KRYPTIK_SIGCHECK_SELFTEST is not.
Refusing to verify signatures against a substituted manifest or keyring."
    warn "SELF-TEST MODE: manifest and/or keyring are substituted, not upstream"
fi

# The list of sources to verify. Production asks fetch-sources.sh, which is
# the single definition of the manifest.
manifest_source() {
    if [[ -n "${KRYPTIK_SIGCHECK_MANIFEST:-}" ]]; then
        cat "$KRYPTIK_SIGCHECK_MANIFEST"
        return
    fi
    "${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list
}

# Import one public key by id. Production asks a keyserver; the self-test
# imports from a local directory, because a keyserver round trip is the one
# part of --fetch-unknown-keys that cannot be exercised offline.
recv_key() {
    local keyid="$1" f
    if [[ -n "${KRYPTIK_SIGCHECK_KEYSOURCE:-}" ]]; then
        for f in "${KRYPTIK_SIGCHECK_KEYSOURCE}/${keyid}.gpg" \
                 "${KRYPTIK_SIGCHECK_KEYSOURCE}/${keyid}.asc"; do
            [[ -f "$f" ]] || continue
            gpg --batch --quiet --import "$f" >/dev/null 2>&1 && return 0
        done
        return 1
    fi
    gpg --batch --quiet --keyserver hkps://keyserver.ubuntu.com \
        --recv-keys "$keyid" >/dev/null 2>&1
}

import_keys() {
    if [[ -f "$IMPORTED_MARK" ]]; then
        dim "  using cached keyring ($(cat "$IMPORTED_MARK") keys)"
        return 0
    fi

    if [[ -n "${KRYPTIK_SIGCHECK_KEYRING:-}" ]]; then
        log "importing substituted keyring (self-test)"
        gpg --batch --quiet --import "$KRYPTIK_SIGCHECK_KEYRING" >/dev/null 2>&1 || true
        local n
        n="$(gpg --batch --list-keys 2>/dev/null | grep -c '^pub' || true)"
        [[ "$n" =~ ^[0-9]+$ ]] || n=0
        printf '%s' "$n" > "$IMPORTED_MARK"
        if [[ "$n" -lt 2 ]]; then
            if [[ "$STRICT" -eq 1 ]]; then
                err "only ${n} key(s) imported"
                die "Without maintainer keys nothing can be authenticated."
            fi
            warn "only ${n} key(s) imported - verification will be mostly unverifiable"
        else
            ok "keyring ready (${n} public keys)"
        fi
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

    # The pinned maintainer keys, fetched BY FINGERPRINT from the one array
    # that also classifies them. A keyserver can serve any key it likes and
    # cannot serve a different key under a given fingerprint, which is what
    # makes this safe; it is also why the second hardcoded copy of this list
    # that used to live here is gone.
    log "fetching pinned maintainer keys (${#PINNED_FPRS[@]})"
    local fpr
    for fpr in "${PINNED_FPRS[@]}"; do
        recv_key "$fpr" || warn "could not fetch pinned key ${fpr}"
    done

    local count
    count="$(gpg --batch --list-keys 2>/dev/null | grep -c '^pub' || true)"
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    printf '%s' "$count" > "$IMPORTED_MARK"

    if [[ "$count" -lt 2 ]]; then
        # No keys means every signature below reports "key not held", which a
        # release gate must not read as an absence of problems.
        if [[ "$STRICT" -eq 1 ]]; then
            err "only ${count} key(s) imported"
            die "Without the maintainer keys nothing can be authenticated, and
--strict will not report a run that could not check anything as a pass.
Restore network access, or re-run without --strict for an informational pass."
        fi
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
declare -a FETCHED_LIST=()

mark_unverifiable() {
    UNVERIFIABLE=$((UNVERIFIABLE + 1))
    UNVERIFIABLE_LIST+=("$1")
}

# Fingerprints listed in keys.manifest: keys that were accepted because a
# signature named them, and have not been confirmed against the project.
#
# WHY THIS IS READ ON EVERY RUN, NOT JUST WHEN FETCHING.
# The imported keyring is cached under build/work/keys. Once a
# --fetch-unknown-keys run has put a key there, every later run finds it
# already held and reports an ordinary GOODSIG - so the "unaudited" label
# lasted exactly one invocation and then evaporated, and --strict would have
# passed those sources on the second run. The durable record of what was never
# audited is keys.manifest, so that is what decides, independently of whatever
# happens to be in the key cache.
declare -a UNAUDITED_FPRS=()
if [[ -f "$KEYS_MANIFEST" ]]; then
    while read -r _pkg fpr _rest; do
        [[ "$fpr" =~ ^[0-9A-Fa-f]{40}$ ]] && UNAUDITED_FPRS+=("${fpr^^}")
    done < <(grep -v '^[[:space:]]*#' "$KEYS_MANIFEST" || true)
fi

# Keys Kryptik has decided to trust IN THE TREE, by fingerprint, as opposed to
# whichever keys the fetched GNU keyring happens to contain.
#
# A signature checked against one of these is a stronger statement than one
# checked against the keyring - the keyring is fetched over the network and
# establishes "signed by whoever the keyring says" - and the inventory reports
# them as different classes rather than one number.
#
# Each entry must be a fingerprint the PROJECT ITSELF publishes on its own
# origin, with the URL recorded here so the claim can be rechecked. Pinning the
# fingerprint is what makes fetching the key from a keyserver safe: a keyserver
# can serve any key it likes, and cannot serve a different key under this
# fingerprint.
#
# One array, used both to fetch and to classify, so the two cannot drift.
PINNED_FPRS=(
    # kernel.org mainline and stable. Pre-existing pins, already relied on to
    # verify the kernel tarball itself.
    "ABAF11C65A2970B130ABE3C479BE3E4300411886"   # Linus Torvalds, mainline
    "647F28654894E3BD457199BE38DBBDC86092693E"   # Greg Kroah-Hartman, stable

    # Thomas Wouters, who signs "3.12.x and 3.13.x source files and tags" per
    # https://www.python.org/downloads/metadata/pgp/ - python.org's own
    # OpenPGP verification page, retrieved 2026-09-11. V_PYTHON is in 3.12.x.
    #
    # Before this pin, python was reported as unverifiable, and for a reason
    # worth recording: python.org publishes BOTH a Sigstore `.sig` and an
    # OpenPGP `.asc`, and verify_any() probed `.sig` first, handed a
    # base64 ECDSA blob to gpg, and reported "inconclusive". See
    # is_pgp_signature() below.
    "7169605F62C751356D054A26A821E680E5FA6305"   # Thomas Wouters, CPython 3.12/3.13

    # OpenSSL. Before these pins openssl - the most security-critical source in
    # the tree - was reported "key not held" and fell to lock-only, because its
    # keys are in no keyring here and --fetch-unknown-keys would have imported
    # whatever key the signature itself named.
    #
    # Two keys are pinned because two are needed. The OMC key signed the
    # currently pinned 3.3.1 (verified 2026-09-11: EXPKEYSIG, RSA/SHA-256 -
    # a VALID signature made 2024-06-04 whose key has since EXPIRED, which is
    # not revocation and which check_sig reports distinctly). The 2026 key
    # signs 3.5.8, the LTS release proposed in
    # provenance/PROPOSAL-openssl-expat.md, so the pin is in place before the
    # bump rather than after it.
    #
    # WHERE THESE FINGERPRINTS COME FROM, precisely, because the two differ:
    # https://openssl-library.org/source/ names B146 647E ... 2D40 in prose as
    # "the canonical trust anchor for verifying OpenSSL Library release
    # artifacts", and says it is cross-certified by the retired key
    # BA5473A2B0587B07FB27CF2D216094DFD0CB81EF - which is not pinned here
    # because nothing Kryptik pins or proposes is signed by it. The OMC
    # fingerprint is not printed on that page; it is the fingerprint of a key
    # in the pubkeys.asc bundle the same page links. Both therefore rest on TLS
    # to openssl-library.org and neither has been confirmed out of band, the
    # same standing as the python pin above. Retrieved 2026-09-11.
    "EFC0A467D613CB83C7ED6D30D894E2CE8B3D79F5"   # OpenSSL OMC, signs 3.3.1
    "B146647E45A7B33947AB226B2A2C87D161692D40"   # OpenSSL 2026 key, signs 3.5.8

    # expat. Verified 2026-09-11: this key GOODSIGs both the currently pinned
    # 2.6.2 and the 2.8.4 proposed in provenance/PROPOSAL-openssl-expat.md,
    # RSA/SHA-256, surviving --weak-digest SHA1.
    #
    # BE CLEAR WHAT THIS PIN DOES NOT ESTABLISH. The fingerprint comes from
    # gentoo.org's Web Key Directory, which serves it over HTTPS for
    # sping@gentoo.org: a THIRD PARTY attesting that the key belongs to that
    # address. It is not circular - the route does not depend on the signature,
    # unlike a keyserver lookup by the id the signature names - but libexpat
    # itself designates NO release signer and publishes no fingerprint on its
    # site, in SECURITY.md, or in its release notes (checked 2026-09-11). So
    # this pin means "the key gentoo.org publishes for sping@gentoo.org signed
    # this", and not "expat's authorised release signer signed this". That gap
    # is recorded as a machine-readable caveat in tools/source-notes.tsv under
    # kind undesignated-signer, so the inventory reports it alongside the class
    # rather than letting the class imply more than it should.
    "3176EF7DB2367F1FCA4F306B1F9B0E909AF37285"   # Sebastian Pipping, expat
)

# All fingerprints of the key that made a signature: the primary and every
# subkey. A GOODSIG names the SIGNING key, while keys.manifest and the pins
# above record primaries, so both have to be compared.
key_fingerprints() {
    gpg --batch --with-colons --fingerprint --fingerprint "$1" 2>/dev/null \
        | awk -F: '$1=="fpr"{print $10}'
}

_key_in() {
    local keyid="$1"; shift
    local fpr known
    [[ -n "$keyid" ]] || return 1
    [[ "$#" -gt 0 ]] || return 1
    while IFS= read -r fpr; do
        for known in "$@"; do
            [[ "${fpr^^}" == "${known^^}" ]] && return 0
        done
    done < <(key_fingerprints "$keyid")
    return 1
}

# Does the key that made this signature appear in the unaudited ledger?
key_is_unaudited() {
    [[ "${#UNAUDITED_FPRS[@]}" -gt 0 ]] || return 1
    _key_in "$1" "${UNAUDITED_FPRS[@]}"
}

key_is_pinned() { _key_in "$1" "${PINNED_FPRS[@]}"; }

# --- published key provenance ----------------------------------------------
#
# tools/key-provenance.tsv records, per key, a publisher that states its
# fingerprint BY A ROUTE THAT DOES NOT DEPEND ON THE SIGNATURE: kernel.org's
# pgpkeys repository, or the Web Key Directory of the signer's own email
# domain. Before this, a source whose key was in no keyring reported "key not
# held" and fell to lock-only, and the only route on offer was
# --fetch-unknown-keys, which imports the key the signature itself named.
#
# Resolved through BASH_SOURCE, like the pins above and unlike
# tools/source-notes.tsv: this is the tool's own knowledge about keys, not data
# about whichever tree is being inventoried.
KEY_PROVENANCE="${KRYPTIK_SIGCHECK_PROVENANCE:-$(dirname "${BASH_SOURCE[0]}")/key-provenance.tsv}"

declare -a PROV_FPR=() PROV_KIND=() PROV_LOC=() PROV_SIGNS=()

load_key_provenance() {
    [[ -f "$KEY_PROVENANCE" ]] || return 0
    local line n=0 bad=0 f k l r s rest
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        read -r f k l r s rest <<< "$line"

        local why=""
        [[ "$f" =~ ^[0-9A-F]{40}$ ]] || why="fingerprint must be 40 uppercase hex characters"
        if [[ -z "$why" ]]; then
            case "$k" in
                korg)
                    if [[ "${KRYPTIK_SIGCHECK_SELFTEST:-0}" == "1" ]]; then
                        [[ "$l" == https://* || "$l" == file://* ]] \
                            || why="a korg locator must be an https or (self-test) file URL"
                    else
                        [[ "$l" == https://* ]] \
                            || why="a korg locator must be an https URL"
                    fi
                    ;;
                wkd)  [[ "$l" == *@*.* ]]     || why="a wkd locator must be an email address" ;;
                *)    why="unknown kind '${k}'" ;;
            esac
        fi
        [[ -z "$why" && ! "$r" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
            && why="retrieved must be a YYYY-MM-DD date"
        [[ -z "$why" && -z "${s//[[:space:]]/}" ]] && why="no source names in signs"
        [[ -z "$why" && -z "${rest//[[:space:]]/}" ]] \
            && why="a row must record the uid it was published under"

        if [[ -n "$why" ]]; then
            err "${KEY_PROVENANCE}:${n}: ${why}"
            bad=$((bad + 1))
            continue
        fi
        PROV_FPR+=("$f"); PROV_KIND+=("$k"); PROV_LOC+=("$l"); PROV_SIGNS+=(",${s},")
    done < "$KEY_PROVENANCE"

    [[ "$bad" -eq 0 ]] || die "${bad} malformed row(s) in ${KEY_PROVENANCE}.
A key-provenance table that cannot be parsed is a tooling fault, not a
verification result: nothing here has been checked."
}

# Fetch the published key(s) for one source, if any, and only if not already
# held. The recorded fingerprint is the anchor: if the locator now serves a
# DIFFERENT key, that is a finding and the key is refused, because a silently
# rotated key is exactly what this table has to be able to notice.
import_provenance_keys_for() {
    local name="$1" i
    for i in "${!PROV_FPR[@]}"; do
        case "${PROV_SIGNS[$i]}" in *",${name},"*) ;; *) continue ;; esac

        # Already held: nothing to fetch, and no reason to touch the network.
        gpg --batch --list-keys "${PROV_FPR[$i]}" >/dev/null 2>&1 && continue

        local tmp got
        tmp="$(mktemp)"
        case "${PROV_KIND[$i]}" in
            korg)
                if ! curl -fsSL --max-time 30 -o "$tmp" "${PROV_LOC[$i]}" 2>/dev/null; then
                    warn "${name}: could not fetch the published key from ${PROV_LOC[$i]}"
                    rm -f "$tmp"; continue
                fi
                got="$(gpg --batch --with-colons --import-options show-only \
                         --import "$tmp" 2>/dev/null \
                       | awk -F: '$1=="fpr"{print $10; exit}')"
                if [[ "${got^^}" != "${PROV_FPR[$i]}" ]]; then
                    err "${name}: ${PROV_LOC[$i]} now publishes ${got:-no key},"
                    err "  not the recorded ${PROV_FPR[$i]}. REFUSING it: a key that"
                    err "  changed at a published location is a finding, not an update."
                    rm -f "$tmp"; continue
                fi
                gpg --batch --quiet --import "$tmp" >/dev/null 2>&1
                ;;
            wkd)
                # --locate-external-key imports on success, so the fingerprint
                # is checked after the fact and the key dropped if it differs.
                if ! gpg --batch --quiet --auto-key-locate clear,wkd \
                       --locate-external-key "${PROV_LOC[$i]}" >/dev/null 2>&1; then
                    warn "${name}: no WKD answer for ${PROV_LOC[$i]}"
                    rm -f "$tmp"; continue
                fi
                if ! gpg --batch --list-keys "${PROV_FPR[$i]}" >/dev/null 2>&1; then
                    err "${name}: the WKD for ${PROV_LOC[$i]} did not serve"
                    err "  ${PROV_FPR[$i]}. REFUSING: the recorded fingerprint is the anchor."
                    gpg --batch --quiet --yes --delete-keys \
                        "$(gpg --batch --with-colons --locate-keys "${PROV_LOC[$i]}" 2>/dev/null \
                           | awk -F: '$1=="fpr"{print $10; exit}')" >/dev/null 2>&1 || true
                    rm -f "$tmp"; continue
                fi
                ;;
        esac
        rm -f "$tmp"
        dim "  ${name}: imported the key ${PROV_KIND[$i]} publishes (${PROV_FPR[$i]})"
    done
    return 0
}

# korg | wkd | empty, for whichever recorded key made this signature.
key_provenance_kind() {
    local keyid="$1" fpr i
    [[ -n "$keyid" ]] || return 0
    [[ "${#PROV_FPR[@]}" -gt 0 ]] || return 0
    while IFS= read -r fpr; do
        for i in "${!PROV_FPR[@]}"; do
            if [[ "${fpr^^}" == "${PROV_FPR[$i]}" ]]; then
                printf '%s' "${PROV_KIND[$i]}"
                return 0
            fi
        done
    done < <(key_fingerprints "$keyid")
    return 0
}

load_key_provenance

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

    # If a publisher states this source's signing key, obtain it from there
    # FIRST. Doing it before the verification rather than in the NO_PUBKEY
    # branch means the published route is always preferred over the circular
    # one, and a key already held costs nothing.
    import_provenance_keys_for "$name"

    out="$(gpg --batch --status-fd 1 --verify "$sigfile" "$datafile" 2>/dev/null || true)"

    # GOODSIG and EXPKEYSIG are handled together because they differ only in
    # keyring freshness, and both have to pass through the keys.manifest check
    # before they can be called verified.
    if printf '%s' "$out" | grep -qE "^\[GNUPG:\] (GOODSIG|EXPKEYSIG)"; then
        local kind
        kind="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) .*/\1/p' | head -1)"
        signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) [0-9A-F]* //p' | head -1)"
        keyid="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) \([0-9A-F]*\).*/\2/p' | head -1)"

        # A key that a publisher states is no longer a key accepted merely
        # because the signature named it, so the published classes are tried
        # before the unaudited ledger and supersede it.
        local pkind
        pkind="$(key_provenance_kind "$keyid")"

        if [[ -z "$pkind" ]] && ! key_is_pinned "$keyid" \
           && key_is_unaudited "$keyid"; then
            warn "${name}: signature valid  [${signer:-unknown}] but by an UNAUDITED key"
            FETCHED=$((FETCHED + 1))
            FETCHED_LIST+=("${name} - ${signer:-unknown} (key ${keyid})")
            report "$name" signature-unaudited-key "${signer:-unknown} (${keyid})"
            return 0
        fi

        local klass=signature-keyring-key
        case "$pkind" in
            korg) klass=signature-korg-published-key ;;
            wkd)  klass=signature-wkd-published-key ;;
        esac
        key_is_pinned "$keyid" && klass=signature-pinned-key

        if [[ "$kind" == "EXPKEYSIG" ]]; then
            ok "${name}: signature valid, signing key expired  [${signer:-unknown}]"
            EXPIRED=$((EXPIRED + 1))
            EXPIRED_LIST+=("${name} - ${signer:-unknown}")
            report "$name" "$klass" "${signer:-unknown} (${keyid}; key expired)"
        else
            ok "${name}: signature valid  [${signer:-unknown}]"
            report "$name" "$klass" "${signer:-unknown} (${keyid})"
        fi
        VERIFIED=$((VERIFIED + 1))
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] REVKEYSIG"; then
        signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] REVKEYSIG [0-9A-F]* //p' | head -1)"
        err "${name}: signature made with a REVOKED key [${signer:-unknown}]"
        REVOKED=$((REVOKED + 1))
        REVOKED_LIST+=("${name} - ${signer:-unknown}")
        # A revoked key can mean the key was compromised, which is the one
        # thing here more serious than BADSIG. docs/supply-chain.md has said
        # since ADR time that REVKEYSIG stops a build; it was counted into a
        # bucket that nothing ever read, so it stopped nothing. It now lands
        # in FAILED like a bad signature does.
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("${name} (REVOKED signing key)")
        report "$name" signature-revoked-key "${signer:-unknown}"
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
            if recv_key "$keyid"; then
                out="$(gpg --batch --status-fd 1 --verify "$sigfile" "$datafile" 2>/dev/null || true)"
                if printf '%s' "$out" | grep -qE "^\[GNUPG:\] (GOODSIG|EXPKEYSIG)"; then
                    signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) [0-9A-F]* //p' | head -1)"
                    local fpr
                    fpr="$(gpg --batch --with-colons --fingerprint "$keyid" 2>/dev/null                            | awk -F: '$1=="fpr"{print $10; exit}')"
                    warn "${name}: signature valid  [${signer:-unknown}] but by an UNAUDITED key"
                    if ! grep -qiF -- "${fpr:-$keyid}" "$KEYS_MANIFEST" 2>/dev/null; then
                        printf '%-18s %-42s %s
' "$name" "${fpr:-$keyid}" "${signer:-unknown}"                             >> "$KEYS_MANIFEST"
                    fi
                    # So that a second package signed by the same key in this
                    # same run is recognised as unaudited too.
                    [[ -n "$fpr" ]] && UNAUDITED_FPRS+=("${fpr^^}")
                    # Deliberately NOT counted as verified. The key came from
                    # the signature it was used to check, so no signer
                    # identity has been established - only self-consistency.
                    FETCHED=$((FETCHED + 1))
                    FETCHED_LIST+=("${name} - ${signer:-unknown} (${fpr:-$keyid})")
                    return 0
                fi
            fi
        fi

        warn "${name}: signing key ${keyid} not held"
        mark_unverifiable "${name} (signing key ${keyid} not held)"
        report "$name" key-not-held "$keyid"
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] BADSIG"; then
        err "${name}: BAD SIGNATURE - the file does not match its signature"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("$name")
        report "$name" signature-bad "the file does not match its signature"
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] ERRSIG"; then
        warn "${name}: signature could not be checked"
        mark_unverifiable "${name} (ERRSIG - key unavailable or unsupported algorithm)"
        report "$name" signature-uncheckable "ERRSIG: key unavailable or unsupported algorithm"
        return 0
    fi

    warn "${name}: inconclusive gpg result"
    mark_unverifiable "${name} (inconclusive)"
    report "$name" inconclusive "gpg produced no status this script recognises"
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
            report "$name" no-signature-upstream "no .sig on the canonical GNU host"
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
# Is this file actually an OpenPGP signature?
#
# A suffix is not a format. python.org publishes BOTH a Sigstore `.sig` - a
# base64 ECDSA blob, 141 bytes - and an OpenPGP `.asc`, and the probe below
# used to take the `.sig`, hand it to gpg, get "no valid OpenPGP data found",
# and report python as inconclusive. The real signature was one suffix away
# the whole time. So a candidate that gpg cannot parse as a signature is not a
# result; it is the wrong file, and the next suffix gets a turn.
is_pgp_signature() {
    [[ -s "$1" ]] || return 1
    gpg --batch --list-packets "$1" 2>/dev/null | grep -q ':signature packet:'
}

verify_any() {
    local name="$1" url="$2" file="$3"
    local suffix sig
    local -a wrong_format=()
    for suffix in .sig .asc .sign; do
        sig="${SIGDIR}/${file}${suffix}"
        if [[ -s "$sig" ]] || quiet_fetch "${url}${suffix}" "$sig" 2>/dev/null; then
            if is_pgp_signature "$sig"; then
                check_sig "$name" "$sig" "${KRYPTIK_SOURCES}/${file}" || true
                return
            fi
            # Do not leave it cached: a non-signature in SIGDIR would shadow
            # the real one on every later run.
            wrong_format+=("${suffix}")
            rm -f "$sig"
            continue
        fi
        rm -f "$sig"
    done
    if [[ "${#wrong_format[@]}" -gt 0 ]]; then
        warn "${name}: upstream publishes ${wrong_format[*]} but none of them is an"
        warn "       OpenPGP signature (Sigstore, minisign or similar)"
        mark_unverifiable "${name} (published ${wrong_format[*]} is not OpenPGP)"
        report "$name" signature-not-openpgp "published ${wrong_format[*]} is not an OpenPGP signature"
        return
    fi
    warn "${name}: no detached signature published (.sig/.asc/.sign)"
    mark_unverifiable "${name} (upstream publishes no signature)"
    report "$name" no-signature-upstream "none of .sig/.asc/.sign is published"
}

# Detached signature alongside the file, at the same URL plus a suffix.
verify_detached() {
    local name="$1" url="$2" file="$3" suffix="${4:-.sig}"
    local sig="${SIGDIR}/${file}${suffix}"

    if [[ ! -s "$sig" ]] && ! quiet_fetch "${url}${suffix}" "$sig"; then
        rm -f "$sig"
        warn "${name}: no .sig published upstream"
        mark_unverifiable "${name} (no signature upstream)"
        report "$name" no-signature-upstream "no ${suffix} published beside the tarball"
        return
    fi
    if ! is_pgp_signature "$sig"; then
        rm -f "$sig"
        warn "${name}: the published ${suffix} is not an OpenPGP signature"
        mark_unverifiable "${name} (published ${suffix} is not OpenPGP)"
        report "$name" signature-not-openpgp "published ${suffix} is not an OpenPGP signature"
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
        report "$name" signature-unavailable "the .tar.sign could not be fetched"
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
        report "$name" decompression-failed "the tarball could not be decompressed"
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
    # Do NOT truncate. This file is the record of which keys were never
    # audited, and truncating it on every run destroyed that record: a second
    # --fetch-unknown-keys run finds every key already cached, fetches
    # nothing, and would have left behind a manifest containing only its own
    # two header lines. Entries accumulate and are deduplicated by
    # fingerprint instead.
    if [[ ! -s "$KEYS_MANIFEST" ]]; then
        printf '# Keys fetched by --fetch-unknown-keys. AUDIT THESE.
' >> "$KEYS_MANIFEST"
        printf '# package           fingerprint                                signer
' >> "$KEYS_MANIFEST"
    fi
fi
import_keys
echo

while read -r name _ver url; do
    [[ -z "$name" ]] && continue
    file="$(basename "$url")"
    # A source that was never downloaded has no signature to check, and that
    # is an unchecked assertion rather than a non-event: this used to `warn`
    # and `continue` without touching any counter, so a run in which nothing
    # had been fetched reported zero problems and exited 0 - and would have
    # satisfied --strict.
    [[ -f "${KRYPTIK_SOURCES}/${file}" ]] || {
        warn "${name}: not downloaded, so its signature cannot be checked"
        mark_unverifiable "${name} (not downloaded)"
        report "$name" not-downloaded "no local copy to check a signature against"
        continue
    }

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
            report "$name" no-signature-upstream "LFS publishes md5sums for the patch set, not per-patch signatures"
            ;;
        *)
            # Everything else: try the two conventional detached-signature
            # suffixes before giving up. Reporting "unknown source" for a
            # package that publishes a perfectly good .sig was hiding real
            # verifiable sources behind a vague label.
            verify_any "$name" "$url" "$file"
            ;;
    esac
done < <(manifest_source)

echo
log "Summary"
ok "verified:     ${VERIFIED}$([[ "$EXPIRED" -gt 0 ]] && printf ' (%s with expired keys)' "$EXPIRED")"
[[ "$FETCHED" -gt 0 ]]      && warn "unaudited:    ${FETCHED} (key taken from the signature itself)"
[[ "$UNVERIFIABLE" -gt 0 ]] && warn "unverifiable: ${UNVERIFIABLE}"
[[ "$REVOKED" -gt 0 ]]      && err  "REVOKED KEYS: ${REVOKED}"
[[ "$FAILED" -gt 0 ]]       && err  "FAILED:       ${FAILED}"

if [[ "${#EXPIRED_LIST[@]}" -gt 0 ]]; then
    echo
    dim "Cryptographically valid, signed with a key the keyring believes expired."
    dim "Routine key extension, not tampering - see docs/supply-chain.md:"
    printf '  - %s\n' "${EXPIRED_LIST[@]}"
fi

if [[ "${#REVOKED_LIST[@]}" -gt 0 ]]; then
    echo
    err "Signed with a REVOKED key. A revocation can mean the key was"
    err "compromised; treat these as unusable until upstream explains why:"
    printf '  - %s\n' "${REVOKED_LIST[@]}" >&2
fi

if [[ "${#FETCHED_LIST[@]}" -gt 0 ]]; then
    echo
    dim "Signed by an UNAUDITED key - self-consistent, signer not established."
    dim "Confirm these fingerprints against the project out-of-band; see keys.manifest:"
    printf '  - %s\n' "${FETCHED_LIST[@]}"
fi

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
# Under --strict, anything not authenticated ends the run. An unverifiable
# source is not a failure, but a release gate that reports a run with fifteen
# of them as a pass is not gating anything.
if [[ "$STRICT" -eq 1 ]] && [[ "$((UNVERIFIABLE + FETCHED))" -gt 0 ]]; then
    err "${UNVERIFIABLE} source(s) unverifiable, ${FETCHED} signed by unaudited keys"
    die "--strict will not pass sources whose signer was never established.
sources.lock pins these by hash, which detects later tampering and says
nothing about the first fetch. Either obtain the maintainer keys and audit
them, or accept the gap deliberately by running without --strict."
fi
if [[ "$UNVERIFIABLE" -gt 0 ]]; then
    warn "${UNVERIFIABLE} source(s) unverified. sources.lock pins them by hash,
which protects against later tampering but not against a bad first fetch."
fi
if [[ "$((UNVERIFIABLE + FETCHED))" -gt 0 ]]; then
    warn "This run is informational. --strict fails here."
fi
ok "No signature verification failures (${VERIFIED} verified)."
