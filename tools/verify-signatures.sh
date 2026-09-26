#!/usr/bin/env bash
# Verify upstream GPG signatures for fetched source tarballs.
#
#   ./tools/verify-signatures.sh [--strict] [--refresh] [--fetch-unknown-keys]
#                                [--report=FILE]
#     --strict              release gate: anything unverified or unaudited fails
#     --refresh             discard cached keys and re-import
#     --fetch-unknown-keys  import keys the signatures name (unaudited)
#     --report=FILE         per-source results to FILE

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

have gpg || die "gpg not found. Install gnupg."

KEYDIR="${KRYPTIK_ROOT}/build/work/keys"
SIGDIR="${KRYPTIK_SOURCES}/.signatures"
GNU_KEYRING="${KEYDIR}/gnu-keyring.gpg"

# A private GNUPGHOME, not --keyring: GnuPG 2.4 with keyboxd silently ignores
# --keyring and verifies against the user's own store.
export GNUPGHOME="${KEYDIR}/gnupg"

FETCH_UNKNOWN=0
STRICT=0
REPORT=""
for a in "$@"; do
    case "$a" in
        --refresh) rm -rf "$GNUPGHOME" "$GNU_KEYRING" ;;
        --fetch-unknown-keys) FETCH_UNKNOWN=1 ;;
        --strict) STRICT=1 ;;
        --report=*) REPORT="${a#--report=}" ;;
        -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done
[[ -n "$REPORT" ]] && : > "$REPORT"

# report <source> <class> <detail>
# One tab-separated line per source, for provenance-inventory.sh. The class is
# an assurance class (which kind of key verified it), not a pass/fail.
report() {
    [[ -n "$REPORT" ]] || return 0
    printf '%s\t%s\t%s\n' "$1" "$2" "${3//$'\t'/ }" >> "$REPORT"
}

# Keys accepted without audit, awaiting out-of-band confirmation. Read on every
# run, not only with --fetch-unknown-keys (see UNAUDITED_FPRS).
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

# Overrides for tools/test-verify-signatures.sh only.
if [[ -n "${KRYPTIK_SIGCHECK_MANIFEST:-}${KRYPTIK_SIGCHECK_KEYRING:-}${KRYPTIK_SIGCHECK_KEYSOURCE:-}${KRYPTIK_SIGCHECK_PROVENANCE:-}" ]]; then
    [[ "${KRYPTIK_SIGCHECK_SELFTEST:-0}" == "1" ]] || die \
"A signature-check override is set (KRYPTIK_SIGCHECK_MANIFEST /
KRYPTIK_SIGCHECK_KEYRING / KRYPTIK_SIGCHECK_KEYSOURCE /
KRYPTIK_SIGCHECK_PROVENANCE) but KRYPTIK_SIGCHECK_SELFTEST is not.
Refusing to verify signatures against a substituted manifest or keyring."
    warn "SELF-TEST MODE: manifest and/or keyring are substituted, not upstream"
fi

# fetch-sources.sh is the one definition of the manifest.
manifest_source() {
    if [[ -n "${KRYPTIK_SIGCHECK_MANIFEST:-}" ]]; then
        cat "$KRYPTIK_SIGCHECK_MANIFEST"
        return
    fi
    "${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list
}

# recv_key <keyid>: from a keyserver, or KRYPTIK_SIGCHECK_KEYSOURCE in tests.
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

    # Fetched over the network, so it gives "signed by whoever the keyring
    # says" unless its keys are checked out of band (docs/supply-chain.md).
    log "fetching GNU keyring"
    if [[ ! -s "$GNU_KEYRING" ]]; then
        quiet_fetch "${CANONICAL_GNU}/gnu-keyring.gpg" "$GNU_KEYRING" \
            || { rm -f "$GNU_KEYRING"; warn "could not fetch GNU keyring"; }
    fi

    if [[ -s "$GNU_KEYRING" ]]; then
        log "importing GNU keyring (a few thousand keys, this takes a moment)"
        gpg --batch --quiet --import "$GNU_KEYRING" 2>/dev/null || true
    fi

    # Safe from a keyserver: it cannot serve another key under a full fingerprint.
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

# Unaudited keys, from keys.manifest. Once cached, such a key gives a plain
# GOODSIG, so the manifest (read on every run) is what keeps it marked.
declare -a UNAUDITED_FPRS=()
if [[ -f "$KEYS_MANIFEST" ]]; then
    while read -r _pkg fpr _rest; do
        [[ "$fpr" =~ ^[0-9A-Fa-f]{40}$ ]] && UNAUDITED_FPRS+=("${fpr^^}")
    done < <(grep -v '^[[:space:]]*#' "$KEYS_MANIFEST" || true)
fi

# Keys trusted by fingerprint in the tree, reported as a stronger class than the
# fetched GNU keyring. Each must be a fingerprint the project publishes on its
# own origin, with that source noted here so it can be rechecked.
PINNED_FPRS=(
    # kernel.org mainline and stable.
    "ABAF11C65A2970B130ABE3C479BE3E4300411886"   # Linus Torvalds, mainline
    "647F28654894E3BD457199BE38DBBDC86092693E"   # Greg Kroah-Hartman, stable

    # Signs CPython 3.12.x and 3.13.x, per
    # https://www.python.org/downloads/metadata/pgp/ (retrieved 2026-09-11).
    "7169605F62C751356D054A26A821E680E5FA6305"   # Thomas Wouters, CPython 3.12/3.13

    # From https://openssl-library.org/source/ (retrieved 2026-09-11): the page
    # names the 2026 key as the release trust anchor, and the OMC key is in the
    # pubkeys.asc it links. Both rest on TLS to that site alone. The OMC key has
    # expired, so its signature on 3.3.1 verifies as EXPKEYSIG.
    "EFC0A467D613CB83C7ED6D30D894E2CE8B3D79F5"   # OpenSSL OMC, signs 3.3.1
    "B146647E45A7B33947AB226B2A2C87D161692D40"   # OpenSSL 2026 key, signs 3.5.8

    # libexpat names no release signer. This is the key gentoo.org's WKD serves
    # for sping@gentoo.org, and the pin means only that; tools/source-notes.tsv
    # carries the undesignated-signer caveat.
    "3176EF7DB2367F1FCA4F306B1F9B0E909AF37285"   # Sebastian Pipping, expat
)

# Primary and subkey fingerprints. GOODSIG names the signing subkey, while the
# pins and keys.manifest record primaries.
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

key_is_unaudited() {
    [[ "${#UNAUDITED_FPRS[@]}" -gt 0 ]] || return 1
    _key_in "$1" "${UNAUDITED_FPRS[@]}"
}

key_is_pinned() { _key_in "$1" "${PINNED_FPRS[@]}"; }

# --- published key provenance ----------------------------------------------

# Per key, where a publisher states its fingerprint by a route independent of
# the signature. Tool data, not tree data, so it is found via BASH_SOURCE.
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
                github)
                    # Exact shape, so "github" cannot point at another host.
                    if [[ "$l" =~ ^https://github\.com/[A-Za-z0-9-]+\.gpg$ ]]; then
                        :
                    elif [[ "${KRYPTIK_SIGCHECK_SELFTEST:-0}" == "1" && "$l" == file://* ]]; then
                        :
                    else
                        why="a github locator must be https://github.com/<account>.gpg"
                    fi
                    # Without the release-author tie the row says only
                    # "GitHub hosts this key".
                    [[ "$rest" == *published\ by* ]] \
                        || why="a github row must record which account published the release"
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

# Import one source's published keys unless already held. The recorded
# fingerprint is the anchor: a locator now serving another key is refused.
import_provenance_keys_for() {
    local name="$1" i
    for i in "${!PROV_FPR[@]}"; do
        case "${PROV_SIGNS[$i]}" in *",${name},"*) ;; *) continue ;; esac

        gpg --batch --list-keys "${PROV_FPR[$i]}" >/dev/null 2>&1 && continue

        local tmp got
        tmp="$(mktemp)"
        case "${PROV_KIND[$i]}" in
            korg|github)
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

# korg, wkd, github or empty: the provenance of the key that made a signature.
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

# check_sig <name> <sigfile> <datafile>: classify gpg's status output.
# EXPKEYSIG counts as verified: the signature is valid and only the keyring's
# copy of the key has expired (maintainers extend expiry; the keyring lags).
check_sig() {
    local name="$1" sigfile="$2" datafile="$3"
    local out signer keyid

    # Before verifying, so a published key wins over --fetch-unknown-keys.
    import_provenance_keys_for "$name"

    out="$(gpg --batch --status-fd 1 --verify "$sigfile" "$datafile" 2>/dev/null || true)"

    if printf '%s' "$out" | grep -qE "^\[GNUPG:\] (GOODSIG|EXPKEYSIG)"; then
        local kind
        kind="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) .*/\1/p' | head -1)"
        signer="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) [0-9A-F]* //p' | head -1)"
        keyid="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] \(GOODSIG\|EXPKEYSIG\) \([0-9A-F]*\).*/\2/p' | head -1)"

        # A published or pinned key is no longer unaudited.
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
            korg)   klass=signature-korg-published-key ;;
            wkd)    klass=signature-wkd-published-key ;;
            github) klass=signature-platform-published-key ;;
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
        # A revoked key may have been compromised: this fails like BADSIG.
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("${name} (REVOKED signing key)")
        report "$name" signature-revoked-key "${signer:-unknown}"
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] NO_PUBKEY"; then
        keyid="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] NO_PUBKEY //p' | head -1)"

        # The key the signature names is circular trust: it proves only who
        # signed. So it goes to keys.manifest for an out-of-band audit and is
        # never counted as verified.
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
                    # So later sources signed by this key count as unaudited too.
                    [[ -n "$fpr" ]] && UNAUDITED_FPRS+=("${fpr^^}")
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

# A suffix is not a format: python.org's .sig is Sigstore, its .asc OpenPGP.
is_pgp_signature() {
    [[ -s "$1" ]] || return 1
    gpg --batch --list-packets "$1" 2>/dev/null | grep -q ':signature packet:'
}

# Try .sig, .asc and .sign; one that is not OpenPGP passes the turn on.
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
            # Not cached: it would shadow the real signature on later runs.
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

# kernel.org signs the uncompressed tar (<name>.tar.sign), for the kernel and
# for util-linux, kbd, kmod, iproute2, libcap and e2fsprogs.
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
    # Never truncate: this is the only record of unaudited keys, and a later
    # run finds them already cached and would not add them back.
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
    # Not downloaded is unverifiable, so --strict fails on it.
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
        *curl.se/ca/*)
            # Unsigned; verify-provenance.sh checks curl.se's .sha256 for it.
            warn "${name}: no OpenPGP signature upstream; the publisher's checksum is verify-provenance's"
            mark_unverifiable "${name} (publisher checksum, see verify-provenance)"
            report "$name" no-signature-upstream "curl.se publishes a .sha256 beside the bundle, checked by tools/verify-provenance.sh"
            ;;
        *linuxfromscratch.org*)
            warn "${name}: LFS patches are not individually signed upstream"
            mark_unverifiable "${name} (upstream publishes no signature)"
            report "$name" no-signature-upstream "LFS publishes md5sums for the patch set, not per-patch signatures"
            ;;
        *)
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
