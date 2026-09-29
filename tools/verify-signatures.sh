#!/usr/bin/env bash
# Verify upstream GPG signatures for fetched source tarballs.
#
#   ./tools/verify-signatures.sh [--strict] [--refresh] [--fetch-unknown-keys]
#                                [--report=FILE] [--notes=FILE]
#     --strict              release gate: anything unverified or unaudited fails,
#                           except a signer no publisher states, when
#                           tools/source-notes.tsv says so (no-usable-key)
#     --refresh             discard cached keys and re-import
#     --fetch-unknown-keys  import keys the signatures name (unaudited)
#     --report=FILE         per-source results to FILE
#     --notes=FILE          the caveats, not tools/source-notes.tsv

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
NOTES="$(dirname "${BASH_SOURCE[0]}")/source-notes.tsv"
for a in "$@"; do
    case "$a" in
        --refresh) rm -rf "$GNUPGHOME" "$GNU_KEYRING" ;;
        --fetch-unknown-keys) FETCH_UNKNOWN=1 ;;
        --strict) STRICT=1 ;;
        --report=*) REPORT="${a#--report=}" ;;
        --notes=*) NOTES="${a#--notes=}" ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done
[[ -n "$REPORT" ]] && : > "$REPORT"

# A signer no publisher states, accepted deliberately: the note names the
# routes that were tried. Such a source is not held against --strict; a note
# for a source whose key is held is stale, and --strict fails on it.
declare -A NOTED_NO_KEY=()
if [[ -f "$NOTES" ]]; then
    while read -r n_pkg n_kind _; do
        [[ "$n_kind" == no-usable-key ]] && NOTED_NO_KEY[$n_pkg]=1
    done < <(grep -v '^[[:space:]]*#' "$NOTES")
fi
NOTED=0
NOTED_LIST=()
declare -A NOTE_USED=()
declare -A SEEN_SOURCE=()

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

# A host that throttles (freedesktop.org answers 418 to a busy runner, others
# 429 or 503) is asked again after a pause; a 404 is an answer.
quiet_fetch() {   # quiet_fetch URL OUT
    local code try
    for try in 1 2 3; do
        if code="$(curl -fsL --connect-timeout 20 --retry 2 --retry-delay 2 \
                        -o "$2" -w '%{http_code}' "$1" 2>/dev/null)"; then return 0; fi
        case "$code" in 418|429|503) sleep $(( try * 5 )) ;; *) break ;; esac
    done
    rm -f "$2"
    return 1
}

# --- keys ------------------------------------------------------------------

CANONICAL_GNU="https://ftp.gnu.org/gnu"

# Overrides for tools/tests/verify-signatures.sh only.
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

# Upstream signs with nothing OpenPGP, by the manifest's own declaration or
# by a listing that holds none: the lock pins the file, and
# tools/verify-provenance.sh checks whatever else upstream publishes. A
# declared signature that is missing or is not a signature stays unverifiable.
UNSIGNED=0
UNSIGNED_LIST=()
mark_unsigned() {
    UNSIGNED=$((UNSIGNED + 1))
    UNSIGNED_LIST+=("$1")
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

    # From https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc
    # (retrieved 2026-09-27), the key file beside the releases. Of its five
    # keys, this one, current since 2021, signs 10.5p1. ssh-keygen checks every
    # release statement, so openssh is on the update path.
    "7168B983815A5EEF59A4ADFD2A3F414E736060BA"   # Damien Miller, OpenSSH

    # From https://www.greenwoodsoftware.com/less/pubkey.asc (retrieved
    # 2026-09-27), linked from the download page beside each release's .sig.
    # DSA-1024 signing with SHA-1: weak, as docs/supply-chain.md says.
    "AE27252BD6846E7D6EAE1DD6F153A7C833235259"   # Mark Nudelman, less

    # From https://www.netfilter.org/files/coreteam-gpg-key-0xD70D1A666ACF2B21.txt
    # (retrieved 2026-09-27), the "key" linked beside each release on the
    # download pages. https://www.netfilter.org/about.html names it the current
    # key, valid until 2028-10-12, and the older keys revoked.
    "8C5F7146A1757A65E2422A94D70D1A666ACF2B21"   # Netfilter Core Team, libnftnl and nftables

    # From https://cmake.org/download/ (retrieved 2026-09-27): beside each
    # release's SHA-256.txt.asc the page names the signer 2D2CEF1034921684 and
    # links it to the keyserver's lookup of this primary, whose signing
    # subkey that is.
    "CBA23971357C2E6590D9EFD3EC8FEF3A7BFB4EDA"   # Brad King, cmake checksum lists

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

# The primary fingerprints of the keys in FILE, one per line.
primaries_in() {
    gpg --batch --with-colons --import-options show-only --import "$1" 2>/dev/null \
        | awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print toupper($10); p = 0 }' || true
}

# anchored_import FPR FILE: merge the key FPR from FILE into the keyring, with
# the revocations, subkeys and signatures FILE carries for it, and nothing else
# FILE holds. A keyring of its own picks it out, and the export is checked to
# be that key alone. Prints FILE's primary fingerprints. Returns 1 when FILE
# lacks FPR, and 2 when FPR is there but cannot be taken alone.
anchored_import() {
    local fpr="$1" file="$2" home found rc=1
    found="$(primaries_in "$file" | tr '\n' ' ')"
    if [[ " ${found} " == *" ${fpr} "* ]]; then
        rc=2
        home="$(mktemp -d)"; chmod 700 "$home"
        if GNUPGHOME="$home" gpg --batch --quiet --import "$file" >/dev/null 2>&1 \
           && GNUPGHOME="$home" gpg --batch --export "$fpr" > "${home}/key.gpg" 2>/dev/null \
           && [[ "$(primaries_in "${home}/key.gpg")" == "$fpr" ]] \
           && gpg --batch --quiet --import "${home}/key.gpg" >/dev/null 2>&1; then
            rc=0
        fi
        GNUPGHOME="$home" gpgconf --kill all >/dev/null 2>&1 || true
        rm -rf "$home"
    fi
    printf '%s' "${found% }"
    return "$rc"
}

# Merge one source's published keys from where they are published, held or
# not, so a revocation or a new subkey published there is seen. The recorded
# fingerprint is the anchor: only that key is taken from what a locator
# serves, and a locator no longer serving it is refused, which fails every
# source the key signs, even with a copy held. Once a run each.
declare -A PROV_FETCHED=() PROV_REFUSED=()
import_provenance_keys_for() {
    local name="$1" i fpr tmp home got rc
    for i in "${!PROV_FPR[@]}"; do
        case "${PROV_SIGNS[$i]}" in *",${name},"*) ;; *) continue ;; esac
        fpr="${PROV_FPR[$i]}"
        [[ -z "${PROV_FETCHED[$fpr]:-}" ]] || continue
        PROV_FETCHED[$fpr]=1

        tmp="$(mktemp)"
        case "${PROV_KIND[$i]}" in
            korg|github)
                if ! curl -fsSL --max-time 30 -o "$tmp" "${PROV_LOC[$i]}" 2>/dev/null; then
                    warn "${name}: could not fetch the published key from ${PROV_LOC[$i]}"
                    rm -f "$tmp"; continue
                fi
                ;;
            wkd)
                # --locate-external-key imports what it finds, so it runs in a
                # keyring of its own and only its export is read.
                home="$(mktemp -d)"; chmod 700 "$home"
                if GNUPGHOME="$home" gpg --batch --quiet --auto-key-locate clear,wkd \
                       --locate-external-key "${PROV_LOC[$i]}" >/dev/null 2>&1; then
                    GNUPGHOME="$home" gpg --batch --export > "$tmp" 2>/dev/null || true
                fi
                GNUPGHOME="$home" gpgconf --kill all >/dev/null 2>&1 || true
                rm -rf "$home"
                if [[ ! -s "$tmp" ]]; then
                    warn "${name}: no WKD answer for ${PROV_LOC[$i]}"
                    rm -f "$tmp"; continue
                fi
                ;;
        esac
        rc=0
        got="$(anchored_import "$fpr" "$tmp")" || rc=$?
        rm -f "$tmp"
        if [[ "$rc" -eq 0 ]]; then
            dim "  ${name}: imported the key ${PROV_KIND[$i]} publishes (${fpr})"
            continue
        fi
        if [[ "$rc" -eq 2 ]]; then
            err "${name}: ${PROV_LOC[$i]} serves ${fpr}, but it could not be taken"
            err "  alone. REFUSING it: the recorded fingerprint is the anchor."
        else
            err "${name}: ${PROV_LOC[$i]} now publishes ${got:-no key},"
            err "  not the recorded ${fpr}. REFUSING it: a key that"
            err "  changed at a published location is a finding, not an update."
        fi
        PROV_REFUSED[$fpr]="${PROV_LOC[$i]}"
    done
    return 0
}

# The locator of a refused key that signs NAME; fails if there is none.
refused_locator_for() {
    local name="$1" i
    for i in "${!PROV_FPR[@]}"; do
        case "${PROV_SIGNS[$i]}" in *",${name},"*) ;; *) continue ;; esac
        if [[ -n "${PROV_REFUSED[${PROV_FPR[$i]}]:-}" ]]; then
            printf '%s' "${PROV_REFUSED[${PROV_FPR[$i]}]}"
            return 0
        fi
    done
    return 1
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

# check_sig <name> <sigfile> <datafile> [how]: classify gpg's status output.
# An empty datafile checks a signed message, which carries its own data.
# EXPKEYSIG counts as verified: the signature is valid and only the keyring's
# copy of the key has expired (maintainers extend expiry; the keyring lags).
# how, when given, ends each report detail.
check_sig() {
    local name="$1" sigfile="$2" datafile="$3" how="${4:+; $4}"
    local out signer keyid
    local -a signed=("$sigfile")
    [[ -n "$datafile" ]] && signed+=("$datafile")

    # Before verifying, so a published key wins over --fetch-unknown-keys.
    import_provenance_keys_for "$name"

    local refused
    if refused="$(refused_locator_for "$name")"; then
        err "${name}: its signing key's published copy at ${refused} was refused"
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("${name} (its published key changed at ${refused})")
        report "$name" published-key-changed "${refused}${how}"
        return 0
    fi

    out="$(gpg --batch --status-fd 1 --verify "${signed[@]}" 2>/dev/null || true)"

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
            report "$name" signature-unaudited-key "${signer:-unknown} (${keyid})${how}"
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
            report "$name" "$klass" "${signer:-unknown} (${keyid}; key expired)${how}"
        else
            ok "${name}: signature valid  [${signer:-unknown}]"
            report "$name" "$klass" "${signer:-unknown} (${keyid})${how}"
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
        report "$name" signature-revoked-key "${signer:-unknown}${how}"
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] NO_PUBKEY"; then
        keyid="$(printf '%s' "$out" | sed -n 's/^\[GNUPG:\] NO_PUBKEY //p' | head -1)"

        # The key the signature names is circular trust: it proves only who
        # signed. So it goes to keys.manifest for an out-of-band audit and is
        # never counted as verified.
        if [[ "$FETCH_UNKNOWN" -eq 1 ]]; then
            if recv_key "$keyid"; then
                out="$(gpg --batch --status-fd 1 --verify "${signed[@]}" 2>/dev/null || true)"
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

        if [[ -n "${NOTED_NO_KEY[$name]:-}" ]]; then
            warn "${name}: signing key ${keyid} not held; no publisher states it (source-notes.tsv), accepted by note"
            NOTED=$((NOTED + 1)); NOTED_LIST+=("${name} (key ${keyid})"); NOTE_USED[$name]=1
            report "$name" key-not-held "${keyid}; no publisher states the key, accepted by note${how}"
            return 0
        fi
        warn "${name}: signing key ${keyid} not held"
        mark_unverifiable "${name} (signing key ${keyid} not held)"
        report "$name" key-not-held "${keyid}${how}"
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] BADSIG"; then
        err "${name}: BAD SIGNATURE - the file does not match its signature"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("$name")
        report "$name" signature-bad "the file does not match its signature${how}"
        return 0
    fi

    if printf '%s' "$out" | grep -q "^\[GNUPG:\] ERRSIG"; then
        warn "${name}: signature could not be checked"
        mark_unverifiable "${name} (ERRSIG - key unavailable or unsupported algorithm)"
        report "$name" signature-uncheckable "ERRSIG: key unavailable or unsupported algorithm${how}"
        return 0
    fi

    warn "${name}: inconclusive gpg result"
    mark_unverifiable "${name} (inconclusive)"
    report "$name" inconclusive "gpg produced no status this script recognises${how}"
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
# A signed message carries its data; a detached signature does not.
is_signed_message() {
    local packets
    packets="$(gpg --batch --list-packets "$1" 2>/dev/null || true)"
    grep -q ':literal data packet:' <<< "$packets"
}

is_pgp_signature() {
    [[ -s "$1" ]] || return 1
    gpg --batch --list-packets "$1" 2>/dev/null | grep -q ':signature packet:'
}

# Try .sig, .asc and .sign; one that is not OpenPGP passes the turn on. The
# report names the suffix found, which the manifest can then declare.
verify_any() {
    local name="$1" url="$2" file="$3"
    local suffix sig
    local -a wrong_format=()
    for suffix in .sig .asc .sign; do
        sig="${SIGDIR}/${file}${suffix}"
        if [[ -s "$sig" ]] || quiet_fetch "${url}${suffix}" "$sig" 2>/dev/null; then
            if is_pgp_signature "$sig"; then
                check_sig "$name" "$sig" "${KRYPTIK_SOURCES}/${file}" "probe found ${suffix}" || true
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
    mark_unsigned "${name} (upstream publishes no signature)"
    report "$name" no-signature-upstream "none of .sig/.asc/.sign is published"
}

# verify_detached <name> <data> <sigurl> [how]: the detached signature at
# sigurl over the file data, cached under its own name.
verify_detached() {
    local name="$1" data="$2" sigurl="$3" how="${4:-}"
    local sig="${SIGDIR}/${sigurl##*/}" suffix=".${sigurl##*.}"

    if [[ ! -s "$sig" ]] && ! quiet_fetch "$sigurl" "$sig"; then
        rm -f "$sig"
        warn "${name}: no ${suffix} published upstream"
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
    # A signed message carries its data: it vouches for this data only if
    # what it carries is exactly this data.
    if is_signed_message "$sig"; then
        local carried="${sig}.carried"
        gpg --batch --quiet --yes --output "$carried" --decrypt "$sig" >/dev/null 2>&1 || true
        if ! cmp -s "$carried" "$data"; then
            rm -f "$carried"
            err "${name}: ${sigurl##*/} is a signed message carrying other data"
            FAILED=$((FAILED + 1)); FAILED_LIST+=("${name} (${sigurl##*/} carries other data)")
            report "$name" signature-bad "${sigurl##*/} carries other data${how:+; ${how}}"
            return
        fi
        rm -f "$carried"
        check_sig "$name" "$sig" "" "$how" || true
        return
    fi
    check_sig "$name" "$sig" "$data" "$how" || true
}

# The digest LIST gives FILE: the first field of the line naming it (a
# leading * marks binary mode), or of a list that is one bare digest.
listed_digest() {  # listed_digest LIST FILE
    awk -v f="$2" '
        NF >= 2 { n = $NF; sub(/^\*/, "", n); if (n == f) { print tolower($1); hit = 1; exit } }
        NF == 1 { bare = tolower($1) }
        END { if (!hit && NR == 1 && bare != "") print bare }' "$1"
}

# verify_sums <name> <url> <file> <signature>: a detached signature beside
# the file over a checksum list, named for the signature without its
# suffix. The file must match its digest in the list, and the signature the
# list.
verify_sums() {
    local name="$1" url="$2" file="$3" signame="$4"
    local listname="${signame%.*}"
    local list="${SIGDIR}/${listname}" want got

    if [[ ! -s "$list" ]] && ! quiet_fetch "${url%/*}/${listname}" "$list"; then
        rm -f "$list"
        warn "${name}: no ${listname} published upstream"
        mark_unverifiable "${name} (no checksum list upstream)"
        report "$name" no-signature-upstream "no ${listname} published beside the tarball"
        return
    fi
    want="$(listed_digest "$list" "$file")"
    case "${#want}" in
        64)  got="$(sha256sum "${KRYPTIK_SOURCES}/${file}" | cut -d' ' -f1)" ;;
        128) got="$(sha512sum "${KRYPTIK_SOURCES}/${file}" | cut -d' ' -f1)" ;;
        *)   got="" ;;
    esac
    if [[ -z "$got" || "$got" != "$want" ]]; then
        err "${name}: ${file} does not match a digest in ${listname}"
        FAILED=$((FAILED + 1)); FAILED_LIST+=("${name} (does not match ${listname})")
        report "$name" signature-bad "the file does not match a digest in ${listname}"
        return
    fi
    verify_detached "$name" "$list" "${url%/*}/${signame}" "signs ${listname}"
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

# The manifest's sig column says how upstream vouches for each file.
while read -r name _ver url sig _; do
    SEEN_SOURCE[$name]=1
    [[ -z "$name" ]] && continue
    file="$(basename "$url")"

    # A kind this script does not know fails: skipping it would pass the row.
    case "$sig" in
        gnu|kernel|sig|asc|stem.sig|sums:?*|probe|sha256|sha256.txt|tag|none) ;;
        *)
            err "${name}: the manifest declares no signature kind this script knows ('${sig}')"
            FAILED=$((FAILED + 1)); FAILED_LIST+=("${name} (unknown signature kind '${sig}')")
            report "$name" signature-kind-unknown "the manifest declares '${sig}'"
            continue
            ;;
    esac

    # Not downloaded is unverifiable, so --strict fails on it.
    [[ -f "${KRYPTIK_SOURCES}/${file}" ]] || {
        warn "${name}: not downloaded, so its signature cannot be checked"
        mark_unverifiable "${name} (not downloaded)"
        report "$name" not-downloaded "no local copy to check a signature against"
        continue
    }

    case "$sig" in
        gnu)    verify_gnu      "$name" "$url" "$file" ;;
        kernel) verify_kernel   "$name" "$url" "$file" ;;
        sig)      verify_detached "$name" "${KRYPTIK_SOURCES}/${file}" "${url}.sig" ;;
        asc)      verify_detached "$name" "${KRYPTIK_SOURCES}/${file}" "${url}.asc" ;;
        stem.sig) verify_detached "$name" "${KRYPTIK_SOURCES}/${file}" "${url%.tar.*}.sig" ;;
        sums:*)   verify_sums     "$name" "$url" "$file" "${sig#sums:}" ;;
        probe)    verify_any      "$name" "$url" "$file" ;;
        sha256|sha256.txt|tag)
            what="the publisher's .${sig}"
            [[ "$sig" == tag ]] && what="the signed tag"
            warn "${name}: no OpenPGP signature upstream; ${what} is verify-provenance's"
            mark_unsigned "${name} (${what}, see verify-provenance)"
            report "$name" no-signature-upstream "no OpenPGP signature; tools/verify-provenance.sh checks ${what}"
            ;;
        none)
            warn "${name}: upstream publishes no signature for it"
            mark_unsigned "${name} (upstream publishes no signature)"
            report "$name" no-signature-upstream "upstream publishes no signature for it"
            ;;
    esac
done < <(manifest_source)

echo
log "Summary"
ok "verified:     ${VERIFIED}$([[ "$EXPIRED" -gt 0 ]] && printf ' (%s with expired keys)' "$EXPIRED")"
[[ "$FETCHED" -gt 0 ]]      && warn "unaudited:    ${FETCHED} (key taken from the signature itself)"
[[ "$UNVERIFIABLE" -gt 0 ]] && warn "unverifiable: ${UNVERIFIABLE}"
[[ "$UNSIGNED" -gt 0 ]]     && dim  "unsigned:     ${UNSIGNED} (no OpenPGP signature upstream; the lock's and verify-provenance's)"
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
    dim "Unverifiable (not proof of tampering - a signature that could not be checked):"
    printf '  - %s\n' "${UNVERIFIABLE_LIST[@]}"
fi

if [[ "${#UNSIGNED_LIST[@]}" -gt 0 ]]; then
    echo
    dim "Publish no OpenPGP signature (sources.lock pins them; tools/verify-provenance.sh checks what else they publish):"
    printf '  - %s\n' "${UNSIGNED_LIST[@]}"
fi

if [[ "$FAILED" -gt 0 ]]; then
    echo
    err "Signature verification FAILED for: ${FAILED_LIST[*]}"
    die "Do not build from these sources. Delete them and re-fetch."
fi

if [[ "$NOTED" -gt 0 ]]; then
    echo
    warn "${NOTED} source(s) signed by a key no publisher states, accepted by note (${NOTES#"$KRYPTIK_ROOT"/}):"
    printf '  - %s\n' "${NOTED_LIST[@]}"
fi
# A note that no unheld key needed: the key is held now, or the source went.
# A signature that could not be checked this run tried no note.
untried_this_run() {   # untried_this_run NAME
    local u
    for u in "${UNVERIFIABLE_LIST[@]}"; do [[ "$u" == "$1 ("* ]] && return 0; done
    return 1
}
STALE_NOTES=()
for n_pkg in "${!NOTED_NO_KEY[@]}"; do
    [[ -n "${NOTE_USED[$n_pkg]:-}" ]] && continue
    untried_this_run "$n_pkg" && continue
    [[ -n "${SEEN_SOURCE[$n_pkg]:-}" ]] && STALE_NOTES+=("$n_pkg")
done
if [[ "${#STALE_NOTES[@]}" -gt 0 ]]; then
    echo
    warn "no-usable-key note(s) for a source whose key is held or whose signature is not checked this way: ${STALE_NOTES[*]}"
    [[ "$STRICT" -eq 1 ]] && die "--strict will not carry a stale note; remove it from ${NOTES#"$KRYPTIK_ROOT"/}"
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
if [[ "$UNSIGNED" -gt 0 ]]; then
    dim "${UNSIGNED} source(s) publish no OpenPGP signature; tools/verify-provenance.sh --strict is their gate."
fi
if [[ "$((UNVERIFIABLE + FETCHED))" -gt 0 ]]; then
    warn "This run is informational. --strict fails here."
fi
ok "No signature verification failures (${VERIFIED} verified)."
