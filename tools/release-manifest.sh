#!/usr/bin/env bash
# Create, sign and verify Kryptik release manifests, and sign the update
# channel's `latest` pointer.
#
#   ./tools/release-manifest.sh create --out FILE [--name N] [--version V]
#                                      [--role development|production]
#                                      [--root DIR] PATH...
#   ./tools/release-manifest.sh sign   --key PRIVKEY MANIFEST
#   ./tools/release-manifest.sh verify --signers FILE [--strict] [--root DIR]
#                                      [--principal NAME] [--exact]
#                                      [--require-role production]
#                                      [--no-downgrade VERSION] MANIFEST
#   ./tools/release-manifest.sh pointer --key PRIVKEY --manifest MANIFEST
#                                      --signers SIGNERS --base BASE --out FILE
#                                      [--issued DATE]
#
# verify re-hashes every listed file; --exact also refuses unlisted files.
# --signers may come from KRYPTIK_RELEASE_SIGNERS; there is no default.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

NAMESPACE="kryptik-release"
MAGIC="KRYPTIK-MANIFEST-1"

usage() { sed -n '2,18p' "${BASH_SOURCE[0]}"; }

[[ "$#" -gt 0 ]] || { usage; exit 1; }
MODE="$1"; shift

have ssh-keygen || die "ssh-keygen not found. Install openssh-client."

do_create() {
    local out="" name="kryptik" version="0" role="development" root="."
    local -a paths=()
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --out)     out="$2"; shift 2 ;;
            --name)    name="$2"; shift 2 ;;
            --version) version="$2"; shift 2 ;;
            --role)    role="$2"; shift 2 ;;
            --root)    root="$2"; shift 2 ;;
            -*) die "create: unknown option $1" ;;
            *)  paths+=("$1"); shift ;;
        esac
    done
    [[ -n "$out" ]] || die "create: --out is required"
    [[ "${#paths[@]}" -gt 0 ]] || die "create: at least one path is required"
    case "$role" in
        development|production) ;;
        *) die "create: --role must be development or production, not '${role}'" ;;
    esac
    [[ -d "$root" ]] || die "create: --root ${root} is not a directory"

    local tmp; tmp="$(mktemp)"
    {
        printf '%s\n' "$MAGIC"
        printf 'name: %s\n' "$name"
        printf 'version: %s\n' "$version"
        printf 'role: %s\n' "$role"
        printf 'created: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$tmp"

    # Paths are relative to --root; absolute ones would have verify check
    # files other than those being installed.
    local p f rel
    local -a files=()
    for p in "${paths[@]}"; do
        if [[ -d "${root}/${p}" ]]; then
            while IFS= read -r f; do files+=("$f"); done \
                < <(cd "$root" && find "$p" -type f | LC_ALL=C sort)
        elif [[ -f "${root}/${p}" ]]; then
            files+=("$p")
        else
            rm -f "$tmp"
            die "create: no such file or directory: ${root}/${p}"
        fi
    done

    # Sorted, so an unchanged tree gives a byte-identical manifest. The "./"
    # that `create --root DIR .` produces is dropped to match --exact's names.
    local -a sorted=()
    while IFS= read -r rel; do rel="${rel#./}"; sorted+=("$rel"); done \
        < <(printf '%s\n' "${files[@]}" | LC_ALL=C sort -u)

    printf 'files: %s\n' "${#sorted[@]}" >> "$tmp"
    printf -- '--\n' >> "$tmp"
    for rel in "${sorted[@]}"; do
        printf '%s  %s  %s\n' \
            "$(sha256_of "${root}/${rel}")" \
            "$(wc -c < "${root}/${rel}" | tr -d ' ')" \
            "$rel" >> "$tmp"
    done

    mv -f "$tmp" "$out"
    ok "wrote ${out}: ${#sorted[@]} file(s), role ${role}, version ${version}"
    warn "UNSIGNED. Sign it before it means anything: ${0##*/} sign --key K ${out}"
}

do_sign() {
    local key="" manifest=""
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --key) key="$2"; shift 2 ;;
            -*) die "sign: unknown option $1" ;;
            *)  manifest="$1"; shift ;;
        esac
    done
    [[ -n "$key" ]]      || die "sign: --key is required"
    [[ -f "$key" ]]      || die "sign: no such key file: ${key}"
    [[ -n "$manifest" ]] || die "sign: a manifest path is required"
    [[ -f "$manifest" ]] || die "sign: no such manifest: ${manifest}"

    head -1 "$manifest" | grep -qxF "$MAGIC" \
        || die "sign: ${manifest} is not a ${MAGIC}"

    rm -f "${manifest}.sig"
    ssh-keygen -Y sign -f "$key" -n "$NAMESPACE" "$manifest" >/dev/null 2>&1 \
        || die "sign: ssh-keygen could not sign with ${key}"
    ok "signed: ${manifest}.sig"

    local role; role="$(awk -F': ' '$1=="role"{print $2; exit}' "$manifest")"
    if [[ "$role" == "development" ]]; then
        warn "This manifest says 'role: development'. A verifier run with"
        warn "--require-role production will refuse it, which is the point."
    fi
}

VERIFIED=0
PROBLEMS=0
problem() { err "$*"; PROBLEMS=$((PROBLEMS + 1)); }

do_verify() {
    local signers="${KRYPTIK_RELEASE_SIGNERS:-}" manifest="" root="."
    local strict=0 exact=0 want_role="" no_downgrade="" want_principal=""
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --signers)      signers="$2"; shift 2 ;;
            --root)         root="$2"; shift 2 ;;
            --require-role) want_role="$2"; shift 2 ;;
            --principal)    want_principal="$2"; shift 2 ;;
            --no-downgrade) no_downgrade="$2"; shift 2 ;;
            --strict)       strict=1; shift ;;
            --exact)        exact=1; shift ;;
            -*) die "verify: unknown option $1" ;;
            *)  manifest="$1"; shift ;;
        esac
    done
    [[ -n "$manifest" ]] || die "verify: a manifest path is required"
    [[ -f "$manifest" ]] || die "verify: no such manifest: ${manifest}"

    [[ -n "$signers" ]] || die \
"verify: --signers FILE is required (or KRYPTIK_RELEASE_SIGNERS).
There is no default trust anchor: a verifier that trusts something by default
eventually trusts the wrong thing without saying so."
    [[ -f "$signers" ]] || die "verify: no such allowed-signers file: ${signers}"

    head -1 "$manifest" | grep -qxF "$MAGIC" \
        || die "verify: ${manifest} is not a ${MAGIC}"

    # The signature, before anything inside the manifest is believed.
    local sig="${manifest}.sig"
    if [[ ! -f "$sig" ]]; then
        problem "no signature at ${sig}; the manifest is unsigned"
        die "verify: refusing to report an unsigned manifest as verified"
    fi

    # Enrolled principals holding the signing key (-Y verify needs one as -I).
    # No match exits non-zero; `|| true` so errexit does not skip the error below.
    local found
    found="$(ssh-keygen -Y find-principals -s "$sig" -f "$signers" 2>/dev/null \
             | LC_ALL=C sort -u || true)"
    if [[ -z "$found" ]]; then
        err "no principal in ${signers} holds the key that signed ${manifest}"
        die "verify: the signing key is not enrolled. A signature by an
unenrolled key is not a weaker verification; it is no verification."
    fi

    local principal
    if [[ -n "$want_principal" ]]; then
        if ! printf '%s\n' "$found" | grep -qxF "$want_principal"; then
            err "manifest was signed by [$(printf '%s' "$found" | tr '\n' ' ')]"
            err "but ${want_principal} was required"
            die "verify: signed by an enrolled key, but not by the identity
this release requires."
        fi
        principal="$want_principal"
    else
        principal="$(printf '%s\n' "$found" | head -1)"
    fi

    local vout; vout="$(mktemp)"
    if ! ssh-keygen -Y verify -f "$signers" -I "$principal" -n "$NAMESPACE" \
            -s "$sig" < "$manifest" > "$vout" 2>&1; then
        err "signature does NOT verify against ${signers}:"
        err "  $(tr '\n' ' ' < "$vout" | cut -c1-200)"
        rm -f "$vout"
        die "verify: refusing to check the contents of a manifest whose
signature did not verify. Nothing inside it can be trusted, including its
role and version headers."
    fi
    rm -f "$vout"
    ok "signature verifies, signed by ${principal}"
    VERIFIED=$((VERIFIED + 1))
    if [[ -z "$want_principal" ]]; then
        dim "  (no --principal given, so this reports who signed it rather"
        dim "   than checking who was required; pass --principal for that)"
    fi

    # Only now are the headers trusted: editing one breaks the signature.
    local role version count
    role="$(awk -F': ' '$1=="role"{print $2; exit}' "$manifest")"
    version="$(awk -F': ' '$1=="version"{print $2; exit}' "$manifest")"
    count="$(awk -F': ' '$1=="files"{print $2; exit}' "$manifest")"

    case "$role" in
        development|production) ok "role: ${role} (inside the signed bytes)" ;;
        *) problem "role header is '${role:-missing}', which is neither development nor production" ;;
    esac

    if [[ -n "$want_role" && "$role" != "$want_role" ]]; then
        problem "manifest role is '${role}', but '${want_role}' was required"
        err "  A development signature is not production trust. Enrolling a"
        err "  production key is a separate, deliberate act."
    fi

    if [[ -n "$no_downgrade" ]]; then
        local oldest
        oldest="$(printf '%s\n%s\n' "$version" "$no_downgrade" | sort -V | head -1)"
        if [[ "$version" != "$no_downgrade" && "$oldest" == "$version" ]]; then
            problem "manifest version ${version} is older than the installed ${no_downgrade}"
            err "  Refusing a downgrade: an attacker who can replay an old"
            err "  signed release can reintroduce a fixed vulnerability."
        else
            ok "version ${version} is not older than the installed ${no_downgrade}"
        fi
    fi

    # A good signature says nothing about files never compared with the manifest.
    local listed=0 missing=0 mismatch=0
    local want_hash want_size rel actual_hash actual_size
    while read -r want_hash want_size rel; do
        [[ -n "$rel" ]] || continue
        # Older signed manifests list "./x" and cannot be rewritten.
        rel="${rel#./}"
        listed=$((listed + 1))
        local path="${root}/${rel}"
        if [[ ! -f "$path" ]]; then
            problem "missing: ${rel}"
            missing=$((missing + 1))
            continue
        fi
        actual_size="$(wc -c < "$path" | tr -d ' ')"
        actual_hash="$(sha256_of "$path")"
        if [[ "$actual_hash" != "$want_hash" ]]; then
            problem "CONTENT MISMATCH: ${rel}"
            err "  manifest ${want_hash}"
            err "  on disk  ${actual_hash}"
            mismatch=$((mismatch + 1))
        elif [[ "$actual_size" != "$want_size" ]]; then
            # Same hash, different size: the manifest contradicts itself.
            problem "SIZE DISAGREES for ${rel}: manifest ${want_size}, disk ${actual_size}"
            mismatch=$((mismatch + 1))
        fi
    done < <(sed -n '/^--$/,$p' "$manifest" | tail -n +2)

    if [[ -n "$count" && "$count" != "$listed" ]]; then
        problem "header says ${count} file(s), body lists ${listed}"
    fi

    if [[ "$missing" -eq 0 && "$mismatch" -eq 0 ]]; then
        ok "${listed} file(s) match the manifest"
    fi

    # A payload can arrive alongside the listed files; --exact refuses it.
    if [[ "$exact" -eq 1 ]]; then
        local extra=0 f
        while IFS= read -r f; do
            [[ "${root}/${f}" == "$manifest" || "${root}/${f}" == "${manifest}.sig" ]] && continue
            if ! sed -n '/^--$/,$p' "$manifest" | tail -n +2 \
                 | awk '{ $1=""; $2=""; sub(/^  /, ""); print }' \
                 | grep -qxF "$f"; then
                problem "present but NOT in the manifest: ${f}"
                extra=$((extra + 1))
            fi
        done < <(cd "$root" && find . -type f -printf '%P\n' | LC_ALL=C sort)
        [[ "$extra" -eq 0 ]] && ok "no unlisted files under ${root}"
    fi

    echo
    if [[ "$PROBLEMS" -gt 0 ]]; then
        die "verify: ${PROBLEMS} problem(s). This release does not match its
signed manifest; do not install or boot it."
    fi
    if [[ "$strict" -eq 1 && "$role" != "production" && -z "$want_role" ]]; then
        warn "verified against a '${role}' manifest."
        warn "--strict does not by itself make a development signature"
        warn "production trust; pass --require-role production for that."
    fi
    ok "manifest verified: signature, role, and every listed file."
}

# The channel's `latest` (docs/design/update-channel.md), signed in its own
# namespace so manifest and pointer signatures cannot stand in for each other.
POINTER_MAGIC="KRYPTIK-LATEST-1"
POINTER_NAMESPACE="kryptik-latest"

# Does MANIFEST's signature verify against SIGNERS, by a principal enrolled there?
manifest_signed_by() {   # MANIFEST SIGNERS
    local who
    who="$(ssh-keygen -Y find-principals -s "$1.sig" -f "$2" 2>/dev/null | head -1 || true)"
    [[ -n "$who" ]] && ssh-keygen -Y verify -f "$2" -I "$who" -n "$NAMESPACE" -s "$1.sig" < "$1" >/dev/null 2>&1
}

do_pointer() {
    local key="" manifest="" signers="" base="" out="" issued=""
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --key)      key="${2:?--key needs a file}"; shift 2 ;;
            --manifest) manifest="${2:?--manifest needs a file}"; shift 2 ;;
            --signers)  signers="${2:?--signers needs a file}"; shift 2 ;;
            --base)     base="${2:?--base needs an address}"; shift 2 ;;
            --out)      out="${2:?--out needs a file}"; shift 2 ;;
            --issued)   issued="${2:?--issued needs a date}"; shift 2 ;;
            *) die "pointer: unknown argument: $1" ;;
        esac
    done
    [[ -f "$key" ]]      || die "pointer: --key is required and must exist"
    [[ -f "$manifest" ]] || die "pointer: --manifest is required and must exist"
    [[ -n "$base" && -n "$out" ]] || die "pointer: --base and --out are required"
    head -1 "$manifest" | grep -qxF "$MAGIC" || die "pointer: ${manifest} is not a ${MAGIC}"
    # Only point at a manifest machines will accept: signed, by a key in SIGNERS.
    [[ -s "${manifest}.sig" ]] || die "pointer: ${manifest} is not signed yet (no ${manifest}.sig)"
    [[ -f "$signers" ]] || die "pointer: --signers is required and must exist (the anchor the image carries)"
    manifest_signed_by "$manifest" "$signers" \
        || die "pointer: ${manifest}.sig does not verify against ${signers}; no statement is written about it"
    case "$base" in *[[:space:]]*) die "pointer: --base must not contain spaces" ;; esac
    local version role
    version="$(awk -F': ' '$1=="version"{print $2; exit}' "$manifest")"
    role="$(awk -F': ' '$1=="role"{print $2; exit}' "$manifest")"
    [[ -n "$version" && -n "$role" ]] || die "pointer: the manifest has no version or no role"
    issued="${issued:-$(date -u +%Y-%m-%dT%H:%M:%S+00:00)}"
    {
        printf '%s\n' "$POINTER_MAGIC"
        printf 'role: %s\n' "$role"
        printf 'version: %s\n' "$version"
        printf 'issued: %s\n' "$issued"
        printf 'manifest-sha256: %s\n' "$(sha256sum "$manifest" | cut -c1-64)"
        printf 'base: %s\n' "$base"
    } > "$out"
    rm -f "${out}.sig"
    ssh-keygen -Y sign -f "$key" -n "$POINTER_NAMESPACE" "$out" < /dev/null >/dev/null 2>&1 \
        || die "pointer: ssh-keygen could not sign with ${key}"
    ok "pointer: ${out} names ${version} (${role}), issued ${issued}; signed as ${out}.sig"
}

case "$MODE" in
    create) do_create "$@" ;;
    sign)   do_sign   "$@" ;;
    verify) do_verify "$@" ;;
    pointer) do_pointer "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown mode '${MODE}' (expected create, sign, verify or pointer)" ;;
esac
