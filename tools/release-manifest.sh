#!/usr/bin/env bash
# Create, sign and verify a Kryptik release manifest.
#
#   ./tools/release-manifest.sh create --out FILE [--name N] [--version V]
#                                      [--role development|production]
#                                      [--root DIR] PATH...
#   ./tools/release-manifest.sh sign   --key PRIVKEY MANIFEST
#   ./tools/release-manifest.sh verify --signers FILE [--strict] [--root DIR]
#                                      [--principal NAME] [--exact]
#                                      [--require-role production]
#                                      [--no-downgrade VERSION] MANIFEST
#
# This is the verification primitive the signed-image and recoverable-update
# work needs: a record of exactly which bytes a release consists
# of, signed, and a check that refuses anything that does not match it.
#
# WHAT IT IS FOR, AND THE MISTAKE IT IS BUILT TO AVOID
#
# An update mechanism that verifies a signature over a *manifest* and then
# installs files it never compared against that manifest has verified nothing —
# the same defect as a signed git tag that was never compared with the tarball
# being built. So `verify` checks the signature AND re-hashes every listed file,
# and `--exact` additionally refuses files that are present but unlisted, which
# is how an extra payload rides along.
#
# DEVELOPMENT SIGNING IS NOT PRODUCTION TRUST
#
# Every manifest carries a mandatory `role:` header. A manifest signed with a
# development key says `role: development`, and `verify --require-role
# production` refuses it. This exists so that a development key cannot be
# quietly promoted by being pointed at a production flow: the role travels
# inside the signed bytes, so changing it invalidates the signature.
#
# THERE IS NO DEFAULT TRUST ANCHOR
#
# `verify` requires `--signers FILE` (or KRYPTIK_RELEASE_SIGNERS). There is
# deliberately no built-in fallback: a verifier that trusts something by
# default will eventually trust the wrong thing silently, and the whole point
# of the tree-binding work in tools/verify-provenance.sh was that an
# unverifiable check must fail rather than pass quietly.
#
# MECHANISM
#
# OpenSSH signatures (`ssh-keygen -Y sign`/`-Y verify`, namespace
# `kryptik-release`) with an allowed-signers file, which is the same mechanism
# and the same kind of anchor Kryptik already verifies for hardened_malloc.
# No new dependency: openssh-client is already required by
# tools/verify-provenance.sh.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

NAMESPACE="kryptik-release"
MAGIC="KRYPTIK-MANIFEST-1"

usage() { sed -n '2,10p' "${BASH_SOURCE[0]}"; }

[[ "$#" -gt 0 ]] || { usage; exit 1; }
MODE="$1"; shift

have ssh-keygen || die "ssh-keygen not found. Install openssh-client."

# ============================================================================
# create
# ============================================================================

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

    # Every path is recorded RELATIVE to --root, so a manifest is not tied to
    # where it was produced. Absolute paths in a manifest are how a verifier
    # ends up checking a different file than the one that gets installed.
    local tmp; tmp="$(mktemp)"
    {
        printf '%s\n' "$MAGIC"
        printf 'name: %s\n' "$name"
        printf 'version: %s\n' "$version"
        printf 'role: %s\n' "$role"
        printf 'created: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$tmp"

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

    # Sorted, so the manifest of an unchanged tree is byte-identical and a diff
    # of two manifests is readable.
    # Canonicalise away a leading "./". `create --root DIR .` is the natural
    # way to manifest a whole tree, and `find . -type f` emits "./usr/bin/x"
    # while --exact's listing emits "usr/bin/x" - so every single file was
    # reported as "present but NOT in the manifest" while simultaneously
    # matching its recorded hash. Found by manifesting the real sysroot.
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

# ============================================================================
# sign
# ============================================================================

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

# ============================================================================
# verify
# ============================================================================

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

    # No default anchor. See the header.
    [[ -n "$signers" ]] || die \
"verify: --signers FILE is required (or KRYPTIK_RELEASE_SIGNERS).
There is no default trust anchor: a verifier that trusts something by default
eventually trusts the wrong thing without saying so."
    [[ -f "$signers" ]] || die "verify: no such allowed-signers file: ${signers}"

    head -1 "$manifest" | grep -qxF "$MAGIC" \
        || die "verify: ${manifest} is not a ${MAGIC}"

    # ---- the signature, before anything inside the manifest is believed ----
    local sig="${manifest}.sig"
    if [[ ! -f "$sig" ]]; then
        problem "no signature at ${sig}; the manifest is unsigned"
        die "verify: refusing to report an unsigned manifest as verified"
    fi

    # `ssh-keygen -Y verify` requires -I: the identity you EXPECTED to have
    # signed. It will not simply tell you who did, which is the right shape -
    # "who signed this" and "is this the signer I require" are different
    # questions, and only the second one is a check.
    #
    # find-principals answers the first: which principals in the allowed-signers
    # file hold the key that made this signature. If none do, the key is not
    # enrolled and there is nothing to verify against.
    # `|| true` inside the substitution: find-principals exits non-zero when
    # nothing matches, and under common.sh's errexit plus ERR trap that aborts
    # the script with a line number instead of reaching the diagnosis below.
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

    # ---- headers, now that they are known to be signed ---------------------
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
        # Sort the two versions and refuse if the manifest is the older one.
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

    # ---- the files ---------------------------------------------------------
    local listed=0 missing=0 mismatch=0
    local want_hash want_size rel actual_hash actual_size
    while read -r want_hash want_size rel; do
        [[ -n "$rel" ]] || continue
        # Manifests written before paths were canonicalised carry "./x"; the
        # signature covers those bytes, so they cannot be rewritten. Normalise
        # on read instead, or such a manifest would stop verifying.
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
            # Cannot happen for sha256-equal files; a disagreement means the
            # manifest itself is inconsistent.
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

    # ---- extra files -------------------------------------------------------
    #
    # An update that only checks the files it was told about cannot see a
    # payload that arrived alongside them.
    if [[ "$exact" -eq 1 ]]; then
        local extra=0 f man_sha
        man_sha="$(sha256_of "$manifest")"
        while IFS= read -r f; do
            [[ "${root}/${f}" == "$manifest" || "${root}/${f}" == "${manifest}.sig" ]] && continue

            # THE ONE EXEMPTION --exact MAKES, and it validates itself.
            #
            # tools/apply-update.sh writes .kryptik-update INSIDE the tree, on
            # purpose: the marker then lands with the same rename as the payload
            # and cannot disagree with it. The consequence is that an INSTALLED
            # tree contains exactly one file no release manifest lists, so
            # `verify --exact` against the manifest it was installed from used
            # to fail forever - found by running the update recovery recipe
            # end to end, where rollback could not be proved complete because
            # the restored tree "did not match its signed manifest".
            #
            # An exemption in a verifier is how holes get made, so this one is
            # narrow and self-checking: the name must be exactly
            # .kryptik-update, it must be at the ROOT of the verified tree, and
            # its manifest-sha256 must name THIS manifest. A marker naming a
            # different manifest is not tolerated - it is a finding, because it
            # means the tree was installed from another release.
            if [[ "$f" == ".kryptik-update" ]]; then
                local marked
                marked="$(awk -F': ' '$1=="manifest-sha256"{print $2; exit}'                           "${root}/${f}" 2>/dev/null)"
                if [[ -n "$marked" && "$marked" == "$man_sha" ]]; then
                    ok "the installer's marker names this manifest"
                    continue
                fi
                problem "the installed marker .kryptik-update names manifest ${marked:-<none>},
not this one (${man_sha}). This tree was installed from a DIFFERENT release,
or the marker was written by something other than apply-update.sh."
                extra=$((extra + 1))
                continue
            fi
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

case "$MODE" in
    create) do_create "$@" ;;
    sign)   do_sign   "$@" ;;
    verify) do_verify "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown mode '${MODE}' (expected create, sign or verify)" ;;
esac
