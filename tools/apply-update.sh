#!/usr/bin/env bash
# Install a signed update, or recover from one that was interrupted.
#
#   ./tools/apply-update.sh --manifest M --signers S --payload DIR --target DIR
#                           [--principal NAME] [--expect-current VERSION]
#                           [--require-role production] [--dry-run]
#   ./tools/apply-update.sh --target DIR --rollback
#   ./tools/apply-update.sh --target DIR --status
#
# THE ORDER IS THE WHOLE DESIGN.
#
# Verify, then swap. Never copy-then-check and never check-then-copy-in-place:
# a half-written target is the failure mode that turns a bad update into an
# unbootable system, and it is the one thing an update tool must not be able to
# produce. So the payload is verified against its signed manifest BEFORE
# anything in the target moves, and the target is then replaced by two
# renames:
#
#     target -> target.previous        (rename, atomic)
#     staged -> target                 (rename, atomic)
#
# A rename within one filesystem either happens or does not. There is no
# instant at which `target` is a mixture of two releases. If the process dies
# between the two renames, `--status` sees it and `--rollback` puts it back;
# that window is one rename wide and is the only one there is.
#
# WHAT THIS DOES NOT DO.
#
# It does not reboot, touch a bootloader, or claim anything about what the
# kernel will load. `verify` proves the bytes match a signature; whether those
# bytes boot is the VM's job to demonstrate, not this tool's to assert. And it
# never verifies the target after installing as though that were the same
# check: the target is the payload, renamed.
#
# Everything cryptographic is delegated to tools/release-manifest.sh, so there
# is one implementation of "is this signed by the right key".

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RM="${TOOLS_DIR}/release-manifest.sh"

MANIFEST=""; SIGNERS=""; PAYLOAD=""; TARGET=""
PRINCIPAL=""; EXPECT_CURRENT=""; WANT_ROLE=""
DRY=0; ROLLBACK=0; STATUS=0
for a in "$@"; do
    case "$a" in
        --manifest=*)        MANIFEST="${a#--manifest=}" ;;
        --signers=*)         SIGNERS="${a#--signers=}" ;;
        --payload=*)         PAYLOAD="${a#--payload=}" ;;
        --target=*)          TARGET="${a#--target=}" ;;
        --principal=*)       PRINCIPAL="${a#--principal=}" ;;
        --expect-current=*)  EXPECT_CURRENT="${a#--expect-current=}" ;;
        --require-role=*)    WANT_ROLE="${a#--require-role=}" ;;
        --dry-run)           DRY=1 ;;
        --rollback)          ROLLBACK=1 ;;
        --status)            STATUS=1 ;;
        -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done

[[ -n "$TARGET" ]] || die "--target=DIR is required"
PREV="${TARGET}.previous"
STAGED="${TARGET}.staged"

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

installed_version() {
    local m="${1}/.kryptik-update"
    [[ -f "$m" ]] || { printf 'unknown'; return; }
    awk -F': ' '$1=="version"{print $2; exit}' "$m" 2>/dev/null || printf 'unknown'
}

if [[ "$STATUS" -eq 1 ]]; then
    log "Update status for ${TARGET}"
    if [[ -d "$TARGET" ]]; then
        ok "target present, version $(installed_version "$TARGET")"
    else
        warn "no target at ${TARGET}"
    fi
    if [[ -d "$PREV" ]]; then
        ok "previous release kept, version $(installed_version "$PREV")"
        dim "  --rollback restores it"
    else
        dim "  no previous release kept"
    fi
    if [[ -d "$STAGED" ]]; then
        # The only state that says an install was interrupted.
        err "an INTERRUPTED install is staged at ${STAGED}"
        err "the target was not replaced; discard the staging directory or"
        err "re-run the same update to complete it"
        exit 2
    fi
    ok "no interrupted install"
    exit 0
fi

# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------

if [[ "$ROLLBACK" -eq 1 ]]; then
    [[ -d "$PREV" ]] || die "rollback: nothing kept at ${PREV}"
    log "Rolling ${TARGET} back to $(installed_version "$PREV")"
    # Same two-rename discipline in reverse, so an interrupted rollback is
    # also recoverable rather than leaving no target at all.
    local_tmp="${TARGET}.rollback-tmp"
    rm -rf "$local_tmp"
    [[ -d "$TARGET" ]] && mv "$TARGET" "$local_tmp"
    mv "$PREV" "$TARGET"
    rm -rf "$local_tmp"
    ok "rolled back to $(installed_version "$TARGET")"
    exit 0
fi

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------

[[ -n "$MANIFEST" ]] || die "--manifest=FILE is required to install"
[[ -n "$SIGNERS" ]]  || die "--signers=FILE is required to install
There is no default trust anchor: see tools/release-manifest.sh."
[[ -n "$PAYLOAD" ]]  || die "--payload=DIR is required to install"
[[ -f "$MANIFEST" ]] || die "no manifest at ${MANIFEST}"
[[ -d "$PAYLOAD" ]]  || die "no payload at ${PAYLOAD}"
[[ -x "$RM" ]]       || die "tools/release-manifest.sh is missing; nothing can be verified"

if [[ -d "$STAGED" ]]; then
    warn "discarding a staging directory left by an interrupted install"
    rm -rf "$STAGED"
fi

# ---- 1. compatibility, before anything is trusted or moved ----------------
#
# An update that does not say which system it applies to is one an attacker
# can replay onto a system it was never meant for. The manifest's version is
# inside the signed bytes, so a mismatch here is a refusal, not a warning.

new_version="$(awk -F': ' '$1=="version"{print $2; exit}' "$MANIFEST")"
[[ -n "$new_version" ]] || die "the manifest carries no version header"

if [[ -n "$EXPECT_CURRENT" ]]; then
    have_now="unknown"
    [[ -d "$TARGET" ]] && have_now="$(installed_version "$TARGET")"
    if [[ "$have_now" != "$EXPECT_CURRENT" ]]; then
        err "this update expects the installed version to be ${EXPECT_CURRENT}"
        err "the target reports ${have_now}"
        die "refusing: an update applied to a system it was not built against
is how a working install becomes a mixture of two releases."
    fi
    ok "compatibility: installed version is ${have_now}, as required"
fi

# ---- 2. verify the payload against the signed manifest --------------------
#
# --exact, always: an update that installs files the manifest does not list is
# an update carrying something nobody signed for.

log "Verifying the payload against its signed manifest"
# release-manifest.sh takes `--signers FILE`, space-separated, not
# `--signers=FILE`. Passing the = form made it die with "unknown option",
# which apply-update.sh then reported as "the payload does not match its
# signed manifest" - a verification failure that had not happened.
declare -a vargs=(verify --signers "$SIGNERS" --root "$PAYLOAD" --exact)
[[ -n "$PRINCIPAL" ]] && vargs+=(--principal "$PRINCIPAL")
[[ -n "$WANT_ROLE" ]] && vargs+=(--require-role "$WANT_ROLE")
if [[ -d "$TARGET" ]]; then
    cur="$(installed_version "$TARGET")"
    [[ "$cur" != "unknown" ]] && vargs+=(--no-downgrade "$cur")
fi
vargs+=("$MANIFEST")

vlog="${TARGET##*/}.verify.log"
vlog="${TMPDIR:-/tmp}/kryptik-${vlog}"
if ! "$RM" "${vargs[@]}" 2>&1 | tee "$vlog"; then
    # A verifier that could not RUN has not established that the payload is
    # bad, and saying so would be a verification result nobody produced. The
    # = form of --signers once triggered exactly this: "unknown option"
    # reported as "does not match its signed manifest".
    if grep -qE 'unknown (option|argument)|is required|no such' "$vlog"; then
        rm -f "$vlog"
        die "the verifier could not run - this is a tooling fault, not a
verification result. The payload has NOT been shown to be bad, and
${TARGET} has not been touched. Fix the invocation and try again."
    fi
    rm -f "$vlog"
    die "the payload does not match its signed manifest.
NOTHING has been installed and ${TARGET} has not been touched."
fi
rm -f "$vlog"
ok "payload verified"

if [[ "$DRY" -eq 1 ]]; then
    ok "--dry-run: verified only, ${TARGET} untouched"
    exit 0
fi

# ---- 3. stage ------------------------------------------------------------
#
# Copied into place beside the target so that the swap is a rename within one
# filesystem. Copying into /tmp and moving would cross filesystems, which
# turns the atomic rename into a non-atomic copy - the exact failure this
# design exists to avoid.

log "Staging into ${STAGED}"
mkdir -p "$(dirname "$STAGED")"
cp -a "$PAYLOAD" "$STAGED"

# The installed-version marker is written into the staged tree, so it lands
# with the same rename as the payload and cannot disagree with it.
{
    printf 'KRYPTIK-UPDATE-1\n'
    printf 'version: %s\n' "$new_version"
    printf 'manifest-sha256: %s\n' "$(sha256_of "$MANIFEST")"
    printf 'installed: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "${STAGED}/.kryptik-update"

# ---- 4. swap -------------------------------------------------------------

log "Installing"
rm -rf "$PREV"
if [[ -d "$TARGET" ]]; then
    mv "$TARGET" "$PREV"
fi
mv "$STAGED" "$TARGET"

ok "installed version ${new_version}"
if [[ -d "$PREV" ]]; then
    dim "  previous release kept at ${PREV} (--rollback restores it)"
fi
dim "  this tool has not rebooted anything and makes no claim that the new"
dim "  tree boots. Demonstrating that is the VM's job."
