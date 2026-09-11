#!/usr/bin/env bash
#
# Sign a Kryptik disk image with a DEVELOPER key.
#
# What this buys, precisely: someone holding the public key can tell whether the
# image in front of them is byte-for-byte the one this builder produced. That is
# all. It is not secure boot, it is not dm-verity, and a developer key is not a
# release key - the signed document says so in a field verify-image.sh refuses
# to ignore, because an image that merely LOOKS signed is worse than an unsigned
# one.
#
# The key lives under ${KRYPTIK_WORK}/keys and never enters the repository.
#
set -Eeuo pipefail

PROG="${0##*/}"
die()  { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
ok()   { printf '  ok %s\n' "$*"; }
note() { printf '     %s\n' "$*"; }

IMAGE="" KERNEL="" KEYDIR="" FORCE_NEW_KEY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)   IMAGE="${2:-}"; shift 2 ;;
        --kernel)  KERNEL="${2:-}"; shift 2 ;;
        --keydir)  KEYDIR="${2:-}"; shift 2 ;;
        --new-key) FORCE_NEW_KEY=1; shift ;;
        -h|--help)
            printf 'usage: %s --image <file> [--kernel <file>] [--keydir <dir>] [--new-key]\n' "$PROG"
            printf 'Signs with a developer ed25519 key, generating one if absent.\n'
            printf 'Writes <image>.sigdoc.json, <image>.sig and <image>.pub.\n'
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$IMAGE" ]] || die "--image is required"
[[ -f "$IMAGE" ]] || die "no such image: ${IMAGE}"
command -v openssl >/dev/null 2>&1 || die "openssl is required"

KEYDIR="${KEYDIR:-${KRYPTIK_WORK:?KRYPTIK_WORK is not set}/keys}"
KEY="${KEYDIR}/dev-image-signing.key"
PUB="${KEYDIR}/dev-image-signing.pub"

mkdir -p "$KEYDIR"
chmod 0700 "$KEYDIR"

if [[ "$FORCE_NEW_KEY" -eq 1 || ! -f "$KEY" ]]; then
    [[ -f "$KEY" ]] && mv -f "$KEY" "${KEY}.$(date +%Y%m%dT%H%M%S).retired"
    # ed25519: no parameter choices to get wrong, and a 64-byte signature.
    openssl genpkey -algorithm ed25519 -out "$KEY" >/dev/null 2>&1 \
        || die "could not generate a signing key"
    chmod 0600 "$KEY"
    ok "generated a new developer signing key"
    note "${KEY}"
    {
        printf 'These are DEVELOPER keys for signing Kryptik images during build.\n\n'
        printf 'They are generated on the build host, they are not escrowed, they are\n'
        printf 'not rotated, and nothing verifies who holds them. An image signed with\n'
        printf 'one of these proves only that it came from this build tree unmodified.\n\n'
        printf 'A release key is a different thing entirely and does not live here.\n'
    } > "${KEYDIR}/README"
fi

openssl pkey -in "$KEY" -pubout -out "$PUB" >/dev/null 2>&1 \
    || die "could not derive the public key"
chmod 0644 "$PUB"

# A short, stable name for "which key signed this", so a verifier can say WHICH
# key it did not trust rather than only "bad signature".
KEY_DER="$(mktemp)"
trap 'rm -f "$KEY_DER"' EXIT INT TERM
openssl pkey -pubin -in "$PUB" -outform DER -out "$KEY_DER" 2>/dev/null \
    || die "could not read the public key back"
KEY_ID="$(sha256sum "$KEY_DER" | cut -c1-16)"

IMAGE_SHA="$(sha256sum "$IMAGE" | cut -d' ' -f1)"
IMAGE_BYTES="$(stat -c %s "$IMAGE")"
KERNEL_SHA=""
if [[ -n "$KERNEL" ]]; then
    [[ -f "$KERNEL" ]] || die "no such kernel: ${KERNEL}"
    KERNEL_SHA="$(sha256sum "$KERNEL" | cut -d' ' -f1)"
fi

DOC="${IMAGE}.sigdoc.json"
SIG="${IMAGE}.sig"
OUTPUB="${IMAGE}.pub"

# The document is what gets signed, so everything a verifier must be able to
# trust has to be IN it. image_sha256 is the load-bearing field: verify-image.sh
# recomputes it from the file on disk and compares.
{
    printf '{\n'
    printf '  "kryptik_signature_version": 1,\n'
    printf '  "key_kind": "developer",\n'
    printf '  "key_id": "%s",\n' "$KEY_ID"
    printf '  "image": "%s",\n' "$(basename "$IMAGE")"
    printf '  "image_sha256": "%s",\n' "$IMAGE_SHA"
    printf '  "image_bytes": %s,\n' "$IMAGE_BYTES"
    printf '  "kernel_sha256": "%s",\n' "$KERNEL_SHA"
    printf '  "signed_at": "%s",\n' "$(date -Iseconds)"
    printf '  "note": "Developer signature. Proves this image is byte-for-byte what the build produced. NOT a release signature, no secure boot, no dm-verity."\n'
    printf '}\n'
} > "$DOC"

openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$DOC" -out "$SIG" \
    || die "signing failed"
cp -f "$PUB" "$OUTPUB"

ok "signed ${IMAGE##*/}"
note "key id    ${KEY_ID} (developer)"
note "sha256    ${IMAGE_SHA}"
note "document  ${DOC}"
note "signature ${SIG} ($(stat -c %s "$SIG") bytes)"
note "public    ${OUTPUB}"
printf '\nVerify with:\n  tools/image/verify-image.sh --image %s --key %s\n' "$IMAGE" "$OUTPUB"
