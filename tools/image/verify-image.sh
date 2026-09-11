#!/usr/bin/env bash
#
# Verify a Kryptik image against a developer signature.
#
# Three things have to hold, and each is checked separately so a failure says
# which one broke:
#
#   1. the signature is valid over the signed document, under the given key
#   2. the document describes THIS image - sha256 recomputed from disk
#   3. the document does not claim to be something it is not
#
# Checking 1 alone would accept a valid signature over a document about a
# different image, which is the classic way signature checking gets it wrong.
#
set -Eeuo pipefail

PROG="${0##*/}"
die()  { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
ok()   { printf '  ok   %s\n' "$*"; }
bad()  { printf '  FAIL %s\n' "$*"; }
note() { printf '       %s\n' "$*"; }

IMAGE="" KEY="" DOC="" SIG="" EXPECT_KIND=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)       IMAGE="${2:-}"; shift 2 ;;
        --key)         KEY="${2:-}"; shift 2 ;;
        --doc)         DOC="${2:-}"; shift 2 ;;
        --sig)         SIG="${2:-}"; shift 2 ;;
        --expect-kind) EXPECT_KIND="${2:-}"; shift 2 ;;
        -h|--help)
            printf 'usage: %s --image <f> --key <pubkey> [--doc <f>] [--sig <f>] [--expect-kind K]\n' "$PROG"
            exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$IMAGE" ]] || die "--image is required"
[[ -f "$IMAGE" ]] || die "no such image: ${IMAGE}"
[[ -n "$KEY"   ]] || die "--key is required"
[[ -f "$KEY"   ]] || die "no such key: ${KEY}"
DOC="${DOC:-${IMAGE}.sigdoc.json}"
SIG="${SIG:-${IMAGE}.sig}"
[[ -f "$DOC" ]] || die "no signed document at ${DOC}"
[[ -f "$SIG" ]] || die "no signature at ${SIG}"
command -v openssl >/dev/null 2>&1 || die "openssl is required"

fail=0
printf 'verifying %s\n' "${IMAGE##*/}"

# --- 1. the signature over the document ------------------------------------
if openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin \
        -in "$DOC" -sigfile "$SIG" >/dev/null 2>&1; then
    ok "signature is valid under $(basename "$KEY")"
else
    bad "signature does NOT verify under $(basename "$KEY")"
    note "either the document was altered, or this is not the signing key"
    fail=$((fail + 1))
fi

# --- 2. the document is about THIS image -----------------------------------
# Fields are read with grep on the file directly. No JSON parser, because the
# target may not have one, and no pipeline into an early-exiting reader.
field() {
    local name="$1" pat="$2"
    grep -oE "\"${name}\"[[:space:]]*:[[:space:]]*${pat}" "$DOC" | head -1 || true
}
doc_sha="$(field image_sha256 '"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' || true)"
doc_bytes="$(field image_bytes '[0-9]+' | grep -oE '[0-9]+$' || true)"

if [[ -z "$doc_sha" ]]; then
    bad "the signed document names no image_sha256"
    fail=$((fail + 1))
else
    real_sha="$(sha256sum "$IMAGE" | cut -d' ' -f1)"
    if [[ "$real_sha" == "$doc_sha" ]]; then
        ok "image matches the signed digest"
        note "${real_sha}"
    else
        bad "image does NOT match the signed digest"
        note "signed for ${doc_sha}"
        note "on disk    ${real_sha}"
        fail=$((fail + 1))
    fi
fi

real_bytes="$(stat -c %s "$IMAGE")"
if [[ -n "$doc_bytes" && "$doc_bytes" != "$real_bytes" ]]; then
    bad "image size does not match the signed document"
    note "signed ${doc_bytes}, on disk ${real_bytes}"
    fail=$((fail + 1))
fi

# --- 3. what kind of signature is this -------------------------------------
kind="$(field key_kind '"[a-z]+"' | grep -oE '[a-z]+"$' | tr -d '"' || true)"
key_id="$(field key_id '"[0-9a-f]+"' | grep -oE '[0-9a-f]+"$' | tr -d '"' || true)"
note "key id ${key_id:-unknown}, kind ${kind:-unknown}"

if [[ -n "$EXPECT_KIND" ]]; then
    if [[ "$kind" == "$EXPECT_KIND" ]]; then
        ok "signature kind is ${EXPECT_KIND} as required"
    else
        bad "signature kind is '${kind:-unknown}', not '${EXPECT_KIND}'"
        fail=$((fail + 1))
    fi
elif [[ "$kind" == "developer" ]]; then
    ok "signature is valid, and is a DEVELOPER signature"
    note "it proves this image is what the build produced, and nothing more:"
    note "no secure boot, no dm-verity, no release key."
fi

printf '\n'
if [[ "$fail" -eq 0 ]]; then
    printf 'VERIFIED\n'
    exit 0
fi
printf 'NOT VERIFIED (%d problem(s))\n' "$fail"
exit 1
