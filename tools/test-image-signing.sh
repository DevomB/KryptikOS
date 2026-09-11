#!/usr/bin/env bash
#
# Does image signing actually refuse the things it claims to refuse?
#
# A signature checker that always says VERIFIED is indistinguishable from one
# that works, right up until it matters. So every denial here is paired with the
# positive control that makes it meaningful: the same harness must accept the
# untampered image, or its refusals prove nothing.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGN="${ROOT}/tools/image/sign-image.sh"
VERIFY="${ROOT}/tools/image/verify-image.sh"

pass=0; fail=0
work=""
cleanup() { [[ -n "$work" && -d "$work" ]] && rm -rf "$work"; }
trap cleanup EXIT INT TERM

green() { printf '  PASS  %s\n' "$*"; pass=$((pass + 1)); }
red()   { printf '  FAIL  %s\n' "$*"; fail=$((fail + 1)); }
note()  { printf '        %s\n' "$*"; }

for t in "$SIGN" "$VERIFY"; do
    [[ -x "$t" ]] || { printf 'missing or not executable: %s\n' "$t"; exit 1; }
done
command -v openssl >/dev/null 2>&1 || { echo "openssl not available - skipping"; exit 77; }

work="$(mktemp -d)" || exit 1
IMG="${work}/fake.img"
KEYDIR="${work}/keys"

# A stand-in for a disk image. The signing tools care about bytes, not layout,
# so a small file exercises exactly the same paths without building a 6G image.
head -c 65536 /dev/urandom > "$IMG"
cp "$IMG" "${IMG}.pristine"

echo "-- signing"
if "$SIGN" --image "$IMG" --keydir "$KEYDIR" >"${work}/sign.log" 2>&1; then
    green "sign-image.sh signed the image"
else
    red "sign-image.sh failed"
    sed 's/^/        /' "${work}/sign.log"
    printf '\npassed %d, failed %d\n' "$pass" "$fail"
    exit 1
fi
[[ -f "${IMG}.sig" ]]          && green "a signature was written"      || red "no signature file"
[[ -f "${IMG}.sigdoc.json" ]]  && green "a signed document was written" || red "no signed document"
[[ -f "${IMG}.pub" ]]          && green "the public key was written"    || red "no public key"

# The private key must not be world readable, and must not be anywhere a
# `git add -A` could reach. It lives under the work tree by construction.
if [[ -f "${KEYDIR}/dev-image-signing.key" ]]; then
    mode="$(stat -c %a "${KEYDIR}/dev-image-signing.key")"
    [[ "$mode" == "600" ]] && green "the private key is 0600" \
                           || red "the private key is ${mode}, not 0600"
else
    red "no private key was generated"
fi

echo
echo "-- the positive control: an untouched image must VERIFY"
if "$VERIFY" --image "$IMG" --key "${IMG}.pub" >"${work}/v.log" 2>&1; then
    green "an untampered image verifies"
else
    red "an untampered image did NOT verify - every refusal below is meaningless"
    sed 's/^/        /' "${work}/v.log"
fi

must_refuse() {
    local what="$1"; shift
    if "$@" >"${work}/v.log" 2>&1; then
        red "${what}: accepted, and must not have been"
        sed 's/^/        /' "${work}/v.log"
    else
        green "${what}: refused"
    fi
}

echo
echo "-- the refusals"

# 1. the image changed after signing
printf 'x' | dd of="$IMG" bs=1 seek=1000 conv=notrunc status=none
must_refuse "a single flipped byte in the image" \
    "$VERIFY" --image "$IMG" --key "${IMG}.pub"
cp -f "${IMG}.pristine" "$IMG"

# 2. the signed document changed
cp "${IMG}.sigdoc.json" "${work}/doc.bak"
sed -i 's/"image_bytes": [0-9]*/"image_bytes": 1/' "${IMG}.sigdoc.json"
must_refuse "an edited signed document" \
    "$VERIFY" --image "$IMG" --key "${IMG}.pub"
cp -f "${work}/doc.bak" "${IMG}.sigdoc.json"

# 3. a valid signature from the wrong key
openssl genpkey -algorithm ed25519 -out "${work}/other.key" >/dev/null 2>&1
openssl pkey -in "${work}/other.key" -pubout -out "${work}/other.pub" >/dev/null 2>&1
must_refuse "a different signing key" \
    "$VERIFY" --image "$IMG" --key "${work}/other.pub"

# 4. a document about a DIFFERENT image, signed correctly. This is the one a
#    naive checker gets wrong: the signature is genuinely valid, and the
#    document simply is not about this file.
head -c 65536 /dev/urandom > "${work}/other.img"
"$SIGN" --image "${work}/other.img" --keydir "$KEYDIR" >/dev/null 2>&1
must_refuse "a valid signature over another image's document" \
    "$VERIFY" --image "$IMG" --key "${IMG}.pub" \
              --doc "${work}/other.img.sigdoc.json" --sig "${work}/other.img.sig"

# 5. a developer signature must not pass as a release one
must_refuse "a developer signature offered as a release signature" \
    "$VERIFY" --image "$IMG" --key "${IMG}.pub" --expect-kind release

# 6. and the ordinary missing-file cases
must_refuse "a missing signature file" \
    "$VERIFY" --image "$IMG" --key "${IMG}.pub" --sig "${work}/nope.sig"

echo
echo "-- and it still verifies afterwards, so nothing above corrupted it"
if "$VERIFY" --image "$IMG" --key "${IMG}.pub" >"${work}/v.log" 2>&1; then
    green "the image still verifies after the tamper tests"
else
    red "the image no longer verifies - a tamper test did not restore state"
    sed 's/^/        /' "${work}/v.log"
fi

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1
