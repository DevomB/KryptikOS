#!/usr/bin/env bash
# Tests for tools/release-manifest.sh, offline, with throwaway ed25519 keys.

set -uo pipefail

# Exported values would override common.sh's derived paths and the signers file.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT
unset KRYPTIK_RELEASE_SIGNERS

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/release-manifest.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in ssh-keygen sha256sum find sort; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }

mkdir -p "${W}/keys"
ssh-keygen -q -t ed25519 -N '' -C release  -f "${W}/keys/rel" </dev/null
ssh-keygen -q -t ed25519 -N '' -C outsider -f "${W}/keys/out" </dev/null

SIGNERS="${W}/keys/allowed_signers"
printf 'release@kryptik.test %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/rel.pub")" \
    > "$SIGNERS"

# Half-made keys would show up as a dozen misleading failures below.
for _f in "${W}/keys/rel" "${W}/keys/rel.pub" "${W}/keys/out" "$SIGNERS"; do
    if [[ ! -s "$_f" ]]; then
        echo "FATAL: test prerequisite missing or empty: ${_f}" >&2
        echo "ssh-keygen did not produce the fixture keys, so nothing below" >&2
        echo "would be testing what it claims to test." >&2
        exit 1
    fi
done

REL="${W}/release"
build_release() {
    rm -rf "$REL"
    mkdir -p "${REL}/boot" "${REL}/usr/bin"
    printf 'pretend bzImage\n'            > "${REL}/boot/vmlinuz"
    printf 'pretend initramfs\n'          > "${REL}/boot/initramfs.cpio.gz"
    printf 'pretend kryptikd binary\n'    > "${REL}/usr/bin/kryptikd"
    printf 'pretend s6-svscan binary\n'   > "${REL}/usr/bin/s6-svscan"
}

MAN="${W}/release.manifest"

make_signed() {  # [version] [role]
    local version="${1:-1.0}" role="${2:-development}"
    rm -f "$MAN" "${MAN}.sig"
    bash "$TOOL" create --out "$MAN" --root "$REL" --name kryptik \
        --version "$version" --role "$role" boot usr > /dev/null 2>&1
    bash "$TOOL" sign --key "${W}/keys/rel" "$MAN" > /dev/null 2>&1
}

verify() {
    NO_COLOR=1 bash "$TOOL" verify --signers "$SIGNERS" --root "$REL" \
        "$MAN" "$@" > "$OUT" 2>&1
    RC=$?
}

expect_pass() {
    local name="$1" want="$2"
    if [[ "$RC" -ne 0 ]]; then red "${name}: expected exit 0, got ${RC}"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: exit 0 but output lacks [${want}]"; show
    else green "$name"; fi
}

expect_fail() {
    local name="$1" want="$2"
    if [[ "$RC" -eq 0 ]]; then red "${name}: PASSED when it should have failed"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: failed, but not for the stated reason [${want}]"; show
    else green "$name"; fi
}

echo "tools/release-manifest.sh"
echo

# Positive controls: a tool that rejected everything would pass the rest.
build_release
make_signed 1.0 development
verify
expect_pass "an untampered signed release verifies" "manifest verified"

verify --strict
expect_pass "it verifies under --strict" "manifest verified"

verify --exact
expect_pass "--exact passes when nothing unlisted is present" "no unlisted files"

if grep -qF "signature verifies, signed by release@kryptik.test" "$OUT"; then
    green "the verifying principal is reported"
else
    red "the principal was not reported"; show
fi

make_signed 2.0 production
verify --require-role production --strict
expect_pass "a production manifest satisfies --require-role production" \
    "role: production"

make_signed 1.0 development
cp "$MAN" "${W}/m1"
make_signed 1.0 development
if diff <(grep -v '^created:' "${W}/m1") <(grep -v '^created:' "$MAN") >/dev/null; then
    green "two manifests of an unchanged tree differ only in the timestamp"
else
    red "manifests of an unchanged tree are not reproducible"
    diff <(grep -v '^created:' "${W}/m1") <(grep -v '^created:' "$MAN") | head -6
fi

# Tampered artifacts.
build_release; make_signed
printf 'backdoor\n' >> "${REL}/usr/bin/kryptikd"
verify
expect_fail "a modified artifact is rejected" "CONTENT MISMATCH: usr/bin/kryptikd"

build_release; make_signed
rm -f "${REL}/boot/initramfs.cpio.gz"
verify
expect_fail "a removed artifact is rejected" "missing: boot/initramfs.cpio.gz"

build_release; make_signed
printf 'extra payload\n' > "${REL}/usr/bin/helper"
verify
expect_pass "an unlisted extra file is invisible without --exact" "manifest verified"
verify --exact
expect_fail "--exact catches a file that rode along" \
    "present but NOT in the manifest: usr/bin/helper"

build_release; make_signed 1.0 development
sed -i 's/^role: development/role: production/' "$MAN"
verify --require-role production
expect_fail "editing the role after signing invalidates the signature" \
    "signature does NOT verify"

build_release; make_signed 1.0 development
sed -i 's/^version: 1.0/version: 9.9/' "$MAN"
verify
expect_fail "editing the version after signing invalidates the signature" \
    "signature does NOT verify"

if ! grep -qF "file(s) match the manifest" "$OUT"; then
    green "no file results are reported for a manifest that did not verify"
else
    red "file results were reported despite a bad signature"; show
fi

# Signer identity.
build_release; make_signed
rm -f "${MAN}.sig"
bash "$TOOL" sign --key "${W}/keys/out" "$MAN" > /dev/null 2>&1
verify
expect_fail "a signature by a key that is not enrolled is rejected" \
    "the signing key is not enrolled"
if grep -qF "no verification" "$OUT"; then
    green "an unenrolled signature is called no verification, not weak verification"
else
    red "the unenrolled case was not described precisely"; show
fi

build_release; make_signed
rm -f "${MAN}.sig"
verify
expect_fail "an unsigned manifest is rejected, not reported as verified" \
    "the manifest is unsigned"

# Development signing is not production trust.
build_release; make_signed 1.0 development
verify --require-role production
expect_fail "a development manifest is refused where production is required" \
    "but 'production' was required"

verify --strict
if [[ "$RC" -eq 0 ]] && grep -qF "does not by itself make a development" "$OUT"; then
    green "--strict on a development manifest says what it does not establish"
else
    red "--strict did not distinguish development signing (exit ${RC})"; show
fi

# Rollback.
build_release; make_signed 1.0 development
verify --no-downgrade 2.0
expect_fail "a downgrade to an older signed release is refused" \
    "is older than the installed"

make_signed 3.0 development
verify --no-downgrade 2.0
expect_pass "an upgrade past the installed version is allowed" \
    "is not older than the installed"

make_signed 2.0 development
verify --no-downgrade 2.0
expect_pass "reinstalling the installed version is allowed" \
    "is not older than the installed"

# Key rotation, which is an edit to the allowed-signers file.
ssh-keygen -q -t ed25519 -N '' -C release-new -f "${W}/keys/new" </dev/null
NEWPUB="$(cut -d' ' -f1,2 < "${W}/keys/new.pub")"
OLDPUB="$(cut -d' ' -f1,2 < "${W}/keys/rel.pub")"

build_release

# Overlap: both keys enrolled.
printf 'release@kryptik.test %s\nrelease@kryptik.test %s\n' "$OLDPUB" "$NEWPUB" \
    > "$SIGNERS"
make_signed 4.0 development
verify
expect_pass "during overlap, a release signed by the old key still verifies" \
    "manifest verified"

rm -f "$MAN" "${MAN}.sig"
bash "$TOOL" create --out "$MAN" --root "$REL" --version 4.0 \
    --role development boot usr > /dev/null 2>&1
bash "$TOOL" sign --key "${W}/keys/new" "$MAN" > /dev/null 2>&1
verify
expect_pass "during overlap, a release signed by the new key verifies" \
    "manifest verified"

# Rotation complete: the retired key is removed.
printf 'release@kryptik.test %s\n' "$NEWPUB" > "$SIGNERS"
verify
expect_pass "after rotation, the new key still verifies" "manifest verified"

make_signed 4.0 development   # signs with the retired key
verify
expect_fail "after rotation, the retired key is refused" \
    "the signing key is not enrolled"

# Restore.
printf 'release@kryptik.test %s\n' "$OLDPUB" > "$SIGNERS"

# A whole-tree manifest (`create --root DIR .`) must still pass --exact.
build_release
rm -f "$MAN" "${MAN}.sig"
bash "$TOOL" create --out "$MAN" --root "$REL" --version 5.0 \
    --role development . > /dev/null 2>&1
bash "$TOOL" sign --key "${W}/keys/rel" "$MAN" > /dev/null 2>&1
verify --exact
expect_pass "a whole-tree manifest created with '.' passes --exact" \
    "no unlisted files"

if grep -qE '^[0-9a-f]{64}  [0-9]+  [.]/' "$MAN"; then
    red "manifest paths still carry a './' prefix"
    grep -m3 -E '  [.]/' "$MAN" | sed 's/^/        /'
else
    green "manifest paths carry no './' prefix"
fi

# Tamper detection must still name a path an operator can act on.
printf 'x\n' >> "${REL}/usr/bin/kryptikd"
verify
expect_fail "a whole-tree manifest still detects a changed file" \
    "CONTENT MISMATCH: usr/bin/kryptikd"

# No default trust anchor.
build_release; make_signed
NO_COLOR=1 bash "$TOOL" verify --root "$REL" "$MAN" > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "no default trust anchor" "$OUT"; then
    green "verify refuses to run without an explicit allowed-signers file"
else
    red "verify ran without --signers (exit ${rc})"; show
fi

# Control: the refusal above is about absence, not about the flag.
KRYPTIK_RELEASE_SIGNERS="$SIGNERS" NO_COLOR=1 \
    bash "$TOOL" verify --root "$REL" "$MAN" > "$OUT" 2>&1
if [[ "$?" -eq 0 ]]; then
    green "KRYPTIK_RELEASE_SIGNERS supplies the anchor"
else
    red "KRYPTIK_RELEASE_SIGNERS was not honoured"; show
fi

# create refuses nonsense.
NO_COLOR=1 bash "$TOOL" create --out "${W}/x.manifest" --root "$REL" \
    --role sortof boot > "$OUT" 2>&1
if [[ "$?" -ne 0 ]] && grep -qF "must be development or production" "$OUT"; then
    green "create refuses a role that is neither development nor production"
else
    red "create accepted an invalid role"; show
fi

NO_COLOR=1 bash "$TOOL" create --out "${W}/y.manifest" --root "$REL" \
    nosuchpath > "$OUT" 2>&1
if [[ "$?" -ne 0 ]] && grep -qF "no such file or directory" "$OUT"; then
    green "create refuses a path that does not exist"
else
    red "create accepted a nonexistent path"; show
fi

NO_COLOR=1 bash "$TOOL" create --out "${W}/z.manifest" --root "$REL" boot \
    > "$OUT" 2>&1
if grep -qF "UNSIGNED" "$OUT"; then
    green "create says plainly that its output is unsigned"
else
    red "create did not warn that the manifest is unsigned"; show
fi

# An unlisted file at the root is refused, whatever its name.
build_release; make_signed
printf 'x\n' > "${REL}/.kryptik-update"
verify --exact
expect_fail "--exact refuses an unlisted file at the root" \
    "present but NOT in the manifest: .kryptik-update"
rm -f "${REL}/.kryptik-update"

# pointer: its output must pass kryptik-update's own check-pointer, under an
# anchor shaped like the image's (each key honoured in one namespace only).
build_release
make_signed 1.0.3 development
ssh-keygen -q -t ed25519 -N '' -C latest -f "${W}/keys/latest" </dev/null
ANCHOR="${W}/keys/anchor"
{
    printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/rel.pub")"
    printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/latest.pub")"
} > "$ANCHOR"
PTR="${W}/latest"
NO_COLOR=1 bash "$TOOL" pointer --key "${W}/keys/latest" --signers "$ANCHOR" --manifest "$MAN" --base 1.0.3/ --out "$PTR" \
    --issued 2027-03-02T14:05:00+00:00 > "$OUT" 2>&1; RC=$?
want="$(printf 'KRYPTIK-LATEST-1\nrole: development\nversion: 1.0.3\nissued: 2027-03-02T14:05:00+00:00\nmanifest-sha256: %s\nbase: 1.0.3/\n' "$(sha256sum "$MAN" | cut -c1-64)")"
if [[ "$RC" -eq 0 && "$(cat "$PTR")" == "$want" && -s "${PTR}.sig" ]]; then
    green "pointer: names the manifest's version and role, its hash, the base and the date, and nothing else"
else
    red "pointer: wrote something else (exit ${RC})"; show; cat "$PTR" 2>/dev/null
fi
if ssh-keygen -Y verify -f "$ANCHOR" -I kryptik-latest -n kryptik-latest -s "${PTR}.sig" < "$PTR" >/dev/null 2>&1 \
   && ! ssh-keygen -Y verify -f "$ANCHOR" -I kryptik-latest -n kryptik-release -s "${PTR}.sig" < "$PTR" >/dev/null 2>&1; then
    green "pointer: signed in its own namespace, and not a signature a manifest could borrow"
else
    red "pointer: the signature is not in kryptik-latest alone"
fi

# The updater's own check, lifted out of the tool as its suite does.
UPD="${ROOT}/tools/update/kryptik-update"
{
    echo 'LATEST_NAMESPACE=kryptik-latest'; echo 'LATEST_MAGIC=KRYPTIK-LATEST-1'
    echo "SIGNERS=${ANCHOR}"
    echo 'say() { printf "%s\n" "$*"; }'
    echo 'die() { printf "REFUSED: %s\n" "$*"; exit 1; }'
    sed -n '/^verify_signed() {/,/^}/p' "$UPD"
    sed -n '/^cmd_check_pointer() {/,/^}/p' "$UPD"
    printf 'SNAP=%q\n' "${W}/snap"; echo 'mkdir -p "$SNAP"'
    echo 'cmd_check_pointer "$1" "$2" && echo ACCEPTED'
} > "${W}/check-pointer.sh"
if bash "${W}/check-pointer.sh" "$PTR" "${PTR}.sig" 2>&1 | grep -qx ACCEPTED; then
    green "pointer: what this tool writes is what kryptik-update's check-pointer accepts"
else
    red "pointer: kryptik-update refuses what this tool wrote: $(bash "${W}/check-pointer.sh" "$PTR" "${PTR}.sig" 2>&1 | tail -1)"
fi
# Signed by the release key instead: a statement the anchor does not honour.
NO_COLOR=1 bash "$TOOL" pointer --key "${W}/keys/rel" --signers "$ANCHOR" --manifest "$MAN" --base 1.0.3/ --out "${W}/latest-by-rel" > /dev/null 2>&1
# Captured first: under pipefail the refusal's exit 1 would fail a pipe to grep.
said="$(bash "${W}/check-pointer.sh" "${W}/latest-by-rel" "${W}/latest-by-rel.sig" 2>&1)"
if [[ "$said" == *"REFUSED:"*"does NOT verify"* && "$said" != *ACCEPTED* ]]; then
    green "pointer: one signed with the release key is refused by the updater, because the anchor honours that key for releases only"
else
    red "pointer: the updater accepted a statement signed by the release key"
fi

NO_COLOR=1 bash "$TOOL" pointer --key "${W}/keys/latest" --signers "$ANCHOR" --manifest "$MAN" --base 1.0.3/ --out "${W}/latest-2" \
    --issued 2027-04-01T00:00:00+00:00 > /dev/null 2>&1
if [[ "$(diff <(cat "$PTR") <(cat "${W}/latest-2") | grep -c '^[<>]')" -eq 2 ]] && grep -qx 'issued: 2027-04-01T00:00:00+00:00' "${W}/latest-2"; then
    green "pointer: re-issued for an unchanged release, only the date differs"
else
    red "pointer: a re-issue changed more than the date"
fi

# A signature is present, but by a key the anchor does not hold.
cp "${MAN}.sig" "${W}/man.sig.good"; ssh-keygen -q -t ed25519 -N "" -f "${W}/keys/stranger" > /dev/null
rm -f "${MAN}.sig"; ssh-keygen -Y sign -f "${W}/keys/stranger" -n kryptik-release "$MAN" < /dev/null > /dev/null 2>&1
NO_COLOR=1 bash "$TOOL" pointer --key "${W}/keys/latest" --signers "$ANCHOR" --manifest "$MAN" --base 1.0.3/ --out "${W}/latest-stranger" > "$OUT" 2>&1; RC=$?
if [[ "$RC" -ne 0 && ! -e "${W}/latest-stranger" ]] && grep -q 'does not verify' "$OUT"; then
    green "pointer: no statement is written about a manifest signed by a key the image does not carry"
else
    red "pointer: wrote a statement for a manifest a stranger signed (exit ${RC})"; show
fi
cp "${W}/man.sig.good" "${MAN}.sig"

rm -f "${MAN}.sig"
NO_COLOR=1 bash "$TOOL" pointer --key "${W}/keys/latest" --signers "$ANCHOR" --manifest "$MAN" --base 1.0.3/ --out "${W}/latest-unsigned" > "$OUT" 2>&1; RC=$?
if [[ "$RC" -ne 0 && ! -e "${W}/latest-unsigned" ]] && grep -q 'is not signed yet' "$OUT"; then
    green "pointer: no statement is written about a manifest nobody has signed"
else
    red "pointer: wrote a statement for an unsigned manifest (exit ${RC})"; show
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
