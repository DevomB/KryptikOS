#!/usr/bin/env bash
# Focused tests for tools/release-manifest.sh — the acceptance checks the
# signed-image and recoverable-update work needs.
#
#   ./tools/test-release-manifest.sh
#
# Deterministic and offline, with real OpenSSH signatures over real files:
# throwaway ed25519 keys generated per run, one enrolled in the allowed-signers
# file and one not.
#
# What is asserted, in the language of the signed-release acceptance criteria:
#
#   * tampered artifacts are rejected — content changed, file removed, file
#     added, and a manifest whose own bytes were edited after signing;
#   * a signature by a key that is not enrolled is rejected;
#   * an unsigned manifest is rejected rather than reported as verified;
#   * development signing is distinguishable from production trust, and a
#     development manifest cannot be promoted by editing its role;
#   * a downgrade to an older signed release is refused;
#   * there is no default trust anchor.
#
# Positive controls throughout: an untampered release must verify, in strict
# mode, or a tool that rejected everything would satisfy the rest.

set -uo pipefail

# See the same note in the other suites.
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

# --- keys -------------------------------------------------------------------

mkdir -p "${W}/keys"
ssh-keygen -q -t ed25519 -N '' -C release  -f "${W}/keys/rel" </dev/null
ssh-keygen -q -t ed25519 -N '' -C outsider -f "${W}/keys/out" </dev/null

SIGNERS="${W}/keys/allowed_signers"
printf 'release@kryptik.test %s\n' "$(cut -d' ' -f1,2 < "${W}/keys/rel.pub")" \
    > "$SIGNERS"

# If key generation half-fails, every verify below reports "no
# allowed-signers file" and this suite prints a dozen confusing failures
# instead of one clear one. Seen once, transiently, while the WSL session
# was dropping connections. A broken prerequisite is not a test result.
for _f in "${W}/keys/rel" "${W}/keys/rel.pub" "${W}/keys/out" "$SIGNERS"; do
    if [[ ! -s "$_f" ]]; then
        echo "FATAL: test prerequisite missing or empty: ${_f}" >&2
        echo "ssh-keygen did not produce the fixture keys, so nothing below" >&2
        echo "would be testing what it claims to test." >&2
        exit 1
    fi
done

# --- the release tree -------------------------------------------------------

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

# ---------------------------------------------------------------------------
# positive controls
# ---------------------------------------------------------------------------

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

# Two manifests of an unchanged tree must differ only in their timestamp:
# entries are sorted, so a diff of two releases shows what actually changed
# rather than a reordering.
make_signed 1.0 development
cp "$MAN" "${W}/m1"
make_signed 1.0 development
if diff <(grep -v '^created:' "${W}/m1") <(grep -v '^created:' "$MAN") >/dev/null; then
    green "two manifests of an unchanged tree differ only in the timestamp"
else
    red "manifests of an unchanged tree are not reproducible"
    diff <(grep -v '^created:' "${W}/m1") <(grep -v '^created:' "$MAN") | head -6
fi

# ---------------------------------------------------------------------------
# tampered artifacts
# ---------------------------------------------------------------------------

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

# Editing the manifest after signing must break the signature, which is what
# stops the role and version headers from being rewritten.
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

# And the contents of an invalid manifest must not be reported at all.
if ! grep -qF "file(s) match the manifest" "$OUT"; then
    green "no file results are reported for a manifest that did not verify"
else
    red "file results were reported despite a bad signature"; show
fi

# ---------------------------------------------------------------------------
# signer identity
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# development signing is not production trust
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# key rotation
# ---------------------------------------------------------------------------
#
# The allowed-signers file IS the rotation mechanism: enrolling a new key and
# retiring an old one are edits to it. These are the acceptance checks for
# that, because a rotation that leaves the retired key working has not
# happened, and one that breaks before the new key is enrolled locks the
# operator out of their own update channel.

ssh-keygen -q -t ed25519 -N '' -C release-new -f "${W}/keys/new" </dev/null
NEWPUB="$(cut -d' ' -f1,2 < "${W}/keys/new.pub")"
OLDPUB="$(cut -d' ' -f1,2 < "${W}/keys/rel.pub")"

build_release

# Overlap: both keys enrolled, so releases signed with either are accepted.
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

# ---------------------------------------------------------------------------
# whole-tree manifests: `.` must not poison --exact
# ---------------------------------------------------------------------------
#
# `create --root DIR .` is the natural way to manifest an entire tree, and
# `find . -type f` emits "./usr/bin/x" while --exact's listing emits
# "usr/bin/x". Every file was then reported as "present but NOT in the
# manifest" while simultaneously matching its recorded hash. Found by
# manifesting the real sysroot, not by reading the code.

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

# ---------------------------------------------------------------------------
# no default trust anchor
# ---------------------------------------------------------------------------

build_release; make_signed
NO_COLOR=1 bash "$TOOL" verify --root "$REL" "$MAN" > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "no default trust anchor" "$OUT"; then
    green "verify refuses to run without an explicit allowed-signers file"
else
    red "verify ran without --signers (exit ${rc})"; show
fi

# The env var is an accepted way to supply it, so the refusal above is about
# absence and not about the flag.
KRYPTIK_RELEASE_SIGNERS="$SIGNERS" NO_COLOR=1 \
    bash "$TOOL" verify --root "$REL" "$MAN" > "$OUT" 2>&1
if [[ "$?" -eq 0 ]]; then
    green "KRYPTIK_RELEASE_SIGNERS supplies the anchor"
else
    red "KRYPTIK_RELEASE_SIGNERS was not honoured"; show
fi

# ---------------------------------------------------------------------------
# create refuses nonsense
# ---------------------------------------------------------------------------

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

# --- the installed-marker exemption to --exact ------------------------------
#
# apply-update.sh writes .kryptik-update INSIDE the tree so the marker lands
# with the same rename as the payload. That leaves an installed tree holding
# one file no release manifest lists, so `verify --exact` against the very
# manifest it was installed from used to fail forever - which meant a rollback
# could not be proved complete. Found by running the recovery recipe end to
# end, not by reading the code.
#
# An exemption in a verifier is how holes get made, so these check that it is
# exactly one name, at the root only, and self-validating.

build_release
MK="${W}/mk.manifest"
bash "$TOOL" create --out "$MK" --root "$REL" --name kryptik-boot     --version 1.0 --role development . > /dev/null 2>&1
bash "$TOOL" sign --key "${W}/keys/rel" "$MK" > /dev/null 2>&1
MK_SHA="$(sha256sum "$MK" | cut -d' ' -f1)"

marker() { printf 'KRYPTIK-UPDATE-1
version: 1.0
manifest-sha256: %s
' "$1"            > "${REL}/.kryptik-update"; }

vex() {
    RC=0
    bash "$TOOL" verify --signers "$SIGNERS" --principal release@kryptik.test         --root "$REL" --exact "$MK" > "$OUT" 2>&1 || RC=$?
}

# Positive control first: without any marker the tree must verify --exact, or
# every case below would pass for the wrong reason.
rm -f "${REL}/.kryptik-update"
vex
if [[ "$RC" -eq 0 ]]; then green "an uninstalled tree verifies --exact"; else red "an uninstalled tree verifies --exact"; show; fi

marker "$MK_SHA"
vex
if [[ "$RC" -eq 0 ]]; then
    green "an installed tree verifies --exact despite the marker"
else
    red "an installed tree verifies --exact despite the marker (exit ${RC})"; show
fi
if grep -qF "marker names this manifest" "$OUT"; then
    green "and says the marker was recognised rather than ignored silently"
else
    red "and says the marker was recognised rather than ignored silently"; show
fi

marker "0000000000000000000000000000000000000000000000000000000000000000"
vex
if [[ "$RC" -ne 0 ]] && grep -qF "DIFFERENT release" "$OUT"; then
    green "a marker naming another manifest is a finding, not an exemption"
else
    red "a marker naming another manifest is a finding, not an exemption (exit ${RC})"; show
fi

printf 'KRYPTIK-UPDATE-1
version: 1.0
' > "${REL}/.kryptik-update"
vex
if [[ "$RC" -ne 0 ]] && grep -qF "<none>" "$OUT"; then
    green "a marker with no manifest-sha256 is refused"
else
    red "a marker with no manifest-sha256 is refused (exit ${RC})"; show
fi

# The exemption is one exact name, not a pattern and not a dotfile rule.
rm -f "${REL}/.kryptik-update"
printf 'x
' > "${REL}/.kryptik-update.bak"
vex
if [[ "$RC" -ne 0 ]] && grep -qF "NOT in the manifest: .kryptik-update.bak" "$OUT"; then
    green "a similarly named file is still refused"
else
    red "a similarly named file is still refused (exit ${RC})"; show
fi
rm -f "${REL}/.kryptik-update.bak"

# Root only: a marker deeper in the tree is unsigned content, not metadata.
mkdir -p "${REL}/usr/share"
marker "$MK_SHA"
cp "${REL}/.kryptik-update" "${REL}/usr/share/.kryptik-update"
vex
if [[ "$RC" -ne 0 ]] && grep -qF "usr/share/.kryptik-update" "$OUT"; then
    green "a marker below the root is still refused"
else
    red "a marker below the root is still refused (exit ${RC})"; show
fi
rm -f "${REL}/usr/share/.kryptik-update" "${REL}/.kryptik-update"

# --- the update channel's statement of what is current -----------------------
# `pointer` writes and signs it; the machine's side is kryptik-update's
# check-pointer. The rows that matter are the ones where the two meet: what
# this tool emits is accepted by the updater's own function, under an anchor
# shaped like the image's (each key honoured in one namespace only).
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
# Into a variable first: the refusal exits 1, and under pipefail that would
# fail the pipeline whatever grep found.
said="$(bash "${W}/check-pointer.sh" "${W}/latest-by-rel" "${W}/latest-by-rel.sig" 2>&1)"
if [[ "$said" == *"REFUSED:"*"does NOT verify"* && "$said" != *ACCEPTED* ]]; then
    green "pointer: one signed with the release key is refused by the updater, because the anchor honours that key for releases only"
else
    red "pointer: the updater accepted a statement signed by the release key"
fi

# Re-issued later for the same release: only the date moves.
NO_COLOR=1 bash "$TOOL" pointer --key "${W}/keys/latest" --signers "$ANCHOR" --manifest "$MAN" --base 1.0.3/ --out "${W}/latest-2" \
    --issued 2027-04-01T00:00:00+00:00 > /dev/null 2>&1
if [[ "$(diff <(cat "$PTR") <(cat "${W}/latest-2") | grep -c '^[<>]')" -eq 2 ]] && grep -qx 'issued: 2027-04-01T00:00:00+00:00' "${W}/latest-2"; then
    green "pointer: re-issued for an unchanged release, only the date differs"
else
    red "pointer: a re-issue changed more than the date"
fi

# A signature file that is there and is not the manifest's signature.
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
