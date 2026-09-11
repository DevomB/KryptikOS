#!/usr/bin/env bash
# Focused tests for tools/release-manifest.sh — the acceptance checks the
# signed-image and recoverable-update work (roadmap M6) needs.
#
#   ./tools/test-release-manifest.sh
#
# Deterministic and offline, with real OpenSSH signatures over real files:
# throwaway ed25519 keys generated per run, one enrolled in the allowed-signers
# file and one not.
#
# What is asserted, in the language of the M6 acceptance criteria:
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

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
