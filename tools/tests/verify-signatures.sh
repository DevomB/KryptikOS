#!/usr/bin/env bash
# Tests for tools/verify-signatures.sh: offline, real GnuPG, per-run keys, a throwaway KRYPTIK_ROOT.

set -uo pipefail

# common.sh prefers these, when exported, to paths derived from KRYPTIK_ROOT.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/tools/verify-signatures.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in gpg curl awk sed grep gzip; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required for this test"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
cleanup() {
    # gpg-agent holds these open; stop it or the temp tree survives.
    for h in "${W}/gnupg-fixture" "${W}/gnupg-build"; do
        [[ -d "$h" ]] || continue
        GNUPGHOME="$h" gpgconf --kill all >/dev/null 2>&1
    done
    rm -rf "$W"
}
trap cleanup EXIT

SRC="${W}/src"
FAKE="${W}/root"
KEYSOURCE="${W}/keysource"
mkdir -p "$SRC" "$KEYSOURCE"

show() { sed 's/^/        /' "$OUT"; }

# --- fixture keys and signatures --------------------------------------------

FIXG="${W}/gnupg-fixture"
BUILDG="${W}/gnupg-build"
mkdir -p "$FIXG" "$BUILDG"
chmod 700 "$FIXG" "$BUILDG"

fixgpg() { GNUPGHOME="$FIXG" gpg --batch --quiet --pinentry-mode loopback \
                                 --passphrase '' "$@"; }

echo "tools/verify-signatures.sh"
echo
echo "  building fixtures (four keys, five signature states)"

for k in good expired revoked unknown; do
    expire=never
    # Signs while valid, verified after expiry: EXPKEYSIG.
    [[ "$k" == expired ]] && expire="seconds=1"
    fixgpg --quick-generate-key "${k} fixture <${k}@example.test>" \
           ed25519 sign "$expire" >/dev/null 2>&1
done

for k in good expired revoked unknown bad; do
    signer="$k"
    [[ "$k" == bad ]] && signer=good
    printf 'fixture payload for %s\n' "$k" > "${SRC}/${k}.tar.gz"
    fixgpg --yes --local-user "${signer}@example.test" \
           --detach-sign -o "${SRC}/${k}.tar.gz.sig" "${SRC}/${k}.tar.gz" \
        >/dev/null 2>&1
done

# Modified after signing: BADSIG.
printf 'TAMPERED AFTER SIGNING\n' >> "${SRC}/bad.tar.gz"

# Upstream publishes nothing alongside this one.
printf 'no signature is published for this\n' > "${SRC}/nosig.tar.gz"

# The tool's keyring: good, expired and revoked; sed strips the ':' guarding gpg's revocation.
REVFPR="$(GNUPGHOME="$FIXG" gpg --batch --list-keys --with-colons revoked@example.test \
          | awk -F: '$1=="fpr"{print $10; exit}')"
GNUPGHOME="$FIXG" gpg --batch --quiet \
    --export good@example.test expired@example.test revoked@example.test \
    > "${W}/pub.gpg"
GNUPGHOME="$BUILDG" gpg --batch --quiet --import "${W}/pub.gpg" >/dev/null 2>&1
sed 's/^://' "${FIXG}/openpgp-revocs.d/${REVFPR}.rev" \
    | GNUPGHOME="$BUILDG" gpg --batch --quiet --import >/dev/null 2>&1
GNUPGHOME="$BUILDG" gpg --batch --quiet --export > "${W}/keyring.gpg"

# The unknown key is served only under the id its signature names: long key id or fingerprint.
UNKFPR="$(GNUPGHOME="$FIXG" gpg --batch --list-keys --with-colons unknown@example.test \
          | awk -F: '$1=="fpr"{print $10; exit}')"
UNKID="${UNKFPR: -16}"
GNUPGHOME="$FIXG" gpg --batch --quiet --export unknown@example.test \
    > "${KEYSOURCE}/${UNKID}.gpg"
cp "${KEYSOURCE}/${UNKID}.gpg" "${KEYSOURCE}/${UNKFPR}.gpg"

: > "${W}/empty-keyring.gpg"

# Let the one-second key expire.
sleep 3

# --- fixture sanity ---------------------------------------------------------

# gpg's own verdict on each fixture, so no case passes for the wrong reason.
VERIFYG="${W}/gnupg-check"
mkdir -p "$VERIFYG"; chmod 700 "$VERIFYG"
GNUPGHOME="$VERIFYG" gpg --batch --quiet --import "${W}/keyring.gpg" >/dev/null 2>&1

raw_state() {
    GNUPGHOME="$VERIFYG" gpg --batch --status-fd 1 --verify \
        "${SRC}/$1.tar.gz.sig" "${SRC}/$1.tar.gz" 2>/dev/null \
        | grep -oE 'GOODSIG|EXPKEYSIG|REVKEYSIG|BADSIG|NO_PUBKEY' | head -1
}

fixture_ok=1
for pair in good:GOODSIG expired:EXPKEYSIG revoked:REVKEYSIG bad:BADSIG \
            unknown:NO_PUBKEY; do
    want="${pair#*:}"
    got="$(raw_state "${pair%:*}")"
    if [[ "$got" != "$want" ]]; then
        echo "  FIXTURE BROKEN: ${pair%:*} is ${got:-nothing}, expected ${want}"
        fixture_ok=0
    fi
done
GNUPGHOME="$VERIFYG" gpgconf --kill all >/dev/null 2>&1
if [[ "$fixture_ok" -ne 1 ]]; then
    echo
    echo "The fixtures do not represent the states under test; aborting rather"
    echo "than reporting assertions that would pass for the wrong reason."
    exit 1
fi
green "fixtures produce GOODSIG, EXPKEYSIG, REVKEYSIG, BADSIG and NO_PUBKEY"
echo

# --- harness ----------------------------------------------------------------

# write_manifest NAME...: rows shaped like fetch-sources.sh --list, each declaring probe.
write_manifest() {
    : > "${W}/manifest"
    local n
    for n in "$@"; do
        printf '%-12s %-10s %s probe listing\n' "$n" "1.0" "file://${SRC}/${n}.tar.gz" \
            >> "${W}/manifest"
    done
}

# add_row <name> <sig>: one more row, declaring how its signature is published.
add_row() {
    printf '%-12s %-10s %s %s listing\n' "$1" "1.0" "file://${SRC}/$1.tar.gz" "$2" \
        >> "${W}/manifest"
}

# A new KRYPTIK_ROOT: no cached keys, no keys.manifest.
fresh_root() {
    rm -rf "$FAKE"
    mkdir -p "${FAKE}/build/config"
    printf 'MIRROR_GNU="https://ftpmirror.gnu.org"\n' \
        > "${FAKE}/build/config/versions.env"
}

KEYRING="${W}/keyring.gpg"

run() {
    KRYPTIK_ROOT="$FAKE" \
    KRYPTIK_SOURCES="$SRC" \
    KRYPTIK_SIGCHECK_SELFTEST=1 \
    KRYPTIK_SIGCHECK_MANIFEST="${W}/manifest" \
    KRYPTIK_SIGCHECK_KEYRING="$KEYRING" \
    KRYPTIK_SIGCHECK_KEYSOURCE="$KEYSOURCE" \
    NO_COLOR=1 \
    bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

expect_pass() {
    local name="$1" want="$2"
    if [[ "$RC" -ne 0 ]]; then
        red "${name}: expected exit 0, got ${RC}"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: exit 0 but output lacks [${want}]"; show
    else
        green "$name"
    fi
}

expect_fail() {
    local name="$1" want="$2"
    if [[ "$RC" -eq 0 ]]; then
        red "${name}: PASSED when it should have failed"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: failed, but not for the stated reason [${want}]"; show
    else
        green "$name"
    fi
}

# --- positive controls ------------------------------------------------------

write_manifest good expired
fresh_root; run
expect_pass "a valid signature by a held key verifies" "signature valid"

write_manifest good expired
fresh_root; run --strict
expect_pass "a fully verified manifest passes --strict" "verified:     2"

write_manifest expired
fresh_root; run --strict
expect_pass "an expired signing key is verified, not tampering" \
    "signing key expired"

write_manifest expired
fresh_root; run
expect_pass "expired keys are listed separately" \
    "signed with a key the keyring believes expired"

# --- fatal in both modes ----------------------------------------------------

write_manifest revoked
fresh_root; run
expect_fail "a revoked signing key fails the informational run too" \
    "REVOKED key"

write_manifest revoked
fresh_root; run
if grep -qF "REVOKED KEYS:" "$OUT" && grep -qF "can mean the key was" "$OUT"; then
    green "a revoked key is summarised and listed, not silently counted"
else
    red "revoked key: not reported in the summary"; show
fi

write_manifest revoked
fresh_root; run --strict
expect_fail "a revoked signing key fails --strict" "REVOKED"

write_manifest bad
fresh_root; run
expect_fail "a signature that does not match its file is fatal" \
    "BAD SIGNATURE"

# --- unverifiable -----------------------------------------------------------

write_manifest nosig
fresh_root; run
expect_pass "no signature published upstream is unsigned, not unverifiable" \
    "no detached signature published"

write_manifest nosig
fresh_root; run --strict
expect_pass "a source that publishes no signature is not held against --strict: the lock's and verify-provenance's" \
    "publish no OpenPGP signature"

write_manifest unknown
fresh_root; run
expect_pass "a signature by an unheld key is unverifiable" "not held"

write_manifest unknown
fresh_root; run --strict
expect_fail "an unheld signing key fails --strict" "unverifiable"

# The same key, no publisher states it, and tools/source-notes.tsv says so.
printf 'unknown  no-usable-key  https://example.invalid/  No route to the key was found. Checked 2026-09-28.\n' > "${W}/notes.tsv"
write_manifest unknown
fresh_root; run --strict "--notes=${W}/notes.tsv"
expect_pass "an unheld key that no publisher states passes --strict when a note accepts it" "accepted by note"
write_manifest good
fresh_root; run --strict "--notes=${W}/notes.tsv"
expect_pass "a note for a source outside the manifest is not this tool's concern" "verified:     1"
printf 'good  no-usable-key  https://example.invalid/  A note that the held key makes stale.\n' > "${W}/notes-stale.tsv"
write_manifest good
fresh_root; run --strict "--notes=${W}/notes-stale.tsv"
expect_fail "a no-usable-key note for a source whose key is held fails --strict" "stale note"

# A noted source whose signature could not be fetched: unverifiable, its note untried, not stale.
printf 'fixture payload for unreached\n' > "${SRC}/unreached.tar.gz"
rm -f "${SRC}/unreached.tar.gz.sig" "${SRC}/.signatures/unreached.tar.gz.sig"
printf 'unreached  no-usable-key  https://example.invalid/  No route to the key was found. Checked 2026-09-28.\n' > "${W}/notes-unreached.tsv"
write_manifest good; add_row unreached sig
fresh_root; run --strict "--notes=${W}/notes-unreached.tsv"
expect_fail "a signature that could not be fetched fails --strict as unverifiable" "unverifiable"
if grep -q "stale note" "$OUT"; then red "a note for a signature that could not be fetched was called stale"; show
else green "a note for a signature that could not be fetched is untried, not stale"; fi

# A manifest row whose file was never downloaded.
write_manifest good notfetched
rm -f "${SRC}/notfetched.tar.gz"
fresh_root; run
expect_pass "a source that was never downloaded is unverifiable" \
    "not downloaded, so its signature cannot be checked"

write_manifest good notfetched
fresh_root; run --strict
expect_fail "a source that was never downloaded fails --strict" "unverifiable"

# --- non-OpenPGP signature files --------------------------------------------

# Like python.org: `shadowed` has a Sigstore-style .sig and a good .asc.
printf 'fixture payload for shadowed\n' > "${SRC}/shadowed.tar.gz"
printf 'MGUCMBOJQYFWjEHjcb7SgCw+RRyHV+y1vbKshHpSSo/jK85X2kajmKLKf3hhR2LT\n' \
    > "${SRC}/shadowed.tar.gz.sig"
fixgpg --yes --local-user good@example.test \
    --detach-sign -o "${SRC}/shadowed.tar.gz.asc" "${SRC}/shadowed.tar.gz" \
    >/dev/null 2>&1

write_manifest shadowed
fresh_root; run
expect_pass "a non-OpenPGP .sig does not shadow a good .asc" "signature valid"

write_manifest shadowed
fresh_root; run --strict
expect_pass "and that source passes --strict" "verified:     1"

if [[ ! -e "${SRC}/.signatures/shadowed.tar.gz.sig" ]]; then
    green "the non-OpenPGP candidate is not left cached"
else
    red "a non-OpenPGP .sig was cached and will shadow the .asc next run"
fi

# `onlyblob` publishes a .sig that is not OpenPGP, and nothing else.
printf 'fixture payload for onlyblob\n' > "${SRC}/onlyblob.tar.gz"
printf 'MGUCMBOJQYFWjEHjcb7SgCw+RRyHV+y1vbKshHpSSo/jK85X2kajmKLKf3hhR2LT\n' \
    > "${SRC}/onlyblob.tar.gz.sig"

write_manifest onlyblob
fresh_root; run
expect_pass "a publisher offering only a non-OpenPGP signature is unverifiable" \
    "none of them is an"

write_manifest onlyblob
fresh_root; run --strict
expect_fail "and it fails --strict rather than being called inconclusive" \
    "unverifiable"

write_manifest good shadowed
fresh_root; run --report="${W}/probe.tsv"
if awk -F'\t' '$1 == "good" && $3 ~ /; probe found \.sig$/ { g = 1 }
               $1 == "shadowed" && $3 ~ /; probe found \.asc$/ { s = 1 }
               END { exit !(g && s) }' "${W}/probe.tsv"; then
    green "a probe row's report names the suffix that verified it"
else
    red "a probe row's report does not name its suffix"
    sed 's/^/        /' "${W}/probe.tsv"
fi

# --- the manifest's sig column ----------------------------------------------

# A declared kind reads only what it names.
: > "${W}/manifest"; add_row shadowed asc
fresh_root; run --strict
expect_pass "a row that declares asc verifies with the .asc" "verified:     1"

: > "${W}/manifest"; add_row shadowed sig
fresh_root; run
expect_pass "a row that declares sig does not fall back to the .asc" \
    "the published .sig is not an OpenPGP signature"

# kernel.org signs the uncompressed tar.
printf 'fixture payload for kern\n' > "${W}/kern.tar"
fixgpg --yes --local-user good@example.test \
    --detach-sign -o "${SRC}/kern.tar.sign" "${W}/kern.tar" >/dev/null 2>&1
gzip -c "${W}/kern.tar" > "${SRC}/kern.tar.gz"
: > "${W}/manifest"; add_row kern kernel
fresh_root; run --strict
expect_pass "a row that declares kernel verifies the uncompressed tar" \
    "verified:     1"

printf 'fixture payload for kern, altered\n' | gzip -c > "${SRC}/kern.tar.gz"
fresh_root; run
expect_fail "a kernel row whose tar is not the signed one fails" "BAD SIGNATURE"

# verify-provenance.sh checks these, so nothing is fetched for them even where a signature exists.
: > "${W}/manifest"; add_row good sha256; add_row expired tag; add_row nosig none
fresh_root; run --report="${W}/declared.tsv"
if [[ "$RC" -eq 0 ]] \
   && grep -qF "good: no OpenPGP signature upstream; the publisher's .sha256 is verify-provenance's" "$OUT" \
   && grep -qF "expired: no OpenPGP signature upstream; the signed tag is verify-provenance's" "$OUT" \
   && grep -qF "nosig: upstream publishes no signature for it" "$OUT" \
   && ! grep -qF "signature valid" "$OUT"; then
    green "sha256 and tag rows are left to verify-provenance.sh, and none to nothing"
else
    red "a sha256, tag or none row was probed or misreported (exit ${RC})"; show
fi
if [[ "$(cut -f2 "${W}/declared.tsv" | sort -u)" == no-signature-upstream ]]; then
    green "sha256, tag and none rows are reported as no signature upstream"
else
    red "they were reported as: $(cut -f2 "${W}/declared.tsv" | sort -u | tr '\n' ' ')"
fi

fresh_root; run --strict
expect_pass "and --strict leaves them to verify-provenance.sh, as unsigned" "publish no OpenPGP signature"

# A kind this script does not know fails, even on a file it could verify.
: > "${W}/manifest"; add_row good telepathy
fresh_root; run
expect_fail "an unknown signature kind fails rather than being skipped" \
    "no signature kind this script knows ('telepathy')"

# Like less: the signature is named without the archive suffix.
printf 'fixture payload for stemmed\n' > "${SRC}/stemmed.tar.gz"
fixgpg --yes --local-user good@example.test \
    --detach-sign -o "${SRC}/stemmed.sig" "${SRC}/stemmed.tar.gz" >/dev/null 2>&1
: > "${W}/manifest"; add_row stemmed stem.sig
fresh_root; run --strict
expect_pass "a row that declares stem.sig verifies with the .sig named for its stem" \
    "verified:     1"
if [[ -s "${SRC}/.signatures/stemmed.sig" && ! -e "${SRC}/.signatures/stemmed.tar.gz.sig" ]]; then
    green "the stem-named signature is cached under its own name"
else
    red "the stem-named signature was cached under the tarball's name"
fi

# probe does not guess a stem: a stem-named file can be another file's signature.
write_manifest stemmed
fresh_root; run
expect_pass "probe does not find a signature named for the stem" \
    "no detached signature published"

: > "${W}/manifest"; add_row good sha256.txt
fresh_root; run
expect_pass "a sha256.txt row is left to verify-provenance.sh" \
    "good: no OpenPGP signature upstream; the publisher's .sha256.txt is verify-provenance's"

# A signed checksum list beside the file, like cmake's (sha256) and pixman's (sha512).
printf 'fixture payload for summed\n' > "${SRC}/summed.tar.gz"
{ printf '%s  other.tar.gz\n' "$(printf other | sha256sum | cut -d' ' -f1)"
  printf '%s  summed.tar.gz\n' "$(sha256sum "${SRC}/summed.tar.gz" | cut -d' ' -f1)"; } \
    > "${SRC}/summed-SHA-256.txt"
fixgpg --yes --local-user good@example.test --armor \
    --detach-sign -o "${SRC}/summed-SHA-256.txt.asc" "${SRC}/summed-SHA-256.txt" >/dev/null 2>&1
: > "${W}/manifest"; add_row summed sums:summed-SHA-256.txt.asc
fresh_root; run --strict --report="${W}/sums.tsv"
expect_pass "a sums row verifies the signed list and the file's digest in it" \
    "verified:     1"
if grep -qF 'signs summed-SHA-256.txt' "${W}/sums.tsv"; then
    green "the report says the signature is over the list"
else
    red "the report does not name the list"; sed 's/^/        /' "${W}/sums.tsv"
fi

printf 'fixture payload for summed512\n' > "${SRC}/summed512.tar.gz"
sha512sum "${SRC}/summed512.tar.gz" | sed 's#  .*#  summed512.tar.gz#' \
    > "${SRC}/summed512.tar.gz.sha512"
fixgpg --yes --local-user good@example.test --armor \
    --detach-sign -o "${SRC}/summed512.tar.gz.sha512.asc" "${SRC}/summed512.tar.gz.sha512" >/dev/null 2>&1
: > "${W}/manifest"; add_row summed512 sums:summed512.tar.gz.sha512.asc
fresh_root; run --strict
expect_pass "a sha512 list verifies the same way" "verified:     1"

# Like pixman's: the .asc is a signed message that carries the list itself.
printf 'fixture payload for carried\n' > "${SRC}/carried.tar.gz"
sha512sum "${SRC}/carried.tar.gz" | sed 's#  .*#  carried.tar.gz#' > "${SRC}/carried.tar.gz.sha512"
fixgpg --yes --local-user good@example.test --armor \
    --sign -o "${SRC}/carried.tar.gz.sha512.asc" "${SRC}/carried.tar.gz.sha512" >/dev/null 2>&1
: > "${W}/manifest"; add_row carried sums:carried.tar.gz.sha512.asc
fresh_root; run --strict
expect_pass "a signed message carrying the list verifies" "verified:     1"

# Its carried list must be the published one.
cp "${SRC}/summed512.tar.gz.sha512" "${W}/other.sha512"
fixgpg --yes --local-user good@example.test --armor \
    --sign -o "${SRC}/carried.tar.gz.sha512.asc" "${W}/other.sha512" >/dev/null 2>&1
rm -f "${SRC}/.signatures/carried.tar.gz.sha512.asc"
fresh_root; run
expect_fail "a signed message carrying another list fails" "is a signed message carrying other data"

# The digest decides, whatever the signature says.
printf 'altered\n' >> "${SRC}/summed.tar.gz"
: > "${W}/manifest"; add_row summed sums:summed-SHA-256.txt.asc
fresh_root; run
expect_fail "a file that does not match its digest in the signed list fails" \
    "does not match a digest in summed-SHA-256.txt"

printf 'fixture payload for unlisted\n' > "${SRC}/unlisted.tar.gz"
: > "${W}/manifest"; add_row unlisted sums:summed-SHA-256.txt.asc
fresh_root; run
expect_fail "a file the signed list does not name fails" \
    "does not match a digest in summed-SHA-256.txt"

# --- unaudited imported keys ------------------------------------------------

write_manifest unknown
fresh_root; run --fetch-unknown-keys
expect_pass "a key imported from the signature is reported as unaudited" \
    "but by an UNAUDITED key"

write_manifest unknown
fresh_root; run --fetch-unknown-keys
if grep -qF "unaudited:    1" "$OUT" && grep -qF "verified:     0" "$OUT"; then
    green "an unaudited key is not counted toward verified"
else
    red "unaudited key was merged into the verified total"; show
fi

write_manifest unknown
fresh_root; run --fetch-unknown-keys
if grep -qiF "$UNKFPR" "${FAKE}/keys.manifest" 2>/dev/null; then
    green "the imported fingerprint is recorded in keys.manifest for audit"
else
    red "keys.manifest does not record the imported fingerprint"
    cat "${FAKE}/keys.manifest" 2>&1 | sed 's/^/        /'
fi

write_manifest unknown
fresh_root; run --fetch-unknown-keys --strict
expect_fail "an unaudited key fails --strict" "signed by unaudited keys"

# --- warm cache: the unaudited label outlives its run -----------------------

write_manifest unknown
fresh_root
run --fetch-unknown-keys                 # imports and records the key
run                                      # key now cached, no flag passed
if grep -qF "but by an UNAUDITED key" "$OUT" && grep -qF "verified:     0" "$OUT"; then
    green "a cached unaudited key is still unaudited on the next run"
else
    red "WARM CACHE REGRESSION: the unaudited label was lost on re-run"; show
fi

run --strict
expect_fail "a cached unaudited key still fails --strict" \
    "signed by unaudited keys"

# Re-running --fetch-unknown-keys must neither truncate nor duplicate the ledger.
before="$(wc -l < "${FAKE}/keys.manifest")"
run --fetch-unknown-keys
after="$(wc -l < "${FAKE}/keys.manifest")"
hits="$(grep -ciF "$UNKFPR" "${FAKE}/keys.manifest" || true)"
if [[ "$after" -ge "$before" && "$hits" -eq 1 ]]; then
    green "re-running --fetch-unknown-keys preserves keys.manifest exactly once"
else
    red "keys.manifest churned: ${before} -> ${after} lines, ${hits} entries"
    sed 's/^/        /' "${FAKE}/keys.manifest"
fi

# Known limit: a cached key without its keys.manifest entry counts as verified; --refresh is next.
rm -f "${FAKE}/keys.manifest"
run
if grep -qF "verified:     1" "$OUT"; then
    green "KNOWN LIMIT: a cached key with no ledger entry counts as verified"
else
    red "the known limit changed; re-read the comment above this case"; show
fi

run --refresh --strict
expect_fail "--refresh discards the cache and the key is unheld again" \
    "unverifiable"

# --- keyring ----------------------------------------------------------------

KEYRING="${W}/empty-keyring.gpg"
write_manifest good
fresh_root; run --strict
expect_fail "an empty keyring fails --strict rather than reporting no problems" \
    "key(s) imported"

write_manifest good
fresh_root; run
expect_pass "an empty keyring warns informationally" "will be mostly unverifiable"
KEYRING="${W}/keyring.gpg"

# --- counts kept apart ------------------------------------------------------

write_manifest good expired revoked bad nosig unknown
fresh_root; run --fetch-unknown-keys
# good and expired verified, unknown unaudited, nosig unsigned, revoked and bad fatal.
for want in "verified:     2" "unaudited:    1" "unsigned:     1" \
            "REVOKED KEYS: 1" "FAILED:       2"; do
    if grep -qF "$want" "$OUT"; then
        green "mixed manifest reports [${want}]"
    else
        red "mixed manifest: missing [${want}]"; show
    fi
done
if [[ "$RC" -ne 0 ]]; then
    green "a mixed manifest containing failures exits non-zero"
else
    red "a mixed manifest containing failures exited 0"; show
fi

# --- missing prerequisites --------------------------------------------------

# mkbin <dir> [tool...]: a PATH directory of the usual tools minus those named.
mkbin() {
    local dir="$1"; shift
    mkdir -p "$dir"
    local t p src
    for t in bash env curl tar gzip sha256sum awk sed grep head tail cut tr \
             mkdir rm mv cp cat ls find sort wc dirname basename chmod \
             mktemp date sleep seq python3 gpg gpgconf id uname od xz gpg2; do
        for p in "$@"; do [[ "$t" == "$p" ]] && continue 2; done
        src="$(command -v "$t" 2>/dev/null)" || continue
        ln -sf "$src" "${dir}/${t}"
    done
}

mkbin "${W}/bin-full"
mkbin "${W}/bin-nogpg" gpg gpg2

# Control: the pruned PATH alone must not break a good run.
write_manifest good
fresh_root
PATH="${W}/bin-full" KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" \
    KRYPTIK_SIGCHECK_SELFTEST=1 KRYPTIK_SIGCHECK_MANIFEST="${W}/manifest" \
    KRYPTIK_SIGCHECK_KEYRING="$KEYRING" NO_COLOR=1 \
    bash "$TOOL" --strict > "$OUT" 2>&1
if [[ "$?" -eq 0 ]] && grep -qF "signature valid" "$OUT"; then
    green "the pruned-PATH harness still verifies with every tool present"
else
    red "the pruned-PATH harness broke a good run"; show
fi

write_manifest good
fresh_root
PATH="${W}/bin-nogpg" KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" \
    KRYPTIK_SIGCHECK_SELFTEST=1 KRYPTIK_SIGCHECK_MANIFEST="${W}/manifest" \
    KRYPTIK_SIGCHECK_KEYRING="$KEYRING" NO_COLOR=1 \
    bash "$TOOL" > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "gpg not found" "$OUT"; then
    green "missing gpg refuses to run at all, in either mode"
else
    red "missing gpg did not refuse (exit ${rc})"; show
fi

if ! grep -qF "No signature verification failures" "$OUT"; then
    green "a run without gpg never reports an absence of failures"
else
    red "a run without gpg reported no failures"; show
fi

PATH="${W}/bin-nogpg" KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" \
    KRYPTIK_SIGCHECK_SELFTEST=1 KRYPTIK_SIGCHECK_MANIFEST="${W}/manifest" \
    KRYPTIK_SIGCHECK_KEYRING="$KEYRING" NO_COLOR=1 \
    bash "$TOOL" --strict > "$OUT" 2>&1
if [[ "$?" -ne 0 ]]; then
    green "missing gpg fails --strict too"
else
    red "missing gpg passed --strict"; show
fi

# --- selftest hooks ---------------------------------------------------------

write_manifest good
fresh_root
KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" \
    KRYPTIK_SIGCHECK_MANIFEST="${W}/manifest" NO_COLOR=1 \
    bash "$TOOL" --strict > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to verify signatures" "$OUT"; then
    green "a substituted manifest is refused without the selftest flag"
else
    red "a substituted manifest was accepted without KRYPTIK_SIGCHECK_SELFTEST"; show
fi

# --- pinned fingerprints ----------------------------------------------------

# A key id in place of a full fingerprint could be collided, yet would still
# report as signature-pinned-key.
PINS="$(awk '/^PINNED_FPRS=\(/{f=1;next} f&&/^\)/{f=0} f' "${ROOT}/tools/verify-signatures.sh" \
        | grep -oE '"[0-9A-Fa-f]+"' | tr -d '"')"

if [[ -n "$PINS" ]]; then
    green "the pinned-fingerprint list is readable and non-empty"
else
    red "the pinned-fingerprint list is readable and non-empty"
fi

badshape="$(printf '%s\n' "$PINS" | grep -vE '^[0-9A-F]{40}$' | tr '\n' ' ')"
if [[ -z "${badshape// /}" ]]; then
    green "every pin is a full 40-character uppercase fingerprint"
else
    red "pins that are not full uppercase fingerprints: ${badshape}"
fi

dupes="$(printf '%s\n' "$PINS" | sort | uniq -d | tr '\n' ' ')"
if [[ -z "${dupes// /}" ]]; then
    green "no fingerprint is pinned twice"
else
    red "duplicated pins: ${dupes}"
fi

# Each pin needs a comment saying whose key it is.
uncommented="$(awk '/^PINNED_FPRS=\(/{f=1;next} f&&/^\)/{f=0} f && /"[0-9A-Fa-f]{40}"/ && $0 !~ /#/' \
               "${ROOT}/tools/verify-signatures.sh" | tr -d ' "' | tr '\n' ' ')"
if [[ -z "${uncommented// /}" ]]; then
    green "every pin carries a comment naming whose key it is"
else
    red "pins with no comment: ${uncommented}"
fi

# --- published key provenance -----------------------------------------------

# file:// locators are accepted only under KRYPTIK_SIGCHECK_SELFTEST.
PROV="${W}/prov"
mkdir -p "$PROV"
GNUPGHOME="$FIXG" gpg --batch --quiet --armor --export unknown@example.test \
    > "${PROV}/unknown.asc"
GNUPGHOME="$FIXG" gpg --batch --quiet --armor --export good@example.test \
    > "${PROV}/good.asc"

if [[ -s "${PROV}/unknown.asc" && -s "${PROV}/good.asc" ]]; then
    green "provenance fixtures: both keys exported"
else
    red "provenance fixtures: export failed, the cases below would be vacuous"
fi

prov_table() { printf '%s\n' "$@" > "${W}/prov.tsv"; }

runprov() {
    KRYPTIK_ROOT="$FAKE" \
    KRYPTIK_SOURCES="$SRC" \
    KRYPTIK_SIGCHECK_SELFTEST=1 \
    KRYPTIK_SIGCHECK_MANIFEST="${W}/manifest" \
    KRYPTIK_SIGCHECK_KEYRING="$KEYRING" \
    KRYPTIK_SIGCHECK_KEYSOURCE="$KEYSOURCE" \
    KRYPTIK_SIGCHECK_PROVENANCE="${W}/prov.tsv" \
    NO_COLOR=1 \
    bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

klass_of() {  # klass_of REPORT NAME
    awk -F'\t' -v N="$2" '$1==N{print $2; exit}' "$1"
}

# Control: with no provenance row the key is not held.
fresh_root
write_manifest unknown
run --report="${W}/r0.tsv"
if [[ "$(klass_of "${W}/r0.tsv" unknown)" == "key-not-held" ]]; then
    green "with no published provenance the key is still not held"
else
    red "with no published provenance the key is still not held (got $(klass_of "${W}/r0.tsv" unknown))"; show
fi

fresh_root
write_manifest unknown
prov_table "${UNKFPR}  korg  file://${PROV}/unknown.asc  2026-09-11  unknown  unknown fixture <unknown@example.test>"
runprov --report="${W}/r1.tsv"
if [[ "$(klass_of "${W}/r1.tsv" unknown)" == "signature-korg-published-key" ]]; then
    green "a published key is fetched from its locator and classed as published"
else
    red "expected signature-korg-published-key, got $(klass_of "${W}/r1.tsv" unknown)"; show
fi
if grep -qF "imported the key korg publishes" "$OUT"; then
    green "and the import says where the key came from"
else
    red "and the import says where the key came from"; show
fi

# The locator serves a different key than the row records: the row must win.
fresh_root
write_manifest unknown
prov_table "${UNKFPR}  korg  file://${PROV}/good.asc  2026-09-11  unknown  deliberately the wrong key"
runprov --report="${W}/r2.tsv"
if grep -qF "REFUSING it" "$OUT" && grep -qF "now publishes" "$OUT"; then
    green "a locator serving a different key is refused as a finding"
else
    red "a locator serving a different key is refused as a finding"; show
fi
if [[ "$RC" -ne 0 && "$(klass_of "${W}/r2.tsv" unknown)" == "published-key-changed" ]]; then
    green "and the source fails rather than borrowing the wrong key"
else
    red "and the source fails (exit ${RC}, got $(klass_of "${W}/r2.tsv" unknown))"; show
fi

fresh_root
write_manifest unknown
printf '%-18s %-42s %s\n' unknown "$UNKFPR" 'unknown fixture' > "${FAKE}/keys.manifest"
prov_table "${UNKFPR}  korg  file://${PROV}/unknown.asc  2026-09-11  unknown  unknown fixture"
runprov --report="${W}/r3.tsv"
if [[ "$(klass_of "${W}/r3.tsv" unknown)" == "signature-korg-published-key" ]]; then
    green "published provenance supersedes a keys.manifest unaudited entry"
else
    red "published provenance supersedes keys.manifest (got $(klass_of "${W}/r3.tsv" unknown))"; show
fi
rm -f "${FAKE}/keys.manifest"

# An unresolvable WKD address must warn, stay unverified and not abort the run.
fresh_root
write_manifest unknown
prov_table "${UNKFPR}  wkd  nobody@wkd-does-not-exist.invalid  2026-09-11  unknown  unresolvable on purpose"
runprov --report="${W}/r4.tsv"
if [[ "$RC" -eq 0 ]] && grep -qF "no WKD answer" "$OUT" \
   && [[ "$(klass_of "${W}/r4.tsv" unknown)" == "key-not-held" ]]; then
    green "an unresolvable wkd locator warns and leaves the source unverified"
else
    red "an unresolvable wkd locator warns and leaves the source unverified (exit ${RC})"; show
fi

# good is held, but its published copy carries a revocation, which the merge must pick up.
GOODFPR="$(GNUPGHOME="$FIXG" gpg --batch --list-keys --with-colons good@example.test \
           | awk -F: '$1=="fpr"{print $10; exit}')"
REVG="${W}/gnupg-revoke"
mkdir -p "$REVG"; chmod 700 "$REVG"
GNUPGHOME="$REVG" gpg --batch --quiet --import "${PROV}/good.asc" >/dev/null 2>&1
sed 's/^://' "${FIXG}/openpgp-revocs.d/${GOODFPR}.rev" \
    | GNUPGHOME="$REVG" gpg --batch --quiet --import >/dev/null 2>&1
GNUPGHOME="$REVG" gpg --batch --quiet --armor --export "$GOODFPR" > "${PROV}/good-revoked.asc"
GNUPGHOME="$REVG" gpgconf --kill all >/dev/null 2>&1

fresh_root
write_manifest good
prov_table "${GOODFPR}  korg  file://${PROV}/good-revoked.asc  2026-09-11  good  good fixture, revoked where it is published"
runprov
if [[ "$RC" -ne 0 ]] && grep -qF "REVOKED key" "$OUT"; then
    green "a held key is merged from its locator, so a revocation published there is seen"
else
    red "a held key is merged from its locator, so a revocation published there is seen (exit ${RC})"; show
fi

# A held key whose locator serves another key: the held copy must not carry the source.
fresh_root
write_manifest good
prov_table "${GOODFPR}  korg  file://${PROV}/unknown.asc  2026-09-11  good  good fixture, whose locator now serves another key"
runprov --report="${W}/r6.tsv"
if [[ "$RC" -ne 0 && "$(klass_of "${W}/r6.tsv" good)" == "published-key-changed" ]] \
   && grep -qF "good (its published key changed at" "$OUT"; then
    green "a held key refused at its locator fails the source it signs"
else
    red "a held key refused at its locator fails the source it signs (exit ${RC}, got $(klass_of "${W}/r6.tsv" good))"; show
fi

# A locator serving the recorded key and another: only the recorded one is taken.
fixgpg --quick-generate-key "extra fixture <extra@example.test>" ed25519 sign never >/dev/null 2>&1
printf 'fixture payload for extra\n' > "${SRC}/extra.tar.gz"
fixgpg --yes --local-user extra@example.test \
       --detach-sign -o "${SRC}/extra.tar.gz.sig" "${SRC}/extra.tar.gz" >/dev/null 2>&1
{ GNUPGHOME="$FIXG" gpg --batch --quiet --export unknown@example.test
  GNUPGHOME="$FIXG" gpg --batch --quiet --export extra@example.test; } > "${PROV}/unknown-and-extra.gpg"

fresh_root
write_manifest extra
prov_table "${UNKFPR}  korg  file://${PROV}/unknown-and-extra.gpg  2026-09-11  extra  a locator that also carries another key"
runprov --report="${W}/r5.tsv"
if [[ "$(klass_of "${W}/r5.tsv" extra)" == "key-not-held" ]] && ! grep -qF "REFUSING" "$OUT"; then
    green "only the recorded key is taken from a locator that serves another as well"
else
    red "only the recorded key is taken from a locator that serves another (got $(klass_of "${W}/r5.tsv" extra))"; show
fi

# A key that signs two sources is fetched once.
fresh_root
write_manifest unknown extra
prov_table "${UNKFPR}  korg  file://${PROV}/unknown.asc  2026-09-11  unknown,extra  unknown fixture"
runprov
if [[ "$(grep -c "imported the key korg publishes" "$OUT")" -eq 1 ]]; then
    green "a key that signs two sources is fetched once a run"
else
    red "a key that signs two sources is fetched once a run"; show
fi

# good's key recorded for another source: the row says nothing about good.
fresh_root
write_manifest good
prov_table "${GOODFPR}  korg  file://${PROV}/good.asc  2026-09-11  other  good fixture, recorded for another source"
runprov --report="${W}/r7.tsv"
if [[ "$RC" -eq 0 && "$(klass_of "${W}/r7.tsv" good)" == "signature-keyring-key" ]]; then
    green "a row gives its class only to the sources it names"
else
    red "a row gives its class only to the sources it names (exit ${RC}, got $(klass_of "${W}/r7.tsv" good))"; show
fi

# A row whose published copy cannot be read this run gives no class.
fresh_root
write_manifest good
prov_table "${GOODFPR}  korg  file://${PROV}/missing.asc  2026-09-11  good  good fixture, its published copy gone"
runprov --report="${W}/r8.tsv"
if [[ "$RC" -eq 0 && "$(klass_of "${W}/r8.tsv" good)" == "signature-keyring-key" ]] \
   && grep -qF "not read this run" "${W}/r8.tsv"; then
    green "a row not read this run gives no class, and the report says so"
else
    red "a row not read this run gives no class (exit ${RC}, got $(klass_of "${W}/r8.tsv" good))"; show
fi
fresh_root
runprov --strict
if [[ "$RC" -ne 0 ]] && grep -qF "published copy at file://${PROV}/missing.asc not read this run" "$OUT"; then
    green "and --strict counts its source unverifiable"
else
    red "and --strict counts its source unverifiable (exit ${RC})"; show
fi

# --- malformed provenance rows ----------------------------------------------

bad_prov() {  # bad_prov ROW NAME
    fresh_root
    write_manifest good
    prov_table "$1"
    runprov
    if [[ "$RC" -ne 0 ]] && grep -qF "malformed" "$OUT"; then
        green "$2"
    else
        red "$2 (exit ${RC})"; show
    fi
}

bad_prov "${UNKFPR,,}  korg  file://${PROV}/unknown.asc  2026-09-11  unknown  lowercase" \
         "a lowercase fingerprint is refused"
bad_prov "DEADBEEF  korg  file://${PROV}/unknown.asc  2026-09-11  unknown  short" \
         "a short key id in place of a fingerprint is refused"
bad_prov "${UNKFPR}  someplace  file://${PROV}/unknown.asc  2026-09-11  unknown  x" \
         "an unknown kind is refused"
bad_prov "${UNKFPR}  korg  http://example.invalid/k.asc  2026-09-11  unknown  x" \
         "a plain-http korg locator is refused"
bad_prov "${UNKFPR}  wkd  not-an-address  2026-09-11  unknown  x" \
         "a wkd locator that is not an address is refused"
bad_prov "${UNKFPR}  korg  file://${PROV}/unknown.asc  11-09-2026  unknown  x" \
         "a non-ISO retrieval date is refused"
bad_prov "${UNKFPR}  korg  file://${PROV}/unknown.asc  2026-09-11" \
         "a row naming no sources is refused"
bad_prov "${UNKFPR}  korg  file://${PROV}/unknown.asc  2026-09-11  unknown" \
         "a row with no published uid recorded is refused"

# --- the platform-published kind --------------------------------------------

# github: the release publisher's account key; its own class, as holding that account defeats both.
fresh_root
write_manifest unknown
prov_table "${UNKFPR}  github  file://${PROV}/unknown.asc  2026-09-11  unknown  unknown fixture; fixture/repo v1.0 was published by nobody"
runprov --report="${W}/g1.tsv"
if [[ "$(klass_of "${W}/g1.tsv" unknown)" == "signature-platform-published-key" ]]; then
    green "a github row classes the signature as platform-published"
else
    red "expected signature-platform-published-key, got $(klass_of "${W}/g1.tsv" unknown)"; show
fi

# One endpoint shape, so "github" cannot point at another host.
bad_prov "${UNKFPR}  github  https://not-github.example/x.gpg  2026-09-11  unknown  x published by someone" \
         "a github locator on another host is refused"
bad_prov "${UNKFPR}  github  https://github.com/acct/extra.gpg  2026-09-11  unknown  x published by someone" \
         "a github locator that is not <account>.gpg is refused"

# Without the release-author tie the row says only "GitHub hosts this key".
bad_prov "${UNKFPR}  github  https://github.com/acct.gpg  2026-09-11  unknown  just a uid, no tie recorded" \
         "a github row with no recorded release author is refused"

# --- the forge-published kind ---------------------------------------------------
fresh_root
write_manifest unknown
prov_table "${UNKFPR}  savannah  file://${PROV}/unknown.asc  2026-09-11  unknown  unknown fixture <unknown@example.test>"
runprov --report="${W}/s1.tsv"
if [[ "$(klass_of "${W}/s1.tsv" unknown)" == "signature-savannah-published-key" ]]; then
    green "a savannah row classes the signature as published by the project's forge"
else
    red "expected signature-savannah-published-key, got $(klass_of "${W}/s1.tsv" unknown)"; show
fi
bad_prov "${UNKFPR}  savannah  https://savannah.example/project/release-gpgkeys.php?group=x&download=1  2026-09-11  unknown  x" \
         "a savannah locator on another host is refused"
bad_prov "${UNKFPR}  savannah  https://savannah.gnu.org/project/memberlist.php?group=x  2026-09-11  unknown  x" \
         "a savannah locator that is not the project's release keyring is refused"

# Shipped github rows need both the endpoint shape and the release-author tie.
gh_bad=0
while read -r _fpr kind loc _ret _signs rest; do
    [[ "$kind" == "github" ]] || continue
    [[ "$loc" =~ ^https://github\.com/[A-Za-z0-9-]+\.gpg$ ]] || gh_bad=$((gh_bad + 1))
    case "$rest" in *"published by"*) ;; *) gh_bad=$((gh_bad + 1)) ;; esac
done < <(grep -E '^[0-9A-F]{40}' "${ROOT}/tools/key-provenance.tsv")
if [[ "$gh_bad" -eq 0 ]]; then
    green "every shipped github row names an account endpoint and its release author"
else
    red "${gh_bad} shipped github row(s) are missing the endpoint shape or the tie"
fi

# --- shipped table, selftest gate -------------------------------------------

fresh_root
write_manifest good
run
if [[ "$RC" -eq 0 ]] && ! grep -qF "malformed" "$OUT"; then
    green "the shipped tools/key-provenance.tsv is well formed"
else
    red "the shipped tools/key-provenance.tsv is well formed (exit ${RC})"
    grep -F "key-provenance" "$OUT" | sed 's/^/        /' | head -5
fi

PINS_T="$(awk '/^# fingerprint/{f=1;next} f&&/^[0-9A-F]{40}/{print $1}' \
          "${ROOT}/tools/key-provenance.tsv")"
if [[ -n "$PINS_T" ]] && [[ -z "$(printf '%s\n' "$PINS_T" | grep -vE '^[0-9A-F]{40}$')" ]]; then
    green "every shipped provenance row names a full uppercase fingerprint"
else
    red "the shipped provenance table has a malformed fingerprint column"
fi
# A key may have a row per project; a key and source in two rows would be ambiguous.
PAIRS_T="$(awk '/^# fingerprint/{f=1;next} f&&/^[0-9A-F]{40}/{n=split($5,s,",");for(i=1;i<=n;i++)print $1" "s[i]}' \
           "${ROOT}/tools/key-provenance.tsv")"
if [[ -z "$(printf '%s\n' "$PAIRS_T" | sort | uniq -d)" ]]; then
    green "no key and source appear in two rows of the shipped table"
else
    red "a key and source in two rows: $(printf '%s\n' "$PAIRS_T" | sort | uniq -d | tr '\n' ' ')"
fi

fresh_root
write_manifest good
prov_table "${UNKFPR}  korg  file://${PROV}/unknown.asc  2026-09-11  unknown  x"
KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" \
    KRYPTIK_SIGCHECK_PROVENANCE="${W}/prov.tsv" NO_COLOR=1 \
    bash "$TOOL" > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to verify signatures" "$OUT"; then
    green "a substituted provenance table is refused without the selftest flag"
else
    red "a substituted provenance table was accepted without the flag (exit ${rc})"; show
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
