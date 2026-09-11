#!/usr/bin/env bash
# Focused tests for tools/verify-signatures.sh.
#
#   ./tools/test-verify-signatures.sh
#
# Deterministic and offline, with real GnuPG rather than stubbed status output.
# Four throwaway ed25519 keys are generated per run and used to produce every
# state the classifier distinguishes:
#
#   GOODSIG     a valid signature by a held key
#   EXPKEYSIG   a signature made while the key was valid, verified after it
#               expired (the key is created with a one-second lifetime)
#   REVKEYSIG   a valid signature by a key whose revocation certificate has
#               been imported
#   BADSIG      a signature whose file was modified afterwards
#   NO_PUBKEY   a signature by a key the keyring does not hold
#
# and one source with no detached signature at all, plus one named in the
# manifest but never downloaded.
#
# Only three things are substituted: which manifest is verified, where the
# keyring comes from, and where --fetch-unknown-keys imports from. check_sig()
# and the summary accounting - what these tests are about - run exactly as in
# production. The repository's keys.manifest, sources.lock and versions.env are
# never read or written; each case builds a throwaway KRYPTIK_ROOT.
#
# The two cases worth reading first are the warm-cache pair. An earlier version
# of this tool labelled --fetch-unknown-keys imports "unaudited" correctly and
# then lost the label on the very next run, because the key was by then in the
# cached keyring and looked like any other GOODSIG. That regression is cheap to
# reintroduce and invisible in a single run, so it is pinned here.

set -uo pipefail

# The tool under test reads KRYPTIK_SOURCES, KRYPTIK_WORK, KRYPTIK_LOCK and
# KRYPTIK_OUT from the environment when they are set, in preference to deriving
# them from KRYPTIK_ROOT. A developer who has any of those exported - pointing
# at the real downloads, say - would otherwise see this suite verify the wrong
# tree and report failures that are nothing to do with the code. Each case sets
# what it needs explicitly, so clear all of them here rather than inheriting.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/verify-signatures.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in gpg curl awk sed grep; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required for this test"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
cleanup() {
    # gpg-agent holds the fixture GNUPGHOMEs open; ask it to stop before the
    # directory goes away, or the temp tree survives the test.
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
    # One second, so that the signature below is made while the key is valid
    # and verified after it is not. That is EXPKEYSIG, which is a valid
    # signature and a stale keyring - not tampering.
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

# Modified after signing. The lock file would catch this too; the point here is
# that gpg reports BADSIG and the tool treats it as fatal.
printf 'TAMPERED AFTER SIGNING\n' >> "${SRC}/bad.tar.gz"

# Upstream publishes nothing alongside this one.
printf 'no signature is published for this\n' > "${SRC}/nosig.tar.gz"

# Keyring handed to the tool: good + expired + revoked, with the revocation
# applied. GnuPG writes a revocation certificate for every generated key, armoured
# with a leading colon on each line so it cannot be imported by accident;
# stripping that is the documented way to use it.
REVFPR="$(GNUPGHOME="$FIXG" gpg --batch --list-keys --with-colons revoked@example.test \
          | awk -F: '$1=="fpr"{print $10; exit}')"
GNUPGHOME="$FIXG" gpg --batch --quiet \
    --export good@example.test expired@example.test revoked@example.test \
    > "${W}/pub.gpg"
GNUPGHOME="$BUILDG" gpg --batch --quiet --import "${W}/pub.gpg" >/dev/null 2>&1
sed 's/^://' "${FIXG}/openpgp-revocs.d/${REVFPR}.rev" \
    | GNUPGHOME="$BUILDG" gpg --batch --quiet --import >/dev/null 2>&1
GNUPGHOME="$BUILDG" gpg --batch --quiet --export > "${W}/keyring.gpg"

# The "unknown" key, reachable only the way --fetch-unknown-keys reaches one:
# by the id the signature itself names. Both the long key id and the
# fingerprint are provided, because that is what gpg may report.
UNKFPR="$(GNUPGHOME="$FIXG" gpg --batch --list-keys --with-colons unknown@example.test \
          | awk -F: '$1=="fpr"{print $10; exit}')"
UNKID="${UNKFPR: -16}"
GNUPGHOME="$FIXG" gpg --batch --quiet --export unknown@example.test \
    > "${KEYSOURCE}/${UNKID}.gpg"
cp "${KEYSOURCE}/${UNKID}.gpg" "${KEYSOURCE}/${UNKFPR}.gpg"

: > "${W}/empty-keyring.gpg"

# The expired key needs to actually be expired before anything is verified.
sleep 3

# --- fixture sanity: the states must be what this suite believes ------------
#
# A positive control on the fixtures themselves. If key generation or the
# revocation import silently failed, every assertion below would still "pass"
# for the wrong reason, so the raw gpg classification is checked first.

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

# write_manifest <name>...
# Rows are `name version url`, the shape fetch-sources.sh --list emits. A
# file:// URL keeps signature discovery on the generic .sig/.asc/.sign path,
# which is the one most sources use.
write_manifest() {
    : > "${W}/manifest"
    local n
    for n in "$@"; do
        printf '%-12s %-10s %s\n' "$n" "1.0" "file://${SRC}/${n}.tar.gz" \
            >> "${W}/manifest"
    done
}

# fresh_root discards the key cache and the ledger; warm_root keeps both, which
# is the state the warm-cache cases are about.
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

# ---------------------------------------------------------------------------
# positive controls
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# hard failures: fatal in both modes
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# unverifiable: not a failure, not a pass
# ---------------------------------------------------------------------------

write_manifest nosig
fresh_root; run
expect_pass "no signature published upstream is unverifiable" \
    "no detached signature published"

write_manifest nosig
fresh_root; run --strict
expect_fail "an unverifiable source fails --strict" \
    "will not pass sources whose signer was never established"

write_manifest unknown
fresh_root; run
expect_pass "a signature by an unheld key is unverifiable" "not held"

write_manifest unknown
fresh_root; run --strict
expect_fail "an unheld signing key fails --strict" "unverifiable"

# A manifest row whose file was never downloaded. This used to warn and
# `continue` without touching a counter, so a run with nothing fetched
# reported no problems at all.
write_manifest good notfetched
rm -f "${SRC}/notfetched.tar.gz"
fresh_root; run
expect_pass "a source that was never downloaded is unverifiable" \
    "not downloaded, so its signature cannot be checked"

write_manifest good notfetched
fresh_root; run --strict
expect_fail "a source that was never downloaded fails --strict" "unverifiable"

# ---------------------------------------------------------------------------
# a suffix is not a format
# ---------------------------------------------------------------------------
#
# python.org publishes both a Sigstore `.sig` (a base64 ECDSA blob) and an
# OpenPGP `.asc`. The probe tried `.sig` first, handed the blob to gpg, got "no
# valid OpenPGP data found" and reported the source as inconclusive — with the
# real signature one suffix away. These cases pin that.

# `shadowed` has a non-OpenPGP .sig and a good .asc.
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

# The wrong-format file must not be left in the signature cache, or it would
# shadow the real one on every later run.
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

# ---------------------------------------------------------------------------
# unaudited imported keys
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# warm cache: the label has to outlive the run that created it
# ---------------------------------------------------------------------------

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

# keys.manifest is the ledger; --fetch-unknown-keys used to truncate it at the
# start of every run, so a second run that fetched nothing erased it.
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

# The documented limit, pinned so that a change to it is visible: the ledger is
# the only record of how a cached key got there. Remove the ledger and the key
# counts as verified - which is why --refresh is the documented remedy, and why
# that remedy is asserted immediately below rather than just described.
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

# ---------------------------------------------------------------------------
# the keyring itself
# ---------------------------------------------------------------------------

KEYRING="${W}/empty-keyring.gpg"
write_manifest good
fresh_root; run --strict
expect_fail "an empty keyring fails --strict rather than reporting no problems" \
    "key(s) imported"

write_manifest good
fresh_root; run
expect_pass "an empty keyring warns informationally" "will be mostly unverifiable"
KEYRING="${W}/keyring.gpg"

# ---------------------------------------------------------------------------
# the buckets must not be merged
# ---------------------------------------------------------------------------

write_manifest good expired revoked bad nosig unknown
fresh_root; run --fetch-unknown-keys
# good + expired verified; unknown unaudited; nosig unverifiable;
# revoked + bad fatal.
for want in "verified:     2" "unaudited:    1" "unverifiable: 1" \
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

# ---------------------------------------------------------------------------
# missing prerequisites
# ---------------------------------------------------------------------------
#
# A real pruned PATH, not a flag: `have gpg` is what the tool calls, so this
# exercises the code that runs. Without gpg NOTHING can be authenticated, and
# the one outcome that must not happen is a run that reports no problems.

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

# Control first: the pruned-PATH harness itself must not break a good run, or
# the two cases below would prove nothing.
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

# ---------------------------------------------------------------------------
# the selftest hooks cannot be used by accident
# ---------------------------------------------------------------------------

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

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
