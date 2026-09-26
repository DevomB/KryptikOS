#!/usr/bin/env bash
# Tests for tools/verify-provenance.sh. Offline, with real fixtures: tags
# SSH-signed by per-run keys, and a publisher on 127.0.0.1. Each case runs the
# tool against a throwaway KRYPTIK_ROOT.

set -uo pipefail

# common.sh prefers these over paths derived from KRYPTIK_ROOT, so an exported
# one would point the tool at the real tree.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/verify-provenance.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in git ssh-keygen python3 tar sha256sum curl; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required for this test"; exit 1; }
done

TMP="$(mktemp -d)"
OUT="${TMP}/out"
RC=0
SRV_PID=""
cleanup() {
    [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

show() { sed 's/^/        /' "$OUT"; }

TAG=14
PREFIX="hardened_malloc-${TAG}"

# --- signing keys -----------------------------------------------------------

mkdir -p "${TMP}/keys"
ssh-keygen -q -t ed25519 -N '' -C intended -f "${TMP}/keys/good" </dev/null
ssh-keygen -q -t ed25519 -N '' -C impostor -f "${TMP}/keys/bad" </dev/null

PRINCIPAL="releases@example.test"
printf '%s %s\n' "$PRINCIPAL" "$(cut -d' ' -f1,2 < "${TMP}/keys/good.pub")" \
    > "${TMP}/keys/allowed_signers"

GOOD_FPR="$(ssh-keygen -lf "${TMP}/keys/good.pub" | awk '{print $2}')"

{
    printf '%s %s\n' "$PRINCIPAL" "$(cut -d' ' -f1,2 < "${TMP}/keys/good.pub")"
    printf '%s %s\n' "$PRINCIPAL" "$(cut -d' ' -f1,2 < "${TMP}/keys/bad.pub")"
} > "${TMP}/keys/both_signers"

# --- fixture upstream repository --------------------------------------------

FIXREPO="${TMP}/upstream"
git init -q "$FIXREPO"
(
    cd "$FIXREPO"
    git config user.name fixture
    git config user.email fixture@example.test
    git config commit.gpgsign false
    mkdir -p src
    printf 'int main(void) { return 0; }\n' > src/main.c
    printf 'all:\n\t$(CC) -o a.out src/main.c\n' > Makefile
    printf 'the intended contents\n' > README
    chmod 755 Makefile
    git add -A
    git commit -q -m "fixture release"

    git -c gpg.format=ssh -c user.signingkey="${TMP}/keys/good" \
        tag -s "$TAG" -m "$TAG"
    git -c gpg.format=ssh -c user.signingkey="${TMP}/keys/bad" \
        tag -s "${TAG}-impostor" -m "${TAG}-impostor"
    git tag -a "${TAG}-unsigned" -m "${TAG}-unsigned"
    git tag "${TAG}-light"
) >/dev/null 2>&1

# --- fixture archives -------------------------------------------------------

ARCHIVES="${TMP}/archives"
mkdir -p "$ARCHIVES"

# What GitHub serves for .../archive/refs/tags/<tag>.tar.gz.
git -C "$FIXREPO" archive --format=tar.gz --prefix="${PREFIX}/" \
    -o "${ARCHIVES}/authentic.tar.gz" "$TAG"

# One file changed, repacked. Its own hash goes in the lock, so only the tree
# binding can catch it.
(
    cd "$TMP"
    rm -rf alter && mkdir alter && cd alter
    tar xzf "${ARCHIVES}/authentic.tar.gz"
    printf 'the intended contents\nplus a line nobody signed\n' > "${PREFIX}/README"
    tar czf "${ARCHIVES}/altered.tar.gz" "${PREFIX}"
) >/dev/null 2>&1

# Two top-level entries, unlike a tag archive.
(
    cd "$TMP"
    rm -rf twotop && mkdir twotop && cd twotop
    tar xzf "${ARCHIVES}/authentic.tar.gz"
    mkdir -p second && printf 'x\n' > second/x
    tar czf "${ARCHIVES}/twotop.tar.gz" "${PREFIX}" second
) >/dev/null 2>&1

# --- fixture publisher (skarnet stand-in) -----------------------------------

# Laid out like skarnet.org/software: <pkg>/<pkg>-<ver>.tar.gz and its .sha256.
SERVE="${TMP}/serve"
S_VER=2.15.1.0
E_VER=2.9.9.2
S6_VER=2.15.1.0
RC_VER=0.7.0.0
INIT_VER=1.2.0.2

mk_pkg() {
    local pkg="$1" ver="$2" body="$3"
    local dir="${SERVE}/${pkg}"
    local tarball="${pkg}-${ver}.tar.gz"
    mkdir -p "$dir"
    printf 'fixture payload for %s %s\n' "$pkg" "$ver" > "${TMP}/payload"
    tar czf "${dir}/${tarball}" -C "$TMP" payload
    cp "${dir}/${tarball}" "${TMP}/sources/${tarball}"
    local digest; digest="$(sha256sum "${dir}/${tarball}" | cut -d' ' -f1)"
    case "$body" in
        good)      printf '%s  %s\n' "$digest" "$tarball" > "${dir}/${tarball}.sha256" ;;
        wrong)     printf '%s  %s\n' "$(printf 0 | sha256sum | cut -d' ' -f1)" \
                          "$tarball" > "${dir}/${tarball}.sha256" ;;
        malformed) printf '<html>404 Not Found</html>\n' > "${dir}/${tarball}.sha256" ;;
        absent)    : ;;
    esac
    printf '%s' "$digest"
}

mkdir -p "${TMP}/sources"
SKALIBS_SHA="$(mk_pkg skalibs        "$S_VER"    good)"
EXECLINE_SHA="$(mk_pkg execline      "$E_VER"    good)"
S6_SHA="$(mk_pkg s6                  "$S6_VER"   good)"
S6RC_SHA="$(mk_pkg s6-rc             "$RC_VER"   good)"
S6INIT_SHA="$(mk_pkg s6-linux-init   "$INIT_VER" good)"

python3 - "$SERVE" "${TMP}/port" >/dev/null 2>&1 <<'PY' &
import http.server, os, socketserver, sys

os.chdir(sys.argv[1])


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 0), Quiet) as httpd:
    with open(sys.argv[2], "w") as fh:
        fh.write(str(httpd.server_address[1]))
    httpd.serve_forever()
PY
SRV_PID=$!

for _ in $(seq 1 50); do
    [[ -s "${TMP}/port" ]] && break
    sleep 0.1
done
PORT="$(cat "${TMP}/port" 2>/dev/null)"
[[ -n "$PORT" ]] || { echo "fixture server did not start"; exit 1; }
SKARNET="http://127.0.0.1:${PORT}"
DEAD_SKARNET="http://127.0.0.1:1"

# --- harness ----------------------------------------------------------------

FAKE="${TMP}/root"

# build_root <hm-archive-path|-> <hm-lock-hash|auto|none>
build_root() {
    local hm_archive="$1" hm_lock="$2"
    rm -rf "$FAKE"
    mkdir -p "${FAKE}/build/config" "${FAKE}/sources"

    cat > "${FAKE}/build/config/versions.env" <<EOF
V_HARDENED_MALLOC=${TAG}
V_SKALIBS=${S_VER}
V_EXECLINE=${E_VER}
V_S6=${S6_VER}
V_S6_RC=${RC_VER}
V_S6_LINUX_INIT=${INIT_VER}
EOF

    cp "${TMP}/sources/"*.tar.gz "${FAKE}/sources/" 2>/dev/null || true

    {
        printf '%s  skalibs-%s.tar.gz\n'       "$SKALIBS_SHA"  "$S_VER"
        printf '%s  execline-%s.tar.gz\n'      "$EXECLINE_SHA" "$E_VER"
        printf '%s  s6-%s.tar.gz\n'            "$S6_SHA"       "$S6_VER"
        printf '%s  s6-rc-%s.tar.gz\n'         "$S6RC_SHA"     "$RC_VER"
        printf '%s  s6-linux-init-%s.tar.gz\n' "$S6INIT_SHA"   "$INIT_VER"
    } > "${FAKE}/sources.lock"

    if [[ "$hm_archive" != "-" ]]; then
        cp "$hm_archive" "${FAKE}/sources/${TAG}.tar.gz"
    fi
    case "$hm_lock" in
        none) ;;
        auto) printf '%s  %s.tar.gz\n' \
                  "$(sha256sum "${FAKE}/sources/${TAG}.tar.gz" | cut -d' ' -f1)" \
                  "$TAG" >> "${FAKE}/sources.lock" ;;
        *)    printf '%s  %s.tar.gz\n' "$hm_lock" "$TAG" >> "${FAKE}/sources.lock" ;;
    esac
}

# run [--strict] [--offline]
# Uses the FIX_* inputs, which cases reassign and then restore.
FIX_SIGNERS="${TMP}/keys/allowed_signers"
FIX_FPR="$GOOD_FPR"
FIX_SKARNET="$SKARNET"
FIX_PATH="$PATH"

run() {
    # A local path is a real git remote: the fetch and signature are genuine.
    env PATH="$FIX_PATH" \
        KRYPTIK_ROOT="$FAKE" \
        KRYPTIK_PROVENANCE_SELFTEST=1 \
        KRYPTIK_HM_REMOTE="$FIXREPO" \
        KRYPTIK_HM_SIGNERS="$FIX_SIGNERS" \
        KRYPTIK_HM_FPR="$FIX_FPR" \
        KRYPTIK_SKARNET_BASE="$FIX_SKARNET" \
        NO_COLOR=1 \
        bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

# set_tag <tag>: the tool takes its tag from V_HARDENED_MALLOC.
set_tag() {
    sed -i "s/^V_HARDENED_MALLOC=.*/V_HARDENED_MALLOC=$1/" \
        "${FAKE}/build/config/versions.env"
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

echo "tools/verify-provenance.sh"
echo

# --- positive controls ------------------------------------------------------

build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_pass "valid authenticated source passes --strict" \
    "reproduces the tree of the"

build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_pass "valid authenticated source names the pinned signer" \
    "signed by the pinned ${PRINCIPAL} key"

build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_pass "publisher checksums agree with the lock" \
    "publisher sha256 agrees with sources.lock"

build_root "${ARCHIVES}/authentic.tar.gz" auto
run
expect_pass "informational run reports no unestablished assertions" \
    "No provenance failures"

# --- tree binding -----------------------------------------------------------

build_root "${ARCHIVES}/altered.tar.gz" auto
run --strict
expect_fail "altered contents are rejected despite a valid tag and lock" \
    "IS NOT THE SIGNED TREE"

build_root "${ARCHIVES}/altered.tar.gz" auto
run --strict
if grep -qF "matches sources.lock" "$OUT" && grep -qF "IS NOT THE SIGNED TREE" "$OUT"; then
    green "lockfile integrity and tree authenticity are reported separately"
else
    red "altered archive: the two assertions were not distinguished"; show
fi

build_root "${ARCHIVES}/twotop.tar.gz" auto
run --strict
expect_fail "an archive without a single top-level directory is rejected" \
    "does not contain exactly one"

# --- signer identity --------------------------------------------------------

build_root "${ARCHIVES}/authentic.tar.gz" auto
set_tag "${TAG}-impostor"
run --strict
expect_fail "a tag signed by the wrong key is rejected" \
    "is not signed by the pinned"

# Both keys are allowed for the principal; only the fingerprint pin rejects this.
build_root "${ARCHIVES}/authentic.tar.gz" auto
set_tag "${TAG}-impostor"
FIX_SIGNERS="${TMP}/keys/both_signers"
run --strict
expect_fail "a valid signature by a non-pinned key is rejected" \
    "with the WRONG key"
FIX_SIGNERS="${TMP}/keys/allowed_signers"

build_root "${ARCHIVES}/authentic.tar.gz" auto
set_tag "${TAG}-unsigned"
run --strict
expect_fail "an unsigned annotated tag is rejected" \
    "carries no signature at all"

build_root "${ARCHIVES}/authentic.tar.gz" auto
set_tag "${TAG}-light"
run --strict
expect_fail "a lightweight tag is rejected" \
    "is not an annotated tag object"

build_root "${ARCHIVES}/authentic.tar.gz" auto
set_tag "99-nonexistent"
run --strict
expect_fail "an unresolvable tag fails --strict rather than skipping" \
    "could not fetch"

# --- lockfile integrity -----------------------------------------------------

build_root "${ARCHIVES}/authentic.tar.gz" \
    0000000000000000000000000000000000000000000000000000000000000000
run --strict
expect_fail "an archive that does not match sources.lock is rejected" \
    "does not match sources.lock"

build_root "${ARCHIVES}/authentic.tar.gz" none
run --strict
expect_fail "an archive with no lock entry is rejected" \
    "has no entry in sources.lock"

# Locked but not downloaded.
build_root - none
printf '%s  %s.tar.gz\n' "$(sha256sum "${ARCHIVES}/authentic.tar.gz" | cut -d' ' -f1)" \
    "$TAG" >> "${FAKE}/sources.lock"
run --strict
expect_fail "an undownloaded allocator archive fails --strict" \
    "is not downloaded"

build_root - none
printf '%s  %s.tar.gz\n' "$(sha256sum "${ARCHIVES}/authentic.tar.gz" | cut -d' ' -f1)" \
    "$TAG" >> "${FAKE}/sources.lock"
run
expect_pass "an undownloaded archive is a warning informationally" \
    "--strict fails here"

# --- publisher checksums ----------------------------------------------------

rm -f "${SERVE}/s6/s6-${S6_VER}.tar.gz.sha256"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_fail "a publisher that no longer publishes a .sha256 fails --strict" \
    "no longer publishes a .sha256"

build_root "${ARCHIVES}/authentic.tar.gz" auto
run
expect_pass "a missing publisher .sha256 is a warning informationally" \
    "--strict fails here"

printf '%s  s6-%s.tar.gz\n' "$S6_SHA" "$S6_VER" \
    > "${SERVE}/s6/s6-${S6_VER}.tar.gz.sha256"

printf '<html>500</html>\n' > "${SERVE}/s6-rc/s6-rc-${RC_VER}.tar.gz.sha256"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run
expect_fail "a .sha256 that is not a digest is a failure, not a skip" \
    "is not a sha256 digest"
printf '%s  s6-rc-%s.tar.gz\n' "$S6RC_SHA" "$RC_VER" \
    > "${SERVE}/s6-rc/s6-rc-${RC_VER}.tar.gz.sha256"

printf '%s  execline-%s.tar.gz\n' \
    0000000000000000000000000000000000000000000000000000000000000000 "$E_VER" \
    > "${SERVE}/execline/execline-${E_VER}.tar.gz.sha256"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run
expect_fail "a publisher checksum that disagrees with the lock is a failure" \
    "PUBLISHER CHECKSUM MISMATCH"
printf '%s  execline-%s.tar.gz\n' "$EXECLINE_SHA" "$E_VER" \
    > "${SERVE}/execline/execline-${E_VER}.tar.gz.sha256"

FIX_SKARNET="$DEAD_SKARNET"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_fail "an unreachable publisher fails --strict" \
    "could not fetch"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run
expect_pass "an unreachable publisher is a warning informationally" \
    "--strict fails here"
FIX_SKARNET="$SKARNET"

# The download is altered while the publisher still agrees with the lock.
build_root "${ARCHIVES}/authentic.tar.gz" auto
printf 'substituted\n' >> "${FAKE}/sources/skalibs-${S_VER}.tar.gz"
run
expect_fail "a tampered download is caught by lockfile integrity alone" \
    "skalibs-${S_VER}.tar.gz does not match sources.lock"

# --- missing prerequisites --------------------------------------------------

# mkbin <dir> [tool...]: a PATH directory of the usual tools minus those named.
mkbin() {
    local dir="$1"; shift
    mkdir -p "$dir"
    local t p
    for t in bash env curl tar gzip sha256sum awk sed grep head tail cut tr \
             mkdir rm mv cp cat ls find sort wc dirname basename chmod \
             mktemp date sleep seq python3 git ssh-keygen id uname od; do
        for p in "$@"; do [[ "$t" == "$p" ]] && continue 2; done
        local src; src="$(command -v "$t" 2>/dev/null)" || continue
        ln -sf "$src" "${dir}/${t}"
    done
}

mkbin "${TMP}/bin-full"
mkbin "${TMP}/bin-nogit" git
mkbin "${TMP}/bin-nossh" ssh-keygen

# Control: the pruned PATH alone must not break a good run.
FIX_PATH="${TMP}/bin-full"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_pass "the pruned-PATH harness still passes with every tool present" \
    "reproduces the tree of the"

FIX_PATH="${TMP}/bin-nogit"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_fail "missing git fails --strict rather than skipping" "missing git"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run
expect_pass "missing git is a warning informationally" "--strict fails here"

FIX_PATH="${TMP}/bin-nossh"
build_root "${ARCHIVES}/authentic.tar.gz" auto
run --strict
expect_fail "missing ssh-keygen fails --strict rather than skipping" \
    "ssh-keygen"
FIX_PATH="$PATH"

# --- --offline --------------------------------------------------------------

build_root "${ARCHIVES}/authentic.tar.gz" auto
run --offline --strict
expect_fail "--offline fails --strict" "will not pass provenance"

build_root "${ARCHIVES}/authentic.tar.gz" auto
run --offline
expect_pass "--offline reports informationally" "--strict fails here"

# --- --report ---------------------------------------------------------------

# provenance-inventory.sh joins rows on the names fetch-sources.sh --list
# prints; a row keyed by a display label would silently drop out.
build_root "${ARCHIVES}/authentic.tar.gz" auto
REPORT="${TMP}/report.tsv"
KRYPTIK_ROOT="$FAKE" \
KRYPTIK_PROVENANCE_SELFTEST=1 \
KRYPTIK_HM_REMOTE="$FIXREPO" \
KRYPTIK_HM_SIGNERS="$FIX_SIGNERS" \
KRYPTIK_HM_FPR="$FIX_FPR" \
KRYPTIK_SKARNET_BASE="$FIX_SKARNET" \
NO_COLOR=1 bash "$TOOL" --report="$REPORT" > "$OUT" 2>&1
rc=$?

missing=""
for name in hardened-malloc skalibs execline s6 s6-rc s6-linux-init; do
    cut -f1 "$REPORT" | grep -qx "$name" || missing="${missing} ${name}"
done
if [[ -z "$missing" && "$rc" -eq 0 ]]; then
    green "--report keys every row by its manifest name"
else
    red "--report rows missing for:${missing:- (none)} (exit ${rc})"
    sed 's/^/        /' "$REPORT"
fi

if cut -f1 "$REPORT" | grep -q ' '; then
    red "--report contains a key with a space, i.e. a display label"
    cut -f1 "$REPORT" | grep ' ' | sed 's/^/        /'
else
    green "--report contains no display labels as keys"
fi

# awk, not grep -E: \t in an ERE is a literal t, not a tab.
if awk -F'\t' '$1=="hardened-malloc" && $2=="tree:established"{found=1}
               END{exit !found}' "$REPORT"; then
    green "--report records the tree assertion as established"
else
    red "--report lacks hardened-malloc tree:established"
    sed 's/^/        /' "$REPORT"
fi

# --- selftest hook ----------------------------------------------------------

build_root "${ARCHIVES}/authentic.tar.gz" auto
KRYPTIK_ROOT="$FAKE" KRYPTIK_HM_REMOTE="$FIXREPO" NO_COLOR=1 \
    bash "$TOOL" --strict > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to verify provenance" "$OUT"; then
    green "substituted inputs are refused without the selftest flag"
else
    red "substituted inputs were accepted without KRYPTIK_PROVENANCE_SELFTEST"; show
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
