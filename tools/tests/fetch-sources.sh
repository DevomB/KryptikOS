#!/usr/bin/env bash
# Tests for tools/fetch-sources.sh, offline: a manifest of file:// URLs, fetched by the real curl.

set -uo pipefail

# common.sh prefers these, when exported, to paths derived from KRYPTIK_ROOT.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/tools/fetch-sources.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in curl sha256sum sort; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }

UPSTREAM="${W}/upstream"      # what the "mirror" serves
FAKE="${W}/root"              # KRYPTIK_ROOT for the run
mkdir -p "$UPSTREAM"

# About 4KB each, so the 1500-byte partials below are shorter than the file.
for f in alpha-1.0 beta-2.0 gamma-3.0; do
    { printf 'upstream payload for %s\n' "$f"
      head -c 4096 /dev/urandom | base64 | head -c 4000
      printf '\n'; } > "${UPSTREAM}/${f}.tar.gz"
done

MANIFEST="${W}/manifest"
{
    printf 'alpha|1.0|file://%s/alpha-1.0.tar.gz|probe|listing\n' "$UPSTREAM"
    printf 'beta|2.0|file://%s/beta-2.0.tar.gz|probe|listing\n'   "$UPSTREAM"
    printf 'gamma|3.0|file://%s/gamma-3.0.tar.gz|probe|listing\n' "$UPSTREAM"
} > "$MANIFEST"

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

# build_root NAME-VER:good|bad|absent...: a lock entry per spec, none for absent.
build_root() {
    rm -rf "$FAKE"
    mkdir -p "${FAKE}/build/config" "${FAKE}/sources"
    : > "${FAKE}/build/config/versions.env"
    : > "${FAKE}/sources.lock"
    local spec f kind
    for spec in "$@"; do
        f="${spec%%:*}"; kind="${spec##*:}"
        case "$kind" in
            good) printf '%s  %s.tar.gz\n' "$(sha_of "${UPSTREAM}/${f}.tar.gz")" "$f" \
                      >> "${FAKE}/sources.lock" ;;
            bad)  printf '%s  %s.tar.gz\n' \
                      0000000000000000000000000000000000000000000000000000000000000000 \
                      "$f" >> "${FAKE}/sources.lock" ;;
            absent) : ;;
        esac
    done
}

# Pre-place a downloaded copy in sources/, optionally tampered.
place() {  # place <name-ver> [tampered]
    cp "${UPSTREAM}/$1.tar.gz" "${FAKE}/sources/$1.tar.gz"
    [[ "${2:-}" == tampered ]] && printf 'tampered\n' >> "${FAKE}/sources/$1.tar.gz"
    return 0
}

run() {
    KRYPTIK_ROOT="$FAKE" \
    KRYPTIK_FETCH_SELFTEST=1 \
    KRYPTIK_FETCH_MANIFEST="$MANIFEST" \
    NO_COLOR=1 \
    bash "$TOOL" "$@" > "$OUT" 2>&1
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

echo "tools/fetch-sources.sh"
echo

# --- positive controls ------------------------------------------------------

build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place alpha-1.0; place beta-2.0; place gamma-3.0
run
expect_pass "an already-downloaded, matching set verifies" "3 package(s) verified"

# Nothing on disk: it must fetch, then verify what it fetched.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
run
expect_pass "an empty sources/ is downloaded and then verified" "3 downloaded"
if [[ -f "${FAKE}/sources/alpha-1.0.tar.gz" ]]; then
    green "the downloaded file is left in sources/"
else
    red "the download did not land in sources/"
fi

run
expect_pass "a second run uses the cached copies" "3 cached"

# A host that refuses: the file comes from the distfiles mirror, under the BLAKE2b of its name.
DIST="${W}/distfiles"
d="$(printf '%s' alpha-1.0.tar.gz | b2sum | cut -c1-2)"
mkdir -p "${DIST}/${d}" && cp "${UPSTREAM}/alpha-1.0.tar.gz" "${DIST}/${d}/"
printf 'alpha|1.0|https://127.0.0.1:9/alpha-1.0.tar.gz|probe|listing\n' > "${W}/manifest-down"
build_root alpha-1.0:good
MANIFEST="${W}/manifest-down" MIRROR_DISTFILES="file://${DIST}" run
expect_pass "a source whose host refuses comes from the distfiles mirror" "1 downloaded"
grep -qF "trying fallback mirror: file://${DIST}/${d}/alpha-1.0.tar.gz" "$OUT" \
    && green "the mirror's path is the BLAKE2b of the file's name" || { red "the mirror was asked another path"; show; }

# A host down, and no distfiles copy: the file comes from the row's own mirror (tools/source-mirrors.tsv),
# its version in place of {VER}, and the lock decides as for the first URL.
ROWM="${W}/rowmirror"
mkdir -p "$ROWM" && cp "${UPSTREAM}/alpha-1.0.tar.gz" "${ROWM}/alpha_1.0.orig.tar.gz"
printf 'alpha  file://%s/alpha_{VER}.orig.tar.gz  .asc\n' "$ROWM" > "${W}/mirrors"
build_root alpha-1.0:good
MANIFEST="${W}/manifest-down" MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors" run
expect_pass "a source whose host refuses comes from its row's mirror" "1 downloaded"
grep -qF "trying fallback mirror: file://${ROWM}/alpha_1.0.orig.tar.gz" "$OUT" \
    && green "the mirror's URL takes the manifest's version" || { red "the row's mirror was not asked, or asked another path"; show; }
printf 'other bytes\n' > "${ROWM}/alpha_1.0.orig.tar.gz"
build_root alpha-1.0:good
MANIFEST="${W}/manifest-down" MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors" run
expect_fail "a mirror's other bytes are refused by the lock" "download failed: alpha 1.0"
grep -qF "file://${ROWM}/alpha_1.0.orig.tar.gz serves other bytes than the lock's" "$OUT" \
    && green "the refusal names the place that served them" || { red "the place with other bytes was not named"; show; }
[[ ! -e "${FAKE}/sources/alpha-1.0.tar.gz" ]] && green "and its bytes are not kept" || red "the other bytes were kept"
# A row with the lock's bytes after the drifted one: the fetch passes over the first.
ROWM2="${W}/rowmirror2"
mkdir -p "$ROWM2" && cp "${UPSTREAM}/alpha-1.0.tar.gz" "${ROWM2}/alpha-1.0.tar.gz"
{ cat "${W}/mirrors"; printf 'alpha  file://%s/alpha-{VER}.tar.gz  -\n' "$ROWM2"; } > "${W}/mirrors-two"
build_root alpha-1.0:good
MANIFEST="${W}/manifest-down" MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors-two" run
expect_pass "a drifted mirror is passed over for the next place with the lock's bytes" "1 downloaded"

# --- the probe: every place asked, nothing downloaded -------------------------

# Each source at two places: its own and a mirror row's.
SECOND="${W}/second"
mkdir -p "$SECOND" && cp "${UPSTREAM}"/*.tar.gz "$SECOND/"
for n in alpha beta gamma; do printf '%s  file://%s/%s-{VER}.tar.gz  -\n' "$n" "$SECOND" "$n"; done > "${W}/mirrors-all"
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors-all" run --probe
expect_pass "--probe finds every source served at both its places" "3 source(s), each served somewhere; 0 by one place alone"
if [[ -z "$(ls -A "${FAKE}/sources")" ]]; then
    green "--probe downloads nothing"
else
    red "--probe left files in sources/: $(ls -A "${FAKE}/sources" | tr '\n' ' ')"
fi

# Its own host refuses and its row's mirror has the file: served, by one place alone.
cp "${UPSTREAM}/alpha-1.0.tar.gz" "${ROWM}/alpha_1.0.orig.tar.gz"
MANIFEST="${W}/manifest-down" MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors" run --probe
expect_pass "--probe counts a source that only its row's mirror serves" "1 source(s), each served somewhere; 1 by one place alone"
grep -qF "alpha 1.0: only file://${ROWM}/alpha_1.0.orig.tar.gz serves it; not https://127.0.0.1:9/alpha-1.0.tar.gz" "$OUT" \
    && green "--probe names the place that serves it and the one that does not" || { red "--probe did not name both places"; show; }

# No place has it: the probe fails, naming the source and every place it asked.
MANIFEST="${W}/manifest-down" MIRROR_DISTFILES="" run --probe
expect_fail "--probe fails on a source no place serves" "alpha 1.0: no place serves it (asked https://127.0.0.1:9/alpha-1.0.tar.gz)"

# A host that gives no answer at all is asked once a pass: its other places count as not serving,
# and what no place served gets a last look, every host asked afresh. Two passes, so said twice.
{ printf 'alpha|1.0|https://127.0.0.1:9/alpha-1.0.tar.gz|probe|listing\n'
  printf 'beta|2.0|https://127.0.0.1:9/beta-2.0.tar.gz|probe|listing\n'; } > "${W}/manifest-silent"
MANIFEST="${W}/manifest-silent" MIRROR_DISTFILES="" run --probe
expect_fail "--probe counts a silent host's later places as not serving" "beta 2.0: no place serves it"
if [[ "$(grep -c '127.0.0.1:9 gave no answer' "$OUT")" -eq 2 ]]; then
    green "and asks a silent host once in each pass, the last look's included, saying so"
else
    red "a silent host was not asked once a pass, or not said so: $(grep -c '127.0.0.1:9 gave no answer' "$OUT")"; show
fi
if [[ "$(grep -c 'no place serves it' "$OUT")" -eq 2 ]]; then
    green "and names each source no place served once, after the last look"
else
    red "the sources no place served were not named once each: $(grep -c 'no place serves it' "$OUT")"; show
fi

# A host that refuses HEAD, as an object store refuses a URL presigned for GET: the probe asks for
# one byte, and the last answer's status decides. Python's server ignores the range, so a file it
# has comes whole (alpha) or is stopped at the cap (big), a redirect's body comes first (moved),
# and a missing file gets a page; whatever exit the curl at hand gives for each.
NH="${W}/nohead-files"
mkdir -p "$NH" && cp "${UPSTREAM}/alpha-1.0.tar.gz" "$NH/" && head -c 204800 /dev/urandom > "${NH}/big-1.0.tar.gz"
cat > "${W}/nohead.py" <<'PY'
import functools, http.server, sys
class NoHead(http.server.SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self.send_error(405)
    def do_GET(self):
        if self.path.startswith("/moved/"):
            body = b"moved " * 400
            self.send_response(302)
            self.send_header("Location", self.path[len("/moved"):])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()
    def log_message(self, *args):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(NoHead, directory=sys.argv[1]))
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
python3 -I "${W}/nohead.py" "$NH" > "${W}/nohead.port" 2>/dev/null &
NOHEAD=$!
trap 'kill "$NOHEAD" 2>/dev/null; rm -rf "$W"' EXIT
for _ in $(seq 1 50); do [[ -s "${W}/nohead.port" ]] && break; sleep 0.1; done
port="$(head -1 "${W}/nohead.port")"
{
    printf 'alpha|1.0|http://127.0.0.1:%s/moved/alpha-1.0.tar.gz|probe|listing\n' "$port"
    printf 'big|1.0|http://127.0.0.1:%s/big-1.0.tar.gz|probe|listing\n' "$port"
    printf 'omega|9.0|http://127.0.0.1:%s/omega-9.0.tar.gz|probe|listing\n' "$port"
} > "${W}/manifest-nohead"
MANIFEST="${W}/manifest-nohead" MIRROR_DISTFILES="" run --probe
expect_fail "--probe asks a host that refuses HEAD for one byte, and a missing file fails" "omega 9.0: no place serves it"
grep -qF "alpha 1.0: only http://127.0.0.1:${port}/moved/alpha-1.0.tar.gz serves it" "$OUT" \
    && green "there, a file behind a redirect counts" || { red "--probe misread the redirect"; show; }
grep -qF "big 1.0: only http://127.0.0.1:${port}/big-1.0.tar.gz serves it" "$OUT" \
    && green "there, a whole file stopped at the cap counts" || { red "--probe misread the file sent whole"; show; }
kill "$NOHEAD" 2>/dev/null; wait "$NOHEAD" 2>/dev/null

# --- mirror rows held to the lock ---------------------------------------------

# Every row's file downloaded and compared, nothing kept.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors-all" run --check-mirrors
expect_pass "--check-mirrors holds every row to the lock" "3 mirror row(s): 3 with the lock's bytes, 0 no longer serving the pin"
if [[ -z "$(ls -A "${FAKE}/sources")" ]]; then
    green "--check-mirrors keeps nothing in sources/"
else
    red "--check-mirrors left files in sources/: $(ls -A "${FAKE}/sources" | tr '\n' ' ')"
fi

# A row serving other bytes fails; one that no longer serves the pin is a warning.
printf 'other bytes\n' > "${SECOND}/beta-2.0.tar.gz"
rm -f "${SECOND}/gamma-3.0.tar.gz"
MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors-all" run --check-mirrors
expect_fail "--check-mirrors fails a row that serves other bytes" "beta 2.0: file://${SECOND}/beta-2.0.tar.gz serves other bytes than the lock's"
grep -qF "gamma 3.0: file://${SECOND}/gamma-3.0.tar.gz does not serve it" "$OUT" \
    && green "and warns of a row that no longer serves the pin" || { red "--check-mirrors did not name the lapsed row"; show; }

# A row for no source here never applies: refused.
printf 'nosuch  file://%s/nosuch-{VER}.tar.gz  -\n' "$SECOND" > "${W}/mirrors-typo"
MIRROR_DISTFILES="" KRYPTIK_FETCH_MIRRORS="${W}/mirrors-typo" run --check-mirrors
expect_fail "--check-mirrors refuses a row for no source" "a row for nosuch, which is no source here"

# --- checksum refusal -------------------------------------------------------

build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place alpha-1.0; place beta-2.0 tampered; place gamma-3.0
run
expect_fail "a tampered download is refused" "CHECKSUM MISMATCH for beta-2.0.tar.gz"
if grep -qF "CHANGED after it was locked" "$OUT" && grep -qF "Do not" "$OUT"; then
    green "the refusal says it is refusing, and which kind of mismatch it is"
else
    red "the mismatch did not produce a refusal message"; show
fi
if grep -qF "3 package(s) verified" "$OUT"; then
    red "it reported a verified count despite the mismatch"; show
else
    green "no verified summary is printed after a mismatch"
fi

if [[ -f "${FAKE}/sources/beta-2.0.tar.gz" ]] && grep -qF "beta-2.0.tar.gz" "$OUT"; then
    green "the offending file is named and left in place for inspection"
else
    red "the offending file was removed or not named"; show
fi

build_root alpha-1.0:good beta-2.0:absent gamma-3.0:good
place alpha-1.0; place beta-2.0; place gamma-3.0
run
expect_fail "a file with no lock entry is refused" \
    "no entry for beta-2.0.tar.gz in sources.lock"

build_root alpha-1.0:absent beta-2.0:absent gamma-3.0:absent
rm -f "${FAKE}/sources.lock"
place alpha-1.0
run
expect_fail "a missing sources.lock is refused" "no entry for"

cat > "${W}/dead-manifest" <<EOF
alpha|1.0|file://${UPSTREAM}/alpha-1.0.tar.gz|probe|listing
missing|9.9|file://${UPSTREAM}/does-not-exist.tar.gz|probe|listing
EOF
build_root alpha-1.0:good
printf '%s  missing-9.9.tar.gz\n' \
    0000000000000000000000000000000000000000000000000000000000000000 \
    >> "${FAKE}/sources.lock"
KRYPTIK_ROOT="$FAKE" KRYPTIK_FETCH_SELFTEST=1 \
    KRYPTIK_FETCH_MANIFEST="${W}/dead-manifest" NO_COLOR=1 \
    bash "$TOOL" > "$OUT" 2>&1
RC=$?
expect_fail "an unfetchable source is refused" "download failed"

# --- interrupted downloads --------------------------------------------------

# Three kinds of leftover .part, which `-C -` resumes from.
part() { printf '%s' "${FAKE}/sources/$1.tar.gz.part"; }

# A genuine interruption: a prefix of the real file.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place beta-2.0; place gamma-3.0
head -c 1500 "${UPSTREAM}/alpha-1.0.tar.gz" > "$(part alpha-1.0)"
run
expect_pass "a truncated partial file is resumed and verifies" "3 package(s) verified"
if [[ ! -e "$(part alpha-1.0)" ]]; then
    green "the partial file is consumed, not left behind"
else
    red "a .part survived a successful download"
fi

# Longer than the upstream file, so the range is unsatisfiable (curl 36 on file://, 33/416 on HTTP).
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place beta-2.0; place gamma-3.0
head -c 100000 /dev/zero > "$(part alpha-1.0)"
run
expect_pass "an over-long stale partial is discarded and the fetch restarts" \
    "3 package(s) verified"
if grep -qF "discarding the partial file" "$OUT"; then
    green "the restart says why it happened rather than blaming the mirror"
else
    red "the over-long partial was handled without explanation"; show
fi
if [[ "$(sha_of "${FAKE}/sources/alpha-1.0.tar.gz")" == "$(sha_of "${UPSTREAM}/alpha-1.0.tar.gz")" ]]; then
    green "the restarted download produced the correct bytes"
else
    red "the restarted download produced wrong bytes"
fi

# A short .part of wrong bytes resumes into a corrupt file that only the lock's hash catches; the
# file is then fetched again whole.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place beta-2.0; place gamma-3.0
head -c 1500 /dev/zero > "$(part alpha-1.0)"
run
expect_pass "a poisoned partial is caught by the lock's hash and fetched again whole" "3 package(s) verified"
if grep -qF "resumed from an earlier partial file has other bytes" "$OUT" \
    && [[ "$(sha_of "${FAKE}/sources/alpha-1.0.tar.gz")" == "$(sha_of "${UPSTREAM}/alpha-1.0.tar.gz")" ]]; then
    green "the restart says why, and ends with the lock's bytes"
else
    red "the poisoned partial went unexplained, or ended with other bytes"; show
fi

# The same mismatch on a file already on disk: it changed after locking.
build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
place alpha-1.0 tampered; place beta-2.0; place gamma-3.0
run
expect_fail "a cached mismatch is diagnosed as a change after locking" \
    "CHANGED after it was locked"
if grep -qF "Do not" "$OUT" && ! grep -qF "downloaded just now" "$OUT"; then
    green "the cached mismatch does not tell them to delete it first"
else
    red "the cached mismatch used the fresh-download wording"; show
fi

if [[ -f "${FAKE}/sources/alpha-1.0.tar.gz" ]]; then
    green "the mismatching file is preserved for inspection"
else
    red "the mismatching file was deleted"
fi

# --- --lock -----------------------------------------------------------------

build_root alpha-1.0:absent
place alpha-1.0; place beta-2.0; place gamma-3.0
run --lock
expect_pass "--lock records what it downloaded" "wrote 3 entries"

if grep -qF "NOT YET AUDITED" "$OUT"; then
    green "--lock says the result is unaudited"
else
    red "--lock did not warn that the lock is unaudited"; show
fi

# The written lock must verify, and be sorted so lock diffs are readable.
run
expect_pass "the lock --lock wrote then verifies" "3 package(s) verified"

if [[ "$(cut -d' ' -f3 "${FAKE}/sources.lock")" == \
      "$(cut -d' ' -f3 "${FAKE}/sources.lock" | LC_ALL=C sort)" ]]; then
    green "the written lock is sorted by filename"
else
    red "the written lock is not sorted"
    sed 's/^/        /' "${FAKE}/sources.lock"
fi

# --lock records whatever is on disk, tampered or not.
build_root alpha-1.0:absent
place alpha-1.0 tampered; place beta-2.0; place gamma-3.0
run --lock
if [[ "$RC" -eq 0 ]] \
   && grep -qF "Lock mode: recording checksums of whatever downloads" "$OUT"; then
    green "--lock records a tampered file and says so"
else
    red "--lock did not state that it records whatever is present"; show
fi

# --- a software image's sources ---------------------------------------------

# Kept in sources/images/, the images' own cache, and named in sources/ by a link.
printf 'upstream payload for delta-4.0\n' > "${UPSTREAM}/delta-4.0.tar.gz"
IMANIFEST="${W}/image-manifest"
printf 'toolkit|delta|4.0|file://%s/delta-4.0.tar.gz|probe|listing\n' "$UPSTREAM" > "$IMANIFEST"
images_root() {
    build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
    mkdir -p "${FAKE}/build/images"
    printf '%s  delta-4.0.tar.gz\n' "$(sha_of "${UPSTREAM}/delta-4.0.tar.gz")" > "${FAKE}/build/images/sources.lock"
}
run_images() {
    KRYPTIK_ROOT="$FAKE" KRYPTIK_FETCH_SELFTEST=1 KRYPTIK_FETCH_MANIFEST="$MANIFEST" \
        KRYPTIK_FETCH_IMAGE_MANIFEST="$IMANIFEST" NO_COLOR=1 bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

images_root
run_images
expect_pass "an image's source is fetched and verified against the images' lock" "4 package(s) verified"
if [[ -f "${FAKE}/sources/images/delta-4.0.tar.gz" && ! -L "${FAKE}/sources/images/delta-4.0.tar.gz" \
      && "$(readlink "${FAKE}/sources/delta-4.0.tar.gz")" == images/delta-4.0.tar.gz ]]; then
    green "it is kept in sources/images/ and named in sources/ by a relative link"
else
    red "the image's source is not in sources/images/ behind a link"; ls -la "${FAKE}/sources" "${FAKE}/sources/images" 2>&1 | sed 's/^/        /'
fi

images_root
run_images --root
expect_pass "--root fetches the root's sources alone" "3 package(s) verified"
if [[ ! -e "${FAKE}/sources/images/delta-4.0.tar.gz" ]]; then
    green "--root leaves the images' sources alone"
else
    red "--root fetched an image's source"
fi

# --root still moves one a cache left at the top, so the root's set is saved without it.
images_root
cp "${UPSTREAM}/delta-4.0.tar.gz" "${FAKE}/sources/delta-4.0.tar.gz"
run_images --root
if [[ "$RC" -eq 0 && -L "${FAKE}/sources/delta-4.0.tar.gz" && -f "${FAKE}/sources/images/delta-4.0.tar.gz" ]]; then
    green "--root moves an image's source left at the top into sources/images/"
else
    red "--root left an image's source at the top (exit ${RC})"; show
fi

# A set cached before images/ existed has the image's file in sources/ itself.
images_root
cp "${UPSTREAM}/delta-4.0.tar.gz" "${FAKE}/sources/delta-4.0.tar.gz"
run_images
expect_pass "an image's source cached in sources/ itself still verifies" "1 cached"
if [[ -L "${FAKE}/sources/delta-4.0.tar.gz" && -f "${FAKE}/sources/images/delta-4.0.tar.gz" ]]; then
    green "it moves into sources/images/, a link left in its place"
else
    red "the image's source was not moved into sources/images/"
fi

# --- a crate's own crates ----------------------------------------------------

# The crate's hash is locked; its Cargo.lock gives the hash of each crate it builds from.
CR="${W}/crates"; mkdir -p "${CR}/dep" "${W}/tool-1.0"
printf 'dep crate\n' > "${CR}/dep/dep-0.1.0.crate"
dep_sum="$(sha_of "${CR}/dep/dep-0.1.0.crate")"
crate_with() {   # crate_with DEP-HASH: tool-1.0.crate whose Cargo.lock locks dep 0.1.0 to DEP-HASH
    printf '[[package]]\nname = "dep"\nversion = "0.1.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n\n[[package]]\nname = "tool"\nversion = "1.0"\n' "$1" > "${W}/tool-1.0/Cargo.lock"
    tar -czf "${UPSTREAM}/tool-1.0.crate" -C "$W" tool-1.0
}
CMANIFEST="${W}/crate-manifest"
printf 'tool|tool|1.0|file://%s/tool-1.0.crate|none|listing\n' "$UPSTREAM" > "$CMANIFEST"
crates_root() {
    build_root alpha-1.0:good beta-2.0:good gamma-3.0:good
    mkdir -p "${FAKE}/build/images"
    printf '%s  tool-1.0.crate\n' "$(sha_of "${UPSTREAM}/tool-1.0.crate")" > "${FAKE}/build/images/sources.lock"
}
run_crates() {
    KRYPTIK_ROOT="$FAKE" KRYPTIK_FETCH_SELFTEST=1 KRYPTIK_FETCH_MANIFEST="$MANIFEST" \
        KRYPTIK_FETCH_IMAGE_MANIFEST="$CMANIFEST" KRYPTIK_CRATES="file://${CR}" NO_COLOR=1 bash "$TOOL" > "$OUT" 2>&1
    RC=$?
}

crate_with "$dep_sum"; crates_root
run_crates
expect_pass "a crate's Cargo.lock brings the crates it names, each verified" "the 1 crates its Cargo.lock names, verified"
[[ -f "${FAKE}/sources/images/crates/dep-0.1.0.crate" ]] \
    && green "they land in sources/images/crates/" || red "the named crate is not in sources/images/crates/"

crate_with 0000000000000000000000000000000000000000000000000000000000000000; crates_root
run_crates
expect_fail "a crate whose bytes are not what the Cargo.lock says is refused" "download failed: crate dep 0.1.0"
grep -qF "file://${CR}/dep/dep-0.1.0.crate serves other bytes than the lock's" "$OUT" \
    && green "the refusal names where the crate's other bytes came from" || { red "the crate's place was not named"; show; }

KRYPTIK_ROOT="$FAKE" NO_COLOR=1 bash "$TOOL" --crates "${UPSTREAM}/tool-1.0.crate" > "$OUT" 2>&1
[[ "$(cat "$OUT")" == "dep 0.1.0 0000000000000000000000000000000000000000000000000000000000000000" ]] \
    && green "--crates prints what a crate's lock names" || { red "--crates printed something else"; show; }

if KRYPTIK_ROOT="$FAKE" KRYPTIK_CRATES="file://${CR}" NO_COLOR=1 bash "$TOOL" --list > "$OUT" 2>&1; then
    red "a crates mirror was taken without the test's manifest"
else
    grep -qF "KRYPTIK_CRATES replaces crates.io" "$OUT" && green "a crates mirror is refused outside the test" || { red "the crates mirror refusal did not say why"; show; }
fi

# --- arguments and the selftest gate ----------------------------------------

run --list
expect_pass "--list prints the manifest without downloading" "alpha"

run --nonsense
expect_fail "an unknown argument is refused" "unknown argument"

build_root alpha-1.0:good
KRYPTIK_ROOT="$FAKE" KRYPTIK_FETCH_MANIFEST="$MANIFEST" NO_COLOR=1 \
    bash "$TOOL" --list > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to fetch or lock" "$OUT"; then
    green "a substituted manifest is refused without the selftest flag"
else
    red "a substituted manifest was accepted without the flag (exit ${rc})"; show
fi

# --- the shipped manifest and the shipped lockfile must agree ---------------

# A row with no lock line is refused at fetch time; a lock line with no row is a hash nobody checks.
# The root's rows are in sources.lock, the software images' in build/images/sources.lock.
bash "$TOOL" --list > "${W}/live-manifest" 2>/dev/null
bash "$TOOL" --list-root > "${W}/root-manifest" 2>/dev/null
names() { awk '{n = $3; sub(/.*\//, "", n); print n}' "$1" | sort -u; }
names "${W}/root-manifest" > "${W}/mf-root"
comm -23 <(names "${W}/live-manifest") "${W}/mf-root" > "${W}/mf-images"
awk '{print $2}' "${ROOT}/sources.lock" | sort -u > "${W}/lk-root"
awk '{print $2}' "${ROOT}/build/images/sources.lock" | sort -u > "${W}/lk-images"

miss="$(comm -23 "${W}/mf-root" "${W}/lk-root" | tr '\n' ' ')$(comm -23 "${W}/mf-images" "${W}/lk-images" | tr '\n' ' ')"
if [[ -z "${miss// /}" ]]; then
    green "every source in the manifest has an entry in its lock"
else
    red "manifest rows with no lock entry: ${miss}"
fi

stale="$(comm -13 "${W}/mf-root" "${W}/lk-root" | tr '\n' ' ')$(comm -13 "${W}/mf-images" "${W}/lk-images" | tr '\n' ' ')"
if [[ -z "${stale// /}" ]]; then
    green "every lock entry corresponds to a manifest row of its own set"
else
    red "lock entries with no manifest row: ${stale}"
fi

# Mozilla's key is taken from the KEY file beside the pinned release; a Firefox bump that left the row
# behind would keep importing a file that never learns a later revocation.
vf="$(sed -n 's/^V_FIREFOX=//p' "${ROOT}/build/images/versions.env")"
if [[ -n "$vf" ]] && grep -Eq "^14F26682D0916CDD81E37B6D61B7B526D98F0353[[:space:]]+origin[[:space:]]+https://archive[.]mozilla[.]org/pub/firefox/releases/${vf//./[.]}esr/KEY[[:space:]]" "${ROOT}/tools/key-provenance.tsv"; then
    green "Mozilla's key row names the KEY file beside the pinned Firefox, ${vf}esr"
else
    red "tools/key-provenance.tsv's Mozilla row does not name releases/${vf:-?}esr/KEY: a Firefox bump moves it too"
fi

# The browser's Rust layer and kryptikd's compiler are one release: both locks hold the same three.
rust_shared="$(awk 'NR == FNR { if ($1 !~ /^#/ && NF == 2) want[$2] = $1; next }
                    ($2 in want) { n++; if (want[$2] != $1) bad = bad " " $2 }
                    END { print n + 0 bad }' "${ROOT}/build/config/rust.lock" "${ROOT}/build/images/sources.lock")"
if [[ "$rust_shared" == 3 ]]; then
    green "build/config/rust.lock and the images' lock hold the same Rust tarballs"
else
    red "the Rust tarballs the two locks share, and those whose hashes differ: ${rust_shared}"
fi

# An unset version leaves a field empty (a URL like gdbm-.tar.gz, a quiet 404) and the row short.
blank="$(awk 'NF != 5 {print $1}' "${W}/live-manifest" | tr '\n' ' ')"
if [[ -z "${blank// /}" ]]; then
    green "no manifest row resolves to an empty field"
else
    red "manifest rows with an empty field, such as the version: ${blank}"
fi

# --- the declared columns ---------------------------------------------------

# A value no tool knows fails there too; here it fails before it ships.
odd="$(awk '
    $4 !~ /^(gnu|kernel|sig|asc|stem\.sig|sums:[^\/]+\.(asc|sig)|probe|sha256|sha256\.txt|sha256sum|stem\.sha256sum|tag|none)$/ { print $1 " sig=" $4; next }
    $5 !~ /^(gnu|vdir|github|listing|rule|eol|follows:.+)$/ { print $1 " new=" $5 }
' "${W}/live-manifest" | tr '\n' ' ')"
if [[ -z "${odd// /}" ]]; then
    green "every row declares a sig and a new that the tools know"
else
    red "rows declaring a value no tool knows: ${odd}"
fi

# gnu, stem.sig, vdir and github work from the URL, so each needs a URL of its shape.
gnu="$(sed -n 's/^MIRROR_GNU="\(.*\)"$/\1/p' "${ROOT}/build/config/versions.env")"
misfit="$(awk -v gnu="${gnu}/" '
    ($4 == "gnu") != (index($3, gnu) == 1) { print $1 " (sig " $4 ")" }
    $5 == "gnu" && index($3, gnu) != 1 { print $1 " (new gnu)" }
    $4 == "stem.sig" && $3 !~ /\.tar\.[^\/.]+$/ { print $1 " (sig stem.sig)" }
    $5 == "vdir" && $3 !~ /\/v[0-9][^\/]*\/[^\/]+$/ { print $1 " (new vdir)" }
    $5 == "github" && $3 !~ /^https:\/\/github\.com\/[^\/]+\/[^\/]+\// { print $1 " (new github)" }
' "${W}/live-manifest" | tr '\n' ' ')"
if [[ -n "$gnu" && -z "${misfit// /}" ]]; then
    green "every gnu, stem.sig, vdir and github row has a URL of that shape"
else
    red "rows whose URL does not fit what they declare: ${misfit:-no MIRROR_GNU found}"
fi

dangling="$(awk 'NR == FNR { row[$1] = 1; next }
                 $5 ~ /^follows:/ && !(substr($5, 9) in row) { print $1 " -> " substr($5, 9) }' \
            "${W}/live-manifest" "${W}/live-manifest" | tr '\n' ' ')"
if [[ -z "${dangling// /}" ]]; then
    green "every follows: names a row of the manifest"
else
    red "rows that follow no row: ${dangling}"
fi

# A rule row reads UNKNOWN without its rule, and a rule with no such row is read by nothing.
awk '$5 == "rule" {print $1}' "${W}/live-manifest" | sort > "${W}/ruled"
grep -v -E '^[[:space:]]*(#|$)' "${ROOT}/tools/currency-rules.tsv" | cut -f1 | sort > "${W}/rules"
unruled="$(comm -23 "${W}/ruled" "${W}/rules" | tr '\n' ' ')"
if [[ -s "${W}/ruled" && -z "${unruled// /}" ]]; then
    green "every row that declares rule has one in tools/currency-rules.tsv"
else
    red "rows that declare rule with no rule: ${unruled:-none declare rule}"
fi
orphan="$(comm -13 "${W}/ruled" "${W}/rules" | tr '\n' ' ')"
if [[ -z "${orphan// /}" ]]; then
    green "every rule in tools/currency-rules.tsv belongs to a row that declares rule"
else
    red "rules no row declares: ${orphan}"
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
