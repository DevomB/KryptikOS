#!/usr/bin/env bash
# Focused tests for tools/check-source-currency.sh.
#
#   ./tools/test-check-source-currency.sh
#
# Deterministic and offline. Upstream directory listings and a GitHub API
# response are served from a throwaway http.server on 127.0.0.1, laid out under
# the same paths the real hosts use, and the tool's host-rewriting hook points
# it there — so the parsing, the version ordering and the per-host strategies
# all run for real.
#
# The cases that matter are the ones where a naive implementation produces a
# CONFIDENTLY WRONG number rather than no number:
#
#   * Perl's odd minor versions are development releases, so 5.45.2 must not
#     beat the stable 5.44.0;
#   * a release candidate is not a release;
#   * a versioned subdirectory only ever offers its own series, so looking only
#     in the file's own directory reports a pin as current when a whole newer
#     series exists;
#   * the kernel has a real support-status check and must not get a version
#     verdict here at all;
#   * a listing that yields nothing is UNKNOWN, never "current".

set -uo pipefail

# See the same note in the other suites.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/check-source-currency.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
SRV_PID=""
cleanup() { [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
show() { sed 's/^/        /' "$OUT"; }

SERVE="${W}/serve"
FAKE="${W}/root"

# --- fixture listings -------------------------------------------------------
#
# Apache-style index pages, which is what these hosts actually serve.

page() {  # page <path> <entries...>
    local path="$1"; shift
    mkdir -p "${SERVE}/${path}"
    {
        printf '<html><head><title>Index</title></head><body><pre>\n'
        local e
        for e in "$@"; do printf '<a href="%s">%s</a>\n' "$e" "$e"; done
        printf '</pre></body></html>\n'
    } > "${SERVE}/${path}/index.html"
}

# GNU: a package directory with a release candidate that must be ignored.
page "ftp.gnu.org/gnu/grub" \
    "grub-2.06.tar.xz" "grub-2.12.tar.xz" "grub-2.14.tar.xz" "grub-2.15rc1.tar.xz"

# GNU, unchanged: pinned is already the newest.
page "ftp.gnu.org/gnu/tar" "tar-1.34.tar.xz" "tar-1.35.tar.xz"

# GNU with nothing parseable: must be UNKNOWN, not "current".
page "ftp.gnu.org/gnu/mystery" "README" "index.txt"

# kernel.org with versioned subdirectories. The pin points into v2.40, and
# v2.42 exists: looking only in v2.40 would report 2.40.4 and call the pin
# nearly current.
page "www.kernel.org/pub/linux/utils/util-linux" "v2.40/" "v2.41/" "v2.42/"
page "www.kernel.org/pub/linux/utils/util-linux/v2.40" \
    "util-linux-2.40.2.tar.xz" "util-linux-2.40.4.tar.xz"
page "www.kernel.org/pub/linux/utils/util-linux/v2.42" \
    "util-linux-2.42.1.tar.xz" "util-linux-2.42.3.tar.xz"

# skarnet.
page "skarnet.org/software/s6" "s6-2.15.1.0.tar.gz" "s6-2.15.0.0.tar.gz"

# python.org: only the pinned series is relevant, and a 3.13 exists.
page "www.python.org/ftp/python" "3.12.5/" "3.12.14/" "3.13.2/"

# cpan: 5.45.x is a DEVELOPMENT series and must lose to 5.44.0.
page "www.cpan.org/src/5.0" \
    "perl-5.40.0.tar.xz" "perl-5.44.0.tar.xz" "perl-5.45.2.tar.xz"

# GitHub: the project's own latest-release designation.
mkdir -p "${SERVE}/api.github.com/repos/madler/zlib/releases/latest"
printf '{"tag_name": "v1.3.2", "prerelease": false}\n' \
    > "${SERVE}/api.github.com/repos/madler/zlib/releases/latest/index.html"

# A GitHub repo whose latest release is a prerelease: not a release.
mkdir -p "${SERVE}/api.github.com/repos/acme/preview/releases/latest"
printf '{"tag_name": "v9.9.9", "prerelease": true}\n' \
    > "${SERVE}/api.github.com/repos/acme/preview/releases/latest/index.html"

# --- fixture server ---------------------------------------------------------

python3 - "$SERVE" "${W}/port" >/dev/null 2>&1 <<'PY' &
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
for _ in $(seq 1 50); do [[ -s "${W}/port" ]] && break; sleep 0.1; done
PORT="$(cat "${W}/port" 2>/dev/null)"
[[ -n "$PORT" ]] || { echo "fixture server did not start"; exit 1; }
BASE="http://127.0.0.1:${PORT}"

# --- fixture manifest -------------------------------------------------------

build_root() {
    rm -rf "$FAKE"
    mkdir -p "${FAKE}/build/config" "${FAKE}/tools"
    cat > "${FAKE}/build/config/versions.env" <<'EOF'
V_PYTHON=3.12.5
V_OPENSSL=3.3.1
EOF
    cat > "${FAKE}/tools/fetch-sources.sh" <<'STUB'
#!/usr/bin/env bash
# Test stub: the same three columns as `fetch-sources.sh --list`.
cat <<'ROWS'
grub         2.12       https://ftpmirror.gnu.org/gnu/grub/grub-2.12.tar.xz
tar          1.35       https://ftpmirror.gnu.org/gnu/tar/tar-1.35.tar.xz
mystery      1.0        https://ftpmirror.gnu.org/gnu/mystery/mystery-1.0.tar.xz
util-linux   2.40.2     https://www.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-2.40.2.tar.xz
s6           2.15.1.0   https://skarnet.org/software/s6/s6-2.15.1.0.tar.gz
python       3.12.5     https://www.python.org/ftp/python/3.12.5/Python-3.12.5.tar.xz
perl         5.40.0     https://www.cpan.org/src/5.0/perl-5.40.0.tar.xz
zlib         1.3.1      https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
preview      1.0        https://github.com/acme/preview/releases/download/v1.0/preview-1.0.tar.gz
linux        6.18.50    https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.50.tar.xz
ROWS
STUB
    chmod 755 "${FAKE}/tools/fetch-sources.sh"
}

run() {
    KRYPTIK_ROOT="$FAKE" \
    KRYPTIK_CURRENCY_SELFTEST=1 \
    KRYPTIK_CURRENCY_BASE="$BASE" \
    GH_TOKEN="" \
    NO_COLOR=1 \
    bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

# field <source> <n>  -> the nth tab-separated field of that TSV row
field() { awk -F'\t' -v s="$1" -v n="$2" '$1==s{print $n; exit}' "$OUT"; }

expect_row() {
    local src="$1" newest="$2" status="$3"
    local gotv gots
    gotv="$(field "$src" 3)"
    gots="$(field "$src" 4)"
    if [[ "$gotv" == "$newest" && "$gots" == "$status" ]]; then
        green "${src}: ${newest:-<none>} / ${status}"
    else
        red "${src}: expected [${newest:-<none>} / ${status}], got [${gotv:-<none>} / ${gots:-<none>}]"
    fi
}

echo "tools/check-source-currency.sh"
echo

build_root
run --tsv

# --- positive controls ------------------------------------------------------

expect_row tar 1.35 current
expect_row s6 2.15.1.0 current

# --- the traps --------------------------------------------------------------

expect_row grub 2.14 BEHIND          # 2.15rc1 must be ignored
expect_row perl 5.44.0 BEHIND        # 5.45.2 is a development series
expect_row python 3.12.14 BEHIND     # within the pinned series, not 3.13.2
expect_row util-linux 2.42.3 BEHIND  # the newer SERIES directory, not v2.40
expect_row zlib 1.3.2 BEHIND
expect_row preview "" UNKNOWN        # a prerelease is not a release
expect_row mystery "" UNKNOWN        # nothing parsed is not "current"
expect_row linux "" deferred         # support status, not version

if [[ "$(field linux 5)" == *check-kernel-eol* ]]; then
    green "the kernel row names the tool that does answer the question"
else
    red "the kernel row does not point at check-kernel-eol.sh: $(field linux 5)"
fi

# --- exit status ------------------------------------------------------------

run
if [[ "$RC" -eq 0 ]]; then
    green "the default run is informational and exits 0 despite BEHIND rows"
else
    red "the default run exited ${RC}"; show
fi

if grep -qF "not automatically a defect" "$OUT"; then
    green "the report says that being behind is not automatically a defect"
else
    red "the report does not qualify what BEHIND means"; show
fi

run --fail-on-behind
if [[ "$RC" -ne 0 ]] && grep -qF "behind upstream" "$OUT"; then
    green "--fail-on-behind turns it into a gate"
else
    red "--fail-on-behind did not fail (exit ${RC})"; show
fi

run --strict
if [[ "$RC" -ne 0 ]] && grep -qF "could not be determined" "$OUT"; then
    green "--strict also refuses a run containing UNKNOWN rows"
else
    red "--strict did not refuse UNKNOWN rows (exit ${RC})"; show
fi

# UNKNOWN must be reported, not folded into anything else.
run
if grep -qE "^warn UNKNOWN: +2" "$OUT" \
   || grep -qE "UNKNOWN: +2" "$OUT"; then
    green "UNKNOWN rows are counted separately"
else
    red "UNKNOWN rows were not counted separately"; show
fi

# --- the selftest hook cannot be used by accident ---------------------------

KRYPTIK_ROOT="$FAKE" KRYPTIK_CURRENCY_BASE="$BASE" NO_COLOR=1 \
    bash "$TOOL" --tsv > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to compare" "$OUT"; then
    green "a substituted upstream is refused without the selftest flag"
else
    red "a substituted upstream was accepted without the flag (exit ${rc})"; show
fi

# --- one unreachable host must not take the report down ---------------------
#
# This is a regression test: curl's exit 22 used to propagate out of a command
# substitution into common.sh's ERR trap and abort the whole run.

KRYPTIK_ROOT="$FAKE" KRYPTIK_CURRENCY_SELFTEST=1 \
    KRYPTIK_CURRENCY_BASE="http://127.0.0.1:1" NO_COLOR=1 \
    bash "$TOOL" --tsv > "$OUT" 2>&1
rows="$(grep -c . "$OUT" || true)"
if [[ "$rows" -ge 10 ]] && ! grep -qF "aborted at" "$OUT"; then
    green "an unreachable upstream yields UNKNOWN rows, not an aborted run"
else
    red "an unreachable upstream aborted the run (${rows} rows)"; show
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
