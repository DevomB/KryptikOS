#!/usr/bin/env bash
# Tests for tools/check-source-currency.sh, offline: fixtures are served on 127.0.0.1 at the real paths.

set -uo pipefail

# common.sh prefers these to paths under KRYPTIK_ROOT; an exported one would point at the real tree.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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

# Apache-style index pages, as the real hosts serve.
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

# kernel.org series subdirectories: the pin is in v2.40, and v2.42 exists.
page "www.kernel.org/pub/linux/utils/util-linux" "v2.40/" "v2.41/" "v2.42/"
page "www.kernel.org/pub/linux/utils/util-linux/v2.40" \
    "util-linux-2.40.2.tar.xz" "util-linux-2.40.4.tar.xz"
page "www.kernel.org/pub/linux/utils/util-linux/v2.42" \
    "util-linux-2.42.1.tar.xz" "util-linux-2.42.3.tar.xz"

# skarnet: four-part versions.
page "skarnet.org/software/s6" "s6-2.15.1.0.tar.gz" "s6-2.15.0.0.tar.gz"

# python.org: only the pinned series is relevant, and a 3.13 exists.
page "www.python.org/ftp/python" "3.12.5/" "3.12.14/" "3.13.2/"

# cpan: 5.45.x is a development series and must lose to 5.44.0.
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

# --- hosts with an API or a page instead of a listing -----------------------

# json PATH BODY: an API answer; the server ignores the query and decodes %2F into a directory.
json() { mkdir -p "${SERVE}/$1"; printf '%s\n' "$2" > "${SERVE}/$1/index.html"; }

# freedesktop: listed by date, and a release candidate looks like 1.32.901.
json "gitlab.freedesktop.org/api/v4/projects/libinput/libinput/releases" \
    '[{"name":"libinput 1.30.4","tag_name":"1.30.4"},{"name":"libinput 1.32.901","tag_name":"1.32.901"},{"name":"libinput 1.32.0","tag_name":"1.32.0"},{"name":"libinput 1.31.3","tag_name":"1.31.3"}]'
json "gitlab.freedesktop.org/api/v4/projects/wayland/wayland/releases" \
    '[{"name":"1.26.91","tag_name":"1.26.91"},{"name":"1.26.0","tag_name":"1.26.0"},{"name":"1.25.0","tag_name":"1.25.0"}]'

# wlroots: tags, pinned series only; "author_name" is not a tag name.
json "gitlab.freedesktop.org/api/v4/projects/wlroots/wlroots/repository/tags" \
    '[{"name":"0.20.2","commit":{"author_name":"9.9.9"}},{"name":"0.19.3","commit":{"author_name":"x"}},{"name":"0.19.2","commit":{"author_name":"x"}},{"name":"0.19.0-rc1","commit":{"author_name":"x"}}]'

# Forgejo tags with a leading v and pre-release spellings that have letters.
json "codeberg.org/api/v1/repos/dwl/dwl/tags" \
    '[{"name":"v0.9-dev","id":"a"},{"name":"v0.8","id":"b"},{"name":"v0.8-rc1","id":"c"},{"name":"v0.7","id":"d"}]'

# less: the newer tarball is a beta; the front page names the general release.
mkdir -p "${SERVE}/www.greenwoodsoftware.com/less"
printf '%s\n' '<p>less-718 has been released for beta testing.</p>' \
    '<p>less-710 has been released for general use.</p>' \
    '<a href="less-718.tar.gz">less-718.tar.gz</a> <a href="less-710.tar.gz">less-710.tar.gz</a>' \
    > "${SERVE}/www.greenwoodsoftware.com/less/index.html"

# lynx: development snapshots beside the release.
page "invisible-mirror.net/archives/lynx/tarballs" \
    "lynx2.9.3.tar.gz" "lynx2.9.3dev.4.tar.gz" "lynx2.9.4dev.2.tar.gz"

# openssh: the portable suffix is part of the version.
page "ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable" \
    "openssh-10.4p1.tar.gz" "openssh-10.5p1.tar.gz" "openssh-10.5p1.tar.gz.asc"

# openssl: the pinned major line only; 4.0.0 is a new major.
page "openssl-library.org/source" \
    "openssl-3.3.1.tar.gz" "openssl-3.6.2.tar.gz" "openssl-4.0.0.tar.gz"

# glibc's release branch, read by git over HTTP from a plain info/refs, past the patch set's commit.
refs() { mkdir -p "${SERVE}/sourceware.org/git/glibc.git/info"; printf '%s\trefs/heads/release/2.40/master\n' "$1" > "${SERVE}/sourceware.org/git/glibc.git/info/refs"; }
refs 1111111111111111111111111111111111111111

# A tags feed for a project that publishes no releases.
mkdir -p "${SERVE}/github.com/a13xp0p0v/kernel-hardening-checker"
printf '%s\n' '<feed><title>Tags from kernel-hardening-checker</title>' \
    '<entry><title>v0.6.17.1</title></entry><entry><title>v0.6.10</title></entry></feed>' \
    > "${SERVE}/github.com/a13xp0p0v/kernel-hardening-checker/tags.atom"

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
V_GLIBC=2.40
EOF
    mkdir -p "${FAKE}/build/patches/glibc-2.40"
    : > "${FAKE}/build/patches/glibc-2.40/0001-release-2.40-master-cdaa5d6db08e.patch"
    # The real rules, so the fixtures answer at the hosts and paths they name.
    cp "${ROOT}/tools/currency-rules.tsv" "${FAKE}/tools/"
    cat > "${FAKE}/tools/fetch-sources.sh" <<'STUB'
#!/usr/bin/env bash
# Test stub: the same columns as `fetch-sources.sh --list`.
cat <<'ROWS'
grub         2.12       https://ftpmirror.gnu.org/gnu/grub/grub-2.12.tar.xz gnu gnu
tar          1.35       https://ftpmirror.gnu.org/gnu/tar/tar-1.35.tar.xz gnu gnu
mystery      1.0        https://ftpmirror.gnu.org/gnu/mystery/mystery-1.0.tar.xz gnu gnu
util-linux   2.40.2     https://www.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-2.40.2.tar.xz kernel vdir
s6           2.15.1.0   https://skarnet.org/software/s6/s6-2.15.1.0.tar.gz sha256 listing
python       3.12.5     https://www.python.org/ftp/python/3.12.5/Python-3.12.5.tar.xz probe rule
perl         5.40.0     https://www.cpan.org/src/5.0/perl-5.40.0.tar.xz probe rule
zlib         1.3.1      https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz probe github
preview      1.0        https://github.com/acme/preview/releases/download/v1.0/preview-1.0.tar.gz probe github
linux        6.18.50    https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.50.tar.xz kernel eol
libinput     1.30.4     https://gitlab.freedesktop.org/libinput/libinput/-/archive/1.30.4/libinput-1.30.4.tar.gz probe rule
wayland      1.26.0     https://gitlab.freedesktop.org/wayland/wayland/-/releases/1.26.0/downloads/wayland-1.26.0.tar.xz probe rule
wlroots      0.19.3     https://gitlab.freedesktop.org/wlroots/wlroots/-/releases/0.19.3/downloads/wlroots-0.19.3.tar.gz probe rule
dwl          0.8        https://codeberg.org/dwl/dwl/releases/download/v0.8/dwl-v0.8.tar.gz probe rule
less         661        https://www.greenwoodsoftware.com/less/less-661.tar.gz probe rule
lynx         2.9.3      https://invisible-mirror.net/archives/lynx/tarballs/lynx2.9.3.tar.gz probe rule
openssh      10.5p1     https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.5p1.tar.gz probe rule
kernel-hardening-checker 0.6.17.1 https://github.com/a13xp0p0v/kernel-hardening-checker/archive/refs/tags/v0.6.17.1.tar.gz probe rule
glibc-fhs-patch 2.40    https://www.linuxfromscratch.org/patches/lfs/12.2/glibc-2.40-fhs-1.patch none follows:glibc
openssl      3.3.1      https://www.openssl.org/source/openssl-3.3.1.tar.gz probe rule
oddity       1.0        https://example.invalid/oddity/oddity-1.0.tar.gz probe telepathy
norule       1.0        https://example.invalid/norule/norule-1.0.tar.gz probe rule
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

# Hosts read through an API or a page.
expect_row libinput 1.32.0 BEHIND    # 1.32.901 is a release candidate; the list is by date
expect_row wayland 1.26.0 current    # 1.26.91 is a release candidate
expect_row wlroots 0.19.3 current    # the pinned series; 0.20.2 is not a drop-in; author_name is not a tag
expect_row dwl 0.8 current           # v0.9-dev and v0.8-rc1 are not releases
expect_row less 710 BEHIND           # 718 is a beta, whatever the directory offers
expect_row lynx 2.9.3 current        # 2.9.4dev.2 is a snapshot
expect_row openssh 10.5p1 current    # the portable suffix is part of the version
expect_row kernel-hardening-checker 0.6.17.1 current   # tags only, no releases
expect_row glibc-fhs-patch "" deferred                 # follows the glibc pin
expect_row glibc-branch 111111111111 BEHIND            # the branch moved past the patch set's commit
expect_row openssl 3.6.2 BEHIND      # the pinned major line, not 4.0.0

# A row the script cannot look up is UNKNOWN, never skipped.
expect_row oddity "" UNKNOWN         # a way to look that the script does not know
expect_row norule "" UNKNOWN         # a rule the rules file does not have

if [[ "$(field linux 5)" == *check-kernel-eol* ]]; then
    green "the kernel row points at check-kernel-eol.sh"
else
    red "the kernel row does not point at check-kernel-eol.sh: $(field linux 5)"
fi

# The branch head at the patch set's commit is current; no answer is UNKNOWN.
refs cdaa5d6db08ee6d7cdcb008ae83b6fe7856291c4
run --tsv --only=glibc-branch
expect_row glibc-branch cdaa5d6db08e current
rm "${SERVE}/sourceware.org/git/glibc.git/info/refs"
run --tsv --only=glibc-branch
expect_row glibc-branch "" UNKNOWN
refs 1111111111111111111111111111111111111111

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

run
if grep -qE "UNKNOWN: +4" "$OUT"; then
    green "UNKNOWN rows are counted separately"
else
    red "UNKNOWN rows were not counted separately"; show
fi

# --- the rules file ---------------------------------------------------------

# A rule that cannot be read fails the run: its row would only read UNKNOWN.
printf 'gawk\tlisting\thttps://ftp.gnu.org/gnu/gawk/\tgawk-[0-9.]+\\.tar\\.xz\t-\n' \
    >> "${FAKE}/tools/currency-rules.tsv"
bad="$(wc -l < "${FAKE}/tools/currency-rules.tsv")"
run --tsv
if [[ "$RC" -ne 0 ]] && grep -qF "currency-rules.tsv:${bad}: a listing's match needs a group" "$OUT"; then
    green "a listing rule with no version group is refused, by line"
else
    red "a listing rule with no version group was not refused (exit ${RC})"; show
fi

build_root
{
    printf 'gawk\tlisting\thttps://ftp.gnu.org/gnu/gawk/\tgawk-([0-9.]+)\\.tar\\.xz\tnewest\n'
    printf 'dwl\tapi\thttps://codeberg.org/api/v1/repos/dwl/dwl/tags?limit=50\tname\t-\n'
} >> "${FAKE}/tools/currency-rules.tsv"
run --tsv
if [[ "$RC" -ne 0 ]] && grep -qF "keep is -, series, major, even or drop90" "$OUT"; then
    green "an unknown keep policy is refused"
else
    red "an unknown keep policy was not refused (exit ${RC})"; show
fi
if grep -qF "a second rule for dwl" "$OUT"; then
    green "a second rule for one source is refused"
else
    red "a second rule for one source was not refused"; show
fi

build_root
rm "${FAKE}/tools/currency-rules.tsv"
run --tsv
if [[ "$RC" -ne 0 ]] && grep -qF "has nowhere to look" "$OUT"; then
    green "a missing rules file fails the run"
else
    red "a missing rules file did not fail the run (exit ${RC})"; show
fi
build_root

# --- selftest hook ----------------------------------------------------------

KRYPTIK_ROOT="$FAKE" KRYPTIK_CURRENCY_BASE="$BASE" NO_COLOR=1 \
    bash "$TOOL" --tsv > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to compare" "$OUT"; then
    green "a substituted upstream is refused without the selftest flag"
else
    red "a substituted upstream was accepted without the flag (exit ${rc})"; show
fi

# --- one unreachable host must not take the report down ---------------------

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
