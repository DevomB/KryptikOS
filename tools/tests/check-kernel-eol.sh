#!/usr/bin/env bash
# Tests for tools/check-kernel-eol.sh. Feeds come from a local http.server, and
# the pin from a throwaway KRYPTIK_ROOT, never the repository's versions.env.

set -uo pipefail

# common.sh prefers these, when exported, to paths derived from KRYPTIK_ROOT.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/check-kernel-eol.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }

TMP="$(mktemp -d)"
SERVE="${TMP}/serve"
mkdir -p "$SERVE"

SRV_PID=""
cleanup() {
    [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# Fixture feeds, shaped like https://www.kernel.org/releases.json.
write_feed() { cat > "${SERVE}/$1"; }

# Series 6.18 current and longterm; 6.12 longterm; 7.1 stable and EOL.
write_feed healthy.json <<'JSON'
{"releases": [
  {"version": "7.3-rc2",   "moniker": "mainline",   "iseol": false},
  {"version": "7.2.4",     "moniker": "stable",     "iseol": false},
  {"version": "7.1.13",    "moniker": "stable",     "iseol": true},
  {"version": "6.18.52",   "moniker": "longterm",   "iseol": false},
  {"version": "6.12.109",  "moniker": "longterm",   "iseol": false},
  {"version": "6.1.187",   "moniker": "longterm",   "iseol": false},
  {"version": "next-20260910", "moniker": "linux-next", "iseol": false}
]}
JSON

# The series is EOL, and the pinned point release is not listed.
write_feed series-eol.json <<'JSON'
{"releases": [
  {"version": "6.18.52",  "moniker": "longterm", "iseol": true},
  {"version": "6.12.109", "moniker": "longterm", "iseol": false}
]}
JSON

# Same shape, but the series was never longterm.
write_feed series-notlts.json <<'JSON'
{"releases": [
  {"version": "6.18.52",  "moniker": "stable",   "iseol": false},
  {"version": "6.12.109", "moniker": "longterm", "iseol": false}
]}
JSON

# Exact match, EOL.
write_feed exact-eol.json <<'JSON'
{"releases": [
  {"version": "6.18.50",  "moniker": "longterm", "iseol": true},
  {"version": "6.12.109", "moniker": "longterm", "iseol": false}
]}
JSON

# The pinned series is gone from the feed entirely.
write_feed absent.json <<'JSON'
{"releases": [
  {"version": "6.12.109", "moniker": "longterm", "iseol": false},
  {"version": "6.6.156",  "moniker": "longterm", "iseol": false}
]}
JSON

# An unknown moniker, and a non-boolean iseol: neither is evidence of support.
write_feed unknown-moniker.json <<'JSON'
{"releases": [
  {"version": "6.18.52",  "moniker": "supported-ish", "iseol": false},
  {"version": "6.12.109", "moniker": "longterm",      "iseol": false}
]}
JSON

write_feed unknown-iseol.json <<'JSON'
{"releases": [
  {"version": "6.18.52",  "moniker": "longterm", "iseol": "no"},
  {"version": "6.12.109", "moniker": "longterm", "iseol": false}
]}
JSON

# The pin is ahead of its healthy series: a typo or an invented version.
write_feed behind-pin.json <<'JSON'
{"releases": [
  {"version": "6.18.9",   "moniker": "longterm", "iseol": false},
  {"version": "6.12.109", "moniker": "longterm", "iseol": false}
]}
JSON

# The series' newest entry is not first; it must be found by version order.
write_feed unsorted-series.json <<'JSON'
{"releases": [
  {"version": "6.18.7",   "moniker": "longterm", "iseol": false},
  {"version": "6.18.60",  "moniker": "longterm", "iseol": false},
  {"version": "6.18.40",  "moniker": "longterm", "iseol": false}
]}
JSON

printf '%s\n' '<html>503 Service Unavailable</html>' > "${SERVE}/malformed.json"
printf '%s\n' '[]' > "${SERVE}/wrong-shape.json"
printf '%s\n' '{"releases": []}' > "${SERVE}/empty-releases.json"

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
BASE="http://127.0.0.1:${PORT}"

# A throwaway KRYPTIK_ROOT holding only versions.env with the given pins.
fake_root() {
    local pinned="$1" hardened="$2"
    local root="${TMP}/root"
    rm -rf "$root"
    mkdir -p "${root}/build/config"
    {
        printf 'V_LINUX=%s\n' "$pinned"
        [[ -n "$hardened" ]] && printf 'V_LINUX_HARDENED=%s\n' "$hardened"
    } > "${root}/build/config/versions.env"
    printf '%s' "$root"
}

# run <pinned> <feed-url> [--strict]
# Output goes to $OUT and status to $RC; called as $(run), RC would be lost.
OUT="${TMP}/out"
RC=0
run() {
    local pinned="$1" url="$2"; shift 2
    local root; root="$(fake_root "$pinned" "${pinned}-hardened1")"
    KRYPTIK_ROOT="$root" \
    KRYPTIK_KERNEL_EOL_SELFTEST=1 \
    KRYPTIK_KERNEL_RELEASES_URL="$url" \
    NO_COLOR=1 \
    bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

show() { sed 's/^/        /' "$OUT"; }

# expect_pass <name> <pinned> <feed> <substring> [--strict]
expect_pass() {
    local name="$1" pinned="$2" feed="$3" want="$4"; shift 4
    run "$pinned" "${BASE}/${feed}" "$@"
    if [[ "$RC" -ne 0 ]]; then
        red "${name}: expected exit 0, got ${RC}"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: exit 0 but output lacks [${want}]"; show
    else
        green "$name"
    fi
}

# expect_fail <name> <pinned> <feed> <substring> [--strict]
expect_fail() {
    local name="$1" pinned="$2" feed="$3" want="$4"; shift 4
    run "$pinned" "${BASE}/${feed}" "$@"
    if [[ "$RC" -eq 0 ]]; then
        red "${name}: PASSED when it should have failed"; show
    elif ! grep -qF -- "$want" "$OUT"; then
        red "${name}: failed, but not for the stated reason [${want}]"; show
    else
        green "$name"
    fi
}

echo "tools/check-kernel-eol.sh"
echo

# Positive controls: a script that always failed would pass every case below.
expect_pass "supported LTS, exact match" \
    6.18.52 healthy.json "is longterm and not end-of-life"
expect_pass "supported LTS, exact match, --strict" \
    6.18.52 healthy.json "is longterm and not end-of-life" --strict

expect_pass "stale but supported LTS is a warning, not a failure" \
    6.18.50 healthy.json "is at 6.18.52 while 6.18.50 is pinned"
expect_pass "stale but supported LTS passes --strict" \
    6.18.50 healthy.json "not a security failure" --strict

expect_pass "series authority is the newest entry, not the first" \
    6.18.50 unsorted-series.json "is at 6.18.60 while 6.18.50 is pinned"

# A pin with no exact entry takes its series' status.
expect_fail "EOL series with no exact entry is not merely outdated" \
    6.18.50 series-eol.json "end-of-life"
expect_fail "non-LTS series with no exact entry is rejected" \
    6.18.50 series-notlts.json "not longterm"
expect_fail "EOL exact match is still rejected" \
    6.18.50 exact-eol.json "end-of-life"

# A non-LTS pin whose exact release is listed (the ADR-009 case).
expect_fail "non-LTS exact match is rejected" \
    7.2.4 healthy.json "not longterm"
expect_fail "EOL non-LTS exact match is rejected" \
    7.1.13 healthy.json "end-of-life"

# Absent, unknown, malformed.
expect_fail "series absent from the feed is not supported" \
    6.18.50 absent.json "not listed by kernel.org"
expect_fail "unrecognised moniker is not supported status" \
    6.18.50 unknown-moniker.json "does not recognise"
expect_fail "non-boolean iseol is not supported status" \
    6.18.50 unknown-iseol.json "expected a"
expect_fail "pin ahead of the whole series cannot be checked" \
    6.18.50 behind-pin.json "newer than anything kernel.org lists"
expect_fail "unparseable feed is a failure, not a pass" \
    6.18.50 malformed.json "not valid JSON"
expect_fail "feed of the wrong shape is a failure, not a pass" \
    6.18.50 wrong-shape.json "expected an object"
expect_fail "feed with no releases is a failure, not a pass" \
    6.18.50 empty-releases.json "no usable"

# Unreachable feed (nothing listens on port 1): only --strict fails.
DEAD="http://127.0.0.1:1/releases.json"

run 6.18.50 "$DEAD"
if [[ "$RC" -eq 0 ]] && grep -qF "strict fails here" "$OUT"; then
    green "network failure warns and continues informationally"
else
    red "network failure: expected exit 0 with a warning, got ${RC}"; show
fi

run 6.18.50 "$DEAD" --strict
if [[ "$RC" -ne 0 ]] && grep -qF "could not be established" "$OUT"; then
    green "network failure fails --strict"
else
    red "network failure under --strict: expected nonzero exit, got ${RC}"; show
fi

expect_fail "HTTP 404 on the feed fails --strict" \
    6.18.50 no-such-file.json "could not be established" --strict

root="$(fake_root 6.18.50 6.18.50-hardened1)"
KRYPTIK_ROOT="$root" KRYPTIK_KERNEL_RELEASES_URL="${BASE}/healthy.json" \
    NO_COLOR=1 bash "$TOOL" --strict > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to check" "$OUT"; then
    green "substituted feed is refused without the selftest flag"
else
    red "substituted feed was accepted without KRYPTIK_KERNEL_EOL_SELFTEST"; show
fi

# linux-hardened pin.
root="$(fake_root 6.18.52 "")"
printf 'V_LINUX_HARDENED=6.12.109-hardened1\n' >> "${root}/build/config/versions.env"
KRYPTIK_ROOT="$root" KRYPTIK_KERNEL_EOL_SELFTEST=1 \
    KRYPTIK_KERNEL_RELEASES_URL="${BASE}/healthy.json" NO_COLOR=1 \
    bash "$TOOL" > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "does not match V_LINUX" "$OUT"; then
    green "mismatched V_LINUX_HARDENED is rejected"
else
    red "mismatched V_LINUX_HARDENED was accepted (exit ${rc})"; show
fi

root="$(fake_root 6.18.52 "")"
KRYPTIK_ROOT="$root" KRYPTIK_KERNEL_EOL_SELFTEST=1 \
    KRYPTIK_KERNEL_RELEASES_URL="${BASE}/healthy.json" NO_COLOR=1 \
    bash "$TOOL" > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "V_LINUX_HARDENED is unset" "$OUT"; then
    green "unset V_LINUX_HARDENED is rejected"
else
    red "unset V_LINUX_HARDENED was accepted (exit ${rc})"; show
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
