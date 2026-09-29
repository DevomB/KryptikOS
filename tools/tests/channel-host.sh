#!/usr/bin/env bash
# Tests for tools/channel-host.sh: its dry run, which is the same publish and
# reissue the workflow runs, on throwaway keys and a stand-in release; and
# what it refuses. No gh, no network.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/tools/channel-host.sh"

for t in ssh-keygen sha256sum curl flock; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} is not installed here; cannot run this test"; exit 77; }
done

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
OUT="${W}/out"; ERR="${W}/err"
show() { sed 's/^/        /' "$ERR"; }
field() { awk -F': ' -v k="$2" '$1 == k { print $2; exit }' "$1"; }

# --- the dry run: publish, then reissue, into the site ------------------------------
S="${W}/site"
NO_COLOR=1 bash "$TOOL" dry-run --site "$S" --channel test > "$OUT" 2> "$ERR"; rc=$?
L="${S}/test/latest"
if [[ "$rc" -eq 0 && -s "$L" && -s "${L}.sig" ]] \
    && [[ "$(field "$L" version)" == 0.0.1 && "$(field "$L" base)" == "https://example.invalid/releases/download/v0.0.1/" ]] \
    && [[ "$(field "$L" role)" == production ]] && grep -q "signed by a throwaway key and signed again" "$OUT"; then
    green "the dry run leaves a statement naming the stand-in release at its download address"
else
    red "the dry run (exit ${rc}): $(cat "$OUT")"; show
fi
if [[ -f "${S}/.nojekyll" && ! -e "${S}/stable" && ! -e "${S}/test/0.0.1" ]]; then
    green "the site holds the statement and nothing else: no stable channel is invented, no payload is copied"
else
    red "the site's contents: $(find "$S" | sed "s|^${S}||" | tr '\n' ' ')"
fi
if grep -q 'issued' "$L" && [[ "$(grep -c 'latest names 0.0.1, issued' "$OUT")" -eq 2 ]]; then
    green "publish and reissue each wrote a statement for the same version"
else
    red "two statements expected: $(cat "$OUT")"
fi

# --- refusals -----------------------------------------------------------------------
NO_COLOR=1 bash "$TOOL" dry-run --site "${W}/site2" --channel stable > "$OUT" 2> "$ERR"; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "not on stable" "$ERR"; then
    green "a dry run is refused on the stable channel"
else
    red "the dry run on stable (exit ${rc})"; show
fi
NO_COLOR=1 bash "$TOOL" dry-run --site "${W}/site3" --channel 'Bad Name' > "$OUT" 2> "$ERR"; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "lowercase letters" "$ERR"; then
    green "a channel name outside lowercase letters, digits and dashes is refused"
else
    red "the bad channel name (exit ${rc})"; show
fi
NO_COLOR=1 bash "$TOOL" reissue --site "${W}/site4" > "$OUT" 2> "$ERR"; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q -E "gh \(GitHub's command line\)|--key is required|no repository" "$ERR"; then
    green "reissue without a key, a repository or gh is refused before anything is touched"
else
    red "reissue with nothing (exit ${rc})"; show
fi
NO_COLOR=1 bash "$TOOL" sideways --site "${W}/site5" > "$OUT" 2> "$ERR"; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "unknown mode" "$ERR"; then
    green "an unknown mode is refused"
else
    red "the unknown mode (exit ${rc})"; show
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
