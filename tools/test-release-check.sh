#!/usr/bin/env bash
# Focused tests for tools/release-check.sh.
#
#   ./tools/test-release-check.sh
#
# Deterministic and offline. Fixture rootfs trees are built here, each with one
# defect, and the real checks run over them. Inventory-driven checks are fed
# hand-written inventory documents, which is the same shape the real tool
# produces.
#
# The case worth reading first is the tree-stability one. The setuid check once
# reported "no unjustified setuid/setgid binaries" over a sysroot the build tab
# was mid-rebuild on, because /usr/bin had not been installed at that instant;
# a minute later the same check found sixteen. A gate whose answer depends on
# when you run it is worse than no gate, so the tool fingerprints the tree and
# refuses a run during which it changed - and that refusal is tested by
# changing the tree while the checks are in flight.
#
# Positive controls first: a clean tree must pass every check, or a tool that
# failed everything would satisfy the rest.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/release-check.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }

FAKE="${W}/root"          # KRYPTIK_ROOT: allowlist, sources.lock, tools
TREE="${W}/tree"          # the built tree under test
SRC="${W}/sources"

# --- fixture KRYPTIK_ROOT ---------------------------------------------------

build_root() {
    rm -rf "$FAKE" "$SRC"
    mkdir -p "${FAKE}/build/config" "${FAKE}/tools" "$SRC"
    : > "${FAKE}/build/config/versions.env"
    cat > "${FAKE}/build/config/setuid-allowlist.txt" <<'EOF'
# Fixture allowlist. Empty by default, as the real one is.
EOF
    # audit-setuid.sh is delegated to, so the real one is linked in.
    ln -sf "${ROOT}/tools/audit-setuid.sh" "${FAKE}/tools/audit-setuid.sh"
    printf 'payload\n' > "${SRC}/thing-1.0.tar.gz"
    printf '%s  thing-1.0.tar.gz\n' \
        "$(sha256sum "${SRC}/thing-1.0.tar.gz" | cut -d' ' -f1)" \
        > "${FAKE}/sources.lock"
}

# --- fixture trees ----------------------------------------------------------

clean_tree() {
    rm -rf "$TREE"
    mkdir -p "${TREE}/usr/bin" "${TREE}/tmp"
    printf '#!/bin/sh\necho hi\n' > "${TREE}/usr/bin/hello"
    chmod 755 "${TREE}/usr/bin/hello"
    chmod 1777 "${TREE}/tmp"      # sticky: correct, must not be flagged
}

run() {
    KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" NO_COLOR=1 \
        bash "$TOOL" --root="$TREE" "$@" > "$OUT" 2>&1
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

echo "tools/release-check.sh"
echo

# --- the checks are named ---------------------------------------------------

KRYPTIK_ROOT="$FAKE" NO_COLOR=1 bash "$TOOL" --list > "$OUT" 2>&1
if grep -qx setuid "$OUT" && grep -qx hardening "$OUT" && grep -qx licences "$OUT"; then
    green "--list names the checks without needing a tree"
else
    red "--list did not name the checks"; show
fi

# --- positive controls ------------------------------------------------------

build_root
clean_tree
run --only=setuid,caps,perms
expect_pass "a clean tree passes setuid, caps and perms" "3 check(s) passed"

run --only=source-availability
expect_pass "sources present and matching passes" "1 locked sources present"

run --only=setuid,caps,perms --strict
expect_pass "a clean tree passes --strict too" "check(s) passed"

# --- setuid -----------------------------------------------------------------

clean_tree
cp "${TREE}/usr/bin/hello" "${TREE}/usr/bin/naughty"
chmod 4755 "${TREE}/usr/bin/naughty"
run --only=setuid
expect_fail "an unjustified setuid binary fails" "unjustified setuid/setgid"
if grep -qF "/usr/bin/naughty" "$OUT"; then
    green "the offending path is named"
else
    red "the setuid failure did not name the file"; show
fi
# The count must be the audit's own, not a grep over lines that include the
# summary sentence.
if grep -qE '\[setuid\] 1 unjustified' "$OUT"; then
    green "the setuid count is the audit's own count, not an off-by-one"
else
    red "the setuid count looks wrong: $(grep -o '\[setuid\][^;]*' "$OUT" | head -1)"
fi

# An allowlisted one is not a finding.
printf '/usr/bin/naughty   # fixture justification\n' \
    >> "${FAKE}/build/config/setuid-allowlist.txt"
run --only=setuid
expect_pass "an allowlisted setuid binary is accepted" "no unjustified"

# --- permissions ------------------------------------------------------------

build_root
clean_tree
printf 'x\n' > "${TREE}/usr/bin/loose"
chmod 666 "${TREE}/usr/bin/loose"
run --only=perms
expect_fail "a world-writable file fails" "world-writable file(s)"

build_root
clean_tree
mkdir -p "${TREE}/var/spill"
chmod 777 "${TREE}/var/spill"      # world-writable, no sticky bit
run --only=perms
expect_fail "a world-writable directory without sticky fails" \
    "directory(ies) without the sticky bit"

# /tmp at 1777 is correct and must not be flagged - that is the control for
# the check above.
build_root
clean_tree
run --only=perms
expect_pass "a sticky world-writable directory is not flagged" "no world-writable"

# --- source availability ----------------------------------------------------

build_root
clean_tree
rm -f "${SRC}/thing-1.0.tar.gz"
run --only=source-availability
expect_fail "a locked source missing from disk fails" "cannot be rebuilt"

build_root
clean_tree
printf 'tampered\n' >> "${SRC}/thing-1.0.tar.gz"
run --only=source-availability
expect_fail "a locked source that does not match its hash fails" \
    "do not
       match their recorded hash"

# --- inventory-driven checks ------------------------------------------------

inv() { cat > "${W}/inv.json"; }

# An offline inventory carries no signature evidence, so it cannot answer the
# provenance question. Reporting 3-of-3 failures would blame the release for
# how the document was generated.
build_root; clean_tree
inv <<'JSON'
{"schema":"kryptik-provenance-inventory-1","offline":true,
 "sources":[{"name":"a","assurance_class":"lock-only","licence":{"spdx":"MIT","method":"x"}}]}
JSON
run --only=provenance --inventory="${W}/inv.json"
expect_pass "an offline inventory makes provenance NOT CHECKED, not failed" \
    "generated with --offline"
if grep -qF "NOT CHECKED" "$OUT"; then
    green "and it is reported as not checked rather than passed quietly"
else
    red "the offline inventory was not reported as unchecked"; show
fi

run --only=provenance --inventory="${W}/inv.json" --strict
expect_fail "--strict refuses a run with an unchecked provenance gate" \
    "will not pass a release whose checks did not all run"

# A real inventory with a lock-only source is a genuine provenance failure.
inv <<'JSON'
{"schema":"kryptik-provenance-inventory-1","offline":false,
 "sources":[{"name":"a","assurance_class":"signature-pinned-key","licence":{"spdx":"MIT","method":"x"}},
            {"name":"b","assurance_class":"lock-only","licence":{"spdx":"MIT","method":"x"}}]}
JSON
run --only=provenance --inventory="${W}/inv.json"
expect_fail "a lock-only source fails the provenance gate" \
    "rest on sources.lock alone"

inv <<'JSON'
{"schema":"kryptik-provenance-inventory-1","offline":false,
 "sources":[{"name":"a","assurance_class":"signature-pinned-key","licence":{"spdx":"MIT","method":"x"}}]}
JSON
run --only=provenance --inventory="${W}/inv.json"
expect_pass "every source above lock-only passes the provenance gate" \
    "carry more than a lockfile hash"

# Licences: not-collected is unchecked; unknown is a failure.
inv <<'JSON'
{"schema":"kryptik-provenance-inventory-1","offline":false,
 "sources":[{"name":"a","assurance_class":"signature-pinned-key",
             "licence":{"spdx":"not-collected","method":"not-collected"}}]}
JSON
run --only=licences --inventory="${W}/inv.json"
expect_pass "an inventory without licence evidence is unchecked, not failed" \
    "carries no licence evidence"

inv <<'JSON'
{"schema":"kryptik-provenance-inventory-1","offline":false,
 "sources":[{"name":"good","assurance_class":"x","licence":{"spdx":"MIT","method":"scan"}},
            {"name":"mystery","assurance_class":"x","licence":{"spdx":"unknown","method":"scan"}}]}
JSON
run --only=licences --inventory="${W}/inv.json"
expect_fail "a source with no established licence fails" "no established licence"
if grep -qF "mystery" "$OUT"; then
    green "the unlicensed source is named"
else
    red "the licence failure did not name the source"; show
fi

# No inventory at all is unchecked, never a pass.
build_root; clean_tree
run --only=provenance,licences
expect_pass "missing inventory leaves both gates unchecked" "no --inventory"
run --only=provenance,licences --strict
expect_fail "--strict refuses when the inventory was never supplied" \
    "did not all run"

# --- a tree that changes mid-run invalidates the run ------------------------
#
# The defect this guards against produced a PASS over a tree being installed
# into. Rather than simulate, the tree really is modified while the checks are
# running: a background sleep-then-touch lands during the source-availability
# pass, which re-hashes files and takes long enough to be raced reliably.

build_root
clean_tree
# Deterministic, not timing-based: wait for the tool to actually start by
# polling for the log its first check writes, then modify the tree while the
# remaining checks run. A fixed one-second sleep raced a sub-second run and
# lost, which made the test pass for the wrong reason.
SENTINEL="${FAKE}/build/work/release-setuid.log"
rm -f "$SENTINEL"
(
    for _ in $(seq 1 400); do
        [[ -e "$SENTINEL" ]] && break
        sleep 0.05
    done
    printf 'late\n' > "${TREE}/usr/bin/arrived-late"
) &
racer=$!
# Two seconds of settle before the closing fingerprint: the racer writes
# within a few milliseconds of the sentinel, and on a fast runner the whole
# run over this small tree finished first (CI reported PASSED where it
# should have failed).
KRYPTIK_RELEASE_CHECK_SETTLE=2 run --only=setuid,caps,perms,source-availability
wait "$racer" 2>/dev/null
expect_fail "a tree that changes during the run invalidates every result" \
    "being written to"
if grep -qF "including any that passed" "$OUT"; then
    green "the refusal says the passing results are void too"
else
    red "the mid-run change did not invalidate the passes"; show
fi

# And the control: an unchanging tree is not falsely accused.
build_root
clean_tree
run --only=setuid,caps,perms
expect_pass "a tree that does not change is not accused of changing" \
    "check(s) passed"

# --- a missing tree is not a pass -------------------------------------------

build_root
KRYPTIK_ROOT="$FAKE" KRYPTIK_SOURCES="$SRC" NO_COLOR=1 \
    bash "$TOOL" --root=/nonexistent/tree > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "nothing to check" "$OUT"; then
    green "a missing tree is refused rather than passing vacuously"
else
    red "a missing tree did not refuse (exit ${rc})"; show
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
