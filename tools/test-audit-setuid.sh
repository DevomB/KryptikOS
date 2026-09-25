#!/usr/bin/env bash
# tools/audit-setuid.sh on a staged tree: it fails on a setuid or setgid file
# the allowlist does not name, and with --strip takes the bit off each such
# file and leaves the named ones alone. Run against a copy of the script beside
# a test allowlist. No root: a user may set these bits on their own files.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/repo/tools" "$T/repo/build/lib" "$T/repo/build/config" "$T/root/usr/bin"
cp "$ROOT/tools/audit-setuid.sh" "$T/repo/tools/"
cp "$ROOT/build/lib/common.sh" "$T/repo/build/lib/"
printf '# test\n/usr/bin/su   # why\n' > "$T/repo/build/config/setuid-allowlist.txt"
for f in su mount wall ls; do printf '#!/bin/sh\n' > "$T/root/usr/bin/$f"; done
chmod 4755 "$T/root/usr/bin/su" "$T/root/usr/bin/mount"
chmod 2755 "$T/root/usr/bin/wall"
chmod 0755 "$T/root/usr/bin/ls"
audit() { NO_COLOR=1 bash "$T/repo/tools/audit-setuid.sh" "$@" 2>&1; }
mode() { stat -c %a "$T/root/usr/bin/$1"; }

out="$(audit "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/mount"* && "$out" == *"/usr/bin/wall"* ]] \
    && ok "an unlisted setuid and an unlisted setgid file fail the audit" || bad "audit: rc=$rc"
[[ "$(mode mount)" == 4755 ]] && ok "the audit alone changes nothing" || bad "the audit changed mount to $(mode mount)"

out="$(audit --strip "$T/root")"; rc=$?
[[ "$rc" -eq 0 ]] && ok "--strip succeeds" || bad "--strip: rc=$rc: $out"
[[ "$(mode mount)/$(mode wall)" == 755/755 ]] && ok "the unlisted files lose the bit" || bad "after --strip: mount $(mode mount), wall $(mode wall)"
[[ "$(mode su)/$(mode ls)" == 4755/755 ]] && ok "the listed file keeps it, and a plain file is untouched" || bad "after --strip: su $(mode su), ls $(mode ls)"
audit "$T/root" > /dev/null && ok "the stripped tree passes the audit" || bad "the stripped tree still fails the audit"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
