#!/usr/bin/env bash
# Tests for tools/audit-setuid.sh, copied beside a test allowlist; a user may setuid its own files.
set -uo pipefail
# An exported KRYPTIK_ROOT (acceptance sets one) would point the copy at the real allowlist.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# Under unshare -r, a TMPDIR owned by an unmapped user is unwritable, even by the namespace's root.
export TMPDIR="$T"
mkdir -p "$T/repo/tools" "$T/repo/build/lib" "$T/repo/build/config" "$T/root/usr/bin"
cp "$ROOT/tools/audit-setuid.sh" "$T/repo/tools/"
cp "$ROOT/build/lib/common.sh" "$T/repo/build/lib/"
L="$T/repo/build/config/setuid-allowlist.txt"
printf '# test\n/usr/bin/su   # why\n' > "$L"
for f in su mount wall ls; do printf '#!/bin/sh\n' > "$T/root/usr/bin/$f"; done
chmod 4755 "$T/root/usr/bin/su" "$T/root/usr/bin/mount"
chmod 2755 "$T/root/usr/bin/wall"
chmod 0755 "$T/root/usr/bin/ls"
audit() { NO_COLOR=1 bash "$T/repo/tools/audit-setuid.sh" "$@" 2>&1; }
mode() { stat -c %a "$T/root/usr/bin/$1"; }

out="$(audit "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/mount"* && "$out" == *"/usr/bin/wall"* ]] \
    && ok "an unlisted setuid and an unlisted setgid file fail the audit" || bad "audit: rc=$rc"
[[ "$(mode mount)/$(mode wall)" == 4755/2755 ]] && ok "the audit changes nothing" || bad "the audit changed mount to $(mode mount)"

chmod 755 "$T/root/usr/bin/mount" "$T/root/usr/bin/wall"
audit "$T/root" > /dev/null && ok "only the listed file keeps a bit: the audit passes" || bad "a tree with su alone still fails"

# A root named with a trailing slash or through a symlink is the same root.
ln -s root "$T/link"
out="$(audit "$T/link/")"; rc=$?
[[ "$rc" -eq 0 ]] && ok "a trailing slash and a symlinked root find the listed file" || bad "trailing slash: rc=$rc: $out"

# An entry with no bit behind it is stale: it would admit the next file of that name unread.
printf '# test\n/usr/bin/su   # why\n/usr/bin/passwd   # gone\n' > "$L"
out="$(audit "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"lists /usr/bin/passwd, which has no setuid or setgid bit here"* ]] \
    && ok "an entry for a missing file fails the audit, naming it" || bad "missing file: rc=$rc: $out"
printf '# test\n/usr/bin/su   # why\n/usr/bin/ls   # no bit\n' > "$L"
out="$(audit "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"lists /usr/bin/ls"* ]] \
    && ok "an entry for a file without the bit fails the audit" || bad "file without bit: rc=$rc: $out"

# A last entry with no newline still counts.
printf '# test\n/usr/bin/su   # why' > "$L"
audit "$T/root" > /dev/null && ok "a last entry with no newline after it is still listed" || bad "no final newline"

# An entry without a justification refuses the audit.
printf '# test\n/usr/bin/su\n' > "$L"
out="$(audit "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/su has no justification"* ]] \
    && ok "an entry without a justification refuses the audit" || bad "no justification: rc=$rc: $out"
printf '# test\n/usr/bin/su   # why\n' > "$L"

# File capabilities: setting one needs CAP_SETFCAP, which a user namespace grants.
C="$T/repo/build/config/capability-allowlist.txt"
printf '# test\n/usr/bin/capok   # why\n' > "$C"
setcap_ns() {   # setcap_ns FILE: cap_net_raw+ep on FILE, set from a user namespace
    unshare -r python3 -c 'import os, struct, sys; os.setxattr(sys.argv[1], "security.capability", struct.pack("<5I", 0x02000001, 1 << 13, 0, 0, 0))' "$1" 2>/dev/null
}
for f in capok capno; do printf '#!/bin/sh\n' > "$T/root/usr/bin/$f"; chmod 755 "$T/root/usr/bin/$f"; done
if setcap_ns "$T/root/usr/bin/capok" && setcap_ns "$T/root/usr/bin/capno"; then
    out="$(audit "$T/root")"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"unjustified file capabilities: /usr/bin/capno"* && "$out" != *"unjustified file capabilities: /usr/bin/capok"* ]] \
        && ok "an unlisted file with capabilities fails the audit, a listed one does not" || bad "capability audit: rc=$rc: $out"
    rm -f "$T/root/usr/bin/capno"
    audit "$T/root" > /dev/null && ok "the listed file's capabilities pass" || bad "listed capabilities still fail"
    rm -f "$T/root/usr/bin/capok"
    out="$(audit "$T/root")"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"lists /usr/bin/capok, which carries no capabilities here"* ]] \
        && ok "a capability entry with no file behind it fails the audit" || bad "stale capability entry: rc=$rc: $out"
else
    printf '  SKIP  file capabilities (no user namespace to set one in)\n'
fi
: > "$C"

# An unreadable directory could hide a binary, so it fails the audit; root reads them all.
if [[ "$(id -u)" -ne 0 ]]; then
    mkdir "$T/root/locked"; chmod 000 "$T/root/locked"
    out="$(audit "$T/root")"; rc=$?
    chmod 755 "$T/root/locked"
    [[ "$rc" -ne 0 && "$out" == *"could not read"* ]] && ok "an unreadable directory fails the audit" || bad "unreadable directory: rc=$rc: $out"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
