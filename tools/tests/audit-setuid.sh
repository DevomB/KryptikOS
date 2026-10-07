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

# A root named with a trailing slash or through a symlink is the same root.
chmod 4755 "$T/root/usr/bin/mount"; ln -s root "$T/link"
out="$(audit --strip "$T/link/")"; rc=$?
[[ "$rc" -eq 0 && "$(mode su)/$(mode mount)" == 4755/755 ]] \
    && ok "a trailing slash and a symlinked root keep the listed file's bit" || bad "trailing slash: rc=$rc su $(mode su) mount $(mode mount): $out"

# --strip refuses this machine's root; a stand-in chmod records any attempt and changes nothing.
mkdir -p "$T/bin"; printf '#!/bin/sh\necho "$@" >> "%s/chmod-called"; exit 1\n' "$T" > "$T/bin/chmod"; chmod 755 "$T/bin/chmod"
out="$(PATH="$T/bin:$PATH" audit --strip /)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"never this machine"* && ! -e "$T/chmod-called" ]] \
    && ok "--strip refuses /" || bad "--strip /: rc=$rc: $out"

# Stripping a hard link to a listed binary strips the listed one too, so the strip fails.
ln "$T/root/usr/bin/su" "$T/root/usr/bin/su2"
out="$(audit --strip "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/su lost its bit"* ]] \
    && ok "stripping a hard link to a listed binary fails, naming it" || bad "hard link: rc=$rc: $out"
rm -f "$T/root/usr/bin/su2"; chmod 4755 "$T/root/usr/bin/su"

# A last entry with no newline still counts; a missing list strips nothing.
L="$T/repo/build/config/setuid-allowlist.txt"
printf '# test\n/usr/bin/su   # why' > "$L"
chmod 4755 "$T/root/usr/bin/mount"
out="$(audit --strip "$T/root")"; rc=$?
[[ "$rc" -eq 0 && "$(mode su)/$(mode mount)" == 4755/755 ]] \
    && ok "a last entry with no newline after it is still listed" || bad "no final newline: rc=$rc su $(mode su): $out"
mv "$L" "$L.away"; chmod 4755 "$T/root/usr/bin/mount"
out="$(audit --strip "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$(mode su)/$(mode mount)" == 4755/4755 ]] \
    && ok "--strip without an allowlist refuses, and changes nothing" || bad "no allowlist: rc=$rc su $(mode su) mount $(mode mount): $out"
mv "$L.away" "$L"; chmod 755 "$T/root/usr/bin/mount"

# An entry without a justification refuses the audit before any file is touched.
printf '# test\n/usr/bin/su\n' > "$L"
chmod 4755 "$T/root/usr/bin/mount"
out="$(audit --strip "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/su has no justification"* && "$(mode su)/$(mode mount)" == 4755/4755 ]] \
    && ok "an entry without a justification refuses the audit, and nothing is stripped" || bad "no justification: rc=$rc su $(mode su) mount $(mode mount): $out"
printf '# test\n/usr/bin/su   # why\n' > "$L"; chmod 755 "$T/root/usr/bin/mount"

# A bind mount of / is still /; a private mount namespace keeps it out of $T's cleanup.
mkdir -p "$T/slash"
if unshare -rm mount --rbind / "$T/slash" 2>/dev/null; then
    out="$(PATH="$T/bin:$PATH" NO_COLOR=1 unshare -rm bash -c 'mount --rbind / "$1" && bash "$2" --strip "$1"' _ "$T/slash" "$T/repo/tools/audit-setuid.sh" 2>&1)"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"never this machine"* && ! -e "$T/chmod-called" ]] \
        && ok "--strip refuses a bind mount of /" || bad "bind mount of /: rc=$rc: $out"
else
    printf '  SKIP  --strip refuses a bind mount of / (no mount namespace here)\n'
fi

# File capabilities: setting or removing one needs CAP_SETFCAP, which a user namespace grants.
printf '# test\n/usr/bin/capok   # why\n' > "$T/repo/build/config/capability-allowlist.txt"
setcap_ns() {   # setcap_ns FILE: cap_net_raw+ep on FILE, set from a user namespace
    unshare -r python3 -c 'import os, struct, sys; os.setxattr(sys.argv[1], "security.capability", struct.pack("<5I", 0x02000001, 1 << 13, 0, 0, 0))' "$1" 2>/dev/null
}
has_cap() { python3 -c 'import os, sys; os.getxattr(sys.argv[1], "security.capability")' "$1" 2>/dev/null; }
strip_ns() { NO_COLOR=1 unshare -r bash "$T/repo/tools/audit-setuid.sh" --strip "$T/root" 2>&1; }
for f in capok capno; do printf '#!/bin/sh\n' > "$T/root/usr/bin/$f"; chmod 755 "$T/root/usr/bin/$f"; done
if setcap_ns "$T/root/usr/bin/capok" && setcap_ns "$T/root/usr/bin/capno"; then
    out="$(audit "$T/root")"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"unjustified file capabilities: /usr/bin/capno"* && "$out" != *"unjustified file capabilities: /usr/bin/capok"* ]] \
        && ok "an unlisted file with capabilities fails the audit, a listed one does not" || bad "capability audit: rc=$rc: $out"
    out="$(strip_ns)"; rc=$?
    { [[ "$rc" -eq 0 ]] && has_cap "$T/root/usr/bin/capok" && ! has_cap "$T/root/usr/bin/capno"; } \
        && ok "--strip removes unlisted capabilities and keeps listed ones" || bad "capability strip: rc=$rc: $out"
    ln "$T/root/usr/bin/capok" "$T/root/usr/bin/capok2"
    out="$(strip_ns)"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"/usr/bin/capok lost its capabilities"* ]] \
        && ok "stripping a hard link to a listed file fails, naming it" || bad "capability hard link: rc=$rc: $out"
    rm -f "$T/root/usr/bin/capok2"
else
    printf '  SKIP  file capabilities (no user namespace to set one in)\n'
fi

# An unreadable directory could hide a binary, so it fails the audit; root reads them all.
if [[ "$(id -u)" -ne 0 ]]; then
    mkdir "$T/root/locked"; chmod 000 "$T/root/locked"
    out="$(audit "$T/root")"; rc=$?
    chmod 755 "$T/root/locked"
    [[ "$rc" -ne 0 && "$out" == *"could not read"* ]] && ok "an unreadable directory fails the audit" || bad "unreadable directory: rc=$rc: $out"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
