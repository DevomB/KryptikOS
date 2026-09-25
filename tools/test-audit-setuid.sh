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

# A root named with a trailing slash, or through a symlink, is the same root:
# the listed file is still recognised, not stripped as unknown.
chmod 4755 "$T/root/usr/bin/mount"; ln -s root "$T/link"
out="$(audit --strip "$T/link/")"; rc=$?
[[ "$rc" -eq 0 && "$(mode su)/$(mode mount)" == 4755/755 ]] \
    && ok "a trailing slash and a symlinked root keep the listed file's bit" || bad "trailing slash: rc=$rc su $(mode su) mount $(mode mount): $out"

# --strip refuses this machine's root before looking at it. A stand-in chmod
# records any attempt, so a broken refusal changes nothing here either.
mkdir -p "$T/bin"; printf '#!/bin/sh\necho "$@" >> "%s/chmod-called"; exit 1\n' "$T" > "$T/bin/chmod"; chmod 755 "$T/bin/chmod"
out="$(PATH="$T/bin:$PATH" audit --strip /)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"never this machine"* && ! -e "$T/chmod-called" ]] \
    && ok "--strip refuses /" || bad "--strip /: rc=$rc: $out"

# A stripped name that is a hard link to a listed binary took the bit off the
# listed one too; the strip says so and fails.
ln "$T/root/usr/bin/su" "$T/root/usr/bin/su2"
out="$(audit --strip "$T/root")"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/su lost its bit"* ]] \
    && ok "stripping a hard link to a listed binary fails, naming it" || bad "hard link: rc=$rc: $out"
rm -f "$T/root/usr/bin/su2"; chmod 4755 "$T/root/usr/bin/su"

# The last entry counts without a newline after it; a missing list strips
# nothing, since by it every binary would lose its bit.
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

# A bind mount of / is this machine's / as much as / is. It is made in a mount
# namespace of the check's own, so it ends with the check and never outlives
# it under $T, where the cleanup would walk into it.
mkdir -p "$T/slash"
if unshare -rm mount --rbind / "$T/slash" 2>/dev/null; then
    out="$(PATH="$T/bin:$PATH" NO_COLOR=1 unshare -rm bash -c 'mount --rbind / "$1" && bash "$2" --strip "$1"' _ "$T/slash" "$T/repo/tools/audit-setuid.sh" 2>&1)"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"never this machine"* && ! -e "$T/chmod-called" ]] \
        && ok "--strip refuses a bind mount of /" || bad "bind mount of /: rc=$rc: $out"
fi

# A directory the audit cannot read could hide a binary: that is a failure.
# Root reads every directory, so this holds only for a user.
if [[ "$(id -u)" -ne 0 ]]; then
    mkdir "$T/root/locked"; chmod 000 "$T/root/locked"
    out="$(audit "$T/root")"; rc=$?
    chmod 755 "$T/root/locked"
    [[ "$rc" -ne 0 && "$out" == *"could not read"* ]] && ok "an unreadable directory fails the audit" || bad "unreadable directory: rc=$rc: $out"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
