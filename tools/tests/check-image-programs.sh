#!/usr/bin/env bash
# Tests for tools/check-image-programs.sh on a fixture root.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/tools/check-image-programs.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/root"; L="$T/list.txt"
mkdir -p "$R/usr/bin" "$R/usr/lib" "$R/usr/share/doc"
printf '#!/bin/sh\n' > "$R/usr/bin/hostname"; chmod 755 "$R/usr/bin/hostname"
printf '#!/bin/sh\n' > "$R/usr/bin/ifconfig"; chmod 755 "$R/usr/bin/ifconfig"
printf '\177ELF rest' > "$R/usr/lib/libz.so.1.3.1"; chmod 755 "$R/usr/lib/libz.so.1.3.1"
printf 'text\n' > "$R/usr/share/doc/README"; chmod 644 "$R/usr/share/doc/README"
cp "$R/usr/lib/libz.so.1.3.1" "$R/usr/lib/libplain.so"; chmod 644 "$R/usr/lib/libplain.so"
ln -s hostname "$R/usr/bin/dnsdomainname"
check() { NO_COLOR=1 bash "$CHECK" "$R" --list "$L" "$@" 2>&1; }

printf 'usr/bin/hostname   # inetutils\nusr/bin/ifconfig\nusr/lib/libz.so.1.*\n' > "$L"
out="$(check)"; rc=$?
[[ "$rc" -eq 0 && "$out" == *"3 executable files"* ]] \
    && ok "executable files are named; data, a non-executable library and symlinks are not" || bad "named tree: rc=$rc: $out"

printf '#!/bin/sh\n' > "$R/usr/bin/["; chmod 755 "$R/usr/bin/["
printf 'usr/bin/[\nusr/bin/hostname\nusr/bin/ifconfig\nusr/lib/libz.so.[0-9].*\n' > "$L"
out="$(check)"; rc=$?
[[ "$rc" -eq 0 && "$out" == *"4 executable files, 3 names and 1 patterns"* ]] \
    && ok "a lone [ is a name, and a closed [...] is a pattern" || bad "brackets: rc=$rc: $out"
rm -f "$R/usr/bin/["
printf 'usr/bin/hostname   # inetutils\nusr/bin/ifconfig\nusr/lib/libz.so.1.*\n' > "$L"

printf '#!/bin/sh\n' > "$R/usr/bin/traceroute"; chmod 4755 "$R/usr/bin/traceroute"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"NOT NAMED  usr/bin/traceroute"* ]] \
    && ok "a program left behind fails, named" || bad "left-behind program: rc=$rc: $out"
rm -f "$R/usr/bin/traceroute"

printf 'usr/bin/hostname\nusr/bin/ifconfig\nusr/lib/libz.so.1.*\nusr/bin/telnet   # gone\n' > "$L"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"NAMES NOTHING  line 4: usr/bin/telnet"* ]] \
    && ok "an entry naming nothing fails, with its line" || bad "stale entry: rc=$rc: $out"

printf 'usr/bin/hostname\nusr/bin/ifconfig\nusr/lib/libz.so.2.*\n' > "$L"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"NOT NAMED  usr/lib/libz.so.1.3.1"* && "$out" == *"usr/lib/libz.so.2.*"* ]] \
    && ok "a pattern for another soname names nothing, and the library stays unnamed" || bad "pattern: rc=$rc: $out"

printf '/usr/bin/hostname\n' > "$L"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"no leading /"* ]] && ok "an absolute entry is refused" || bad "absolute entry: rc=$rc: $out"

out="$(check --write "$T/written.txt")"; rc=$?
[[ "$rc" -eq 0 && "$(cat "$T/written.txt")" == $'usr/bin/hostname\nusr/bin/ifconfig\nusr/lib/libz.so.1.3.1' ]] \
    && ok "--write lists what the root holds, sorted" || bad "--write: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
