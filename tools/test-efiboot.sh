#!/usr/bin/env bash
# Test kryptik-efiboot's forget, built with EFIVARS pointing at a directory of
# stand-in variables (efivarfs files: 4 bytes of attributes, then the data).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
V="$T/efivars"; mkdir -p "$V"
G=8be4df61-93ca-11d2-aa0d-00e098032b8c
if gcc -std=gnu11 -Wall -Wextra -DEFIVARS="\"$V/\"" -o "$T/efiboot" "$ROOT/tools/efi/kryptik-efiboot.c"; then
    ok "the tool compiles with EFIVARS overridden"
else
    bad "the tool compiles with EFIVARS overridden"; exit 1
fi

# var NAME BYTES: write a variable, attributes 0x7 then BYTES (a printf
# format, so \xNN is a byte).
var() { printf '\x07\x00\x00\x00'"$2" > "$V/$1-$G"; }
# data NAME: the variable's data as hex, or "absent".
data() { if [[ -f "$V/$1-$G" ]]; then od -An -tx1 -j4 -v "$V/$1-$G" | tr -d ' \n'; else echo absent; fi; }
# The firmware's own disk entry, both slot entries, an order with slot b in
# front of the disk entry, and a BootNext for slot a.
MACHINE='\x01\x00\x00\x00\x00\x00U\x00E\x00F\x00I\x00\x00\x00'
reset() {
    rm -f "$V"/*
    var Boot0001 "$MACHINE"
    var Boot00A0 '\x01\x00\x00\x00\x00\x00K\x00a\x00\x00\x00'
    var Boot00B0 '\x01\x00\x00\x00\x00\x00K\x00b\x00\x00\x00'
    var BootOrder '\xb0\x00\x01\x00\xa0\x00'
    var BootNext '\xa0\x00'
}

echo "-- forget after a commit"
reset
"$T/efiboot" forget > "$T/out" 2>&1; rc=$?
check "forget succeeds" "$rc" "0"
check "BootOrder keeps the machine's own entry and nothing of Kryptik's" "$(data BootOrder)" "0100"
check "slot a's entry is gone" "$(data Boot00A0)" "absent"
check "slot b's entry is gone" "$(data Boot00B0)" "absent"
check "BootNext is gone" "$(data BootNext)" "absent"
check "the machine's own entry is untouched" "$(data Boot0001)" "01000000000055004500460049000000"
"$T/efiboot" forget > "$T/out" 2>&1; rc=$?
check "forget with nothing left to forget still succeeds" "$rc" "0"
check "and changes nothing" "$(data BootOrder)|$(data Boot0001)" "0100|01000000000055004500460049000000"

echo "-- forget when the order named only Kryptik"
rm -f "$V"/*; var Boot00A0 '\x01\x00\x00\x00\x00\x00K\x00a\x00\x00\x00'; var BootOrder '\xa0\x00'
"$T/efiboot" forget > "$T/out" 2>&1; rc=$?
check "forget succeeds" "$rc" "0"
check "an order left empty is deleted, for the firmware to regenerate" "$(data BootOrder)" "absent"

echo "-- forget on a firmware with no variables at all"
rm -f "$V"/*
"$T/efiboot" forget > "$T/out" 2>&1; rc=$?
check "forget succeeds" "$rc" "0"

echo "-- the machine's order survives arming and forgetting in any order"
reset; rm -f "$V/BootNext-$G"; var BootOrder '\x01\x00\xa0\x00\x02\x00\xb0\x00'; var Boot0002 "$MACHINE"
"$T/efiboot" forget > "$T/out" 2>&1
check "two machine entries keep their order with Kryptik's taken out between them" "$(data BootOrder)" "01000200"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
