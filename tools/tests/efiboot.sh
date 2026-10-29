#!/usr/bin/env bash
# kryptik-efiboot, built with stand-ins for its EFIVARS, SYSBLOCK and DEVICES paths, and for blkid.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
V="$T/efivars"; mkdir -p "$V" "$T/bin" "$T/sys/esp1"
G=8be4df61-93ca-11d2-aa0d-00e098032b8c
if gcc -std=gnu11 -Wall -Wextra -DEFIVARS="\"$V/\"" -DSYSBLOCK="\"$T/sys/\"" -DDEVICES="\"$T/devices.sh\"" \
       -o "$T/efiboot" "$ROOT/tools/efi/kryptik-efiboot.c"; then
    ok "the tool compiles with its paths overridden"
else
    bad "the tool compiles with its paths overridden"; exit 1
fi

# The ESP is /dev/esp1, partition 1, labelled kryptik-esp; any other device has another label.
printf '#!/bin/sh\n[ "$1 $2" = "part kryptik-esp" ] && echo /dev/esp1\n' > "$T/devices.sh"
cat > "$T/bin/blkid" <<'EOF'
#!/bin/sh
# blkid -s TAG -o value DEV
case "$2" in
    PARTUUID) echo 0f2c1a3b-4d5e-6f70-8192-a3b4c5d6e7f8 ;;
    PARTLABEL) if [ "$5" = /dev/esp1 ]; then echo kryptik-esp; else echo other; fi ;;
esac
EOF
chmod +x "$T/devices.sh" "$T/bin/blkid"
echo 2048 > "$T/sys/esp1/start"; echo 1048576 > "$T/sys/esp1/size"; echo 1 > "$T/sys/esp1/partition"
efiboot() { PATH="$T/bin:$PATH" "$T/efiboot" "$@"; }

# var NAME BYTES: an efivarfs file, attributes 0x7 then BYTES as a printf format (\xNN is a byte).
var() { printf '\x07\x00\x00\x00'"$2" > "$V/$1-$G"; }
# data NAME: the variable's data as hex, or "absent".
data() { if [[ -f "$V/$1-$G" ]]; then od -An -tx1 -j4 -v "$V/$1-$G" | tr -d ' \n'; else echo absent; fi; }
# ucs2 TEXT: TEXT in UCS-2 with its terminator, as a printf format.
ucs2() { local s="$1" i out=""; for ((i = 0; i < ${#s}; i++)); do out+="$(printf '\\x%02x\\x00' "'${s:i:1}")"; done; printf '%s' "$out\\x00\\x00"; }
# opt DESC FILE: an active load option whose path is only FILE, as a printf format.
opt() {
    local fl=$(( 4 + 2 * (${#2} + 1) ))
    printf '\\x01\\x00\\x00\\x00\\x%02x\\x%02x%s\\x04\\x04\\x%02x\\x%02x%s\\x7f\\xff\\x04\\x00' \
        $(( (fl + 4) & 255 )) $(( (fl + 4) >> 8 )) "$(ucs2 "$1")" $(( fl & 255 )) $(( fl >> 8 )) "$(ucs2 "$2")"
}
# netopt DESC: an active load option that boots from the network (a MAC node), as a printf format.
netopt() { printf '\\x01\\x00\\x00\\x00\\x29\\x00%s\\x03\\x0b\\x25\\x00%s\\x01\\x7f\\xff\\x04\\x00' "$(ucs2 "$1")" "$(printf '\\x00%.0s' $(seq 32))"; }
KA="$(opt 'Kryptik slot a' '\EFI\kryptik\kryptik-a.efi')"
KB="$(opt 'Kryptik slot b' '\EFI\kryptik\kryptik-b.efi')"
WIN="$(opt 'Windows Boot Manager' '\EFI\Microsoft\Boot\bootmgfw.efi')"
# The machine's disk entry, both slot entries, slot b ahead of the disk in BootOrder, BootNext a.
MACHINE='\x01\x00\x00\x00\x00\x00U\x00E\x00F\x00I\x00\x00\x00'
reset() {
    rm -f "$V"/*
    var Boot0001 "$MACHINE"
    var Boot00A0 "$KA"
    var Boot00B0 "$KB"
    var BootOrder '\xb0\x00\x01\x00\xa0\x00'
    var BootNext '\xa0\x00'
}

echo "-- forget after a commit"
reset
efiboot forget > "$T/out" 2>&1; rc=$?
check "forget succeeds" "$rc" "0"
check "BootOrder keeps the machine's own entry and nothing of Kryptik's" "$(data BootOrder)" "0100"
check "slot a's entry is gone" "$(data Boot00A0)" "absent"
check "slot b's entry is gone" "$(data Boot00B0)" "absent"
check "BootNext is gone" "$(data BootNext)" "absent"
check "the machine's own entry is untouched" "$(data Boot0001)" "01000000000055004500460049000000"
efiboot forget > "$T/out" 2>&1; rc=$?
check "forget with nothing left to forget still succeeds" "$rc" "0"
check "and changes nothing" "$(data BootOrder)|$(data Boot0001)" "0100|01000000000055004500460049000000"

echo "-- forget when the order named only Kryptik"
rm -f "$V"/*; var Boot00A0 "$KA"; var BootOrder '\xa0\x00'
efiboot forget > "$T/out" 2>&1; rc=$?
check "forget succeeds" "$rc" "0"
check "an order left empty is deleted, for the firmware to regenerate" "$(data BootOrder)" "absent"

echo "-- forget on a firmware with no variables at all"
rm -f "$V"/*
efiboot forget > "$T/out" 2>&1; rc=$?
check "forget succeeds" "$rc" "0"

echo "-- the machine's order survives arming and forgetting in any order"
reset; rm -f "$V/BootNext-$G"; var BootOrder '\x01\x00\xa0\x00\x02\x00\xb0\x00'; var Boot0002 "$MACHINE"
efiboot forget > "$T/out" 2>&1
check "two machine entries keep their order with Kryptik's taken out between them" "$(data BootOrder)" "01000200"

echo "-- another system's entry on Kryptik's number"
rm -f "$V"/*; var Boot0001 "$MACHINE"; var Boot00A0 "$WIN"; var BootOrder '\x01\x00\xa0\x00'
win="$(data Boot00A0)"
efiboot set-next a > "$T/out" 2>&1; rc=$?
check "set-next succeeds" "$rc" "0"
check "the other system's Boot00A0 is not overwritten" "$(data Boot00A0)" "$win"
check "slot a's entry takes the next free number" "$(efiboot list | grep -cF 'Boot00A1: Kryptik slot a  file=\EFI\kryptik\kryptik-a.efi')" "1"
check "BootNext names it" "$(data BootNext)" "a100"
check "BootOrder gains it at the end" "$(data BootOrder)" "0100a000a100"
efiboot ensure a > "$T/out" 2>&1
check "arming again reuses it" "$(grep -c 'Boot00A1 already points at' "$T/out")|$(find "$V" -name 'Boot00A?-*' | wc -l)" "1|2"
efiboot forget > "$T/out" 2>&1; rc=$?
check "forget succeeds" "$rc" "0"
check "forget removes Kryptik's entry wherever it is" "$(data Boot00A1)" "absent"
check "and leaves the other system's entry and its place in BootOrder" "$(data Boot00A0)|$(data BootOrder)" "$win|0100a000"
check "BootNext, which named Kryptik's entry, is gone" "$(data BootNext)" "absent"

echo "-- entries Kryptik did not make"
rm -f "$V"/*; var Boot00A0 "$(opt 'Kryptik slot a' '\EFI\other\grubx64.efi')"; var Boot00B0 "$WIN"
var BootOrder '\xa0\x00\xb0\x00'; var BootNext '\xb0\x00'
a0="$(data Boot00A0)"
efiboot forget > "$T/out" 2>&1
check "an entry is Kryptik's only if its description and its file both say so" "$(data Boot00A0)|$(data BootOrder)" "$a0|a000b000"
check "a BootNext that names another system's entry is left alone" "$(data BootNext)" "b000"
rm -f "$V"/*; var BootNext '\x05\x00'
efiboot forget > "$T/out" 2>&1
check "a BootNext that names no entry at all goes" "$(data BootNext)" "absent"

echo "-- ensure on a named partition (kryptik-recover, from a medium)"
rm -f "$V"/*
efiboot ensure b /dev/esp1 > "$T/out" 2>&1; rc=$?
check "ensure with a kryptik-esp partition named succeeds" "$rc" "0"
check "slot b's entry is Boot00B0, on it" "$(efiboot list | grep -cF 'Boot00B0: Kryptik slot b  file=\EFI\kryptik\kryptik-b.efi')|$(data BootOrder)" "1|b000"
rm -f "$V"/*
efiboot ensure b /dev/sdz9 > "$T/out" 2>&1; rc=$?
check "a partition without the kryptik-esp label is refused, and nothing is written" "$rc|$(grep -c 'is not a kryptik-esp partition' "$T/out")|$(find "$V" -type f | wc -l)" "1|1|0"

echo "-- a new entry goes ahead of network boot, never ahead of another system's"
NET="$(netopt 'IPv4 Network')"
rm -f "$V"/*; var Boot0000 "$WIN"; var Boot0001 "$MACHINE"; var Boot0002 "$NET"; var Boot0003 "$NET"
var BootOrder '\x00\x00\x01\x00\x02\x00\x03\x00'
efiboot ensure a > "$T/out" 2>&1; rc=$?
check "ensure succeeds" "$rc" "0"
check "slot a's entry goes after the disks and ahead of both network entries" "$(data BootOrder)" "00000100a00002000300"
rm -f "$V"/*; var Boot0000 "$WIN"; var Boot0002 "$NET"; var BootOrder '\x02\x00\x00\x00'
efiboot ensure a > "$T/out" 2>&1
check "but behind another system's entry listed after the network" "$(data BootOrder)" "02000000a000"
rm -f "$V"/*; var Boot0002 "$NET"; var BootOrder '\x02\x00'
efiboot ensure a > "$T/out" 2>&1
check "and first in an order of network boot alone" "$(data BootOrder)" "a0000200"

echo "-- keep: the committed slot's entry where Kryptik's stood"
# The trial's entry went in after slot a's; committed, slot b takes the place slot a had.
rm -f "$V"/*; var Boot0001 "$MACHINE"; var Boot0002 "$NET"; var Boot00A0 "$KA"; var BootOrder '\x01\x00\xa0\x00\x02\x00'
efiboot set-next b > "$T/out" 2>&1
check "a trial's entry goes behind the committed one, ahead of the network" "$(data BootOrder)" "0100a000b0000200"
efiboot keep b > "$T/out" 2>&1; rc=$?
check "keep succeeds" "$rc" "0"
check "slot b's entry stands where slot a's did, and slot a's is gone" "$(data BootOrder)|$(data Boot00A0)|$(data BootNext)" "0100b0000200|absent|absent"
check "slot b's entry is Boot00B0" "$(efiboot list | grep -cF 'Boot00B0: Kryptik slot b  file=\EFI\kryptik\kryptik-b.efi')" "1"
# Moved first in the firmware's setup, it stays first.
rm -f "$V"/*; var Boot0000 "$WIN"; var Boot0001 "$MACHINE"; var Boot00A0 "$KA"; var BootOrder '\xa0\x00\x00\x00\x01\x00'
efiboot keep a > "$T/out" 2>&1
check "an entry the user moved first stays first" "$(data BootOrder)" "a00000000100"
rm -f "$V"/*; var Boot0001 "$MACHINE"; var Boot0002 "$NET"; var BootOrder '\x01\x00\x02\x00'
efiboot keep a > "$T/out" 2>&1
check "with no Kryptik entry in the order it goes where ensure puts one" "$(data BootOrder)" "0100a0000200"
rm -f "$V"/*; var Boot0001 "$MACHINE"; var Boot00A0 "$KA"; var BootOrder '\x01\x00\xa0\x00'
efiboot keep b /dev/sdz9 > "$T/out" 2>&1; rc=$?
check "an entry that cannot be made exits 3, with Kryptik's others forgotten" "$rc|$(data BootOrder)|$(data Boot00A0)" "3|0100|absent"
efiboot keep c > "$T/out" 2>&1; rc=$?
check "a slot other than a or b is refused before anything is forgotten" "$rc|$(data BootOrder)" "2|0100"

echo "-- an order longer than 254 entries"
# 300 of the machine's own numbers, 0x1000 up: past the 508 bytes a 512-byte read held.
rm -f "$V"/*; long=""; want=""
for k in $(seq 0 299); do
    n=$(( 0x1000 + k ))
    long+="$(printf '\\x%02x\\x%02x' $(( n & 255 )) $(( n >> 8 )))"; want+="$(printf '%02x%02x' $(( n & 255 )) $(( n >> 8 )))"
done
var BootOrder "$long"
efiboot ensure a > "$T/out" 2>&1; rc=$?
check "ensure succeeds" "$rc" "0"
check "the order keeps all 300 and gains slot a's entry at its end" "$(data BootOrder)" "${want}a000"
efiboot forget > "$T/out" 2>&1; rc=$?
check "forget takes out Kryptik's entry and gives back all 300" "$rc|$(data BootOrder)" "0|${want}"
check "list names the last of them" "$(efiboot list | grep -c ' Boot112B$')" "1"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
