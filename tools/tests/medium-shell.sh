#!/usr/bin/env bash
# The test "this is an install medium", as the console wrapper, the tty1 getty
# and the control-disk reader each make it, against the four command lines
# stage 06 signs: a medium gets the root shell, an installed slot the login
# prompt. Offline.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# As 06-iso.sh writes them; the verity table is one long quoted word.
common='ro rootwait console=tty0 console=ttyS0,115200 panic=10 loglevel=4 mitigations=auto,nosmt pti=on page_alloc.shuffle=1 hash_pointers=always nosmt'
table='0 3145728 verity 1 PARTLABEL=kryptik-media PARTLABEL=kryptik-media 4096 4096 393216 393216 sha256 ab12 cd34 1 panic_on_corruption'
printf 'dm-mod.waitfor=PARTLABEL=kryptik-media dm-mod.create="kroot,,0,ro,%s" root=/dev/dm-0 %s kryptik.media=usb\n' "$table" "$common" > "$T/usb"
printf 'dm-mod.create="kmedia,,0,ro,0 6291456 linear /dev/sr0 1234;kroot,,1,ro,%s" root=/dev/dm-1 %s kryptik.media=iso\n' "$table" "$common" > "$T/iso"
printf 'dm-mod.waitfor=PARTLABEL=kryptik-a dm-mod.create="kroot,,0,ro,%s" root=/dev/dm-0 %s kryptik.slot=a\n' "$table" "$common" > "$T/slot-a"
printf 'dm-mod.waitfor=PARTLABEL=kryptik-b dm-mod.create="kroot,,0,ro,%s" root=/dev/dm-0 %s kryptik.slot=b\n' "$table" "$common" > "$T/slot-b"

first=""
for f in build/recipes/console.sh build/services/getty-tty1/run build/service-scripts/testctl.sh; do
    # The file's own grep, its file argument left off.
    cmd="$(sed -n "s|.*\(grep -q[A-Za-z]* '[^']*kryptik[^']*'\) /proc/cmdline.*|\1|p" "${ROOT}/${f}")"
    if [[ "$(grep -c . <<<"$cmd")" -ne 1 ]]; then red "${f}: one test of /proc/cmdline for kryptik.media expected, found: ${cmd:-none}"; continue; fi
    [[ -z "$first" ]] && first="$cmd"
    [[ "$cmd" == "$first" ]] && green "${f}: the same test as the others" || red "${f}: its test differs: ${cmd}"
    for line in usb iso; do
        if eval "$cmd" '"$T/$line"'; then green "${f}: the ${line} medium's command line is a medium's"; else red "${f}: the ${line} medium is not seen as one"; fi
    done
    for line in slot-a slot-b; do
        if eval "$cmd" '"$T/$line"'; then red "${f}: an installed ${line} is taken for a medium"; else green "${f}: an installed ${line} is not a medium"; fi
    done
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
