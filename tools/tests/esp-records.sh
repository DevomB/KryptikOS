#!/usr/bin/env bash
# The ESP's records as the tools show them (build/service-scripts/esp-records.sh):
# in the shape Kryptik writes them, and as unknown otherwise. Then the writers,
# which every tool that writes the ESP uses.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/build/service-scripts/esp-records.sh"
PASS=0; FAIL=0
check() {
    if [[ "$2" == "$3" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1))
    else printf '  FAIL  %s (got %q, want %q)\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
rec() { printf '%b' "$1" > "$T/rec"; }   # rec BYTES: the record, backslash escapes read

echo "-- committed-slot"
rec 'a\n'; check "slot a" "$(esp_slot "$T/rec")" a
rec 'b'; check "slot b, written without a newline" "$(esp_slot "$T/rec")" b
rec 'c\n'; check "a letter that is no slot" "$(esp_slot "$T/rec")" unknown
rec '\033]0;owned\007a\n'; check "a terminal sequence before the slot" "$(esp_slot "$T/rec")" unknown
rec 'a\r\n'; check "a carriage return after it" "$(esp_slot "$T/rec")" unknown
rec 'a; reboot\n'; check "more on the line" "$(esp_slot "$T/rec")" unknown
rec ''; check "an empty record" "$(esp_slot "$T/rec")" unknown
check "no record" "$(esp_slot "$T/absent")" unknown
check "no record, read as the caller says" "$(esp_slot "$T/absent" none)" none

echo "-- version-a and version-b"
rec '1.0.0\n'; check "a release" "$(esp_version "$T/rec")" 1.0.0
rec '1.0.10'; check "a release, written without a newline" "$(esp_version "$T/rec")" 1.0.10
rec '0.1.20261007.1a2b3c4d\n'; check "a development build" "$(esp_version "$T/rec")" 0.1.20261007.1a2b3c4d
rec '0.1.20261007.1a2b3c4d.1\n'; check "the update suite's second build" "$(esp_version "$T/rec")" 0.1.20261007.1a2b3c4d.1
rec '1.0\n'; check "two parts" "$(esp_version "$T/rec")" unknown
rec '01.0.0\n'; check "a leading zero" "$(esp_version "$T/rec")" unknown
rec '9.9.9 (newest)\n'; check "words after a version" "$(esp_version "$T/rec")" unknown
rec '1.0.0\033[2J\n'; check "a terminal sequence after a version" "$(esp_version "$T/rec")" unknown
rec '\n1.0.0\n'; check "a version on the second line" "$(esp_version "$T/rec")" unknown
rec "$(printf '1.%.0s' $(seq 40))0\n"; check "a version longer than any release's" "$(esp_version "$T/rec")" unknown
rec ''; check "an empty record" "$(esp_version "$T/rec")" unknown
check "no record" "$(esp_version "$T/absent")" unknown
check "no record, read as the caller says" "$(esp_version "$T/absent" none)" none

echo "-- writing a record"
mkdir -p "$T/esp/kryptik"
esp_put "$T/esp/kryptik/committed-slot" b; rc=$?
check "a record is written whole, and no temporary is left" "$rc|$(cat "$T/esp/kryptik/committed-slot")|$(ls -A "$T/esp/kryptik")" "0|b|committed-slot"
# A temporary that cannot be made, as a full or read-only ESP refuses it: a directory in its place stops root too.
mkdir "$T/esp/kryptik/committed-slot.new"
esp_put "$T/esp/kryptik/committed-slot" a; rc=$?
check "a record that cannot be written fails, and the old one stays whole" "$([[ $rc -ne 0 ]] && echo failed)|$(cat "$T/esp/kryptik/committed-slot")" "failed|b"
rmdir "$T/esp/kryptik/committed-slot.new"

echo "-- placing a kernel"
printf 'kernel-b' > "$T/esp/kernel-b"; printf 'kernel-a' > "$T/esp/BOOTX64.EFI"
esp_place "$T/esp/kernel-b" "$T/esp/BOOTX64.EFI"; rc=$?
check "a kernel is copied into place, and no temporary is left" "$rc|$(cat "$T/esp/BOOTX64.EFI")|$([[ -e "$T/esp/BOOTX64.EFI.new" ]] && echo left || echo none)" "0|kernel-b|none"
printf 'kernel-a' > "$T/esp/BOOTX64.EFI"
cmp() { return 1; }   # the copy reads back from the device other than it was written
esp_place "$T/esp/kernel-b" "$T/esp/BOOTX64.EFI"; rc=$?
unset -f cmp
check "a copy that reads back wrong never takes the name, and its temporary goes" \
    "$([[ $rc -ne 0 ]] && echo failed)|$(cat "$T/esp/BOOTX64.EFI")|$([[ -e "$T/esp/BOOTX64.EFI.new" ]] && echo left || echo none)" "failed|kernel-a|none"

echo "-- every tool writes the records through esp_put"
own="$(grep -nE '>[[:space:]]*"[^"]*kryptik/(committed-slot|version-)' "$ROOT/tools/install/kryptik-install.sh" "$ROOT/tools/update/kryptik-update" \
    "$ROOT/tools/update/kryptik-recover" "$ROOT/build/service-scripts/boot-success.sh" | sed "s|$ROOT/||")"
check "no tool writes a record by a redirection of its own" "$own" ""

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
