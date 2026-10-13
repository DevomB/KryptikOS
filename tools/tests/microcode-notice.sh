#!/usr/bin/env bash
# Tests for build/service-scripts/microcode-notice.sh, sourced as sysinit sources it: the login
# prompt names microcode the kernel refused, and says nothing once none was. Offline, with dmesg
# stood in for.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/build/service-scripts/microcode-notice.sh"
SYSINIT="${ROOT}/build/service-scripts/sysinit.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

mkdir -p "$T/bin"
printf '#!/bin/sh\ncat "%s/kernel.log"\n' "$T" > "$T/bin/dmesg"
chmod +x "$T/bin/dmesg"
NOTICE="$T/issue.d/kryptik-microcode.issue"
boot() {   # boot SHELL LOG-LINE...: microcode_notice under SHELL, with that kernel log
    local sh="$1"; shift
    printf '%s\n' "$@" > "$T/kernel.log"
    PATH="$T/bin:$PATH" MICROCODE_NOTICE="$NOTICE" "$sh" -c '. "$1"; microcode_notice' sh "$SCRIPT" > "$T/said" 2>&1
}

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    echo "-- ${sh}"
    rm -rf "$T/issue.d"
    # amd.c's line on a Zen 5 whose firmware predates the fix, as each CPU logs it.
    boot "$sh" '[    0.000000] microcode: Current revision: 0x0b404023' \
        '[    0.000000] microcode: No sha256 digest for patch ID: 0xb404108 found' \
        '[    0.412345] microcode: No sha256 digest for patch ID: 0xb404108 found'; rc=$?
    if [[ "$rc" -eq 0 ]] && grep -qx "kryptik microcode: the kernel refused this processor's microcode, as the machine's firmware predates AMD's 2025 fix for microcode signatures, so it runs the firmware's older one: update the machine's firmware (BIOS)" "$NOTICE" 2>/dev/null \
       && grep -q 'login prompt says so' "$T/said"; then
        green "a refused patch is named on the login prompt and the console"
    else
        red "a refused patch" "exit ${rc}; notice: $(cat "$NOTICE" 2>&1); said: $(cat "$T/said")"
    fi
    [[ "$(wc -l < "$NOTICE" 2>/dev/null)" -eq 1 ]] && green "one line however many CPUs logged it" || red "one line" "$(cat "$NOTICE" 2>&1)"

    # Microcode applied (or none to apply, as in a virtual machine): no notice, and the last
    # boot's is gone.
    boot "$sh" '[    0.000000] microcode: Current revision: 0x0b404023' \
        '[    0.000000] microcode: Updated early from: 0x0b404023'; rc=$?
    [[ "$rc" -eq 0 && ! -e "$NOTICE" && ! -s "$T/said" ]] && green "applied microcode leaves no notice, and clears an old one" \
        || red "applied microcode" "exit ${rc}; notice: $(cat "$NOTICE" 2>&1); said: $(cat "$T/said")"

    # A kernel log it cannot read is not a refusal, and the function returns 0.
    printf '#!/bin/sh\nexit 1\n' > "$T/bin/dmesg"
    boot "$sh"; rc=$?
    printf '#!/bin/sh\ncat "%s/kernel.log"\n' "$T" > "$T/bin/dmesg"
    [[ "$rc" -eq 0 && ! -e "$NOTICE" ]] && green "an unreadable kernel log names nothing, and returns 0" \
        || red "an unreadable kernel log" "exit ${rc}; notice: $(cat "$NOTICE" 2>&1)"
done

# sysinit runs under sh -e: it sources the file and calls the function where a failure is let pass.
if grep -qxF '. /usr/libexec/kryptik/microcode-notice.sh' "$SYSINIT" && grep -qxF 'microcode_notice || true' "$SYSINIT"; then
    green "sysinit sources it and calls it before the first login prompt"
else
    red "sysinit does not source microcode-notice.sh and call microcode_notice || true"
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
