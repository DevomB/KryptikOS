#!/bin/sh
# A line on the login prompt when the kernel refused this processor's microcode. An AMD processor
# whose firmware predates AMD's 2025 fix for microcode signatures takes only a patch whose SHA-256
# the kernel holds (arch/x86/kernel/cpu/microcode/amd.c), and otherwise keeps the firmware's own
# microcode: without this, only the kernel log would say so. POSIX sh, sourced by sysinit.
#   microcode_notice   write the notice when the kernel log has a refusal, else remove it

MICROCODE_NOTICE="${MICROCODE_NOTICE:-/run/issue.d/kryptik-microcode.issue}"

microcode_notice() {
    if dmesg 2>/dev/null | grep -q 'microcode: No sha256 digest for patch ID'; then
        mkdir -p "${MICROCODE_NOTICE%/*}"
        echo "kryptik microcode: the kernel refused this processor's microcode, as the machine's firmware predates AMD's 2025 fix for microcode signatures, so it runs the firmware's older one: update the machine's firmware (BIOS)" > "$MICROCODE_NOTICE"
        echo "sysinit: the kernel refused this processor's microcode; the login prompt says so"
    else
        rm -f "$MICROCODE_NOTICE"
    fi
}
