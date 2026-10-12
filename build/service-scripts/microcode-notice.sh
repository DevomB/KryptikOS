#!/bin/sh
# A line on the login prompt when the kernel refused this processor's microcode. An AMD processor
# whose firmware predates AMD's 2025 fix for microcode signatures takes only a patch whose SHA-256
# the kernel holds (arch/x86/kernel/cpu/microcode/amd.c), and otherwise keeps the firmware's own
# microcode: without this, only the kernel log would say so.
notice="${KRYPTIK_MICROCODE_NOTICE:-/run/issue.d/kryptik-microcode.issue}"
if dmesg 2>/dev/null | grep -q 'microcode: No sha256 digest for patch ID'; then
    mkdir -p "${notice%/*}"
    echo "kryptik: this processor runs its firmware's older microcode: the kernel refused Kryptik's, as the machine's firmware predates AMD's 2025 fix for microcode signatures. Update the machine's firmware (BIOS)." > "$notice"
    echo "microcode-notice: the kernel refused this processor's microcode; the login prompt says so"
else
    rm -f "$notice"
fi
# Always 0: sysinit runs under sh -e.
exit 0
