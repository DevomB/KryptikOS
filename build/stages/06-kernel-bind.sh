#!/usr/bin/env bash
# Stage 06, chroot half: relink the kernel with a compiled-in command line.
#
#   03-chroot-prep.sh run /kryptik/build/stages/06-kernel-bind.sh VARIANT...
#
# For each VARIANT, /kryptik-work/images/cmdlines/VARIANT.txt holds the exact
# command line (one line). CONFIG_CMDLINE is set to it, bzImage is relinked
# (modules are untouched: nothing they depend on changes), and the result is
# written to /kryptik-work/images/kernels/VARIANT.efi. The host half signs it.
#
# Why this is a relink and not a config change in the fragment: the command
# line carries the verity root hash, which exists only after the root image
# is built from the very sysroot that holds this kernel's modules. Binding
# the hash into the kernel is what makes the root and the kernel one signed
# unit (Design 08).
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config
require_inside_chroot "stage 06 (kernel bind)" "iso"

KSRC="${KRYPTIK_WORK}/build/linux-${V_LINUX}"
CMDLINES="${KRYPTIK_WORK}/images/cmdlines"
KERNELS="${KRYPTIK_WORK}/images/kernels"
JOBS="${KRYPTIK_JOBS:-$(kryptik_default_jobs)}"
[[ -d "$KSRC" ]] || die "no kernel build tree at ${KSRC}; run make kernel first"
[[ -f "$KSRC/.config" ]] || die "no .config in ${KSRC}"
[[ "$#" -gt 0 ]] || die "usage: 06-kernel-bind.sh VARIANT..."
mkdir -p "$KERNELS"

cd "$KSRC"
grep -q '^CONFIG_CMDLINE_OVERRIDE=y' .config || die "CONFIG_CMDLINE_OVERRIDE is not set in the kernel config; the command line would not be bound"
grep -q '^CONFIG_EFI_STUB=y' .config || die "CONFIG_EFI_STUB is not set; the kernel is not a UEFI application"

for variant in "$@"; do
    f="${CMDLINES}/${variant}.txt"
    [[ -f "$f" ]] || die "no command line at ${f}"
    cmdline="$(head -1 "$f")"
    [[ ${#cmdline} -lt 1900 ]] || die "${variant}: command line is ${#cmdline} bytes; COMMAND_LINE_SIZE is 2048"
    log "binding ${variant}"
    dim "  $(printf '%s' "$cmdline" | sed 's/sha256 [0-9a-f]\{64\} [0-9a-f]*/sha256 <hash> <salt>/')"
    # scripts/config writes the value verbatim between quotes, so the inner
    # double quotes around dm-mod.create's value must arrive escaped.
    esc="${cmdline//\"/\\\"}"
    scripts/config --set-str CONFIG_CMDLINE "$esc"
    scripts/config --enable CONFIG_CMDLINE_BOOL
    scripts/config --enable CONFIG_CMDLINE_OVERRIDE
    make -s olddefconfig
    got="$(scripts/config --state CONFIG_CMDLINE)"
    [[ "$got" == "$cmdline" ]] || die "${variant}: .config holds a different command line:
  wanted: ${cmdline}
  got:    ${got}"
    make -s -j"$JOBS" bzImage
    out="${KERNELS}/${variant}.efi"
    cp arch/x86/boot/bzImage "$out"
    # The EFI stub keeps the built-in command line uncompressed; prove the
    # image carries this one and not the previous variant's.
    marker="${cmdline##* }"   # the last word is the variant tag (kryptik.slot=/kryptik.media=)
    if [[ "$(grep -a -c -F -- "$marker" "$out")" -lt 1 ]]; then
        die "${variant}: ${out} does not contain '${marker}'"
    fi
    if [[ "$(grep -a -c -F -- "root=/dev/dm-" "$out")" -lt 1 ]]; then
        die "${variant}: ${out} does not contain the root= setting"
    fi
    ok "${variant}: $(stat -c %s "$out") bytes, sha256 $(sha256_of "$out")"
done
