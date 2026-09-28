#!/usr/bin/env bash
# efiboot: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# The firmware side of the A/B trial: writes Boot#### and BootNext through
# efivarfs. Its source hash is an argument, so a source change rebuilds it.
s_efiboot() {
    local src="${KRYPTIK_ROOT}/tools/efi/kryptik-efiboot.c"
    [[ -f "$src" ]] || { echo "no source at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    # shellcheck disable=SC2086  # CFLAGS/LDFLAGS are deliberately word-split
    gcc $CFLAGS $LDFLAGS -std=gnu11 -Wall -Wextra -o /usr/sbin/kryptik-efiboot "$src"
    local out
    out="$(/usr/sbin/kryptik-efiboot 2>&1 || true)"
    case "$out" in *usage*) echo "ok: kryptik-efiboot runs" ;; *) echo "FAIL: kryptik-efiboot does not run: ${out}"; return 1 ;; esac
}
