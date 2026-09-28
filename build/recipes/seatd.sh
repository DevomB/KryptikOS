#!/usr/bin/env bash
# seatd: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_seatd() {
    meson_build "${V_SEATD}.tar.gz" "seatd-${V_SEATD}" \
        -Dlibseat-logind=disabled -Dlibseat-seatd=enabled -Dlibseat-builtin=disabled \
        -Dserver=enabled -Dexamples=disabled -Dman-pages=disabled
    seatd -v 2>&1 | head -1 || true
}
