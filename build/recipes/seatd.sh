#!/usr/bin/env bash

s_seatd() {
    meson_build "${V_SEATD}.tar.gz" "seatd-${V_SEATD}" \
        -Dlibseat-logind=disabled -Dlibseat-seatd=enabled -Dlibseat-builtin=disabled \
        -Dserver=enabled -Dexamples=disabled -Dman-pages=disabled
    seatd -v 2>&1 | head -1 || true
}
