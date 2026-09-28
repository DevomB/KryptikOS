#!/usr/bin/env bash
# wayland: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_wayland() {
    meson_build "wayland-${V_WAYLAND}.tar.xz" "wayland-${V_WAYLAND}" \
        -Ddocumentation=false -Dtests=false -Ddtd_validation=false
    wayland-scanner --version 2>&1 | sed -n 1p
}
