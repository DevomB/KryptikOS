#!/usr/bin/env bash

s_wayland() {
    meson_build "wayland-${V_WAYLAND}.tar.xz" "wayland-${V_WAYLAND}" \
        -Ddocumentation=false -Dtests=false -Ddtd_validation=false
    wayland-scanner --version 2>&1 | sed -n 1p
}
