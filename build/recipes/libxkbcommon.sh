#!/usr/bin/env bash

s_libxkbcommon() {
    meson_build "libxkbcommon-${V_LIBXKBCOMMON}.tar.gz" "libxkbcommon-xkbcommon-${V_LIBXKBCOMMON}" \
        -Denable-docs=false -Denable-x11=false -Denable-xkbregistry=false \
        -Denable-wayland=false -Denable-tools=false -Denable-bash-completion=false
}
