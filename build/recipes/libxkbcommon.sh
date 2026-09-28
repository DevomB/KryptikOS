#!/usr/bin/env bash
# libxkbcommon: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_libxkbcommon() {
    meson_build "libxkbcommon-${V_LIBXKBCOMMON}.tar.gz" "libxkbcommon-xkbcommon-${V_LIBXKBCOMMON}" \
        -Denable-docs=false -Denable-x11=false -Denable-xkbregistry=false \
        -Denable-wayland=false -Denable-tools=false -Denable-bash-completion=false
}
