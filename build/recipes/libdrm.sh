#!/usr/bin/env bash
# libdrm: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_libdrm() {
    meson_build "libdrm-${V_LIBDRM}.tar.xz" "libdrm-${V_LIBDRM}" \
        -Dudev=true -Dvalgrind=disabled -Dtests=false -Dcairo-tests=disabled \
        -Dman-pages=disabled -Dintel=disabled -Dradeon=disabled -Damdgpu=disabled \
        -Dnouveau=disabled -Dvmwgfx=disabled -Dfreedreno=disabled -Dvc4=disabled -Detnaviv=disabled
}
