#!/usr/bin/env bash

s_libdrm() {
    meson_build "libdrm-${V_LIBDRM}.tar.xz" "libdrm-${V_LIBDRM}" \
        -Dudev=true -Dvalgrind=disabled -Dtests=false -Dcairo-tests=disabled \
        -Dman-pages=disabled -Dintel=disabled -Dradeon=disabled -Damdgpu=disabled \
        -Dnouveau=disabled -Dvmwgfx=disabled -Dfreedreno=disabled -Dvc4=disabled -Detnaviv=disabled
}
