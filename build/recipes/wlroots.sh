#!/usr/bin/env bash

# The pixman renderer only, as the others need Mesa; virtio-gpu and simpledrm take dumb buffers.
s_wlroots() {
    meson_build "wlroots-${V_WLROOTS}.tar.gz" "wlroots-${V_WLROOTS}" \
        -Dxwayland=disabled -Dexamples=false -Drenderers=[] -Dallocators=[] \
        -Dbackends=drm,libinput -Dsession=enabled -Dxcb-errors=disabled -Dlibliftoff=disabled
    pkg-config --modversion "wlroots-${V_WLROOTS%.*}"
}
