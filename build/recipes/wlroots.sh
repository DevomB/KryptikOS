#!/usr/bin/env bash
# wlroots: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# wlroots with the pixman renderer only: GLES2, Vulkan and GBM need Mesa and
# LLVM. The DRM backend uses dumb buffers, which virtio-gpu and simpledrm have.
s_wlroots() {
    meson_build "wlroots-${V_WLROOTS}.tar.gz" "wlroots-${V_WLROOTS}" \
        -Dxwayland=disabled -Dexamples=false -Drenderers=[] -Dallocators=[] \
        -Dbackends=drm,libinput -Dsession=enabled -Dxcb-errors=disabled -Dlibliftoff=disabled
    pkg-config --modversion "wlroots-${V_WLROOTS%.*}"
}
