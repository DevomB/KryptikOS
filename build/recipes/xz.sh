#!/usr/bin/env bash
# xz: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_xz_native() {
    native_build "xz-${V_XZ}.tar.xz" "xz-${V_XZ}" \
        --disable-static --docdir="/usr/share/doc/xz-${V_XZ}"
    rm -fv /usr/lib/liblzma.la
}
