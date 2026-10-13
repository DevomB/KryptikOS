#!/usr/bin/env bash

s_xz_native() {
    native_build "xz-${V_XZ}.tar.xz" "xz-${V_XZ}" \
        --disable-static --docdir="/usr/share/doc/xz-${V_XZ}"
    rm -fv /usr/lib/liblzma.la
}
