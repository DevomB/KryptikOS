#!/usr/bin/env bash

s_libcap() {
    local src; src="$(unpack "libcap-${V_LIBCAP}.tar.xz" "libcap-${V_LIBCAP}")"
    cd "$src"
    # Do not install the static libraries.
    sed -i '/install -m.*STA/d' libcap/Makefile
    make prefix=/usr lib=lib
    make prefix=/usr lib=lib install
}
