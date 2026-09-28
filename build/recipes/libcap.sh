#!/usr/bin/env bash
# libcap: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_libcap() {
    local src; src="$(unpack "libcap-${V_LIBCAP}.tar.xz" "libcap-${V_LIBCAP}")"
    cd "$src"
    # Do not install the static libraries.
    sed -i '/install -m.*STA/d' libcap/Makefile
    make prefix=/usr lib=lib
    make prefix=/usr lib=lib install
}
