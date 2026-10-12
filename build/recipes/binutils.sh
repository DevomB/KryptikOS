#!/usr/bin/env bash

s_binutils_native() {
    local src; src="$(unpack "binutils-${V_BINUTILS}.tar.xz" "binutils-${V_BINUTILS}")"
    cd "$src"
    mkdir -p build && cd build
    # --with-stage1-ldflags=: the default static libgcc and libstdc++ (stage 02's) lack CET notes.
    # No gold: nothing selects it, and binutils drops it from 2.44.
    ../configure --prefix=/usr --sysconfdir=/etc \
        --enable-ld=default --enable-plugins --enable-shared --disable-werror \
        --enable-64-bit-bfd --enable-new-dtags --with-system-zlib \
        --enable-default-hash-style=gnu --with-stage1-ldflags= --enable-gprofng=no
    make tooldir=/usr
    make tooldir=/usr install
    rm -fv /usr/lib/lib{bfd,ctf,ctf-nobfd,opcodes,sframe}.a
    # A cached sysroot still holds what a build with gold installed.
    rm -fv /usr/bin/ld.gold /usr/bin/dwp
    # gcc searches stage 02's /usr/<triple> tools before PATH; tooldir=/usr put these in /usr/bin.
    local t; t="$(gcc -dumpmachine)"
    rm -rf "/usr/${t:?}"
    local p
    for p in as ld; do
        [[ "$(gcc -print-prog-name="$p")" == "$p" ]] \
            || { echo "FAIL: gcc runs $(gcc -print-prog-name="$p"), not the ${p} on PATH"; return 1; }
    done
}
