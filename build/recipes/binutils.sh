#!/usr/bin/env bash

s_binutils_native() {
    local src; src="$(unpack "binutils-${V_BINUTILS}.tar.xz" "binutils-${V_BINUTILS}")"
    cd "$src"
    mkdir -p build && cd build
    # --with-stage1-ldflags=: the default static libgcc and libstdc++ (stage 02's) lack CET notes.
    ../configure --prefix=/usr --sysconfdir=/etc --enable-gold \
        --enable-ld=default --enable-plugins --enable-shared --disable-werror \
        --enable-64-bit-bfd --enable-new-dtags --with-system-zlib \
        --enable-default-hash-style=gnu --with-stage1-ldflags= --enable-gprofng=no
    make tooldir=/usr
    make tooldir=/usr install
    rm -fv /usr/lib/lib{bfd,ctf,ctf-nobfd,opcodes,sframe}.a
    # gcc searches stage 02's /usr/<triple> tools before PATH; tooldir=/usr put these in /usr/bin.
    local t; t="$(gcc -dumpmachine)"
    rm -rf "/usr/${t:?}"
    local p
    for p in as ld; do
        [[ "$(gcc -print-prog-name="$p")" == "$p" ]] \
            || { echo "FAIL: gcc runs $(gcc -print-prog-name="$p"), not the ${p} on PATH"; return 1; }
    done
}
