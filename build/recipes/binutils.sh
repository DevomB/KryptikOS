#!/usr/bin/env bash
# binutils: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_binutils_native() {
    local src; src="$(unpack "binutils-${V_BINUTILS}.tar.xz" "binutils-${V_BINUTILS}")"
    cd "$src"
    mkdir -p build && cd build
    # --with-stage1-ldflags= : the shared top-level configure would link the
    # programs with -static-libgcc -static-libstdc++, whose objects (stage
    # 02's) carry no CET note, and ld would drop it from ld, as and the rest.
    # No gprofng, a profiler nothing here uses.
    ../configure --prefix=/usr --sysconfdir=/etc --enable-gold \
        --enable-ld=default --enable-plugins --enable-shared --disable-werror \
        --enable-64-bit-bfd --enable-new-dtags --with-system-zlib \
        --enable-default-hash-style=gnu --with-stage1-ldflags= --enable-gprofng=no
    make tooldir=/usr
    make tooldir=/usr install
    rm -fv /usr/lib/lib{bfd,ctf,ctf-nobfd,opcodes,sframe}.a
    # Stage 02's binutils went into the target's tool directory, which gcc
    # searches before PATH; tooldir=/usr put these in /usr/bin instead.
    local t; t="$(gcc -dumpmachine)"
    rm -rf "/usr/${t:?}"
    local p
    for p in as ld; do
        [[ "$(gcc -print-prog-name="$p")" == "$p" ]] \
            || { echo "FAIL: gcc runs $(gcc -print-prog-name="$p"), not the ${p} on PATH"; return 1; }
    done
}
