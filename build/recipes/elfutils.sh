#!/usr/bin/env bash
# elfutils: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_elfutils() {
    local src; src="$(unpack "elfutils-${V_ELFUTILS}.tar.bz2" "elfutils-${V_ELFUTILS}")"
    cd "$src"
    ./configure --prefix=/usr --disable-debuginfod --enable-libdebuginfod=dummy
    make
    # Only libelf; the rest of elfutils is developer tooling.
    make -C libelf install
    install -vm644 config/libelf.pc /usr/lib/pkgconfig
    rm -fv /usr/lib/libelf.a
}
