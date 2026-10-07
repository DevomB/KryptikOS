#!/usr/bin/env bash

s_kbd() {
    local src; src="$(unpack "kbd-${V_KBD}.tar.xz" "kbd-${V_KBD}")"
    cd "$src"
    sed -i '/RESIZECONS_PROGS=/s/yes/no/' configure
    sed -i 's/resizecons.8 //' docs/man/man8/Makefile.in

    # --disable-tests: generating the test suite needs autom4te, and there is no autoconf.
    ./configure --prefix=/usr --disable-vlock --disable-tests
    make
    make install
}
