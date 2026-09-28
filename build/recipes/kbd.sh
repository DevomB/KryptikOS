#!/usr/bin/env bash
# kbd: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_kbd() {
    local src; src="$(unpack "kbd-${V_KBD}.tar.xz" "kbd-${V_KBD}")"
    cd "$src"
    sed -i '/RESIZECONS_PROGS=/s/yes/no/' configure
    sed -i 's/resizecons.8 //' docs/man/man8/Makefile.in

    # --disable-tests: generating the test suite needs autom4te, and there is no
    # autoconf here.
    ./configure --prefix=/usr --disable-vlock --disable-tests
    make
    make install
}
