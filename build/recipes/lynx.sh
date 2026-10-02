#!/usr/bin/env bash

s_lynx() {
    local src; src="$(unpack "lynx${V_LYNX}.tar.bz2" "lynx${V_LYNX}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc/lynx --with-zlib --with-bzlib \
        --with-ssl --with-screen=ncursesw --enable-locale-charset \
        --datadir=/usr/share/doc/lynx
    make
    make install
    lynx -version | sed -n 1p
}
