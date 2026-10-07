#!/usr/bin/env bash

s_eudev() {
    local src; src="$(unpack "eudev-${V_EUDEV}.tar.gz" "eudev-${V_EUDEV}")"
    cd "$src"
    ./configure --prefix=/usr --bindir=/usr/sbin --sysconfdir=/etc \
        --enable-manpages --disable-static
    make
    mkdir -pv /usr/lib/udev/rules.d
    mkdir -pv /etc/udev/rules.d
    make install
}
