#!/usr/bin/env bash

s_dhcpcd() {
    local src; src="$(unpack "dhcpcd-${V_DHCPCD}.tar.xz" "dhcpcd-${V_DHCPCD}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib/dhcpcd \
        --dbdir=/var/lib/dhcpcd --runstatedir=/run --privsepuser=dhcpcd
    make
    make install
    dhcpcd --version | sed -n 1p
}
