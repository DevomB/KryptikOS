#!/usr/bin/env bash
# dhcpcd: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_dhcpcd() {
    local src; src="$(unpack "dhcpcd-${V_DHCPCD}.tar.xz" "dhcpcd-${V_DHCPCD}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib/dhcpcd \
        --dbdir=/var/lib/dhcpcd --runstatedir=/run --privsepuser=dhcpcd
    make
    make install
    dhcpcd --version | sed -n 1p
}
