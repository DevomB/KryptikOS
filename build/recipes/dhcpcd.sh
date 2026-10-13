#!/usr/bin/env bash

s_dhcpcd() {
    local src; src="$(unpack "dhcpcd-${V_DHCPCD}.tar.xz" "dhcpcd-${V_DHCPCD}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib/dhcpcd \
        --dbdir=/var/lib/dhcpcd --runstatedir=/run --privsepuser=dhcpcd
    make
    make install
    # Kryptik's own in place of the sample, which sends a DUID made from a hardware address:
    # RFC 7844's anonymity profile, so a network learns no hostname and no vendor class, and a
    # client ID made from the address the interface has when it asks, which Wi-Fi sets per
    # network. The options the net zone reads are asked for again after it.
    cat > /etc/dhcpcd.conf <<'EOF'
# The net zone's dhcpcd (docs/design/net-zone.md).
persistent
anonymous
option domain_name_servers, classless_static_routes, interface_mtu
require dhcp_server_identifier
slaac private
EOF
    dhcpcd --version | sed -n 1p
}
