#!/bin/sh
# The net zone's own startup (Design 03/03a): the process kryptikd runs as
# the nic zone's command. Zone 0 moved the physical NIC and the uplink's
# addresses in, created the bridge kryptik0 (10.19.0.1/24, fd19::1/64) and
# enabled forwarding; this is what runs behind that, inside the zone, with
# the CAP_NET_ADMIN the nic zone keeps:
#
#   dhcpcd   takes over the uplink lease on the NIC (or keeps the carried
#            static configuration when there is no DHCP server)
#   nft      NAT: routed zones (10.19.0.0/24) masquerade out of the NIC;
#            forwarding is allowed only bridge -> NIC and established replies;
#            nothing from the outside reaches a zone unsolicited
#   dnsmasq  the resolver at 10.19.0.1 / fd19::1 that routed zones' resolv.conf
#            already names, forwarding to the uplink's servers
#
# Everything here is in the zone: a compromised net zone owns this script's
# effects and nothing outside its namespace (Design 03 "treated as hostile").
set -u
say() { echo "netzone: $*"; }
NIC="${1:-eth0}"
BR=kryptik0

[ -d /proc/sys/net/ipv4 ] || { say "no network stack"; exit 1; }
ip link show "$NIC" >/dev/null 2>&1 || { say "no uplink interface ${NIC} in this zone; zone 0 did not move it"; exit 1; }
ip link show "$BR" >/dev/null 2>&1 || { say "no bridge ${BR}; zone 0 did not create it"; exit 1; }

# --- uplink: DHCP if anyone answers, else what zone 0 carried over ---------
if command -v dhcpcd >/dev/null 2>&1; then
    mkdir -p /run/dhcpcd /var/lib/dhcpcd 2>/dev/null
    # -b background, -q quiet, --nohook resolv.conf: we own resolv.conf below.
    if dhcpcd -b -q -t 15 --nohook resolv.conf --nodev "$NIC" 2>/dev/null; then
        say "dhcpcd started on ${NIC}"
    else
        say "dhcpcd did not start on ${NIC}; keeping the carried-over configuration"
    fi
fi

# --- NAT and the forwarding policy ------------------------------------------
if command -v nft >/dev/null 2>&1; then
    nft -f - <<EOF
table inet kryptik {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "${BR}" oifname "${NIC}" accept
        iifname "${BR}" oifname "${BR}" drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "${NIC}" ip saddr 10.19.0.0/24 masquerade
        oifname "${NIC}" ip6 saddr fd19::/64 masquerade
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "${NIC}" ct state new tcp dport 53 drop
        iifname "${NIC}" ct state new udp dport 53 drop
    }
}
EOF
    if [ $? -eq 0 ]; then say "nftables: masquerade 10.19.0.0/24 and fd19::/64 via ${NIC}; forward bridge->uplink only"; else say "nftables FAILED to load; routed zones have no NAT"; fi
else
    say "no nft; routed zones are forwarded without NAT"
fi
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

# --- the resolver routed zones already point at ----------------------------
if command -v dnsmasq >/dev/null 2>&1; then
    up=/run/uplink-resolv.conf
    # what the uplink gave us (dhcpcd's lease) or what was carried over
    if [ -r /run/dhcpcd/resolv.conf ]; then cp /run/dhcpcd/resolv.conf "$up"
    elif [ -r /etc/resolv.conf ] && grep -q '^nameserver' /etc/resolv.conf; then cp /etc/resolv.conf "$up"
    else : > "$up"; fi
    # QEMU user networking's resolver, when nothing else is known
    grep -q '^nameserver' "$up" || echo "nameserver 10.0.2.3" >> "$up"
    dnsmasq --keep-in-foreground --no-daemon --no-hosts --bind-interfaces \
            --listen-address=10.19.0.1 --listen-address=fd19::1 --listen-address=127.0.0.1 \
            --resolv-file="$up" --no-poll --cache-size=1000 --local-service \
            --pid-file=/run/dnsmasq.pid --user=root &
    DNSPID=$!
    say "dnsmasq listening on 10.19.0.1/fd19::1, forwarding to $(grep '^nameserver' "$up" | tr '\n' ' ')"
else
    say "no dnsmasq; routed zones have no resolver"
    DNSPID=""
fi
say "ready: uplink ${NIC} ($(ip -4 -o addr show "$NIC" 2>/dev/null | awk '{print $4}' | tr '\n' ' ')) bridge ${BR}"
# Stay up for as long as the zone runs; kryptikd stops us with SIGTERM.
trap 'say "stopping"; [ -n "$DNSPID" ] && kill $DNSPID 2>/dev/null; command -v dhcpcd >/dev/null 2>&1 && dhcpcd -x 2>/dev/null; exit 0' TERM INT
if [ -n "$DNSPID" ]; then wait "$DNSPID"; else while :; do sleep 3600; done; fi
