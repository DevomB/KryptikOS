#!/bin/sh
# The net zone's own startup (Design 03/03a): the process kryptikd runs as
# the nic zone's command. Zone 0 moved the physical NIC and the uplink's
# addresses in and created the bridge kryptik0 (10.19.0.1/24, fd19::1/64);
# this is what runs behind that, inside the zone, with the CAP_NET_ADMIN the
# nic zone keeps:
#
#   nft      the policy, FIRST and atomically: routed zones (10.19.0.0/24)
#            masquerade out of the NIC; forwarding is allowed only
#            bridge -> NIC and established replies; nothing from the outside
#            reaches a zone unsolicited; zones cannot reach each other
#   forward  enabled only once the policy is loaded; disabled before, and
#            disabled again if the policy ever cannot be loaded
#   dhcpcd   takes over the uplink lease on the NIC (or keeps the carried
#            static configuration when there is no DHCP server)
#   dnsmasq  the resolver at 10.19.0.1 / fd19::1 that routed zones' resolv.conf
#            already names, forwarding to the uplink's servers
#
# FAIL CLOSED. The first version logged a failed nftables load and enabled
# forwarding anyway, which is a router with no firewall. Now: forwarding is
# off until the ruleset is loaded and checked, a ruleset that fails to load is
# retried without ever opening the path, and the readiness line says what is
# actually true. Readiness has three parts and each is reported on its own:
#
#   netzone: READY uplink=<addr|none> nat=yes dns=<yes|no>
#   netzone: NOT READY <reason>            (forwarding is off)
#
# A missing uplink address (no DHCP answer, nothing carried over) is reported
# and retried by dhcpcd itself; the firewall and the resolver do not wait for
# it, because nothing is exposed without an address anyway. Everything here
# is in the zone: a compromised net zone owns this script's effects and
# nothing outside its namespace (Design 03 "treated as hostile").
set -u
say() { echo "netzone: $*"; }
NIC="${1:-eth0}"
BR=kryptik0
STATUS=/run/netzone-status

forwarding() {   # forwarding on|off
    v=0; [ "$1" = on ] && v=1
    echo "$v" > /proc/sys/net/ipv4/ip_forward 2>/dev/null || return 1
    echo "$v" > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true
}
report() {   # report READY|NOT READY ...: on stdout and in a file for the tests
    say "$*"
    printf '%s\n' "$*" > "$STATUS.new" 2>/dev/null && mv -f "$STATUS.new" "$STATUS" 2>/dev/null || true
}

[ -d /proc/sys/net/ipv4 ] || { report "NOT READY no network stack"; exit 1; }
# Nothing forwards until the policy is in place - whatever zone 0 set.
forwarding off
ip link show "$NIC" >/dev/null 2>&1 || { report "NOT READY no uplink interface ${NIC} in this zone; zone 0 did not move it"; exit 1; }
ip link show "$BR" >/dev/null 2>&1 || { report "NOT READY no bridge ${BR}; zone 0 did not create it"; exit 1; }
command -v nft >/dev/null 2>&1 || { report "NOT READY no nft in this image; refusing to route without a firewall"; exit 1; }

RULES="table inet kryptik {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname \"${BR}\" oifname \"${NIC}\" accept
        iifname \"${BR}\" oifname \"${BR}\" drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname \"${NIC}\" ip saddr 10.19.0.0/24 masquerade
        oifname \"${NIC}\" ip6 saddr fd19::/64 masquerade
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname \"${NIC}\" ct state new tcp dport 53 drop
        iifname \"${NIC}\" ct state new udp dport 53 drop
    }
}"

# Load the ruleset atomically (one nft -f is one transaction), then read it
# back: the policy is what the kernel holds, not what we sent.
load_policy() {
    printf '%s\n' "$RULES" | nft -c -f - 2>/tmp/nft.err || { say "nftables: ruleset does not validate: $(tr '\n' ' ' < /tmp/nft.err)"; return 1; }
    nft flush ruleset 2>/dev/null || true
    printf '%s\n' "$RULES" | nft -f - 2>/tmp/nft.err || { say "nftables: load FAILED: $(tr '\n' ' ' < /tmp/nft.err)"; return 1; }
    live="$(nft list table inet kryptik 2>/dev/null)"
    case "$live" in
        *"policy drop"*"masquerade"*) ;;
        *) say "nftables: the loaded table is not the policy (missing drop policy or masquerade)"; nft flush ruleset 2>/dev/null; return 1 ;;
    esac
    return 0
}

policy_ok=0
if load_policy; then
    policy_ok=1
    forwarding on || { report "NOT READY cannot enable forwarding"; policy_ok=0; }
    [ "$policy_ok" = 1 ] && say "nftables: masquerade 10.19.0.0/24 and fd19::/64 via ${NIC}; forward bridge->uplink only; forwarding enabled"
else
    forwarding off
    report "NOT READY firewall policy did not load; forwarding stays off; retrying"
fi

# --- uplink: DHCP if anyone answers, else what zone 0 carried over ---------
# /run and /var/lib are this zone's own tmpfs mounts (kryptikd gives the nic
# zone both; every other zone's /run is read-only): dhcpcd's pid file and
# control socket, its lease database, and the files below live there. The
# first version of this zone had neither, and dhcpcd died on its pid file
# before it ever asked for a lease.
#
# dhcpcd runs as this zone's root WITHOUT its own privilege separation: the
# zone's passwd is synthesized (root and nobody), so the dhcpcd user it was
# built with does not exist here and it says so once, then carries on
# unseparated. The zone - its own user, mount, network and pid namespaces,
# seccomp and Landlock - is the sandbox; nothing dhcpcd could do reaches
# past it. That one line is filtered; every other error is kept.
uplink_addr() { ip -4 -o addr show "$NIC" 2>/dev/null | awk '{print $4}' | head -1; }
if command -v dhcpcd >/dev/null 2>&1; then
    mkdir -p /run/dhcpcd /var/lib/dhcpcd 2>/dev/null
    # -b: background at once and keep asking for as long as the zone runs;
    # -q: errors only; --nodev: no device manager in here. The resolv.conf
    # hook stays on: /etc/resolv.conf is this zone's own file (under /tmp),
    # and what dhcpcd writes there is what the resolver below forwards to.
    if dhcpcd -b -q --nodev "$NIC" 2>/tmp/dhcpcd.err; then
        grep -v 'no such user dhcpcd' /tmp/dhcpcd.err
        # Give the lease up to 15 s to arrive so the resolver starts with the
        # uplink's servers; a slower one is picked up by dhcpcd all the same.
        n=0
        while [ "$n" -lt 30 ] && [ -z "$(uplink_addr)" ]; do sleep 0.5; n=$((n+1)); done
        [ -n "$(uplink_addr)" ] && sleep 1   # let the hook finish resolv.conf
        say "dhcpcd on ${NIC}: uplink=$(uplink_addr || true)"
    else
        cat /tmp/dhcpcd.err
        say "dhcpcd did not start on ${NIC}; keeping the carried-over configuration"
    fi
else
    say "no dhcpcd; keeping the carried-over configuration"
fi

# --- the resolver routed zones already point at ----------------------------
DNSPID=""
start_dns() {
    command -v dnsmasq >/dev/null 2>&1 || { say "no dnsmasq; routed zones have no resolver"; return 1; }
    up=/run/uplink-resolv.conf
    # What the uplink gave us: dhcpcd's hook wrote /etc/resolv.conf from the
    # lease, or zone 0 carried a static one over. (printf, not ':', creates
    # the empty file: a redirection that fails on a special builtin ends a
    # POSIX sh outright, which is how this script once died on a read-only
    # /run without a word.)
    if [ -r /etc/resolv.conf ] && grep -q '^nameserver' /etc/resolv.conf; then
        grep '^nameserver' /etc/resolv.conf > "$up"
    else
        printf '' > "$up"
    fi
    # QEMU user networking's resolver, when nothing else is known
    grep -q '^nameserver' "$up" || echo "nameserver 10.0.2.3" >> "$up"
    dnsmasq --keep-in-foreground --no-daemon --no-hosts --bind-interfaces \
            --listen-address=10.19.0.1 --listen-address=fd19::1 --listen-address=127.0.0.1 \
            --resolv-file="$up" --no-poll --cache-size=1000 --local-service \
            --pid-file=/run/dnsmasq.pid --user=root &
    DNSPID=$!
    sleep 1
    if kill -0 "$DNSPID" 2>/dev/null; then
        say "dnsmasq listening on 10.19.0.1/fd19::1, forwarding to $(grep '^nameserver' "$up" | tr '\n' ' ')"
        return 0
    fi
    say "dnsmasq exited at once"; DNSPID=""; return 1
}
dns_ok=0
start_dns && dns_ok=1

status_line() {
    a="$(uplink_addr)"
    if [ "$policy_ok" = 1 ]; then
        report "READY uplink=${a:-none} nat=yes dns=$([ "$dns_ok" = 1 ] && echo yes || echo no) bridge=${BR} nic=${NIC}"
    else
        report "NOT READY firewall policy not loaded; forwarding off; uplink=${a:-none} dns=$([ "$dns_ok" = 1 ] && echo yes || echo no)"
    fi
}
status_line

# Stay up for as long as the zone runs; kryptikd stops us with SIGTERM. While
# up: retry a policy that failed to load (never opening the path before it
# does), restart the resolver if it dies, and re-report on changes.
cleanup() {
    say "stopping"
    forwarding off
    [ -n "$DNSPID" ] && kill "$DNSPID" 2>/dev/null
    command -v dhcpcd >/dev/null 2>&1 && dhcpcd -x 2>/dev/null
    exit 0
}
trap cleanup TERM INT
while :; do
    changed=0
    if [ "$policy_ok" != 1 ]; then
        if load_policy && forwarding on; then policy_ok=1; changed=1; say "nftables: policy loaded on retry; forwarding enabled"; fi
    elif ! nft list table inet kryptik >/dev/null 2>&1; then
        # The policy vanished from under us (a flush from inside the zone,
        # say): close the path and start again.
        forwarding off; policy_ok=0; changed=1; say "nftables: the policy is gone; forwarding disabled"
    fi
    if [ -n "$DNSPID" ] && ! kill -0 "$DNSPID" 2>/dev/null; then
        say "dnsmasq died; restarting"; DNSPID=""; dns_ok=0; changed=1
        start_dns && dns_ok=1
    fi
    [ "$changed" = 1 ] && status_line
    sleep 10 &
    wait $!
done
