#!/bin/sh
# The net zone's own startup (docs/design/net-zone.md): the process kryptikd runs as
# the nic zone's command. Zone 0 moved every physical interface in - wired
# ones by the netdev, wireless ones by their wiphy - with the uplink's
# addresses, and created the bridge kryptik0 (10.19.0.1/24, fd19::1/64);
# this is what runs behind that, inside the zone, with the CAP_NET_ADMIN the
# nic zone keeps:
#
#   uplinks  discovered here, not named: every interface that sits on a bus
#            device (/sys/class/net/<n>/device exists), which is the rule
#            kryptikd used to decide what to move. A radio is an uplink with
#            a wiphy (/sys/class/net/<n>/phy80211), whatever its name
#   nft      the policy, FIRST and atomically: routed zones (10.19.0.0/24)
#            masquerade out of the uplinks; forwarding is allowed only
#            bridge -> uplink and established replies; nothing from the
#            outside reaches a zone unsolicited; zones cannot reach each other
#   forward  enabled only once the policy is loaded; disabled before, and
#            disabled again if the policy ever cannot be loaded
#   wifi     wpa_supplicant on each radio, from /etc/wpa_supplicant.conf
#            when kryptikd bound one in (`kryptik wifi add` writes it in
#            zone 0); a radio with no file is reported, not an error
#   dhcpcd   takes over the lease on every uplink (or keeps the carried
#            static configuration when there is no DHCP server); a radio
#            gets its lease once it has associated
#   dnsmasq  the resolver at 10.19.0.1 / fd19::1 that routed zones' resolv.conf
#            already names, forwarding to the uplink's servers
#
# FAIL CLOSED. The first version logged a failed nftables load and enabled
# forwarding anyway, which is a router with no firewall. Now: forwarding is
# off until the ruleset is loaded and checked, a ruleset that fails to load is
# retried without ever opening the path, and the readiness line says what is
# actually true. Readiness has four parts and each is reported on its own:
#
#   netzone: READY uplink=<addr|none> nat=yes dns=<yes|no> wifi=<ssid|connecting|unconfigured|none> ...
#   netzone: NOT READY <reason>            (forwarding is off)
#
# A missing uplink address (no DHCP answer, nothing carried over) is reported
# and retried by dhcpcd itself; the firewall and the resolver do not wait for
# it, because nothing is exposed without an address anyway. Everything here
# is in the zone: a compromised net zone owns this script's effects and
# nothing outside its namespace: the net zone is treated as hostile. That
# includes the Wi-Fi passphrases: the one party that must know them is the
# one that associates.
set -u
say() { echo "netzone: $*"; }
BR=kryptik0
STATUS=/run/netzone-status
WPA_CONF=/etc/wpa_supplicant.conf
WPA_CTRL=/run/wpa_supplicant

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
ip link show "$BR" >/dev/null 2>&1 || { report "NOT READY no bridge ${BR}; zone 0 did not create it"; exit 1; }
command -v nft >/dev/null 2>&1 || { report "NOT READY no nft in this image; refusing to route without a firewall"; exit 1; }

# --- the uplinks: what zone 0 moved in ---------------------------------------
# The positional parameters hold them from here on ("$@" is the one list a
# POSIX sh has). The bridge and the routed zones' veth ports have no bus
# device and never qualify, so nothing here can mistake a zone's port for
# the way out.
set --
WIRELESS=""
for d in /sys/class/net/*; do
    n="${d##*/}"
    [ "$n" = lo ] && continue
    [ -e "$d/device" ] || continue
    set -- "$@" "$n"
    [ -e "$d/phy80211" ] && WIRELESS="${WIRELESS:+$WIRELESS }$n"
done
[ $# -gt 0 ] || { report "NOT READY no uplink interface in this zone; zone 0 moved nothing in"; exit 1; }
say "uplinks: $* (wireless: ${WIRELESS:-none})"

# nft takes the uplinks as one anonymous set: { "eth0", "wlan0" }.
NICSET=""
for n in "$@"; do NICSET="${NICSET:+$NICSET, }\"$n\""; done
NICSET="{ $NICSET }"

RULES="table inet kryptik {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname \"${BR}\" oifname ${NICSET} accept
        iifname \"${BR}\" oifname \"${BR}\" drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname ${NICSET} ip saddr 10.19.0.0/24 masquerade
        oifname ${NICSET} ip6 saddr fd19::/64 masquerade
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname ${NICSET} ct state new tcp dport 53 drop
        iifname ${NICSET} ct state new udp dport 53 drop
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
    [ "$policy_ok" = 1 ] && say "nftables: masquerade 10.19.0.0/24 and fd19::/64 via ${NICSET}; forward bridge->uplink only; forwarding enabled"
else
    forwarding off
    report "NOT READY firewall policy did not load; forwarding stays off; retrying"
fi

# --- wireless: associate before asking for a lease ---------------------------
# /etc/wpa_supplicant.conf is zone 0's credentials file, bound in read-only
# by kryptikd when `kryptik wifi add` has written one; it names the control
# directory (ctrl_interface=/run/wpa_supplicant) that wpa_cli reads status
# from. One supplicant per radio; each keeps its pid under /run so the loop
# below can tell a dead one from a slow one.
wpa_pid() { cat "/run/wpa_supplicant.$1.pid" 2>/dev/null; }
start_wifi() {   # start_wifi <radio>: 0 started or already running, 1 not
    n="$1"
    p="$(wpa_pid "$n")"
    if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then return 0; fi
    command -v wpa_supplicant >/dev/null 2>&1 || { say "wifi: no wpa_supplicant in this image; ${n} stays unassociated"; return 1; }
    [ -r "$WPA_CONF" ] || { say "wifi: ${n}: no ${WPA_CONF} (nothing added with 'kryptik wifi add'); unconfigured"; return 1; }
    mkdir -p "$WPA_CTRL" 2>/dev/null
    if wpa_supplicant -B -i "$n" -c "$WPA_CONF" -C "$WPA_CTRL" -P "/run/wpa_supplicant.$n.pid" 2>/tmp/wpa.err; then
        say "wifi: wpa_supplicant on ${n} (pid $(wpa_pid "$n"))"
        return 0
    fi
    say "wifi: wpa_supplicant did not start on ${n}: $(tr '\n' ' ' < /tmp/wpa.err)"
    return 1
}
# The one word the readiness line carries for Wi-Fi: none (no radio),
# unconfigured (a radio, no credentials file), connecting (a supplicant
# running, not yet associated), or the SSID it associated with.
wifi_state() {
    [ -n "$WIRELESS" ] || { echo none; return; }
    [ -r "$WPA_CONF" ] || { echo unconfigured; return; }
    st=connecting
    for n in $WIRELESS; do
        s="$(wpa_cli -p "$WPA_CTRL" -i "$n" status 2>/dev/null)" || continue
        case "$s" in
            *"wpa_state=COMPLETED"*)
                st="$(printf '%s\n' "$s" | sed -n 's/^ssid=//p' | head -1)"
                [ -n "$st" ] || st=associated
                break ;;
        esac
    done
    echo "$st"
}
for n in $WIRELESS; do start_wifi "$n"; done
wifi_last="$(wifi_state)"

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
uplink_addr() {   # the first IPv4 address any uplink holds
    for n in "$@"; do
        a="$(ip -4 -o addr show "$n" 2>/dev/null | awk '{print $4}' | head -1)"
        [ -n "$a" ] && { echo "$a"; return; }
    done
}
if command -v dhcpcd >/dev/null 2>&1; then
    mkdir -p /run/dhcpcd /var/lib/dhcpcd 2>/dev/null
    # -b: background at once and keep asking for as long as the zone runs;
    # -q: errors only; --nodev: no device manager in here. Only the uplinks
    # are named, so the bridge and the zones' ports are never asked for a
    # lease. The resolv.conf hook stays on: /etc/resolv.conf is this zone's
    # own file (under /tmp), and what dhcpcd writes there is what the
    # resolver below forwards to.
    if dhcpcd -b -q --nodev "$@" 2>/tmp/dhcpcd.err; then
        grep -v 'no such user dhcpcd' /tmp/dhcpcd.err
        # Give the lease up to 15 s to arrive so the resolver starts with the
        # uplink's servers; a slower one is picked up by dhcpcd all the same.
        i=0
        while [ "$i" -lt 30 ] && [ -z "$(uplink_addr "$@")" ]; do sleep 0.5; i=$((i+1)); done
        [ -n "$(uplink_addr "$@")" ] && sleep 1   # let the hook finish resolv.conf
        say "dhcpcd on $*: uplink=$(uplink_addr "$@" || true)"
    else
        cat /tmp/dhcpcd.err
        say "dhcpcd did not start on $*; keeping the carried-over configuration"
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
    # --local=/test/: the reserved test TLD (RFC 6761) is answered here, never
    # forwarded. The guest check asks 10.19.0.1 for kryptik.test to prove a
    # routed zone reaches this resolver; with the uplink up that query went
    # upstream and, on a host whose resolver was slow, timed out - a verdict
    # about the internet, not about the path the check is for.
    # QEMU user networking's resolver, when nothing else is known
    grep -q '^nameserver' "$up" || echo "nameserver 10.0.2.3" >> "$up"
    dnsmasq --keep-in-foreground --no-daemon --no-hosts --bind-interfaces \
            --listen-address=10.19.0.1 --listen-address=fd19::1 --listen-address=127.0.0.1 \
            --resolv-file="$up" --no-poll --cache-size=1000 --local-service             --local=/test/ \
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
    a="$(uplink_addr "$@")"
    w="$(wifi_state)"
    if [ "$policy_ok" = 1 ]; then
        report "READY uplink=${a:-none} nat=yes dns=$([ "$dns_ok" = 1 ] && echo yes || echo no) wifi=${w} bridge=${BR} uplinks=$*"
    else
        report "NOT READY firewall policy not loaded; forwarding off; uplink=${a:-none} dns=$([ "$dns_ok" = 1 ] && echo yes || echo no) wifi=${w}"
    fi
}
status_line "$@"

# Stay up for as long as the zone runs; kryptikd stops us with SIGTERM. While
# up: retry a policy that failed to load (never opening the path before it
# does), restart the resolver or a supplicant that died, and re-report on
# changes - a radio that associates after the first line is one.
cleanup() {
    say "stopping"
    forwarding off
    [ -n "$DNSPID" ] && kill "$DNSPID" 2>/dev/null
    for n in $WIRELESS; do p="$(wpa_pid "$n")"; [ -n "$p" ] && kill "$p" 2>/dev/null; done
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
    for n in $WIRELESS; do
        p="$(wpa_pid "$n")"
        if [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null; then
            say "wifi: wpa_supplicant on ${n} died; restarting"; rm -f "/run/wpa_supplicant.$n.pid"; start_wifi "$n"; changed=1
        fi
    done
    wifi_now="$(wifi_state)"
    if [ "$wifi_now" != "$wifi_last" ]; then wifi_last="$wifi_now"; changed=1; say "wifi: ${wifi_now}"; fi
    [ "$changed" = 1 ] && status_line "$@"
    sleep 10 &
    wait $!
done
