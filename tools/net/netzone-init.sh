#!/bin/sh
# The net zone's command (docs/design/net-zone.md): firewall, Wi-Fi, DHCP, DNS, time and updates.
# Fails closed: forwarding stays off until the nft policy is loaded and read back. Reports:
#
#   netzone: READY uplink=<addr|none> nat=yes dns=<yes|no> wifi=<ssid|connecting|unconfigured|none>
#                  time=<offset|no-answer|no-uplink|...> ...
#   netzone: NOT READY <reason>            (forwarding is off)
set -u
# printf, not echo: a word from the network (an SSID, a server's reason for a
# refusal) is printed as it came, and dash's echo would act on its backslashes.
say() { printf 'netzone: %s\n' "$*"; }
BR=kryptik0
STATUS=/run/netzone-status
WPA_CONF=/etc/wpa_supplicant.conf   # bound in read-only from zone 0 (kryptik wifi add)
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
# The zone definitions, on the root this zone shares read-only with zone 0.
ZONES="${1:-/usr/lib/kryptik/zones}"

[ -d /proc/sys/net/ipv4 ] || { report "NOT READY no network stack"; exit 1; }
# Nothing forwards until the policy is in place, whatever zone 0 set.
forwarding off
ip link show "$BR" >/dev/null 2>&1 || { report "NOT READY no bridge ${BR}; zone 0 did not create it"; exit 1; }
command -v nft >/dev/null 2>&1 || { report "NOT READY no nft in this image; refusing to route without a firewall"; exit 1; }

# --- the uplinks: what zone 0 moved in ---------------------------------------

# Interfaces on a bus device, the rule kryptikd moves them by: never the bridge or a zone's veth.
set --   # the uplinks from here on: "$@" is POSIX sh's only list
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

# The routed zones whose definition says [network] local = true, each by the
# address kryptikd gives it (netzone.rs, host_number). A file this zone cannot
# read names nobody.
local_zones() {   # local_zones DIR: "10.19.0.K fd19::K" for each
    for f in "$1"/*.toml; do
        [ -r "$f" ] || continue
        awk '
            { sub(/#.*/, ""); gsub(/[ \t]/, "") }
            /^\[/ { section = $0; next }
            section == "[network]" && ($0 == "local=true" || $0 == "local=\"true\"") { claims = 1 }
            section == "[network]" && $0 == "mode=\"routed\"" { routed = 1 }
            section == "[identity]" && /^uid_base="?[0-9]+"?$/ { base = $0; gsub(/[^0-9]/, "", base) }
            END {
                k = (base - 131072) / 65536 + 2
                if (claims && routed && base != "" && k == int(k) && k >= 2 && k < 250) printf "10.19.0.%d fd19::%x\n", k, k
            }' "$f"
    done
}
LOCAL4="$(local_zones "$ZONES" | awk '{ print $1 }' | tr '\n' ',' | sed 's/,$//')"
LOCAL6="$(local_zones "$ZONES" | awk '{ print $2 }' | tr '\n' ',' | sed 's/,$//')"
SET4="set local4 { type ipv4_addr; }"; SET6="set local6 { type ipv6_addr; }"
[ -z "$LOCAL4" ] || SET4="set local4 { type ipv4_addr; elements = { ${LOCAL4} } }"
[ -z "$LOCAL6" ] || SET6="set local6 { type ipv6_addr; elements = { ${LOCAL6} } }"
# IPV6_FREEBIND sends from any address, so the bridge takes 10.19.0.K and fd19::K
# only from host K's MAC, 02:19:00:00:00:K (netzone.rs zone_mac), which no zone can change.
PIN4="$(awk 'BEGIN { for (k = 2; k < 250; k++) printf "%s10.19.0.%d . 02:19:00:00:00:%02x", (k > 2 ? ", " : ""), k, k }')"
PIN6="$(awk 'BEGIN { for (k = 2; k < 250; k++) printf "%sfd19::%x . 02:19:00:00:00:%02x", (k > 2 ? ", " : ""), k, k }')"

# A zone goes out by a gateway (gw4, gw6) and never to the gateway itself:
# the rest of what an uplink reaches is the network it sits on, open to local4
# and local6 alone. With no gateway in the sets nothing goes out, so a new
# lease opens no way in before sync_gateways has seen it. From the bridge the
# net zone takes in only what is addressed to the bridge: its own address on an
# uplink is the net zone, not the network a local zone may reach.
RULES="table inet kryptik {
    set gw4 { type ipv4_addr; }
    set gw6 { type ipv6_addr; }
    ${SET4}
    ${SET6}
    set pin4 { type ipv4_addr . ether_addr; elements = { ${PIN4} } }
    set pin6 { type ipv6_addr . ether_addr; elements = { ${PIN6} } }
    chain prerouting {
        type filter hook prerouting priority raw; policy accept;
        iifname \"${BR}\" ip saddr . ether saddr != @pin4 drop
        iifname \"${BR}\" ip6 saddr . ether saddr @pin6 accept
        iifname \"${BR}\" ip6 saddr fe80::/10 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
        iifname \"${BR}\" meta nfproto ipv6 drop
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname \"${BR}\" oifname ${NICSET} ip saddr @local4 accept
        iifname \"${BR}\" oifname ${NICSET} ip6 saddr @local6 accept
        iifname \"${BR}\" oifname ${NICSET} rt ip nexthop @gw4 ip daddr != @gw4 accept
        iifname \"${BR}\" oifname ${NICSET} rt ip6 nexthop @gw6 ip6 daddr != @gw6 accept
        iifname \"${BR}\" oifname ${NICSET} reject with icmpx type admin-prohibited
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
        iifname \"${BR}\" ip daddr != 10.19.0.1 drop
        iifname \"${BR}\" ip6 daddr != { fd19::1, fe80::/10, ff02::/16 } drop
    }
}"

# One nft -f is one transaction; reading it back checks what the kernel holds, not what was sent.
load_policy() {
    printf '%s\n' "$RULES" | nft -c -f - 2>/tmp/nft.err || { say "nftables: ruleset does not validate: $(tr '\n' ' ' < /tmp/nft.err)"; return 1; }
    nft flush ruleset 2>/dev/null || true
    printf '%s\n' "$RULES" | nft -f - 2>/tmp/nft.err || { say "nftables: load FAILED: $(tr '\n' ' ' < /tmp/nft.err)"; return 1; }
    live="$(nft list table inet kryptik 2>/dev/null)"
    for want in "@pin6 accept" "policy drop" "masquerade"; do
        case "$live" in
            *"$want"*) ;;
            *) say "nftables: the loaded table is not the policy (no \"${want}\")"; nft flush ruleset 2>/dev/null; return 1 ;;
        esac
    done
    GATEWAYS=""
    return 0
}

# The gateways the uplinks' routes go by, as "4 ADDRESS" or "6 ADDRESS".
uplink_gateways() {   # uplink_gateways <uplink>...
    for n in "$@"; do
        ip -4 route show dev "$n" 2>/dev/null | awk '$2 == "via" { print 4, $3 }'
        ip -6 route show dev "$n" 2>/dev/null | awk '$2 == "via" { print 6, $3 }'
    done | sort -u
}
# Put them in gw4 and gw6 when they have changed: one transaction, so the
# sets are never seen half filled. 1 when nft refuses it.
GATEWAYS=""
sync_gateways() {   # sync_gateways <uplink>...
    now="$(uplink_gateways "$@")"
    [ "$now" = "$GATEWAYS" ] && return 0
    gw4="$(printf '%s\n' "$now" | sed -n 's/^4 //p' | tr '\n' ',' | sed 's/,$//')"
    gw6="$(printf '%s\n' "$now" | sed -n 's/^6 //p' | tr '\n' ',' | sed 's/,$//')"
    {
        echo "flush set inet kryptik gw4"
        echo "flush set inet kryptik gw6"
        [ -z "$gw4" ] || echo "add element inet kryptik gw4 { $gw4 }"
        [ -z "$gw6" ] || echo "add element inet kryptik gw6 { $gw6 }"
    } | nft -f - 2>/tmp/nft.err || { say "nftables: the gateways could not be set: $(tr '\n' ' ' < /tmp/nft.err)"; return 1; }
    GATEWAYS="$now"
    say "nftables: zones go out by ${gw4:-no IPv4 gateway} and ${gw6:-no IPv6 gateway}; the uplinks' own networks are refused${LOCAL4:+ but to $LOCAL4}"
}

policy_ok=0
if load_policy && sync_gateways "$@"; then
    policy_ok=1
    forwarding on || { report "NOT READY cannot enable forwarding"; policy_ok=0; }
    [ "$policy_ok" = 1 ] && say "nftables: masquerade 10.19.0.0/24 and fd19::/64 via ${NICSET}; forward bridge->uplink only; forwarding enabled"
else
    forwarding off
    report "NOT READY firewall policy did not load; forwarding stays off; retrying"
fi

# --- wireless: associate before asking for a lease ---------------------------

# One supplicant per radio, each with a pid file so the loop can tell a dead one from a slow one.
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
# The status line's wifi=: none (no radio), unconfigured (no credentials), connecting, or the SSID.
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
uplink_addr() {   # the first IPv4 address any uplink holds
    for n in "$@"; do
        a="$(ip -4 -o addr show "$n" 2>/dev/null | awk '{print $4}' | head -1)"
        [ -n "$a" ] && { echo "$a"; return; }
    done
}
if command -v dhcpcd >/dev/null 2>&1; then
    mkdir -p /run/dhcpcd /var/lib/dhcpcd 2>/dev/null   # the zone's own tmpfs mounts
    # -b: background and retry; --nodev: no device manager. Its parsers drop to the dhcpcd user;
    # Kryptik's hook, which trusts nothing it is handed, writes the zone's resolv.conf.
    if dhcpcd -b -q --nodev -c /usr/libexec/kryptik/dhcpcd-hook "$@" 2>/tmp/dhcpcd.err; then
        cat /tmp/dhcpcd.err
        # Up to 15 s for a lease, so the resolver starts with its servers.
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
# The lease named a gateway: until it is in the sets, only local zones go out.
[ "$policy_ok" = 1 ] && { sync_gateways "$@" || { forwarding off; policy_ok=0; }; }

# --- the resolver routed zones already point at ----------------------------
DNSPID=""
RESOLV=/etc/resolv.conf            # this zone's own: dhcpcd's hook, or zone 0's static copy
UPSTREAM=/run/uplink-resolv.conf   # what dnsmasq forwards to
# sync_upstream: the uplink's servers, written for dnsmasq; 0 when they are
# other servers than the file held. A lease can come after the wait above, and
# another network names other servers. A resolv.conf that names none leaves
# the file as it is: a lease that lapsed is no reason to forget the last ones.
sync_upstream() {
    new="$(grep '^nameserver' "$RESOLV" 2>/dev/null)"
    [ -n "$new" ] || return 1
    [ "$new" != "$(cat "$UPSTREAM" 2>/dev/null)" ] || return 1
    printf '%s\n' "$new" > "$UPSTREAM.new" 2>/dev/null && mv -f "$UPSTREAM.new" "$UPSTREAM" 2>/dev/null
}
start_dns() {
    command -v dnsmasq >/dev/null 2>&1 || { say "no dnsmasq; routed zones have no resolver"; return 1; }
    sync_upstream
    # QEMU user networking's resolver, when nothing else is known
    grep -q '^nameserver' "$UPSTREAM" 2>/dev/null || echo "nameserver 10.0.2.3" > "$UPSTREAM"
    # --local=/test/ (RFC 6761) stays here: the guest check resolves kryptik.test through it.
    # --no-poll: the file is read again on SIGHUP, which the loop below sends.
    dnsmasq --keep-in-foreground --no-daemon --no-hosts --bind-interfaces \
            --listen-address=10.19.0.1 --listen-address=fd19::1 --listen-address=127.0.0.1 \
            --resolv-file="$UPSTREAM" --no-poll --cache-size=1000 --local-service --local=/test/ \
            --pid-file=/run/dnsmasq.pid --user=root &
    DNSPID=$!
    sleep 1
    if kill -0 "$DNSPID" 2>/dev/null; then
        say "dnsmasq listening on 10.19.0.1/fd19::1, forwarding to $(grep '^nameserver' "$UPSTREAM" | tr '\n' ' ')"
        return 0
    fi
    say "dnsmasq exited at once"; DNSPID=""; return 1
}
dns_ok=0
start_dns && dns_ok=1

# --- the time: measured here, decided in zone 0 (docs/design/time.md) --------

# Zone 0's source list, `server HOST` or `pool HOST` per line; without it, pool.ntp.org.
TIME_CONF=/etc/kryptik/time.conf
SNTP="${KRYPTIK_SNTP:-/usr/libexec/kryptik/sntp-offset.py}"
# The zone's broker socket; overridable so the offline suite can stand one up.
BROKER="${KRYPTIK_BROKER:-/run/kryptik/broker}"
TIME_STATE=not-asked
time_sources() {
    if [ -r "$TIME_CONF" ]; then
        sed -n 's/^[[:space:]]*\(server\|pool\)[[:space:]][[:space:]]*\([A-Za-z0-9._:-][A-Za-z0-9._:-]*\)[[:space:]]*$/\1 \2/p' "$TIME_CONF" | head -16
    else
        echo "pool pool.ntp.org"
    fi
}
ask_time() {   # ask_time <uplink>...: sets TIME_STATE
    { command -v python3 >/dev/null 2>&1 && [ -r "$SNTP" ]; } || { TIME_STATE=no-client; return; }
    [ -n "$(uplink_addr "$@")" ] || { TIME_STATE=no-uplink; return; }
    # The sources become "$@", a flag and a name each, so no name is split or expanded.
    set --
    while read -r kind host; do
        [ -n "$host" ] || continue
        case "$kind" in
            pool|server) set -- "$@" "--$kind" "$host" ;;
        esac
    done <<EOF
$(time_sources)
EOF
    [ $# -gt 0 ] || { TIME_STATE=unconfigured; say "time: ${TIME_CONF} names no server or pool"; return; }
    # "OFFSET N": seconds to add, the median of N servers; no output means no answer, not zero.
    out="$(python3 "$SNTP" --timeout "${KRYPTIK_SNTP_TIMEOUT:-8}" "$@" 2>/dev/null)"
    off="${out%% *}"; nsrc="${out##* }"
    case "$off" in
        [+-][0-9]*.[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
        *) TIME_STATE=no-answer; return ;;
    esac
    case "$nsrc" in [1-9]|1[0-6]) ;; *) TIME_STATE=no-answer; return ;; esac
    TIME_STATE="$off"
    # A long wait: zone 0 may be asking the user.
    told="$(python3 -c 'import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(90)
s.connect(sys.argv[3])
s.sendall(("time-offset %s %s\n" % (sys.argv[1], sys.argv[2])).encode()); s.shutdown(socket.SHUT_WR)
print(s.recv(4096).decode("utf-8", "replace").strip())' "$off" "$nsrc" "$BROKER" 2>&1 | head -1)"
    say "time: the clock is off by ${off} s (the median of ${nsrc} server(s)); zone 0: ${told:-no reply}"
}
ask_time "$@"
time_ticks=0

# --- updates (docs/design/update-channel.md) ---------------------------------

# Zone 0 has no network: update-fetch.py carries the bytes; zone 0 names the channel and verifies.
UPDATE_CONF=/etc/kryptik/update.conf
UPDATE_FETCH="${KRYPTIK_UPDATE_FETCH:-/usr/libexec/kryptik/update-fetch.py}"
UPDATE_BROUGHT=/run/kryptik-update-statement-brought
UPDATE_PID=""
update_run() {   # update_run latest|poll: in the background, one at a time; 1 while the last one runs
    { command -v python3 >/dev/null 2>&1 && [ -r "$UPDATE_FETCH" ] && [ -r "$UPDATE_CONF" ]; } || return 0
    [ -n "$UPDATE_PID" ] && kill -0 "$UPDATE_PID" 2>/dev/null && return 1
    (
        out="$(python3 "$UPDATE_FETCH" "$1" --broker "$BROKER" 2>&1)"; rc=$?
        out="$(printf '%s\n' "$out" | tail -1)"
        # Zone 0's answer counts only from a fetch that ended well: the last
        # line of one that failed is the far host's words.
        case "$rc:$1:$out" in
            0:poll:idle|*:*:) ;;
            0:latest:ok*) : > "$UPDATE_BROUGHT"; say "update: zone 0 on the statement of what is current: ${out}" ;;
            *) say "update $1: ${out}" ;;
        esac
    ) &
    UPDATE_PID=$!
}
update_ticks=0; statement_ticks=999999

status_line() {
    a="$(uplink_addr "$@")"
    w="$(wifi_state)"
    if [ "$policy_ok" = 1 ]; then
        report "READY uplink=${a:-none} nat=yes dns=$([ "$dns_ok" = 1 ] && echo yes || echo no) wifi=${w} time=${TIME_STATE} bridge=${BR} uplinks=$*"
    else
        report "NOT READY firewall policy not loaded; forwarding off; uplink=${a:-none} dns=$([ "$dns_ok" = 1 ] && echo yes || echo no) wifi=${w} time=${TIME_STATE}"
    fi
}
status_line "$@"

# Until SIGTERM: retry a failed policy, restart a dead resolver or supplicant, report any change.
cleanup() {
    say "stopping"
    forwarding off
    [ -n "$DNSPID" ] && kill "$DNSPID" 2>/dev/null
    [ -n "$UPDATE_PID" ] && kill "$UPDATE_PID" 2>/dev/null
    for n in $WIRELESS; do p="$(wpa_pid "$n")"; [ -n "$p" ] && kill "$p" 2>/dev/null; done
    exit 0
}
trap cleanup TERM INT
while :; do
    changed=0
    if [ "$policy_ok" != 1 ]; then
        if load_policy && sync_gateways "$@" && forwarding on; then policy_ok=1; changed=1; say "nftables: policy loaded on retry; forwarding enabled"; fi
    elif ! nft list table inet kryptik >/dev/null 2>&1; then
        # The policy vanished (a flush inside the zone, say): close the path.
        forwarding off; policy_ok=0; changed=1; say "nftables: the policy is gone; forwarding disabled"
    elif ! sync_gateways "$@"; then
        forwarding off; policy_ok=0; changed=1
    fi
    if [ -n "$DNSPID" ] && ! kill -0 "$DNSPID" 2>/dev/null; then
        say "dnsmasq died; restarting"; DNSPID=""; dns_ok=0; changed=1
        start_dns && dns_ok=1
    elif [ -n "$DNSPID" ] && sync_upstream; then
        kill -HUP "$DNSPID" 2>/dev/null
        say "dnsmasq: now forwarding to $(tr '\n' ' ' < "$UPSTREAM")"
    fi
    for n in $WIRELESS; do
        p="$(wpa_pid "$n")"
        if [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null; then
            say "wifi: wpa_supplicant on ${n} died; restarting"; rm -f "/run/wpa_supplicant.$n.pid"; start_wifi "$n"; changed=1
        fi
    done
    wifi_now="$(wifi_state)"
    if [ "$wifi_now" != "$wifi_last" ]; then
        wifi_last="$wifi_now"; changed=1; say "wifi: ${wifi_now}"
        # A radio that just associated: ask the time now.
        case "$wifi_now" in none|unconfigured|connecting) ;; *) time_ticks=999999 ;; esac
    fi
    # 10 s ticks: the time hourly once measured, else every 5 min (zone 0 takes a claim per 10 min).
    time_ticks=$((time_ticks + 1))
    case "$TIME_STATE" in
        -*|+*|[0-9]*) time_every=360 ;;
        *) time_every=30 ;;
    esac
    if [ "$time_ticks" -ge "$time_every" ]; then
        time_ticks=0; time_was="$TIME_STATE"
        ask_time "$@"
        [ "$TIME_STATE" != "$time_was" ] && changed=1
    fi
    # Statement daily once zone 0 took one, else half-hourly; a poll a minute sees `update fetch`.
    update_ticks=$((update_ticks + 1)); statement_ticks=$((statement_ticks + 1))
    if [ -n "$(uplink_addr "$@")" ]; then
        if [ -e "$UPDATE_BROUGHT" ]; then statement_every=8640; else statement_every=180; fi
        if [ "$statement_ticks" -ge "$statement_every" ]; then
            # Asked again at the next pass when a poll was still running.
            update_run latest && statement_ticks=0
        elif [ "$update_ticks" -ge 6 ]; then
            update_ticks=0; update_run poll
        fi
    fi
    [ "$changed" = 1 ] && status_line "$@"
    sleep 10 &
    wait $!
done
