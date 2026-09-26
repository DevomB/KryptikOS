#!/bin/sh
# The net zone's startup (docs/design/net-zone.md), run by kryptikd as the nic
# zone's command: firewall and NAT, Wi-Fi, DHCP, the zones' resolver, the clock
# offset and update fetching. Fails closed: forwarding stays off until the nft
# policy is loaded and read back. Reports one line:
#
#   netzone: READY uplink=<addr|none> nat=yes dns=<yes|no> wifi=<ssid|connecting|unconfigured|none>
#                  time=<offset|no-answer|no-uplink|...> ...
#   netzone: NOT READY <reason>            (forwarding is off)
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
# Nothing forwards until the policy is in place, whatever zone 0 set.
forwarding off
ip link show "$BR" >/dev/null 2>&1 || { report "NOT READY no bridge ${BR}; zone 0 did not create it"; exit 1; }
command -v nft >/dev/null 2>&1 || { report "NOT READY no nft in this image; refusing to route without a firewall"; exit 1; }

# --- the uplinks: what zone 0 moved in ---------------------------------------
# Every interface on a bus device, the rule kryptikd moves them by, so never
# the bridge or a zone's veth; radios are those with phy80211. From here on
# they are "$@", a POSIX sh's only list.
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
# /etc/wpa_supplicant.conf is bound in read-only from zone 0 (`kryptik wifi
# add`). One supplicant per radio, each with a pid file so the loop below can
# tell a dead one from a slow one.
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
# The readiness line's wifi=: none (no radio), unconfigured (no credentials),
# connecting, or the associated SSID.
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
# /run and /var/lib are this zone's own writable tmpfs mounts. dhcpcd runs
# unseparated as the zone's root (the zone has no dhcpcd user), with the zone
# as its sandbox; its one complaint about that is filtered out.
uplink_addr() {   # the first IPv4 address any uplink holds
    for n in "$@"; do
        a="$(ip -4 -o addr show "$n" 2>/dev/null | awk '{print $4}' | head -1)"
        [ -n "$a" ] && { echo "$a"; return; }
    done
}
if command -v dhcpcd >/dev/null 2>&1; then
    mkdir -p /run/dhcpcd /var/lib/dhcpcd 2>/dev/null
    # -b: background at once and keep trying; --nodev: no device manager here.
    # Only the uplinks are named. The resolv.conf hook stays on: it writes this
    # zone's own /etc/resolv.conf, which the resolver below forwards to.
    if dhcpcd -b -q --nodev "$@" 2>/tmp/dhcpcd.err; then
        grep -v 'no such user dhcpcd' /tmp/dhcpcd.err
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

# --- the resolver routed zones already point at ----------------------------
DNSPID=""
start_dns() {
    command -v dnsmasq >/dev/null 2>&1 || { say "no dnsmasq; routed zones have no resolver"; return 1; }
    up=/run/uplink-resolv.conf
    # The uplink's servers, from dhcpcd's hook or zone 0's static copy. printf,
    # not ':': a failed redirection on a special builtin exits a POSIX sh.
    if [ -r /etc/resolv.conf ] && grep -q '^nameserver' /etc/resolv.conf; then
        grep '^nameserver' /etc/resolv.conf > "$up"
    else
        printf '' > "$up"
    fi
    # QEMU user networking's resolver, when nothing else is known
    grep -q '^nameserver' "$up" || echo "nameserver 10.0.2.3" >> "$up"
    # --local=/test/: the test TLD (RFC 6761) is never forwarded; the guest
    # check resolves kryptik.test here to prove a zone reaches this resolver.
    dnsmasq --keep-in-foreground --no-daemon --no-hosts --bind-interfaces \
            --listen-address=10.19.0.1 --listen-address=fd19::1 --listen-address=127.0.0.1 \
            --resolv-file="$up" --no-poll --cache-size=1000 --local-service --local=/test/ \
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

# --- the time: measured here, decided in zone 0 (docs/design/time.md) --------
# This zone cannot set the clock (no CAP_SYS_TIME): it measures the offset and
# sends it to zone 0 as an untrusted claim. Zone 0 names the sources in
# time.conf (`server HOST` or `pool HOST` per line); without it, the pool.
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
    # The sources become "$@", a flag and a name each, so no name is ever
    # split or expanded.
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
    # "OFFSET N": seconds to add to the clock, the median of N servers. No
    # output means no answer, never a zero offset.
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

# --- updates ---------------------------------------------------------------------
# Zone 0 has no network, so this zone asks it (docs/design/update-channel.md).
# update-fetch.py only carries bytes; zone 0 names the channel in update.conf
# and verifies everything. Without update.conf nothing is fetched.
UPDATE_CONF=/etc/kryptik/update.conf
UPDATE_FETCH="${KRYPTIK_UPDATE_FETCH:-/usr/libexec/kryptik/update-fetch.py}"
UPDATE_BROUGHT=/run/kryptik-update-statement-brought
UPDATE_PID=""
update_run() {   # update_run latest|poll: in the background, one at a time
    { command -v python3 >/dev/null 2>&1 && [ -r "$UPDATE_FETCH" ] && [ -r "$UPDATE_CONF" ]; } || return 0
    [ -n "$UPDATE_PID" ] && kill -0 "$UPDATE_PID" 2>/dev/null && return 0
    (
        out="$(python3 "$UPDATE_FETCH" "$1" --broker "$BROKER" 2>&1 | tail -1)"
        case "$1:$out" in
            poll:idle|*:) ;;
            latest:ok*) : > "$UPDATE_BROUGHT"; say "update: zone 0 on the statement of what is current: ${out}" ;;
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

# Run until kryptikd sends SIGTERM: retry a policy that failed to load, restart
# a dead resolver or supplicant, and report again on any change.
cleanup() {
    say "stopping"
    forwarding off
    [ -n "$DNSPID" ] && kill "$DNSPID" 2>/dev/null
    [ -n "$UPDATE_PID" ] && kill "$UPDATE_PID" 2>/dev/null
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
        # The policy vanished (a flush inside the zone, say): close the path.
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
    if [ "$wifi_now" != "$wifi_last" ]; then
        wifi_last="$wifi_now"; changed=1; say "wifi: ${wifi_now}"
        # A radio that just associated: ask the time now.
        case "$wifi_now" in none|unconfigured|connecting) ;; *) time_ticks=999999 ;; esac
    fi
    # A tick is 10 s. The time: hourly once measured, else every 5 minutes
    # (zone 0 takes at most one claim per 10 minutes anyway).
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
    # Updates: the statement daily once zone 0 has taken one, else every 30
    # minutes; a poll every minute, which is how `kryptik update fetch` is seen.
    update_ticks=$((update_ticks + 1)); statement_ticks=$((statement_ticks + 1))
    if [ -n "$(uplink_addr "$@")" ]; then
        if [ -e "$UPDATE_BROUGHT" ]; then statement_every=8640; else statement_every=180; fi
        if [ "$statement_ticks" -ge "$statement_every" ]; then
            statement_ticks=0; update_run latest
        elif [ "$update_ticks" -ge 6 ]; then
            update_ticks=0; update_run poll
        fi
    fi
    [ "$changed" = 1 ] && status_line "$@"
    sleep 10 &
    wait $!
done
