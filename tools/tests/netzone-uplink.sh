#!/usr/bin/env bash
# Tests for the net zone's rule on the networks its uplinks sit on
# (tools/net/netzone-init.sh): the zones a definition lets through, by the
# address kryptikd gives each; each address pinned to its zone's MAC; the
# gateways as the sets take them; and the order of the rules. Offline, with
# stand-ins for ip and nft, under each POSIX shell here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/tools/net/netzone-init.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
same()  { if [[ "$2" == "$3" ]]; then green "$1"; else red "$1" "got '$(tr '\n' '|' <<<"$2")', want '$(tr '\n' '|' <<<"$3")'"; fi; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# The parts under test, as the script has them: the three functions, and the
# lines from the zones' addresses to the end of the ruleset.
for f in local_zones uplink_gateways sync_gateways; do sed -n "/^${f}() {/,/^}/p" "$SCRIPT"; done > "$T/functions.sh"
sed -n '/^LOCAL4=/,/^}"$/p' "$SCRIPT" > "$T/rules.sh"
grep -q '^sync_gateways() {' "$T/functions.sh" && grep -q '^RULES=' "$T/rules.sh" \
    || { echo "could not find the functions or the ruleset in ${SCRIPT#"$ROOT"/} (did their first lines move?)"; exit 1; }

zone() {   # zone DIR NAME UID_BASE NETWORK-LINES...: a definition as the shipped ones are written
    local dir="$1" name="$2" base="$3"; shift 3
    mkdir -p "$dir"
    {
        printf '# %s\n\n[zone]\nname        = "%s"\n\n[network]\n' "$name" "$name"
        printf '%s\n' "$@"
        printf '\n[storage]\nmode = "ephemeral"\nsize = "64M"\n\n[identity]\nuid_base = %s\n\n[ui]\nborder_color   = "#ba7c02"\n' "$base"
    } > "$dir/$name.toml"
}
# The addresses netzone.rs's own test gives for these bases: 2, 3, 7 and 249;
# kryptikd reads a quoted number as the number, so the tenth counts too.
zone "$T/z" first  131072   'mode = "routed"' 'local = true'
zone "$T/z" second 196608   'mode = "routed"' 'local = true   # the portal zone'
zone "$T/z" third  458752   'mode = "routed"' 'local="true"'
zone "$T/z" quoted '"655360"' 'mode = "routed"' 'local = true'
zone "$T/z" last   16318464 'mode = "routed"' 'local = true'
zone "$T/z" beyond 16384000 'mode = "routed"' 'local = true'
zone "$T/z" plain  262144   'mode = "routed"'
zone "$T/z" denied 327680   'mode = "routed"' 'local = false'
zone "$T/z" asked  393216   'mode = "routed"' '# local = true'
zone "$T/z" nonet  524288   'mode = "none"' 'local = true'
zone "$T/z" odd    589825   'mode = "routed"' 'local = true'
printf '\n[storage]\nlocal = true\n' >> "$T/z/plain.toml"

# Stand-ins: ip prints the routes of the day, nft records what it is fed.
mkdir -p "$T/bin"
cat > "$T/bin/ip" <<'EOF'
#!/bin/sh
cat "$ROUTES/$1.$5" 2>/dev/null
EOF
cat > "$T/bin/nft" <<'EOF'
#!/bin/sh
echo "nft $*" >> "$NFT_LOG"; cat >> "$NFT_LOG"
[ -z "${NFT_FAILS:-}" ] || { echo "Error: stand-in refusal" >&2; exit 1; }
EOF
chmod +x "$T/bin/ip" "$T/bin/nft"
mkdir -p "$T/routes"
printf 'default via 10.0.2.2 proto dhcp src 10.0.2.15 metric 1002\n10.0.2.0/24 proto dhcp scope link src 10.0.2.15 metric 1002\n' > "$T/routes/-4.eth0"
printf 'fec0::/64 proto ra metric 1002 pref medium\nfe80::/64 proto kernel metric 256 pref medium\ndefault via fe80::2 proto ra metric 1002 pref medium\n' > "$T/routes/-6.eth0"
printf '198.51.100.0/24 via 192.168.77.1 proto dhcp src 192.168.77.52 metric 3003\n192.168.77.0/24 proto dhcp scope link src 192.168.77.52 metric 3003\n' > "$T/routes/-4.wlan0"

cat > "$T/harness.sh" <<EOF
say() { echo "SAY: \$*"; }
. "$T/functions.sh"
GATEWAYS=""; LOCAL4="10.19.0.5"
case "\$1" in
    zones) local_zones "\$2" ;;
    gateways) shift; uplink_gateways "\$@" ;;
    sync)
        sync_gateways eth0 wlan0; echo "rc=\$? held=\$(printf '%s' "\$GATEWAYS" | tr '\n' ',')"
        sync_gateways eth0 wlan0; echo "rc=\$? again"
        ROUTES="$T/noroutes"; export ROUTES
        sync_gateways eth0 wlan0; echo "rc=\$? held=\$(printf '%s' "\$GATEWAYS" | tr '\n' ',')"
        ROUTES="$T/routes"; NFT_FAILS=1; export NFT_FAILS
        sync_gateways eth0 wlan0; echo "rc=\$? held=\$(printf '%s' "\$GATEWAYS" | tr '\n' ',')" ;;
    rules) BR=kryptik0; NICSET='{ "eth0", "wlan0" }'; ZONES="\$2"; . "$T/rules.sh"; printf '%s\n' "\$RULES" ;;
esac
EOF

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    run() { PATH="$T/bin:$PATH" ROUTES="$T/routes" NFT_LOG="$T/nft.log" "$sh" "$T/harness.sh" "$@" 2>&1; }
    echo "-- ${sh}: the zones a definition lets through"
    same "a zone is named by the address its uid_base gives it, as kryptikd derives it" \
        "$(run zones "$T/z" | LC_ALL=C sort)" "$(printf '10.19.0.10 fd19::a\n10.19.0.2 fd19::2\n10.19.0.249 fd19::f9\n10.19.0.3 fd19::3\n10.19.0.7 fd19::7')"
    same "the shipped zones: untrusted alone" "$(run zones "${ROOT}/compartments/zones")" "10.19.0.5 fd19::5"
    same "a directory this zone cannot read names nobody" "$(run zones "$T/none")" ""

    echo "-- ${sh}: the gateways"
    same "each route's gateway, once; a network an uplink sits on is no gateway" \
        "$(run gateways eth0 wlan0)" "$(printf '4 10.0.2.2\n4 192.168.77.1\n6 fe80::2')"
    : > "$T/nft.log"
    out="$(run sync)"
    same "the sets are filled, left alone while nothing changed, emptied with the routes, and a refusal is told" "$out" \
        "$(printf 'SAY: nftables: zones go out by 10.0.2.2,192.168.77.1 and fe80::2; the uplinks'"'"' own networks are refused but to 10.19.0.5\nrc=0 held=4 10.0.2.2,4 192.168.77.1,6 fe80::2\nrc=0 again\nSAY: nftables: zones go out by no IPv4 gateway and no IPv6 gateway; the uplinks'"'"' own networks are refused but to 10.19.0.5\nrc=0 held=\nSAY: nftables: the gateways could not be set: Error: stand-in refusal \nrc=1 held=')"
    same "one transaction each time: both sets flushed, then filled" "$(cat "$T/nft.log")" \
        "$(printf 'nft -f -\nflush set inet kryptik gw4\nflush set inet kryptik gw6\nadd element inet kryptik gw4 { 10.0.2.2,192.168.77.1 }\nadd element inet kryptik gw6 { fe80::2 }\nnft -f -\nflush set inet kryptik gw4\nflush set inet kryptik gw6\nnft -f -\nflush set inet kryptik gw4\nflush set inet kryptik gw6\nadd element inet kryptik gw4 { 10.0.2.2,192.168.77.1 }\nadd element inet kryptik gw6 { fe80::2 }')"

    echo "-- ${sh}: the ruleset"
    rules="$(run rules "${ROOT}/compartments/zones")"
    grep -qF 'set local4 { type ipv4_addr; elements = { 10.19.0.5 } }' <<<"$rules" && grep -qF 'set local6 { type ipv6_addr; elements = { fd19::5 } }' <<<"$rules" \
        && green "the zones let through are in the ruleset from its first load" || red "the local sets" "$(grep 'set local' <<<"$rules" | tr '\n' '|')"
    forward="$(sed -n '/chain forward {/,/^    }$/p' <<<"$rules" | grep -oE 'established,related accept|ip6? saddr @local[46] accept|rt ip6? nexthop @gw[46] ip6? daddr != @gw[46] accept|reject with icmpx type admin-prohibited|oifname "kryptik0" drop' | tr '\n' '|')"
    same "replies first, then the local zones, then what a gateway carries but the gateway itself, then the refusal" "$forward" \
        'established,related accept|ip saddr @local4 accept|ip6 saddr @local6 accept|rt ip nexthop @gw4 ip daddr != @gw4 accept|rt ip6 nexthop @gw6 ip6 daddr != @gw6 accept|reject with icmpx type admin-prohibited|oifname "kryptik0" drop|'
    pairs4="$(grep 'set pin4 ' <<<"$rules" | grep -oE '10\.19\.0\.[0-9]+ \. 02:19:00:00:00:[0-9a-f]{2}' \
        | awk '{ split($1, a, "."); n++; if (sprintf("%02x", a[4]) == substr($3, 16)) ok++ } END { print n + 0, ok + 0 }')"
    pairs6="$(grep 'set pin6 ' <<<"$rules" | grep -oE 'fd19::[0-9a-f]+ \. 02:19:00:00:00:[0-9a-f]{2}' \
        | awk '{ h = substr($1, 7); n++; if ((length(h) == 1 ? "0" h : h) == substr($3, 16)) ok++ } END { print n + 0, ok + 0 }')"
    same "hosts 2 to 249 each have both addresses pinned to their own MAC" "$pairs4 $pairs6" "248 248 248 248"
    pre="$(sed -n '/chain prerouting {/,/^    }$/p' <<<"$rules" | grep -oE 'priority raw|ip saddr \. ether saddr != @pin4 drop|ip6 saddr \. ether saddr @pin6 accept|ip6 saddr fe80::/10 icmpv6 type \{ nd-neighbor-solicit, nd-neighbor-advert \} accept|meta nfproto ipv6 drop' | tr '\n' '|')"
    same "from the bridge, ahead of conntrack: IPv4 off its pin dropped, IPv6 on its pin taken, neighbour discovery from a link-local address taken, other IPv6 dropped" "$pre" \
        'priority raw|ip saddr . ether saddr != @pin4 drop|ip6 saddr . ether saddr @pin6 accept|ip6 saddr fe80::/10 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept|meta nfproto ipv6 drop|'
    input="$(sed -n '/chain input {/,/^    }$/p' <<<"$rules" | grep -oE 'ct state new (tcp|udp) dport 53 drop|"kryptik0" .*(accept|drop)$' | tr '\n' '|')"
    same "into the net zone: no resolver for an uplink; from the bridge replies, DNS and echo on the bridge's addresses, neighbour discovery, and nothing else" "$input" \
        'ct state new tcp dport 53 drop|ct state new udp dport 53 drop|"kryptik0" ct state established,related accept|"kryptik0" ip daddr 10.19.0.1 meta l4proto { tcp, udp } th dport 53 accept|"kryptik0" ip6 daddr fd19::1 meta l4proto { tcp, udp } th dport 53 accept|"kryptik0" ip daddr 10.19.0.1 icmp type echo-request accept|"kryptik0" ip6 daddr fd19::1 icmpv6 type echo-request accept|"kryptik0" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept|"kryptik0" drop|'
    rules="$(run rules "$T/none")"
    grep -qF 'set local4 { type ipv4_addr; }' <<<"$rules" && green "with no zone let through the sets are empty, and every zone is refused" || red "the empty local sets" "$(grep 'set local' <<<"$rules" | tr '\n' '|')"
done

# The MAC the script pins each host to is the one kryptikd gives its eth0.
grep -qF '[0x02, 0x19, 0, 0, 0, k]' "${ROOT}/compartments/kryptikd/src/netlink.rs" \
    && green "netlink.rs gives host k the MAC 02:19:00:00:00:k the pin expects" \
    || red "netlink.rs's zone_mac is not 02:19:00:00:00:k" "$(grep -A2 'fn zone_mac' "${ROOT}/compartments/kryptikd/src/netlink.rs" | tr '\n' ' ')"

# Where this user may make a network namespace, nft itself reads the ruleset.
# A kernel without the pieces is no finding here; a ruleset nft cannot parse is.
if command -v nft >/dev/null 2>&1 && unshare -rn true 2>/dev/null; then
    PATH="$T/bin:$PATH" sh "$T/harness.sh" rules "${ROOT}/compartments/zones" > "$T/ruleset.nft"
    if err="$(unshare -rn nft -c -f "$T/ruleset.nft" 2>&1)"; then green "nft accepts the ruleset"
    elif grep -qi 'syntax error\|unexpected' <<<"$err"; then red "nft cannot parse the ruleset" "$(head -3 <<<"$err" | tr '\n' ' ')"
    else echo "        (nft here could not check it: $(head -1 <<<"$err"))"; fi
else
    echo "        (no nft, or no network namespace for this user: the ruleset is not given to nft here)"
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
