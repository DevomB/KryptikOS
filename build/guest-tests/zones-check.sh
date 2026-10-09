#!/usr/bin/env bash
# Zones suite, run as root in the installed guest by tools/image/zones-test.sh:
# zones, networking and encrypted storage, with the shipped zone files.
# Output: "ZT PASS|FAIL|INFO name - detail"; a check that cannot run fails.
# A routed zone's bridge address follows from its uid_base
# (netzone::host_number): 10.19.0.((uid_base - 131072) / 65536 + 2).
set -u
Z=/usr/lib/kryptik/zones
R=/var/lib/kryptik/zones
KD=/usr/bin/kryptikd
LOG=/var/log/kryptik/zones-check
mkdir -p "$LOG" /root/zt
PASS=0; FAIL=0
pass() { echo "ZT PASS $1${2:+ - $2}"; PASS=$((PASS + 1)); }
fail() { echo "ZT FAIL $1${2:+ - $2}"; FAIL=$((FAIL + 1)); }
info() { echo "ZT INFO $*"; }
# Run CMD in a zone with a time limit; sets ZRC and ZOUT and keeps the output.
zrun() {   # zrun ZONE TIMEOUT [--passphrase-file F] -- CMD...
    local zone="$1" t="$2"; shift 2
    local extra=()
    while [[ "$1" != "--" ]]; do extra+=("$1"); shift; done; shift
    timeout -k 5 "$t" "$KD" run "$zone" --zones "$Z" --rootfs "$R" "${extra[@]}" -- "$@" > "$LOG/$zone.out" 2> "$LOG/$zone.err"
    ZRC=$?
    ZOUT="$(cat "$LOG/$zone.out")"
}
host_of() { local b; b="$(sed -n 's/^uid_base *= *\([0-9]*\).*/\1/p' "$Z/$1.toml")"; echo $(( (b - 131072) / 65536 + 2 )); }
# The catch-all log, oldest first: s6-log moves current aside, through previous
# to @<stamp>.s, at about 100 KB, so a count read from current alone can go back.
uncaught() { cat /run/uncaught-logs/@* /run/uncaught-logs/previous /run/uncaught-logs/current 2>/dev/null; }
netzone_said() { uncaught | grep -a "netzone: $1"; }
ready_count() { netzone_said READY | grep -c .; }
last_ready() { netzone_said READY | tail -1; }
[[ "$(id -u)" = 0 ]] || { fail "root" "this must run as root"; echo "ZT END"; exit 1; }
echo "ZT BEGIN $(date -Iseconds 2>/dev/null)"

# --- zones: the kernel and the zone set --------------------------------------
if "$KD" check --target --zones "$Z" > "$LOG/check.out" 2>&1; then
    pass "kernel-support" "kryptikd check --target passes on $(uname -r)"
else
    fail "kernel-support" "$(tail -3 "$LOG/check.out" | tr '\n' ' ')"
fi
zones="$("$KD" list --zones "$Z" 2>/dev/null | tr '\n' ' ')"
[[ "$zones" == *work* && "$zones" == *net* && "$zones" == *vault* && "$zones" == *untrusted* ]] && pass "shipped-zones" "$zones" || fail "shipped-zones" "$zones"
[[ -f "$Z/policy/work.seccomp" ]] && pass "policies" "seccomp policies installed beside the zones" || fail "policies" "no work.seccomp in $Z/policy"

# --- zones: the net zone and zone 0 --------------------------------------------
if [[ "$(s6-svstat -o up /run/service/net-zone 2>/dev/null)" = true ]]; then pass "net-zone-up" "supervised and up"; else fail "net-zone-up" "$(s6-svstat /run/service/net-zone 2>&1)"; fi
ready=""
for _ in $(seq 1 30); do
    ready="$(last_ready)"
    [[ -n "$ready" ]] && break; sleep 1
done
if [[ "$ready" == *"nat=yes"* ]]; then pass "net-ready" "$ready"; else fail "net-ready" "no READY line with nat=yes in the catch-all log (last: $(netzone_said '' | tail -1))"; fi
# The routed zones' resolver, named on its own: routed-dns only times out.
if [[ "$ready" == *" dns=yes "* ]]; then pass "net-dns" "dnsmasq is running"; else fail "net-dns" "$(uncaught | grep -a 'dnsmasq' | tail -2 | tr '\n' ' ')"; fi
# dhcpcd's privilege separation: what parses a lease runs as the net zone's
# dhcpcd user (host uid_base + 100) in an empty root, with no capability and
# dhcpcd's own seccomp filter over the zone's, while a helper stays its root;
# and the lease, which that helper writes, arrived.
net_base="$(sed -n 's/^uid_base *= *\([0-9]*\).*/\1/p' "$Z/net.toml")"
nz_init="$(cut -d' ' -f1 /run/kryptik/zones/net/init.pid 2>/dev/null)"
separated=0; helpers=0; seen=""
for p in $(pgrep -x dhcpcd); do
    uid="$(awk '/^Uid:/ { print $2 }' "/proc/$p/status" 2>/dev/null)"
    caps="$(awk '/^CapEff:/ { print $2 }' "/proc/$p/status" 2>/dev/null)"
    filters="$(awk '/^Seccomp_filters:/ { print $2 }' "/proc/$p/status" 2>/dev/null)"
    # 2>&1: a root that cannot be listed is not an empty one.
    inside="$(ls -A "/proc/$p/root" 2>&1 | head -3 | tr '\n' ',')"
    seen="${seen} ${p}:uid=${uid},caps=${caps},filters=${filters},root=$(readlink "/proc/$p/root" 2>/dev/null)[${inside}]"
    if [[ "$uid" == "$((net_base + 100))" && "$caps" == 0000000000000000 && "${filters:-0}" -ge 2 && -z "$inside" ]]; then
        separated=$((separated + 1))
    fi
    [[ "$uid" == "$net_base" ]] && helpers=$((helpers + 1))
done
leased="$(nsenter -t "${nz_init:-0}" -m sh -c 'ls /var/lib/dhcpcd/*.lease 2>/dev/null' | head -1)"
if [[ "$separated" -ge 1 && "$helpers" -ge 1 && -n "$leased" ]]; then
    pass "dhcpcd-separated" "${separated} dhcpcd process(es) as uid $((net_base + 100)) in an empty root with no capability under two filters, ${helpers} root helper, lease ${leased}"
else
    fail "dhcpcd-separated" "separated ${separated}, helpers ${helpers}, lease ${leased:-none}:${seen:- no dhcpcd running}"
fi
# dnsmasq answers the routed zones as the net zone's nobody (host uid_base +
# 65534), keeping at most CAP_NET_BIND_SERVICE: fd19::1 stays tentative on a
# bridge with no port yet, so dnsmasq binds it later.
dns_dropped=0; dns_root=0; dns_seen=""
for p in $(pgrep -x dnsmasq); do
    ids="$(awk '/^Uid:/ { print $2, $3, $4, $5 }' "/proc/$p/status" 2>/dev/null)"
    eff="$(awk '/^CapEff:/ { print $2 }' "/proc/$p/status" 2>/dev/null)"
    prm="$(awk '/^CapPrm:/ { print $2 }' "/proc/$p/status" 2>/dev/null)"
    dns_seen="${dns_seen} ${p}:uid=${ids// /,},eff=${eff},prm=${prm}"
    n=$((net_base + 65534))
    if [[ "$ids" == "$n $n $n $n" && "$eff" =~ ^0000000000000(000|400)$ && "$prm" =~ ^0000000000000(000|400)$ ]]; then
        dns_dropped=$((dns_dropped + 1))
    fi
    [[ "$ids" == "$net_base "* ]] && dns_root=$((dns_root + 1))
done
if [[ "$dns_dropped" -ge 1 && "$dns_root" -eq 0 ]]; then
    pass "dnsmasq-unprivileged" "${dns_dropped} dnsmasq process(es) as uid $((net_base + 65534)) with no capability but CAP_NET_BIND_SERVICE, none as the net zone's root"
else
    fail "dnsmasq-unprivileged" "dropped ${dns_dropped}, as root ${dns_root}:${dns_seen:- no dnsmasq running}"
fi
if ip link show eth0 >/dev/null 2>&1; then fail "zone0-nic" "eth0 is still in zone 0"; else pass "zone0-nic" "eth0 is not in zone 0 (moved into the net zone)"; fi
if [[ -z "$(ip route show default 2>/dev/null)" ]]; then pass "zone0-no-route" "zone 0 has no default route"; else fail "zone0-no-route" "$(ip route show default)"; fi
if ping -c1 -W2 10.0.2.2 >/dev/null 2>&1; then fail "zone0-offline" "zone 0 reached the VM gateway"; else pass "zone0-offline" "zone 0 cannot reach the VM gateway"; fi

# --- zones: a routed zone reaches the world through net; vault reaches nothing --
# The IPv6 echo waits out duplicate address detection: from a still-tentative
# address it fails at once with EADDRNOTAVAIL.
UNT=$(host_of untrusted); PER=$(host_of personal)
zrun untrusted 40 -- sh -c 'ip -4 -o addr show eth0; python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.1 3 >/dev/null 2>&1 && echo BRIDGE-OK; if ping -c 1 -W 3 10.19.0.1 > /tmp/ping.out 2>&1; then echo PING-OK; else echo "PING-FAIL rc=$? $(tail -1 /tmp/ping.out)"; fi; python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.0.2.2 3 >/dev/null 2>&1 && echo GATEWAY-OK; ip -6 -o addr show eth0 | grep -q " fd19:" && echo ULA-OK; ip -6 -o addr show eth0 | grep -qE " (2|3)[0-9a-f]{3}:" && echo GLOBAL6-PRESENT; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do ip -6 -o addr show eth0 | grep -q tentative || break; sleep 0.5; done; python3 /usr/lib/kryptik/guest-tests/icmp-echo.py fd19::1 3 >/dev/null 2>&1 && echo BRIDGE6-OK; if ping -c 1 -W 3 fd19::1 > /tmp/ping6.out 2>&1; then echo PING6-OK; else echo "PING6-FAIL rc=$? $(tail -1 /tmp/ping6.out)"; fi; python3 - <<"PY"
import socket, struct
q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07kryptik\x04test\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
try:
    s.sendto(q, ("10.19.0.1", 53)); d, _ = s.recvfrom(512)
    print("DNS-ANSWERED rcode=%d" % (d[3] & 0x0f))
except Exception as e:
    print("DNS-NOANSWER %s" % e)
PY'
[[ "$ZOUT" == *"10.19.0.$UNT/24"* ]] && pass "routed-address" "untrusted is 10.19.0.$UNT (from its identity)" || fail "routed-address" "$(head -2 "$LOG/untrusted.out" | tr '\n' ' ') rc=$ZRC $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
[[ "$ZOUT" == *BRIDGE-OK* ]] && pass "routed-bridge" "untrusted reaches the bridge" || fail "routed-bridge"
# The image's ping, with no privilege: the ICMP datagram socket ping_group_range opens.
[[ "$ZOUT" == *PING-OK* ]] && pass "routed-ping" "ping reaches the bridge from a routed zone" || fail "routed-ping" "$(grep -o 'PING-FAIL.*' "$LOG/untrusted.out")"
[[ "$ZOUT" == *GATEWAY-OK* ]] && pass "routed-egress" "untrusted reaches the VM gateway through net (NAT)" || fail "routed-egress" "no GATEWAY-OK"
[[ "$ZOUT" == *ULA-OK* ]] && pass "routed-ipv6-ula" || fail "routed-ipv6-ula"
[[ "$ZOUT" == *GLOBAL6-PRESENT* ]] && fail "routed-ipv6-noglobal" "a global IPv6 address reached a routed zone" || pass "routed-ipv6-noglobal" "no global IPv6 address in the zone"
[[ "$ZOUT" == *BRIDGE6-OK* ]] && pass "routed-ipv6-bridge" || fail "routed-ipv6-bridge"
[[ "$ZOUT" == *PING6-OK* ]] && pass "routed-ping6" "ping reaches the bridge over IPv6" || fail "routed-ping6" "$(grep -o 'PING6-FAIL.*' "$LOG/untrusted.out")"
[[ "$ZOUT" == *DNS-ANSWERED* ]] && pass "routed-dns" "$(grep -o 'DNS-ANSWERED.*' "$LOG/untrusted.out")" || fail "routed-dns" "$(grep -o 'DNS-.*' "$LOG/untrusted.out")"

# The lease reaches the zone's resolv.conf: every server the resolver forwards
# to comes from there, and under QEMU the stand-in is the lease's own server,
# so a hook that wrote nothing would go unseen without this.
net_init="$(cut -d' ' -f1 /run/kryptik/zones/net/init.pid 2>/dev/null)"
netsh() { nsenter -t "${net_init:-0}" -m sh -c "$1" 2>&1; }
lease_dns="$(netsh 'grep "^nameserver" /etc/resolv.conf')"
if [[ "$lease_dns" == nameserver* ]]; then
    pass "net-lease-names-resolver" "the net zone's resolv.conf: $(tr '\n' ' ' <<<"$lease_dns")"
else
    fail "net-lease-names-resolver" "the net zone's resolv.conf names no server (${lease_dns:-nothing read}); $(netsh 'ls -l /etc/resolv.conf; ls /tmp /run/dhcpcd 2>&1 | head -12' | tr '\n' ' ')"
fi
# The resolver follows the servers a lease names. The net zone's resolv.conf
# is written with the servers dnsmasq has and one more, as a lease that came
# late or another network would change it, and then without it: each time
# the zone's 10 s pass writes dnsmasq's file, and dnsmasq, woken by a query,
# reads it and logs the servers it now uses. Its own servers stay throughout,
# so names still resolve.
forwards_to() {   # forwards_to yes|no: wait until dnsmasq's file does, or does not, name the added server
    for _ in $(seq 1 40); do
        if netsh 'grep -q "^nameserver 192\.0\.2\.53$" /run/uplink-resolv.conf' > /dev/null; then [[ "$1" == yes ]] && return 0
        else [[ "$1" == no ]] && return 0; fi
        sleep 1
    done
    return 1
}
reads() { uncaught | grep -ac 'dnsmasq\[[0-9]*\]: reading /run/uplink-resolv\.conf'; }
# dnsmasq's lines from its last read of the file on.
last_read() { uncaught | grep -a 'dnsmasq\[[0-9]*\]: ' | awk '/: reading \/run\/uplink-resolv\.conf/ { s = "" } { s = s $0 "\n" } END { printf "%s", s }'; }
poke='import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(struct.pack(">HHHHHH", 7, 0x100, 1, 0, 0, 0) + b"\x07kryptik\x04test\x00\x00\x01\x00\x01", ("127.0.0.1", 53))
s.recv(512)'
read_after() {   # read_after N: query dnsmasq, which looks at its file at most once a second, until it has read it more than N times
    for _ in $(seq 1 20); do
        nsenter -t "${net_init:-0}" -n python3 -c "$poke" > /dev/null 2>&1
        [[ "$(reads)" -gt "$1" ]] && { sleep 2; return 0; }   # its server lines follow
        sleep 1
    done
    return 1
}
was="$(netsh 'grep "^nameserver" /run/uplink-resolv.conf')"
before="$(reads)"
if [[ "$was" == nameserver* ]] && wrote="$(netsh "printf '%s\n' '${was}' 'nameserver 192.0.2.53' > /etc/resolv.conf")"; then
    forwards_to yes; came=$?
    read_after "$before"; read1=$?
    gained="$(last_read | grep -c 'using nameserver 192\.0\.2\.53#53')"
    before="$(reads)"
    netsh "printf '%s\n' '${was}' > /etc/resolv.conf" > /dev/null
    forwards_to no; went=$?
    read_after "$before"; read2=$?
    kept="$(last_read | grep -c 'using nameserver 192\.0\.2\.53#53')"
    if [[ "$came" -eq 0 && "$went" -eq 0 && "$read1" -eq 0 && "$read2" -eq 0 && "$gained" -ge 1 && "$kept" -eq 0 ]]; then
        pass "dns-follows-lease" "a server the net zone's resolv.conf gained reached dnsmasq, which used it, and left it again with the lease"
    else
        fail "dns-follows-lease" "file gained: rc=$came, read: rc=$read1, used: $gained; file lost: rc=$went, read: rc=$read2, still used: $kept; $(last_read | tail -3 | tr '\n' ' ')"
    fi
else
    fail "dns-follows-lease" "dnsmasq's servers could not be read in the net zone (init ${net_init:-none}), or its resolv.conf not written: ${was:-nothing read} ${wrote:-}"
fi
# dnsmasq is still there after reading its servers again, as routed-dns found it.
zrun untrusted 20 -- python3 -c 'import socket, struct
q = struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + b"\x07kryptik\x04test\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(q, ("10.19.0.1", 53)); d, _ = s.recvfrom(512); print("DNS-STILL-ANSWERED rcode=%d" % (d[3] & 0x0f))'
[[ "$ZOUT" == *DNS-STILL-ANSWERED* ]] && pass "dns-after-reload" "$(grep -o 'DNS-STILL-ANSWERED.*' "$LOG/untrusted.out")" || fail "dns-after-reload" "no answer from the resolver: $(tail -1 "$LOG/untrusted.err")"

# (the vault is probed once its volume exists, under storage below)

# --- zones: separation between routed zones; fail-closed on a net restart -------
printf 'personal-pass\n' > /root/zt/personal.pass; chmod 600 /root/zt/personal.pass
"$KD" volume init personal --size 64M --passphrase-file /root/zt/personal.pass > "$LOG/vol-personal.out" 2>&1 \
    && pass "volume-init" "personal: $(tail -1 "$LOG/vol-personal.out")" || fail "volume-init" "$(tail -2 "$LOG/vol-personal.out" | tr '\n' ' ')"
# A zone that sends from another zone's address. The rule that opens the
# uplink's own network goes by a packet's source, and IPV6_FREEBIND lets an
# unprivileged socket send from an address its host does not hold. personal
# sends to the bridge's resolver port from its own addresses (the control) and
# with FREEBIND from untrusted's. Counters in the net zone say what reached it, ahead of its
# own chains, and what it took in after them.
net_init="$(cut -d' ' -f1 /run/kryptik/zones/net/init.pid 2>/dev/null)"
netns() { nsenter -t "${net_init:-0}" -n "$@"; }
own4="10.19.0.$PER"; other4="10.19.0.$UNT"
own6="fd19::$(printf '%x' "$PER")"; other6="fd19::$(printf '%x' "$UNT")"
netns nft -f - > "$LOG/source-probe.err" 2>&1 <<EOF
table inet ztprobe {
    chain pre {
        type filter hook prerouting priority -350;
        iifname "kryptik0" udp dport 53 counter comment "pre-any"
        ip saddr $own4 udp dport 53 counter comment "pre-own4"
        ip saddr $other4 udp dport 53 counter comment "pre-other4"
        ip6 saddr $own6 udp dport 53 counter comment "pre-own6"
        ip6 saddr $other6 udp dport 53 counter comment "pre-other6"
    }
    chain taken {
        type filter hook input priority 100;
        ip saddr $own4 udp dport 53 counter comment "taken-own4"
        ip saddr $other4 udp dport 53 counter comment "taken-other4"
        ip6 saddr $own6 udp dport 53 counter comment "taken-own6"
        ip6 saddr $other6 udp dport 53 counter comment "taken-other6"
    }
}
EOF
# Each send binds its source, so none goes from the link-local address; the
# zone's own IPv6 address is usable only once duplicate address detection ends.
zrun personal 40 --passphrase-file /root/zt/personal.pass -- python3 -c '
import errno, socket, sys, time
own4, other4, own6, other6 = sys.argv[1:5]
def tentative():
    try:
        with open("/proc/net/if_inet6") as f:
            return any(r.split()[5] == "eth0" and int(r.split()[4], 16) & 0x40 for r in f)
    except OSError:
        return False
for _ in range(40):
    if not tentative():
        break
    time.sleep(0.25)
else:
    print("DAD-PENDING")
def send(what, family, src, dst, freebind):
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if freebind:   # IP_FREEBIND, IPV6_FREEBIND
            s.setsockopt(*((socket.IPPROTO_IP, 15) if family == socket.AF_INET else (socket.IPPROTO_IPV6, 78)), 1)
        s.bind((src, 0))
        for _ in range(3):
            s.sendto(b"zt", (dst, 53))
        print(what + "-SENT")
    except OSError as e:
        print("%s-REFUSED %s" % (what, errno.errorcode.get(e.errno, e)))
    finally:
        s.close()
send("OWN4", socket.AF_INET, own4, "10.19.0.1", False)
send("OTHER4", socket.AF_INET, other4, "10.19.0.1", True)
send("OWN6", socket.AF_INET6, own6, "fd19::1", False)
send("OTHER6", socket.AF_INET6, other6, "fd19::1", True)
# a datagram still waiting on neighbour discovery goes with the namespace
time.sleep(1)
' "$own4" "$other4" "$own6" "$other6"
table="$(netns nft list table inet ztprobe 2>&1)"
netns nft delete table inet ztprobe 2>/dev/null
declare -A seen
for c in pre-any pre-own4 pre-other4 pre-own6 pre-other6 taken-own4 taken-other4 taken-own6 taken-other6; do
    seen[$c]="$(sed -n "s/.*counter packets \([0-9]*\) .*\"$c\".*/\1/p" <<<"$table" | head -1)"
done
counts="reached the net zone (IPv4/IPv6): own ${seen[pre-own4]:--}/${seen[pre-own6]:--}, untrusted's ${seen[pre-other4]:--}/${seen[pre-other6]:--}, any ${seen[pre-any]:--}; taken in: own ${seen[taken-own4]:--}/${seen[taken-own6]:--}, untrusted's ${seen[taken-other4]:--}/${seen[taken-other6]:--}; personal: $(tr '\n' ' ' <<<"$ZOUT")"
probe_err="$(cat "$LOG/source-probe.err"; [[ -n "${seen[pre-any]}" ]] || head -2 <<<"$table")"
if [[ "${seen[taken-own4]:-0}" -eq 0 || "${seen[taken-own6]:-0}" -eq 0 ]]; then
    fail "zone-source-pinned" "the probe has no path: personal's own datagrams were not taken in; ${counts}${probe_err:+; nft: $(tr '\n' ' ' <<<"$probe_err" | cut -c1-200)}"
elif [[ "${seen[taken-other4]:-0}" -gt 0 || "${seen[taken-other6]:-0}" -gt 0 ]]; then
    fail "zone-source-pinned" "the net zone took in datagrams personal sent from untrusted's addresses; ${counts}"
else
    pass "zone-source-pinned" "personal's own datagrams were taken in and none from untrusted's addresses; ${counts}"
fi
# From the bridge the net zone takes in only what it serves there. A listener on
# every address in its namespace stands in for one it does not serve to zones,
# as dhcpcd's is once it holds two uplinks; a datagram over its own loopback is
# the control, and "end" closes the listener once untrusted has sent.
netns timeout 120 python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", 5467))
s.settimeout(90)
print("LISTENING", flush=True)
while True:
    d, a = s.recvfrom(64)
    if d == b"end":
        break
    print("HEARD " + a[0], flush=True)
' > "$LOG/bridge-listener.out" 2>&1 &
lpid=$!
for _ in $(seq 1 20); do grep -q LISTENING "$LOG/bridge-listener.out" 2>/dev/null && break; sleep 0.5; done
zrun untrusted 40 -- python3 -c '
import socket, time
def tentative():
    try:
        with open("/proc/net/if_inet6") as f:
            return any(r.split()[5] == "eth0" and int(r.split()[4], 16) & 0x40 for r in f)
    except OSError:
        return False
for _ in range(40):
    if not tentative():
        break
    time.sleep(0.25)
for family, dst in ((socket.AF_INET, "10.19.0.1"), (socket.AF_INET6, "fd19::1")):
    s = socket.socket(family, socket.SOCK_DGRAM)
    for _ in range(3):
        s.sendto(b"zt", (dst, 5467))
    s.close()
time.sleep(1)
print("SENT")
'
netns python3 -c 'import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.sendto(b"zt", ("::1", 5467)); s.sendto(b"end", ("::1", 5467))'
wait "$lpid"
heard="$(grep '^HEARD' "$LOG/bridge-listener.out" | tr '\n' ' ')"
if [[ "$heard" != *"HEARD ::1 "* ]]; then
    fail "bridge-ports-closed" "the probe has no listener: $(head -c 300 "$LOG/bridge-listener.out" | tr '\n' ' ')"
elif [[ "$ZOUT" != *SENT* ]]; then
    fail "bridge-ports-closed" "untrusted did not send: rc=$ZRC $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
elif [[ "$heard" == *"10.19.0."* || "$heard" == *"fd19::"* ]]; then
    fail "bridge-ports-closed" "the net zone took in what untrusted sent to a port the bridge does not serve: ${heard}"
else
    pass "bridge-ports-closed" "a listener on every net zone address heard its own loopback and nothing untrusted sent to 10.19.0.1 or fd19::1"
fi
# personal stays up in the background for the separation and restart checks
setsid "$KD" run personal --zones "$Z" --rootfs "$R" --passphrase-file /root/zt/personal.pass -- sh -c 'echo PERSONAL-UP; sleep 600' > "$LOG/personal-bg.out" 2>&1 &
PBG=$!
for _ in $(seq 1 60); do grep -q PERSONAL-UP "$LOG/personal-bg.out" 2>/dev/null && break; sleep 0.5; done
grep -q PERSONAL-UP "$LOG/personal-bg.out" && pass "encrypted-zone-start" "personal up on its LUKS2 volume" || fail "encrypted-zone-start" "$(tail -3 "$LOG/personal-bg.out" | tr '\n' ' ')"
[[ -e /dev/mapper/kryptik-zone-personal ]] && pass "mapping-while-running" "/dev/mapper/kryptik-zone-personal exists while the zone runs" || fail "mapping-while-running"
# The passphrase search, made while a zone that took one runs (the verdict is
# with the storage checks). It must find that launcher's command line, or
# finding no passphrase says nothing. The [e] and [s] keep a grep's own
# command line from matching.
pp_seen=0; pp_leak=0
grep -qs 'passphrase-fil[e]' /proc/[0-9]*/cmdline && pp_seen=1
grep -rqs 'personal-pas[s]' /run/kryptik /proc/[0-9]*/cmdline && pp_leak=1
# An echo that gets no answer shows separation only while personal holds the
# address that was tried, and untrusted has a path: it reaches the bridge.
per_init="$(cut -d' ' -f1 /run/kryptik/zones/personal/init.pid 2>/dev/null)"
per_addr="$(nsenter -t "${per_init:-0}" -n ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | head -1)"
zrun untrusted 30 -- sh -c "python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.1 3 >/dev/null 2>&1 && echo BRIDGE-OK; python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.$PER 2 >/dev/null 2>&1 && echo CROSS-ZONE-REACHED || echo CROSS-ZONE-BLOCKED; test -e /var/lib/kryptik/volumes && echo VOLUMES-VISIBLE || echo VOLUMES-ABSENT; echo \"HOMES=\$(ls /home 2>&1 | tr '\n' ' ')\""
[[ "$ZOUT" == *BRIDGE-OK* && "$ZOUT" == *CROSS-ZONE-BLOCKED* && "$per_addr" == "10.19.0.$PER/24" ]] && pass "zone-separation" "untrusted reaches the bridge and not personal, which holds 10.19.0.$PER on it" || fail "zone-separation" "$ZOUT; personal's address: ${per_addr:-none}; $(grep -h 'network path' "$LOG/untrusted.err" | tail -1)"
[[ "$ZOUT" == *VOLUMES-ABSENT* ]] && pass "volume-hidden" "no /var/lib/kryptik/volumes inside untrusted" || fail "volume-hidden" "the volume directory is visible from untrusted, or the probe did not run: $ZOUT"
homes="$(sed -n 's/^HOMES=//p' <<<"$ZOUT")"
[[ "$(tr -d ' ' <<<"$homes")" == untrusted ]] && pass "home-hidden" "/home in untrusted holds its own directory and no other zone's" || fail "home-hidden" "/home in untrusted: ${homes:-not listed}"
# untrusted again at once: its last run's port stays in the net zone until the
# kernel has torn that run's namespace down, and the new run must not lose its
# path to it.
zrun untrusted 30 -- sh -c 'python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.1 3 >/dev/null 2>&1 && echo BRIDGE-OK'
if [[ "$ZOUT" == *BRIDGE-OK* ]] && ! grep -q 'has no network path' "$LOG/untrusted.err"; then
    pass "routed-restart-path" "untrusted, started again as its last run ended, reaches the bridge"
else
    fail "routed-restart-path" "rc ${ZRC}: $(tr '\n' ' ' <<<"$ZOUT") $(grep -h 'network path' "$LOG/untrusted.err" | tail -1)"
fi
# No writable mount is shared by two zones, /tmp among them, and the net zone
# mounts nothing of another zone's volume: every pair of the zones running
# now (net and personal at least), by device and root, the device nodes every
# zone binds aside.
writable_mounts() {   # writable_mounts PID: "dev root" of each writable mount but a device node
    awk '{ split($0, h, " - "); split(h[2], s, " "); if ($6 ~ /^rw/ && s[3] ~ /^rw/) print $3, $4, $5 }' "/proc/$1/mountinfo" 2>/dev/null |
        while read -r dev rt mnt; do [[ -c "/proc/$1/root$mnt" ]] || echo "$dev $rt"; done | sort -u
}
mount_dev() { awk -v m="$2" '$5 == m { print $3 }' "/proc/$1/mountinfo" 2>/dev/null | tail -1; }   # mount_dev PID PATH
net_pid="$(cut -d' ' -f1 /run/kryptik/zones/net/init.pid 2>/dev/null)"
per_pid="$(cut -d' ' -f1 /run/kryptik/zones/personal/init.pid 2>/dev/null)"
running=()
for f in /run/kryptik/zones/*/init.pid; do
    p="$(cut -d' ' -f1 "$f" 2>/dev/null)"; z="${f%/init.pid}"
    # A stopped zone's pid may be anyone's now: a zone's init has a mount namespace of its own.
    [[ -n "$p" && -r "/proc/$p/mountinfo" && "$(readlink "/proc/$p/ns/mnt")" != "$(readlink /proc/self/ns/mnt)" ]] \
        && running+=("${z##*/} $p $(mount_dev "$p" /tmp)")
done
shared=""
for ((i = 0; i < ${#running[@]}; i++)); do
    read -r zi pi ti <<<"${running[i]}"
    for ((j = i + 1; j < ${#running[@]}; j++)); do
        read -r zj pj tj <<<"${running[j]}"
        both="$(comm -12 <(writable_mounts "$pi") <(writable_mounts "$pj") | tr '\n' ';')"
        [[ -z "$both" && "$ti" != "$tj" ]] || shared="${shared} ${zi}+${zj}: ${both:-/tmp ${ti}}"
    done
done
names="$(for r in "${running[@]}"; do printf '%s ' "${r%% *}"; done)"
if [[ " $names" != *" net "* || " $names" != *" personal "* || "$(printf '%s\n' "${running[@]}" | awk 'NF < 3' | grep -c .)" -gt 0 ]]; then
    fail "no-shared-writable-mount" "the running zones' mount tables could not be read: $(printf '%s; ' "${running[@]}")"
elif [[ -n "$shared" ]]; then
    fail "no-shared-writable-mount" "zones share writable mounts:${shared}"
else
    pass "no-shared-writable-mount" "no two of the running zones (${names% }) share a writable mount, and each /tmp is its own"
fi
per_home="$(mount_dev "${per_pid:-0}" /home/personal)"
if [[ -z "$per_home" || ! -r "/proc/${net_pid:-0}/mountinfo" ]]; then
    fail "net-zone-no-zone-data" "personal's home (${per_home:-not found}) or the net zone's table (${net_pid:-no init}) could not be read"
elif awk -v d="$per_home" '$3 == d { f = 1 } END { exit !f }' "/proc/${net_pid}/mountinfo"; then
    fail "net-zone-no-zone-data" "the net zone mounts personal's volume (${per_home})"
else
    pass "net-zone-no-zone-data" "nothing the net zone mounts is on personal's volume (${per_home})"
fi
# No swap area, so no zone's memory reaches a disk, and no D-Bus: no shared bus between zones.
swaps="$(tail -n +2 /proc/swaps 2>/dev/null | grep -c .)"
[[ "$swaps" == 0 ]] && pass "no-swap" "no swap area is active" || fail "no-swap" "$(tail -n +2 /proc/swaps | tr '\n' ' ')"
if command -v dbus-daemon >/dev/null 2>&1 || [[ -e /run/dbus ]] || pgrep -x dbus-daemon >/dev/null 2>&1; then
    fail "no-dbus" "a D-Bus daemon or socket exists: $(command -v dbus-daemon) $(ls -d /run/dbus 2>/dev/null)"
else
    pass "no-dbus" "no D-Bus daemon, socket or running bus"
fi
# The network the uplink sits on: untrusted's definition opens it ([network]
# local) and personal's does not. The bridge answers personal, so the refusal
# is the rule's and not a dead path.
ppid="$(cut -d' ' -f1 /run/kryptik/zones/personal/init.pid 2>/dev/null)"
if [[ -n "$ppid" ]] && nsenter -t "$ppid" -n ping -c1 -W3 10.19.0.1 >/dev/null 2>&1 \
   && ! nsenter -t "$ppid" -n ping -c1 -W3 10.0.2.2 >/dev/null 2>&1; then
    pass "uplink-refused" "personal reaches the bridge and is refused the VM gateway, which untrusted reached"
else
    fail "uplink-refused" "personal (init ${ppid:-none}) reached the VM gateway, or not even the bridge; $(netzone_said 'nftables: zones go out' | tail -1)"
fi
# The net zone's own address on the uplink is the net zone, not the network the
# uplink sits on. untrusted, which may reach that network, reaches the VM
# gateway and neither of the net zone's addresses beside it.
nz="$(cut -d' ' -f1 /run/kryptik/zones/net/init.pid 2>/dev/null)"
uplink4="$([[ -n "$nz" ]] && nsenter -t "$nz" -n ip -4 -o addr show eth0 2>/dev/null | awk '{ split($4, a, "/"); print a[1]; exit }')"
uplink6="$([[ -n "$nz" ]] && nsenter -t "$nz" -n ip -6 -o addr show eth0 2>/dev/null | awk '$4 !~ /^fe80:/ { split($4, a, "/"); print a[1]; exit }')"
# The bridge first, as routed-egress does, so the gateway's echo is not the
# zone's first packet; its NOPONG line says why if it still fails.
zrun untrusted 40 -- sh -c "python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.1 3 >/dev/null 2>&1
python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.0.2.2 5 > /tmp/gw.out 2>&1 && echo GATEWAY-OK || echo \"GATEWAY-NO \$(tail -1 /tmp/gw.out)\"
python3 /usr/lib/kryptik/guest-tests/icmp-echo.py ${uplink4:-192.0.2.1} 3 >/dev/null 2>&1 && echo UPLINK4-REACHED || echo UPLINK4-REFUSED
[ -z '${uplink6}' ] || { python3 /usr/lib/kryptik/guest-tests/icmp-echo.py '${uplink6}' 3 >/dev/null 2>&1 && echo UPLINK6-REACHED || echo UPLINK6-REFUSED; }"
if [[ -n "$uplink4" && "$ZOUT" == *GATEWAY-OK* && "$ZOUT" == *UPLINK4-REFUSED* && "$ZOUT" != *UPLINK6-REACHED* ]]; then
    pass "uplink-address-refused" "untrusted reaches the VM gateway and not the net zone's own uplink address ${uplink4}${uplink6:+ or ${uplink6}}"
else
    fail "uplink-address-refused" "the net zone's uplink addresses: ${uplink4:-none} ${uplink6:-none}; untrusted (rc ${ZRC}): $(tr '\n' ' ' <<<"$ZOUT") $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
fi

# net zone restart: routed zones fail closed while it is down, recover after
before="$(ready_count)"
s6-svc -d /run/service/net-zone; sleep 3
zrun untrusted 20 -- sh -c 'python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.0.2.2 2 >/dev/null 2>&1 && echo EGRESS-WHILE-DOWN || echo CLOSED-WHILE-DOWN; ip -o link show eth0 >/dev/null 2>&1 && echo HAS-ETH0 || echo NO-ETH0'
[[ "$ZOUT" == *CLOSED-WHILE-DOWN* ]] && pass "fail-closed" "no egress while the net zone is down ($(grep -o 'HAS-ETH0\|NO-ETH0' "$LOG/untrusted.out" | head -1))" || fail "fail-closed" "$ZOUT"
# untrusted again, kept running from while the net zone is down: attached when
# it comes back, it must resolve through the bridge, with no restart.
setsid "$KD" run untrusted --zones "$Z" --rootfs "$R" -- sh -c 'echo UNTRUSTED-UP; sleep 600' > "$LOG/untrusted-down.out" 2>&1 &
UDOWN=$!
for _ in $(seq 1 40); do grep -q UNTRUSTED-UP "$LOG/untrusted-down.out" 2>/dev/null && break; sleep 0.5; done
s6-svc -u /run/service/net-zone
ok=0
for _ in $(seq 1 60); do
    after="$(ready_count)"
    [[ "$after" -gt "$before" ]] && { ok=1; break; }; sleep 1
done
[[ "$ok" = 1 ]] && pass "net-restart-ready" "the net zone came back READY after a restart" || fail "net-restart-ready" "no new READY line ($before -> $after)"
sleep 2
# kryptik.test is local to the bridge's dnsmasq: NXDOMAIN (EAI_NONAME) is its
# answer, where a zone with no resolver gets EAI_AGAIN.
udpid="$(cut -d' ' -f1 /run/kryptik/zones/untrusted/init.pid 2>/dev/null)"
resolved="$([[ -n "$udpid" ]] && nsenter -t "$udpid" -m -n /usr/bin/python3 -c 'import os, socket
names = open("/etc/resolv.conf").read().splitlines() if os.path.exists("/etc/resolv.conf") else ["NO-RESOLV-CONF"]
print(" ".join(names[:2]))
try:
    socket.getaddrinfo("kryptik.test", 53); print("ANSWERED")
except socket.gaierror as e:
    print("ANSWERED" if e.errno == socket.EAI_NONAME else "NO-ANSWER %s" % e)' 2>&1 | tr '\n' ' ')"
if [[ "$resolved" == *ANSWERED* && "$resolved" != *NO-ANSWER* ]]; then
    pass "resolver-after-attach" "untrusted, started while the net zone was down, resolves through the bridge once attached (${resolved})"
else
    fail "resolver-after-attach" "untrusted (init ${udpid:-none}): ${resolved:-nothing ran}; $(tail -2 "$LOG/untrusted-down.out" | tr '\n' ' ')"
fi
"$KD" stop untrusted >/dev/null 2>&1; wait "$UDOWN" 2>/dev/null
zrun untrusted 30 -- sh -c 'python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.0.2.2 3 >/dev/null 2>&1 && echo GATEWAY-OK || echo GATEWAY-FAIL'
[[ "$ZOUT" == *GATEWAY-OK* ]] && pass "egress-after-restart" "a zone started after the restart has egress" || fail "egress-after-restart" "$ZOUT"
# personal, running across the restart, was reattached. It is refused the VM
# gateway, so the bridge is as far as it can show; untrusted shows egress below.
ppid="$(cut -d' ' -f1 /run/kryptik/zones/personal/init.pid 2>/dev/null)"
if [[ -n "$ppid" ]] && nsenter -t "$ppid" -n ping -c1 -W3 10.19.0.1 >/dev/null 2>&1; then pass "reattach-after-restart" "personal, running across the restart, reaches the net zone again"; else fail "reattach-after-restart" "personal (init ${ppid:-none}) does not reach the bridge after the net restart"; fi
# A zone that may reach the gateway, kept running across a second restart: it
# goes out through the gateway before, has no path while the net zone is down,
# and goes out again once reattached. Meanwhile the uplink is back in zone 0
# under its own name, down and with no address, and the next start takes it.
setsid "$KD" run untrusted --zones "$Z" --rootfs "$R" -- sh -c 'echo UNTRUSTED-UP; sleep 600' > "$LOG/untrusted-bg.out" 2>&1 &
UBG=$!
for _ in $(seq 1 40); do grep -q UNTRUSTED-UP "$LOG/untrusted-bg.out" 2>/dev/null && break; sleep 0.5; done
upid="$(cut -d' ' -f1 /run/kryptik/zones/untrusted/init.pid 2>/dev/null)"
# ping, not icmp-echo.py: the zone's ping_group_range names its own gid, not
# root's, so root in its namespace needs ping's raw socket.
gateway_echo() { [[ -n "$upid" ]] && nsenter -t "$upid" -n ping -c1 -W"$1" 10.0.2.2 >/dev/null 2>&1; }
physical() { local d; for d in /sys/class/net/*; do [[ -e "$d/device" ]] && printf '%s ' "${d##*/}"; done; }
out_before=no; gateway_echo 3 && out_before=yes
before="$(ready_count)"
s6-svc -d /run/service/net-zone
returned=""
for _ in $(seq 1 20); do returned="$(ip -o link show eth0 2>/dev/null)"; [[ -n "$returned" ]] && break; sleep 0.5; done
flags="$(sed -n 's/^[0-9]*: eth0: <\([^>]*\)>.*/\1/p' <<<"$returned")"
held="$(ip -o addr show eth0 2>/dev/null | awk '{ print $4 }' | tr '\n' ' ')"
if [[ -n "$flags" && ",$flags," != *",UP,"* && -z "$held" && "$(physical)" == "eth0 " ]]; then
    pass "uplink-returned" "while the net zone is down the uplink is back in zone 0 as eth0, down and with no address"
else
    fail "uplink-returned" "zone 0 while the net zone is down: ${returned:-no eth0}; addresses: ${held:-none}; physical interfaces: $(physical)"
fi
eth0_gone=no; [[ -n "$upid" ]] && ! nsenter -t "$upid" -n ip -o link show eth0 >/dev/null 2>&1 && eth0_gone=yes
out_down=no; gateway_echo 2 && out_down=yes
s6-svc -u /run/service/net-zone
ok=0
for _ in $(seq 1 60); do
    after="$(ready_count)"
    [[ "$after" -gt "$before" ]] && { ok=1; break; }; sleep 1
done
if [[ "$ok" = 1 ]] && ! ip link show eth0 >/dev/null 2>&1; then pass "uplink-retaken" "the next net zone start took eth0 from zone 0 again and came READY"; else fail "uplink-retaken" "READY again: $ok; zone 0 still holds: $(physical)"; fi
sleep 2
out_after=no; gateway_echo 3 && out_after=yes
if [[ "$out_before" = yes && "$eth0_gone" = yes && "$out_down" = no && "$out_after" = yes ]]; then
    pass "reattach-egress" "untrusted, running across a restart, reached the VM gateway before it, had no eth0 and no path while the net zone was down, and reaches the gateway again once reattached"
else
    fail "reattach-egress" "untrusted (init ${upid:-none}): gateway before ${out_before}; eth0 gone while down ${eth0_gone}; gateway while down ${out_down}; gateway after ${out_after}; $(tail -2 "$LOG/untrusted-bg.out" | tr '\n' ' ')"
fi
"$KD" stop untrusted >/dev/null 2>&1; wait "$UBG" 2>/dev/null

# --- zones: the net zone over a radio -----------------------------------------------
# QEMU has no radio, so mac80211_hwsim makes two. phy1 goes into a network
# namespace of its own as the access point (the image's wpa_supplicant in AP
# mode and dnsmasq for the lease); phy0 stays in zone 0 for the net zone to
# take on its next start, which `kryptikd wifi add` causes. The station is
# the net zone's own wpa_supplicant, under its filter, on the shipped kernel.
AP_SSID=kryptik-hwsim; AP_PASS=hwsim-passphrase; AP_ADDR=192.168.77.1
# An address the access point routes to, past the network the radio is on.
AP_FAR=198.51.100.1
WIFI_DIR=/var/lib/kryptik/wifi
ready_after() {   # ready_after COUNT TEXT SECONDS: the newest READY line once there are more than COUNT and it holds TEXT
    local before="$1" text="$2" n="$3"
    while [[ "$n" -gt 0 ]]; do
        if [[ "$(ready_count)" -gt "$before" && "$(last_ready)" == *"$text"* ]]; then last_ready; return 0; fi
        sleep 1; n=$((n - 1))
    done
    last_ready; return 1
}
wl_of_phy() {   # wl_of_phy phyN: the netdev on that wiphy, in this namespace
    local d
    for d in /sys/class/net/*; do
        [[ "$(basename "$(readlink -f "$d/phy80211" 2>/dev/null)")" = "$1" ]] && { basename "$d"; return 0; }
    done
    return 1
}
# The namespace is a sleeper's, entered for its network alone: a cloned mount
# namespace would keep a running zone's volume open past its stop.
ap() { nsenter -t "$AP_HOLD" -n "$@"; }
ap_wpa() { ap wpa_cli -p /run/zt-ap-ctrl -i "$AP_IF" "$@" 2>/dev/null; }
STA_IF=""; AP_IF=""; AP_HOLD=""
if modprobe mac80211_hwsim radios=2 2> "$LOG/hwsim.err"; then
    for _ in $(seq 1 20); do [[ -e /sys/class/ieee80211/phy1 ]] && break; sleep 0.5; done
    STA_IF="$(wl_of_phy phy0)"; AP_IF="$(wl_of_phy phy1)"
fi
if [[ -n "$STA_IF" && -n "$AP_IF" ]]; then
    pass "wifi-module" "the signed mac80211_hwsim loaded with two radios: $STA_IF on phy0, $AP_IF on phy1"
else
    fail "wifi-module" "$(tr '\n' ' ' < "$LOG/hwsim.err") radios: $(ls /sys/class/ieee80211 2>/dev/null | tr '\n' ' ')"
fi
ap_up=0
if [[ -n "$AP_IF" ]]; then
    unshare -n sleep 900 > /dev/null 2>&1 & AP_HOLD=$!
    for _ in $(seq 1 25); do [[ "$(readlink "/proc/$AP_HOLD/ns/net" 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ]] && break; sleep 0.2; done
fi
if [[ -n "$AP_HOLD" ]] && iw phy phy1 set netns "$AP_HOLD" 2> "$LOG/ap.err"; then
    cat > /root/zt/ap.conf <<EOF
ctrl_interface=/run/zt-ap-ctrl
ap_scan=2
network={
	ssid="$AP_SSID"
	mode=2
	frequency=2412
	key_mgmt=WPA-PSK
	proto=RSN
	pairwise=CCMP
	psk="$AP_PASS"
}
EOF
    ap ip link set lo up
    ap ip addr add "$AP_ADDR/24" dev "$AP_IF"
    ap ip addr add "$AP_FAR/32" dev lo
    ap wpa_supplicant -B -i "$AP_IF" -c /root/zt/ap.conf -P /run/zt-ap-wpa.pid -f "$LOG/ap-wpa.log" >> "$LOG/ap.err" 2>&1
    for _ in $(seq 1 30); do ap_wpa status | grep -q '^wpa_state=COMPLETED' && { ap_up=1; break; }; sleep 1; done
    ap dnsmasq --port=0 --interface="$AP_IF" --bind-interfaces --dhcp-range=192.168.77.10,192.168.77.90,1h \
       --dhcp-option=121,198.51.100.0/24,"$AP_ADDR" \
       --dhcp-leasefile=/run/zt-ap.leases --pid-file=/run/zt-ap-dnsmasq.pid --user=root >> "$LOG/ap.err" 2>&1 || ap_up=0
fi
[[ "$ap_up" = 1 ]] && pass "wifi-ap" "$AP_SSID beacons on $AP_IF in its own namespace ($(ap_wpa status | grep -E '^(mode|freq)=' | tr '\n' ' ')) with a DHCP server" || fail "wifi-ap" "$(tr '\n' ' ' < "$LOG/ap.err" | cut -c1-200) status: $(ap_wpa status | tr '\n' ' ' | cut -c1-120)"
# The credentials, as the user gives them: one file, 0400, owned by the net
# zone's identity, and the add restarts the net zone.
before="$(ready_count)"
printf '%s\n' "$AP_PASS" | "$KD" wifi add "$AP_SSID" --wifi-dir "$WIFI_DIR" --zones "$Z" > "$LOG/wifi-add.out" 2>&1
NET_UID="$(sed -n 's/^uid_base *= *\([0-9]*\).*/\1/p' "$Z/net.toml")"
if grep -q "added network \"$AP_SSID\"; the net zone is restarting" "$LOG/wifi-add.out" \
   && [[ "$(stat -c '%a %u' "$WIFI_DIR/wpa_supplicant.conf" 2>/dev/null)" = "400 $NET_UID" ]] \
   && "$KD" wifi list --wifi-dir "$WIFI_DIR" 2>/dev/null | grep -qx "$AP_SSID"; then
    pass "wifi-add" "kryptikd wifi add wrote the file 0400 for uid $NET_UID, lists the SSID, and restarted the net zone"
else
    fail "wifi-add" "$(tr '\n' ' ' < "$LOG/wifi-add.out") file: $(stat -c '%a %u' "$WIFI_DIR/wpa_supplicant.conf" 2>&1) list: $("$KD" wifi list --wifi-dir "$WIFI_DIR" 2>&1 | tr '\n' ' ')"
fi
line="$(ready_after "$before" " wifi=$AP_SSID " 90)"
kills="$(dmesg 2>/dev/null | grep -a 'type=1326' | grep -ac 'comm="wpa_supplicant"')"
if [[ "$line" == *" wifi=$AP_SSID "* && "${kills:-0}" = 0 ]]; then
    pass "wifi-associated" "the net zone's supplicant joined $AP_SSID over $STA_IF with no filter kill: ${line#*netzone: }"
else
    fail "wifi-associated" "newest READY line: ${line:-none}; filter kills of wpa_supplicant: ${kills:-0}; $(netzone_said wifi | tail -3 | tr '\n' ' ')"
fi
net_init="$(cut -d' ' -f1 /run/kryptik/zones/net/init.pid 2>/dev/null)"
lease=""
for _ in $(seq 1 40); do
    [[ -n "$net_init" ]] && lease="$(nsenter -t "$net_init" -n ip -4 -o addr show "$STA_IF" 2>/dev/null | awk '{print $4}' | head -1)"
    [[ "$lease" == 192.168.77.* ]] && break; sleep 1
done
[[ "$lease" == 192.168.77.* ]] && pass "wifi-lease" "$STA_IF in the net zone leased $lease from the access point" || fail "wifi-lease" "$STA_IF holds ${lease:-no address}; leases given: $(tr '\n' ' ' < /run/zt-ap.leases 2>/dev/null)"
zrun untrusted 40 -- sh -c "python3 /usr/lib/kryptik/guest-tests/icmp-echo.py $AP_ADDR 3 >/dev/null 2>&1 && echo AP-REACHED || echo AP-UNREACHED"
sta_seen="$(ap_wpa all_sta | grep -ciE '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')"
if [[ "$ZOUT" == *AP-REACHED* && "${sta_seen:-0}" -ge 1 ]]; then
    pass "wifi-egress" "a routed zone reached the access point ($AP_ADDR) through the net zone over the radio, which lists $sta_seen station"
else
    fail "wifi-egress" "$ZOUT; stations at the access point: ${sta_seen:-0}; $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
fi
# personal's definition does not open the radio's own network: once the net
# zone has taken the access point as a gateway, its address is refused
# personal, and what lies past it is not.
ppid="$(cut -d' ' -f1 /run/kryptik/zones/personal/init.pid 2>/dev/null)"
for _ in $(seq 1 30); do
    netzone_said 'nftables: zones go out' | tail -1 | grep -q "$AP_ADDR" && break; sleep 1
done
far=1; near=0
if [[ -n "$ppid" ]]; then
    nsenter -t "$ppid" -n ping -c1 -W3 "$AP_FAR" >/dev/null 2>&1; far=$?
    nsenter -t "$ppid" -n ping -c1 -W3 "$AP_ADDR" >/dev/null 2>&1; near=$?
fi
if [[ "$far" -eq 0 && "$near" -ne 0 ]]; then
    pass "wifi-beyond" "personal is refused the access point's own address and reaches $AP_FAR past it"
else
    fail "wifi-beyond" "personal (init ${ppid:-none}): $AP_FAR rc=$far, $AP_ADDR rc=$near; $(netzone_said 'nftables: zones go out' | tail -1); routes: $(nsenter -t "$net_init" -n ip -4 route 2>/dev/null | tr '\n' ';')"
fi
# Back to the wire: the access point, its namespace (whose end returns phy1
# to zone 0) and the radios go first, so the net zone the forget restarts
# finds none.
for f in /run/zt-ap-dnsmasq.pid /run/zt-ap-wpa.pid; do p="$(cat "$f" 2>/dev/null)"; [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
[[ -n "$AP_HOLD" ]] && kill "$AP_HOLD" 2>/dev/null
sleep 1
modprobe -r mac80211_hwsim 2>> "$LOG/hwsim.err" || info "wifi-module-removal $(tail -1 "$LOG/hwsim.err")"
before="$(ready_count)"
"$KD" wifi forget "$AP_SSID" --wifi-dir "$WIFI_DIR" --zones "$Z" > "$LOG/wifi-forget.out" 2>&1
line="$(ready_after "$before" " wifi=none " 90)"
if grep -q "forgot network \"$AP_SSID\"" "$LOG/wifi-forget.out" && [[ "$line" == *" wifi=none "* && "$line" == *" nat=yes "* ]] \
   && ! "$KD" wifi list --wifi-dir "$WIFI_DIR" 2>/dev/null | grep -qx "$AP_SSID"; then
    pass "wifi-forget" "the network is forgotten and the net zone is READY on the wire again with no radio"
else
    fail "wifi-forget" "$(tr '\n' ' ' < "$LOG/wifi-forget.out") newest READY: ${line:-none}"
fi

# --- the clock: zone 0 decides, the net zone only claims ----------------------------
# (docs/design/time.md) This moves the real clock of a disposable machine and
# puts it back from the boot clock, which nothing here touches.
up_s() { cut -d' ' -f1 /proc/uptime | cut -d. -f1; }
T_WALL0="$(date +%s)"; T_UP0="$(up_s)"
true_now() { echo $(( T_WALL0 + $(up_s) - T_UP0 )); }
put_clock_back() { date -u -s "@$(true_now)" >/dev/null 2>&1; command -v hwclock >/dev/null 2>&1 && hwclock --systohc -u >/dev/null 2>&1; rm -f /var/lib/kryptik/time/state; }
FLOOR="$("$KD" time status 2>/dev/null | sed -n 's/^floor  *\([0-9-]* [0-9:]*\) UTC.*/\1/p')"
# An unknown floor must stay unknown: `date -d " UTC"` is today's midnight.
FLOOR_S=0; [[ -n "$FLOOR" ]] && FLOOR_S="$(date -u -d "${FLOOR} UTC" +%s 2>/dev/null || echo 0)"
# Claims go through the net zone's broker socket from inside its user and mount
# namespaces: host uid = net's uid_base, the only peer that broker accepts.
net_init="$(cut -d' ' -f1 /run/kryptik/zones/net/init.pid 2>/dev/null)"
claim() {   # claim SECONDS -> the broker's one-line reply
    rm -f /var/lib/kryptik/time/state      # each row is judged on its own, not against the last one's window
    nsenter -t "$net_init" -U -m /usr/bin/python3 -c 'import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(20); s.connect("/run/kryptik/broker")
s.sendall(("time-offset %s 1\n" % sys.argv[1]).encode()); s.shutdown(socket.SHUT_WR)
print(s.recv(4096).decode("utf-8", "replace").strip())' "$1" 2>&1 | head -1
}

if grep -q 'time floor' /var/log/kryptik/time.log 2>/dev/null; then pass "time-floor-ran" "$(tail -1 /var/log/kryptik/time.log | cut -c1-160)"; else fail "time-floor-ran" "the boot service left no line in /var/log/kryptik/time.log"; fi
ready_time="$(last_ready | grep -o 'time=[^ ]*')"
info "time-reported ${ready_time:-the readiness line has no time= field} (no answer through this network is reported as that, never as a pass)"

if [[ "$FLOOR_S" -gt 0 ]]; then
    # a dead RTC's clock: the year 2000
    date -u -s "@946684800" >/dev/null 2>&1
    said="$("$KD" time floor 2>&1)"
    got="$(date +%s)"
    # `time status` prints the floor to the minute; the clamp sets it to the second.
    if (( got >= FLOOR_S && got <= FLOOR_S + 90 )); then pass "time-clamp" "a clock set to 2000-01-01 came back at the build date: ${said}"; else fail "time-clamp" "clock reads $(date -u -d "@$got" +%F) after the clamp, floor is ${FLOOR}: ${said}"; fi
    put_clock_back

    # The newest release committed to, as whoever writes the state partition
    # could leave it: dated 2099, signed by a key the anchor does not list.
    rel=/var/lib/kryptik/time/release
    rm -rf "$rel" /root/zt/forger /root/zt/forger.pub; mkdir -p "$rel"
    printf 'KRYPTIK-MANIFEST-1\nname: kryptik\nversion: 99.0\nrole: %s\ncreated: 2099-01-01T00:00:00Z\nfiles: 0\n--\n' \
        "$(cat /usr/share/kryptik/trust/required-role 2>/dev/null)" > "$rel/manifest"
    ssh-keygen -q -t ed25519 -N '' -f /root/zt/forger >/dev/null 2>&1
    ssh-keygen -Y sign -f /root/zt/forger -n kryptik-release "$rel/manifest" >/dev/null 2>&1
    st="$("$KD" time status 2>&1)"
    f="$(sed -n 's/^floor  *\([0-9-]* [0-9:]*\) UTC.*/\1/p' <<<"$st")"
    if [[ -s "$rel/manifest.sig" && "$f" == "$FLOOR" && "$st" == *"not used"*"not enrolled"* ]]; then
        pass "time-floor-forged" "a release dated 2099 that the release key did not sign leaves the floor at ${FLOOR}"
    else
        fail "time-floor-forged" "floor '${f}', build date '${FLOOR}': $(tr '\n' ' ' <<<"$st")"
    fi
    rm -rf "$rel" /root/zt/forger /root/zt/forger.pub

    if [[ -n "$net_init" ]]; then
        before="$(date +%s)"; r="$(claim 120)"; after="$(date +%s)"
        moved=$(( after - before ))
        if [[ "$r" == "ok stepped" ]] && (( moved >= 118 && moved <= 140 )); then pass "time-claim-stepped" "the net zone's claim of +120 s moved the clock by ${moved} s (${r})"; else fail "time-claim-stepped" "reply '${r}', clock moved ${moved} s"; fi
        put_clock_back

        before="$(date +%s)"; r="$(claim -999999999)"; after="$(date +%s)"
        if [[ "$r" == error:*"before the floor"* ]] && (( after - before < 30 )); then pass "time-claim-floor" "a claim below the build date is refused and the clock is untouched"; else fail "time-claim-floor" "reply '${r}', clock moved $(( after - before )) s"; fi

        # past the bound with nobody at a trusted window: refused, not applied
        before="$(date +%s)"; r="$(claim 90000)"; after="$(date +%s)"
        if [[ "$r" == error:*consent* ]] && (( after - before < 90 )); then pass "time-claim-consent" "a day's jump is not applied without the person (${r#error: })"; else fail "time-claim-consent" "reply '${r}', clock moved $(( after - before )) s"; fi
        put_clock_back

        # End to end, only where a time server answers: with the clock 300 s
        # fast, the restarted net zone must measure about -300 and zone 0 must
        # correct it (tools/tests/netzone-time.sh checks the sign offline).
        case "$ready_time" in
            time=-[0-9]*|time=[0-9]*)
                date -u -s "@$(( $(true_now) + 300 ))" >/dev/null 2>&1; rm -f /var/lib/kryptik/time/state
                n0="$(ready_count)"
                s6-svc -r /run/service/net-zone
                for _ in $(seq 1 90); do [[ "$(ready_count)" -gt "$n0" ]] && break; sleep 1; done
                m="$(last_ready | grep -o 'time=[^ ]*' | cut -d= -f2)"
                err=$(( $(date +%s) - $(true_now) ))
                if [[ "$m" == -29[0-9]* || "$m" == -30[0-9]* || "$m" == -31[0-9]* ]] && (( err > -10 && err < 10 )); then
                    pass "time-sign" "a clock 300 s fast was measured as ${m} s and zone 0 put it right (now ${err} s from true)"
                else
                    fail "time-sign" "a clock 300 s fast was measured as '${m}', and the clock is now ${err} s from true"
                fi
                put_clock_back ;;
            *) info "time-sign not measured: no time server answered through this network (${ready_time:-no time= field})" ;;
        esac
    else
        fail "time-claim-stepped" "the net zone is not running, so nothing can make a claim"
    fi
else
    fail "time-clamp" "kryptikd time status names no floor (no /etc/kryptik-image.json built_at?)"
fi

# --- zones: resource limits and lifecycle ------------------------------------------
# A python fork storm: bash retries a failed fork for about 15 s, so a shell
# loop would not reach pids.max within the timeout. When the zone's pid 1
# exits, the sleepers go with it.
STORM='import os, time
n = 0
for i in range(3000):
    try:
        p = os.fork()
    except BlockingIOError:
        break
    if p == 0:
        time.sleep(300); os._exit(0)
    n += 1
print("FORKED=%d" % n)
print("LIMIT-SURVIVED")'
zrun untrusted 60 -- /usr/bin/python3 -c "$STORM"
if [[ "$ZOUT" == *LIMIT-SURVIVED* ]]; then
    forked="$(grep -o 'FORKED=[0-9]*' "$LOG/untrusted.out" | cut -d= -f2)"
    limit="$(sed -n 's/^pids_max *= *\([0-9]*\).*/\1/p' "$Z/untrusted.toml")"
    # At most the limit, and at least half of it, or the check proves nothing.
    [[ -n "$forked" && "$forked" -le "${limit:-1024}" && "$forked" -ge $(( ${limit:-1024} / 2 )) ]] && pass "pids-limit" "bounded at pids_max=$limit (forked $forked before EAGAIN), zone survived" || fail "pids-limit" "forked=$forked limit=$limit"
else
    fail "pids-limit" "the zone did not survive the fork storm: $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
fi
# dd's own status and words: a tmpfs that took all 3000 MiB is not bounded.
zrun untrusted 60 -- sh -c 'out=$(dd if=/dev/zero of=$HOME/big bs=1M count=3000 2>&1); echo "DD-RC=$?"; echo "$out" | grep -o "No space left on device" | head -1; rm -f $HOME/big; echo TMPFS-SURVIVED'
if [[ "$ZOUT" == *TMPFS-SURVIVED* && "$ZOUT" == *"No space left on device"* ]] && grep -qx 'DD-RC=1' <<<"$ZOUT"; then
    pass "ephemeral-size-bound" "untrusted's 2G tmpfs refused 3000 MiB (No space left on device) and the zone survived"
else
    fail "ephemeral-size-bound" "$(tr '\n' ' ' <<<"$ZOUT") $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
fi
# The cpu limit reaches the kernel: while untrusted runs, its leaf says what its file says.
setsid "$KD" run untrusted --zones "$Z" --rootfs "$R" -- sleep 20 > "$LOG/untrusted-cpu.out" 2>&1 &
UCPU=$!
cpu_line=""
for _ in $(seq 1 40); do
    for leaf in /sys/fs/cgroup/kryptik/untrusted.*; do [[ -f "$leaf/cpu.max" ]] && cpu_line="$(cat "$leaf/cpu.max")"; done
    [[ -n "$cpu_line" ]] && break; sleep 0.5
done
"$KD" stop untrusted >/dev/null 2>&1; wait "$UCPU" 2>/dev/null
[[ "$cpu_line" == "200000 100000" ]] && pass "cpu-max-set" "untrusted's cgroup has cpu.max=${cpu_line} (its file says cpu_max = \"200%\")" || fail "cpu-max-set" "cpu.max=${cpu_line:-unread}: $(tail -2 "$LOG/untrusted-cpu.out" | tr '\n' ' ')"
# lifecycle: repeated start/stop, stop while running, registry clean
repeat_bad=""
for i in 1 2 3; do zrun untrusted 20 -- true; [[ "$ZRC" = 0 ]] || repeat_bad="$repeat_bad start $i exited $ZRC;"; done
[[ -z "$repeat_bad" ]] && pass "lifecycle-repeat" "untrusted started and exited three times" || fail "lifecycle-repeat" "$repeat_bad"
# "absent" is the registry's word for a zone with no entry: an error from
# status, or a stale entry, is not a clean registry.
reg="$("$KD" status untrusted 2>&1 | head -1)"
[[ "$reg" == "untrusted  absent" ]] && pass "lifecycle-registry" "$reg" || fail "lifecycle-registry" "${reg:-status printed nothing}"
"$KD" stop personal >/dev/null 2>&1; wait "$PBG" 2>/dev/null
for _ in $(seq 1 20); do [[ -e /dev/mapper/kryptik-zone-personal ]] || break; sleep 0.5; done
[[ -e /dev/mapper/kryptik-zone-personal ]] && fail "stop-closes-volume" "mapping still present after stop" || pass "stop-closes-volume" "the LUKS mapping is gone after stop"
mountpoint -q "$R/personal" && fail "stop-unmounts" "plaintext still mounted" || pass "stop-unmounts" "nothing mounted at $R/personal after stop"

# --- zones: a terminal and a text browser work in a zone --------------------------
# ncurses opens terminfo with setfsuid around it (a soft refusal in the zone
# filter), and man and lynx read their configuration from the zone's /etc
# (rootfs::ETC_RO_FILES and ETC_RO_DIRS).
zrun untrusted 20 -- tput -T xterm cols
[[ "$ZOUT" == 80 ]] && pass "terminal-terminfo" "tput opened terminfo in untrusted" || fail "terminal-terminfo" "rc=$ZRC out=$ZOUT $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
zrun untrusted 30 -- sh -c 'man -P cat ls 2>&1 | head -3'
grep -qi 'ls(1)' <<<"$ZOUT" && pass "man-page" "man read ls(1) in untrusted" || fail "man-page" "$(tr '\n' ' ' <<<"$ZOUT" | cut -c1-200)"
zrun untrusted 60 -- sh -c 'mkdir -p "$HOME/www" && echo "<h1>text-browser-ok</h1>" > "$HOME/www/index.html"
python3 -m http.server 8765 --bind 127.0.0.1 --directory "$HOME/www" > /dev/null 2>&1 & srv=$!
for i in 1 2 3 4 5 6 7 8 9 10; do python3 -c "import socket; socket.create_connection((\"127.0.0.1\", 8765), 1)" 2>/dev/null && break; sleep 0.3; done
lynx -dump http://127.0.0.1:8765/ 2>&1 | head -5; kill $srv'
[[ "$ZOUT" == *text-browser-ok* ]] && pass "text-browser" "lynx in untrusted read a page from a server in the zone" || fail "text-browser" "$(tr '\n' ' ' <<<"$ZOUT" | cut -c1-200) $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
# TLS verifies against OpenSSL's default CA file, /etc/ssl/cert.pem: the same
# count stage 04 checks in zone 0.
zrun untrusted 20 -- python3 -c 'import ssl; print("CAS=%d" % len(ssl.create_default_context().get_ca_certs()))'
cas="$(grep -o 'CAS=[0-9]*' <<<"$ZOUT" | cut -d= -f2)"
[[ "${cas:-0}" -ge 100 ]] && pass "tls-trust" "python's default TLS context in untrusted finds $cas CAs" || fail "tls-trust" "found ${cas:-no} CAs: $(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"

# --- storage: encrypted storage lifecycle ----------------------------------------
printf 'wrong-pass\n' > /root/zt/wrong.pass; chmod 600 /root/zt/wrong.pass
zrun personal 30 --passphrase-file /root/zt/wrong.pass -- sh -c 'echo SHOULD-NOT-RUN'
# Refused for the passphrase, in kryptikd's words: a start that failed or
# timed out for another reason is not this refusal.
if [[ "$ZRC" != 0 && "$ZOUT" != *SHOULD-NOT-RUN* && ! -e /dev/mapper/kryptik-zone-personal ]] && grep -q 'wrong passphrase' "$LOG/personal.err" "$LOG/personal.out"; then pass "wrong-passphrase" "refused as a wrong passphrase, no mapping left"; else fail "wrong-passphrase" "rc=$ZRC out=$ZOUT $(tail -2 "$LOG/personal.err" | tr '\n' ' ')"; fi
zrun personal 30 --passphrase-file /root/zt/personal.pass -- sh -c 'echo secret-data-1 > "$HOME/keep" && sync && echo WROTE'
[[ "$ZOUT" == *WROTE* ]] && pass "persist-write" || fail "persist-write" "$(tail -2 "$LOG/personal.err" | tr '\n' ' ')"
zrun personal 30 --passphrase-file /root/zt/personal.pass -- sh -c 'cat "$HOME/keep"'
[[ "$ZOUT" == *secret-data-1* ]] && pass "persist-reopen" "data survives stop and restart" || fail "persist-reopen" "$ZOUT"
[[ -e /dev/mapper/kryptik-zone-personal ]] && fail "no-mapping-after" || pass "no-mapping-after" "no mapping after the zone exited"
[[ -z "$(ls -A "$R/personal" 2>/dev/null)" ]] && pass "no-plaintext-after" "the mount point is empty after the zone exited" || fail "no-plaintext-after" "$(ls -A "$R/personal" | head -3 | tr '\n' ' ')"
zrun untrusted 30 -- sh -c 'echo ephemeral-1 > "$HOME/eph" && test -f "$HOME/eph" && echo EPH-WROTE'
eph_wrote="$ZOUT"
zrun untrusted 30 -- sh -c 'test -f "$HOME/eph" && echo EPH-STILL-THERE || echo EPH-GONE'
[[ "$eph_wrote" == *EPH-WROTE* && "$ZOUT" == *EPH-GONE* ]] && pass "ephemeral-gone" "a file untrusted wrote did not survive a restart" || fail "ephemeral-gone" "first run: ${eph_wrote:-wrote nothing}; second: $ZOUT"
# concurrent start of the same zone
setsid "$KD" run personal --zones "$Z" --rootfs "$R" --passphrase-file /root/zt/personal.pass -- sh -c 'echo P2-UP; sleep 60' > "$LOG/personal-bg2.out" 2>&1 &
PBG2=$!
for _ in $(seq 1 40); do grep -q P2-UP "$LOG/personal-bg2.out" 2>/dev/null && break; sleep 0.5; done
zrun personal 20 --passphrase-file /root/zt/personal.pass -- sh -c 'echo SECOND-INSTANCE'
# With the first instance seen up, and refused in the registry's words.
if grep -q P2-UP "$LOG/personal-bg2.out" && [[ "$ZRC" != 0 && "$ZOUT" != *SECOND-INSTANCE* ]] && grep -q 'already running' "$LOG/personal.err"; then
    pass "concurrent-start-refused" "$(grep -o 'already running.*' "$LOG/personal.err" | head -1)"
else
    fail "concurrent-start-refused" "rc=$ZRC first instance: $(tail -1 "$LOG/personal-bg2.out") second: $(tail -1 "$LOG/personal.err")"
fi
"$KD" stop personal >/dev/null 2>&1; wait "$PBG2" 2>/dev/null
# full volume
zrun personal 120 --passphrase-file /root/zt/personal.pass -- sh -c 'out=$(dd if=/dev/zero of="$HOME/fill" bs=1M 2>&1); echo "FILL-RC=$?"; echo "$out" | grep -o "No space left on device" | head -1; rm -f "$HOME/fill"; cat "$HOME/keep"; echo FULL-SURVIVED'
[[ "$ZOUT" == *"No space left on device"* && "$ZOUT" == *FULL-SURVIVED* && "$ZOUT" == *secret-data-1* ]] && pass "full-volume" "ENOSPC inside the volume; the zone and its data survived" || fail "full-volume" "$(tr '\n' ' ' <<<"$ZOUT") $(tail -2 "$LOG/personal.err" | tr '\n' ' ')"
# header backup and restore
if "$KD" volume backup-header personal /root/zt/personal.hdr > "$LOG/hdr.out" 2>&1; then
    # Zero both LUKS2 headers: cryptsetup falls back to the secondary one, at
    # the metadata size (16 KiB by default).
    dd if=/dev/zero of="$R/../volumes/personal.luks" bs=4096 count=16 conv=notrunc status=none
    zrun personal 30 --passphrase-file /root/zt/personal.pass -- sh -c 'echo OPENED-DAMAGED'
    [[ "$ZRC" != 0 && "$ZOUT" != *OPENED-DAMAGED* ]] && pass "damaged-header-refused" "a volume with both headers zeroed does not open" || fail "damaged-header-refused" "rc=$ZRC"
    if "$KD" volume restore-header personal /root/zt/personal.hdr >> "$LOG/hdr.out" 2>&1; then
        zrun personal 30 --passphrase-file /root/zt/personal.pass -- sh -c 'cat "$HOME/keep"'
        [[ "$ZOUT" == *secret-data-1* ]] && pass "header-restore" "the restored header opens the volume; data intact" || fail "header-restore" "$ZOUT"
    else
        fail "header-restore" "$(tail -2 "$LOG/hdr.out" | tr '\n' ' ')"
    fi
else
    fail "header-backup" "$(tail -2 "$LOG/hdr.out" | tr '\n' ' ')"
fi
# destroy: dev gets a volume, runs, and loses the volume once stopped; while
# it runs the volume stays.
printf 'dev-pass\n' > /root/zt/dev.pass; chmod 600 /root/zt/dev.pass
"$KD" volume init dev --size 64M --passphrase-file /root/zt/dev.pass > "$LOG/vol-dev.out" 2>&1 || fail "volume-destroy" "dev volume init: $(tail -1 "$LOG/vol-dev.out")"
setsid "$KD" run dev --zones "$Z" --rootfs "$R" --passphrase-file /root/zt/dev.pass -- sh -c 'echo DEV-UP; sleep 60' > "$LOG/dev-bg.out" 2>&1 &
DBG=$!
for _ in $(seq 1 60); do grep -q DEV-UP "$LOG/dev-bg.out" 2>/dev/null && break; sleep 0.5; done
refused="$("$KD" volume destroy dev 2>&1)"; rrc=$?
"$KD" stop dev >/dev/null 2>&1; wait "$DBG" 2>/dev/null
for _ in $(seq 1 20); do [[ -e /dev/mapper/kryptik-zone-dev ]] || break; sleep 0.5; done
gone="$("$KD" volume destroy dev 2>&1)"; grc=$?
if [[ "$rrc" != 0 && "$refused" == *"stop the zone first"* && "$grc" = 0 && ! -e "$R/../volumes/dev.luks" ]]; then pass "volume-destroy" "refused while dev ran; the container went once it stopped"; else fail "volume-destroy" "running: rc=$rrc ${refused}; stopped: rc=$grc ${gone}"; fi
# the vault: encrypted, offline
printf 'vault-pass\n' > /root/zt/vault.pass; chmod 600 /root/zt/vault.pass
"$KD" volume init vault --size 64M --passphrase-file /root/zt/vault.pass > "$LOG/vol-vault.out" 2>&1 || fail "vault-volume" "$(tail -1 "$LOG/vol-vault.out")"
zrun vault 30 --passphrase-file /root/zt/vault.pass -- sh -c 'echo LINKS=$(ip -o link | grep -vc " lo:"); python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.1 1 >/dev/null 2>&1 && echo VAULT-REACHED-BRIDGE || echo VAULT-ISOLATED; ping -c 1 -W 1 10.19.0.1 > /tmp/ping.out 2>&1; echo "VAULT-PING rc=$? $(tail -1 /tmp/ping.out)"; echo vault-secret > "$HOME/v" && echo VAULT-WROTE'
# 2 is ping's error exit; 1 would mean a packet went out and no reply came.
grep -qE 'VAULT-PING rc=2 ' <<<"$ZOUT" && pass "vault-ping" "ping in an offline zone fails without sending: $(grep -o 'VAULT-PING.*' <<<"$ZOUT")" || fail "vault-ping" "$(grep -o 'VAULT-PING.*' <<<"$ZOUT")"
[[ "$ZOUT" == *VAULT-ISOLATED* && "$ZOUT" == *VAULT-WROTE* && "$ZOUT" == *LINKS=0* ]] && pass "vault-offline" "vault has loopback only, no path to the bridge, and keeps data" || fail "vault-offline" "$(tr '\n' ' ' <<<"$ZOUT") $(tail -1 "$LOG/vault.err")"
# No passphrase on any command line or in the registry: while personal ran
# (above), and now that every zone that took one has stopped.
if [[ "$pp_seen" != 1 ]]; then
    fail "no-passphrase-leak" "the search did not see personal's launcher while it ran, so it proves nothing"
elif [[ "$pp_leak" = 1 ]] || grep -rqs 'personal-pas[s]\|vault-pas[s]\|dev-pas[s]' /run/kryptik /proc/[0-9]*/cmdline; then
    fail "no-passphrase-leak" "a passphrase appeared in the registry or a command line"
else
    pass "no-passphrase-leak" "no passphrase in /run/kryptik or any command line, while personal ran and after the zones stopped"
fi

# --- the system allocator (ADR-005), in zone 0 and in a zone -----------------------
grep -q /usr/lib/libhardened_malloc.so /proc/self/maps && pass "allocator-zone0" "zone 0 runs on hardened_malloc" || fail "allocator-zone0" "libhardened_malloc.so is not mapped in zone 0"
zrun untrusted 30 -- grep -c /usr/lib/libhardened_malloc.so /proc/self/maps
[[ "$ZRC" = 0 ]] && pass "allocator-zone" "a process in untrusted runs on it too" || fail "allocator-zone" "rc=$ZRC $(tail -1 "$LOG/untrusted.err")"

# --- the installed root: privilege only where the allowlist says -------------------
# Stage 06 fails the build on any other bit; the installed root shows it: a setuid or
# setgid bit is on the listed binaries alone (build/config/setuid-allowlist.txt)
# and file capabilities are on none (capability-allowlist.txt is empty).
setuid_found="$(find / -xdev -type f -perm /6000 2>/dev/null | LC_ALL=C sort | tr '\n' ' ')"
[[ "$setuid_found" == "/usr/bin/passwd /usr/bin/su " ]] && pass "setuid-only-allowed" "on the root filesystem: ${setuid_found}" || fail "setuid-only-allowed" "found: ${setuid_found:-none}"
# The scan ends with how many files it read: one that died early, or walked
# nothing, has not shown that no file carries a capability.
capscan="$(python3 - <<'PY'
import os, stat
dev = os.lstat("/").st_dev
out = []
seen = 0
for d, dirs, files in os.walk("/"):
    dirs[:] = [x for x in dirs if os.lstat(os.path.join(d, x)).st_dev == dev]
    for name in files:
        p = os.path.join(d, name)
        try:
            if not stat.S_ISREG(os.lstat(p).st_mode):
                continue
            seen += 1
            os.getxattr(p, "security.capability", follow_symlinks=False)
        except OSError:
            continue
        out.append(p)
print("scanned=%d capped=%s" % (seen, " ".join(out)))
PY
)"
scanned="$(sed -n 's/^scanned=\([0-9]*\) capped=.*/\1/p' <<<"$capscan")"; capped="${capscan#*capped=}"
[[ "${scanned:-0}" -ge 1000 && -z "$capped" ]] && pass "no-file-capabilities" "none of the $scanned files on the root filesystem carries security.capability" || fail "no-file-capabilities" "${capscan:-the scan printed nothing}"

# --- the kernel tunables, as the verified root's file says --------------------------
# sysinit applies /usr/lib/kryptik/sysctl.d at boot; every key reads back with
# the file's value, whitespace aside, or the line is named.
sysctl_bad=""; sysctl_keys=0
while IFS= read -r line; do
    line="${line%%#*}"; [[ "$line" == *=* ]] || continue
    key="$(printf '%s' "${line%%=*}" | tr -d '[:space:]')"
    want="$(printf '%s' "${line#*=}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    got="$(tr -s '[:space:]' ' ' < "/proc/sys/${key//.//}" 2>/dev/null | sed 's/ $//')"
    sysctl_keys=$((sysctl_keys + 1))
    [[ "$got" == "$want" ]] || sysctl_bad="${sysctl_bad}${key}=${got:-unreadable} (wanted ${want}); "
done < /usr/lib/kryptik/sysctl.d/99-kryptik-hardening.conf
# A file that is missing or holds no key reads back nothing wrong.
[[ "$sysctl_keys" -gt 0 && -z "$sysctl_bad" ]] && pass "sysctls-applied" "all $sysctl_keys keys in 99-kryptik-hardening.conf read back as written" || fail "sysctls-applied" "${sysctl_bad:-no key read from 99-kryptik-hardening.conf}"

echo "ZT SUMMARY passed=$PASS failed=$FAIL"
echo "ZT END"
[[ "$FAIL" -eq 0 ]]
