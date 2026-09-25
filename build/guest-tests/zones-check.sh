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
for p in "$Z"/policy/*.seccomp; do [[ -f "$p" ]] || fail "policies" "no policy files"; done
[[ -f "$Z/policy/work.seccomp" ]] && pass "policies" "seccomp policies installed beside the zones"

# --- zones: the net zone and zone 0 --------------------------------------------
if [[ "$(s6-svstat -o up /run/service/net-zone 2>/dev/null)" = true ]]; then pass "net-zone-up" "supervised and up"; else fail "net-zone-up" "$(s6-svstat /run/service/net-zone 2>&1)"; fi
ready=""
for _ in $(seq 1 30); do
    ready="$(grep -h 'netzone: READY' /run/uncaught-logs/current /run/uncaught-logs/@* 2>/dev/null | tail -1)"
    [[ -n "$ready" ]] && break; sleep 1
done
if [[ "$ready" == *"nat=yes"* ]]; then pass "net-ready" "$ready"; else fail "net-ready" "no READY line with nat=yes in the catch-all log (last: $(grep -h 'netzone:' /run/uncaught-logs/current 2>/dev/null | tail -1))"; fi
if ip link show eth0 >/dev/null 2>&1; then fail "zone0-nic" "eth0 is still in zone 0"; else pass "zone0-nic" "eth0 is not in zone 0 (moved into the net zone)"; fi
if [[ -z "$(ip route show default 2>/dev/null)" ]]; then pass "zone0-no-route" "zone 0 has no default route"; else fail "zone0-no-route" "$(ip route show default)"; fi
if ping -c1 -W2 10.0.2.2 >/dev/null 2>&1; then fail "zone0-offline" "zone 0 reached the VM gateway"; else pass "zone0-offline" "zone 0 cannot reach the VM gateway"; fi

# --- zones: a routed zone reaches the world through net; vault reaches nothing --
# The IPv6 echo waits out duplicate address detection: from a still-tentative
# address it fails at once with EADDRNOTAVAIL.
UNT=$(host_of untrusted); PER=$(host_of personal)
zrun untrusted 40 -- sh -c 'ip -4 -o addr show eth0; python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.1 3 >/dev/null 2>&1 && echo BRIDGE-OK; python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.0.2.2 3 >/dev/null 2>&1 && echo GATEWAY-OK; ip -6 -o addr show eth0 | grep -q " fd19:" && echo ULA-OK; ip -6 -o addr show eth0 | grep -qE " (2|3)[0-9a-f]{3}:" && echo GLOBAL6-PRESENT; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do ip -6 -o addr show eth0 | grep -q tentative || break; sleep 0.5; done; python3 /usr/lib/kryptik/guest-tests/icmp-echo.py fd19::1 3 >/dev/null 2>&1 && echo BRIDGE6-OK; python3 - <<"PY"
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
[[ "$ZOUT" == *GATEWAY-OK* ]] && pass "routed-egress" "untrusted reaches the VM gateway through net (NAT)" || fail "routed-egress" "no GATEWAY-OK"
[[ "$ZOUT" == *ULA-OK* ]] && pass "routed-ipv6-ula" || fail "routed-ipv6-ula"
[[ "$ZOUT" == *GLOBAL6-PRESENT* ]] && fail "routed-ipv6-noglobal" "a global IPv6 address reached a routed zone" || pass "routed-ipv6-noglobal" "no global IPv6 address in the zone"
[[ "$ZOUT" == *BRIDGE6-OK* ]] && pass "routed-ipv6-bridge" || fail "routed-ipv6-bridge"
[[ "$ZOUT" == *DNS-ANSWERED* ]] && pass "routed-dns" "$(grep -o 'DNS-ANSWERED.*' "$LOG/untrusted.out")" || fail "routed-dns" "$(grep -o 'DNS-.*' "$LOG/untrusted.out")"

# (the vault is probed once its volume exists, under storage below)

# --- zones: separation between routed zones; fail-closed on a net restart -------
printf 'personal-pass\n' > /root/zt/personal.pass; chmod 600 /root/zt/personal.pass
"$KD" volume init personal --size 64M --passphrase-file /root/zt/personal.pass > "$LOG/vol-personal.out" 2>&1 \
    && pass "volume-init" "personal: $(tail -1 "$LOG/vol-personal.out")" || fail "volume-init" "$(tail -2 "$LOG/vol-personal.out" | tr '\n' ' ')"
# personal stays up in the background for the separation and restart checks
setsid "$KD" run personal --zones "$Z" --rootfs "$R" --passphrase-file /root/zt/personal.pass -- sh -c 'echo PERSONAL-UP; sleep 600' > "$LOG/personal-bg.out" 2>&1 &
PBG=$!
for _ in $(seq 1 60); do grep -q PERSONAL-UP "$LOG/personal-bg.out" 2>/dev/null && break; sleep 0.5; done
grep -q PERSONAL-UP "$LOG/personal-bg.out" && pass "encrypted-zone-start" "personal up on its LUKS2 volume" || fail "encrypted-zone-start" "$(tail -3 "$LOG/personal-bg.out" | tr '\n' ' ')"
[[ -e /dev/mapper/kryptik-zone-personal ]] && pass "mapping-while-running" "/dev/mapper/kryptik-zone-personal exists while the zone runs" || fail "mapping-while-running"
zrun untrusted 30 -- sh -c "python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.$PER 2 >/dev/null 2>&1 && echo CROSS-ZONE-REACHED || echo CROSS-ZONE-BLOCKED; ls /var/lib/kryptik/volumes 2>&1 | head -1; ls /home 2>&1 | tr '\n' ' '"
[[ "$ZOUT" == *CROSS-ZONE-BLOCKED* ]] && pass "zone-separation" "untrusted cannot reach personal (10.19.0.$PER) on the bridge" || fail "zone-separation" "$ZOUT"
[[ "$ZOUT" == *"volumes"* && "$ZOUT" != *"No such"* ]] && fail "volume-hidden" "the volume directory is visible from untrusted" || pass "volume-hidden" "no /var/lib/kryptik/volumes inside untrusted"
[[ "$ZOUT" == *"personal"* ]] && fail "home-hidden" "another zone's home is visible" || pass "home-hidden" "no other zone's home under /home"

# net zone restart: routed zones fail closed while it is down, recover after
# Not `|| echo 0`: grep -c prints 0 and also exits 1.
before="$(grep -hc 'netzone: READY' /run/uncaught-logs/current 2>/dev/null)"; before="${before:-0}"
s6-svc -d /run/service/net-zone; sleep 3
zrun untrusted 20 -- sh -c 'python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.0.2.2 2 >/dev/null 2>&1 && echo EGRESS-WHILE-DOWN || echo CLOSED-WHILE-DOWN; ip -o link show eth0 >/dev/null 2>&1 && echo HAS-ETH0 || echo NO-ETH0'
[[ "$ZOUT" == *CLOSED-WHILE-DOWN* ]] && pass "fail-closed" "no egress while the net zone is down ($(grep -o 'HAS-ETH0\|NO-ETH0' "$LOG/untrusted.out" | head -1))" || fail "fail-closed" "$ZOUT"
s6-svc -u /run/service/net-zone
ok=0
for _ in $(seq 1 60); do
    after="$(grep -hc 'netzone: READY' /run/uncaught-logs/current 2>/dev/null)"; after="${after:-0}"
    [[ "$after" -gt "$before" ]] && { ok=1; break; }; sleep 1
done
[[ "$ok" = 1 ]] && pass "net-restart-ready" "the net zone came back READY after a restart" || fail "net-restart-ready" "no new READY line ($before -> $after)"
sleep 2
zrun untrusted 30 -- sh -c 'python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.0.2.2 3 >/dev/null 2>&1 && echo GATEWAY-OK || echo GATEWAY-FAIL'
[[ "$ZOUT" == *GATEWAY-OK* ]] && pass "egress-after-restart" "a zone started after the restart has egress" || fail "egress-after-restart" "$ZOUT"
# the running zone was reattached
ppid="$(cat /run/kryptik/zones/personal/init.pid 2>/dev/null | cut -d' ' -f1)"
if [[ -n "$ppid" ]] && nsenter -t "$ppid" -n ping -c1 -W3 10.0.2.2 >/dev/null 2>&1; then pass "reattach-after-restart" "the zone that was running has egress again"; else fail "reattach-after-restart" "personal (init $ppid) has no egress after the net restart"; fi

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
ready_time="$(grep -h 'netzone: READY' /run/uncaught-logs/current 2>/dev/null | tail -1 | grep -o 'time=[^ ]*')"
info "time-reported ${ready_time:-the readiness line has no time= field} (no answer through this network is reported as that, never as a pass)"

if [[ "$FLOOR_S" -gt 0 ]]; then
    # a dead RTC's clock: the year 2000
    date -u -s "@946684800" >/dev/null 2>&1
    said="$("$KD" time floor 2>&1)"
    got="$(date +%s)"
    # `time status` prints the floor to the minute; the clamp sets it to the second.
    if (( got >= FLOOR_S && got <= FLOOR_S + 90 )); then pass "time-clamp" "a clock set to 2000-01-01 came back at the build date: ${said}"; else fail "time-clamp" "clock reads $(date -u -d "@$got" +%F) after the clamp, floor is ${FLOOR}: ${said}"; fi
    put_clock_back

    if [[ -n "$net_init" ]]; then
        before="$(date +%s)"; r="$(claim 120)"; after="$(date +%s)"
        moved=$(( after - before ))
        if [[ "$r" == "ok stepped" ]] && (( moved >= 118 && moved <= 140 )); then pass "time-claim-stepped" "the net zone's claim of +120 s moved the clock by ${moved} s (${r})"; else fail "time-claim-stepped" "reply '${r}', clock moved ${moved} s"; fi
        put_clock_back

        before="$(date +%s)"; r="$(claim -999999999)"; after="$(date +%s)"
        if [[ "$r" == error:*"before this system was built"* ]] && (( after - before < 30 )); then pass "time-claim-floor" "a claim below the build date is refused and the clock is untouched"; else fail "time-claim-floor" "reply '${r}', clock moved $(( after - before )) s"; fi

        # past the bound with nobody at a trusted window: refused, not applied
        before="$(date +%s)"; r="$(claim 90000)"; after="$(date +%s)"
        if [[ "$r" == error:*consent* ]] && (( after - before < 90 )); then pass "time-claim-consent" "a day's jump is not applied without the person (${r#error: })"; else fail "time-claim-consent" "reply '${r}', clock moved $(( after - before )) s"; fi
        put_clock_back

        # End to end, only where a time server answers: with the clock 300 s
        # fast, the restarted net zone must measure about -300 and zone 0 must
        # correct it (tools/test-netzone-time.sh checks the sign offline).
        case "$ready_time" in
            time=-[0-9]*|time=[0-9]*)
                date -u -s "@$(( $(true_now) + 300 ))" >/dev/null 2>&1; rm -f /var/lib/kryptik/time/state
                n0="$(grep -hc 'netzone: READY' /run/uncaught-logs/current 2>/dev/null)"; n0="${n0:-0}"
                s6-svc -r /run/service/net-zone
                for _ in $(seq 1 90); do n1="$(grep -hc 'netzone: READY' /run/uncaught-logs/current 2>/dev/null)"; [[ "${n1:-0}" -gt "$n0" ]] && break; sleep 1; done
                m="$(grep -h 'netzone: READY' /run/uncaught-logs/current | tail -1 | grep -o 'time=[^ ]*' | cut -d= -f2)"
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
zrun untrusted 60 -- sh -c 'dd if=/dev/zero of=$HOME/big bs=1M count=3000 2>&1 | tail -1; echo DD-RC=$?; rm -f $HOME/big; echo TMPFS-SURVIVED'
[[ "$ZOUT" == *TMPFS-SURVIVED* ]] && pass "ephemeral-size-bound" "untrusted's 2G tmpfs refused 3000 MiB and the zone survived" || fail "ephemeral-size-bound" "$(tail -2 "$LOG/untrusted.err" | tr '\n' ' ')"
# lifecycle: repeated start/stop, stop while running, registry clean
for i in 1 2 3; do zrun untrusted 20 -- true; [[ "$ZRC" = 0 ]] || fail "lifecycle-repeat" "start $i exited $ZRC"; done
[[ "$ZRC" = 0 ]] && pass "lifecycle-repeat" "untrusted started and exited three times"
"$KD" status untrusted 2>&1 | grep -qi 'running' && fail "lifecycle-registry" "untrusted still registered as running" || pass "lifecycle-registry" "$("$KD" status untrusted 2>&1 | head -1)"
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
if [[ "$ZRC" != 0 && "$ZOUT" != *SHOULD-NOT-RUN* && ! -e /dev/mapper/kryptik-zone-personal ]]; then pass "wrong-passphrase" "refused, no mapping left"; else fail "wrong-passphrase" "rc=$ZRC out=$ZOUT"; fi
zrun personal 30 --passphrase-file /root/zt/personal.pass -- sh -c 'echo secret-data-1 > "$HOME/keep" && sync && echo WROTE'
[[ "$ZOUT" == *WROTE* ]] && pass "persist-write" || fail "persist-write" "$(tail -2 "$LOG/personal.err" | tr '\n' ' ')"
zrun personal 30 --passphrase-file /root/zt/personal.pass -- sh -c 'cat "$HOME/keep"'
[[ "$ZOUT" == *secret-data-1* ]] && pass "persist-reopen" "data survives stop and restart" || fail "persist-reopen" "$ZOUT"
[[ -e /dev/mapper/kryptik-zone-personal ]] && fail "no-mapping-after" || pass "no-mapping-after" "no mapping after the zone exited"
[[ -z "$(ls -A "$R/personal" 2>/dev/null)" ]] && pass "no-plaintext-after" "the mount point is empty after the zone exited" || fail "no-plaintext-after" "$(ls -A "$R/personal" | head -3 | tr '\n' ' ')"
zrun untrusted 30 -- sh -c 'echo ephemeral-1 > "$HOME/eph" && echo EPH-WROTE'
zrun untrusted 30 -- sh -c 'test -f "$HOME/eph" && echo EPH-STILL-THERE || echo EPH-GONE'
[[ "$ZOUT" == *EPH-GONE* ]] && pass "ephemeral-gone" "untrusted's data did not survive a restart" || fail "ephemeral-gone" "$ZOUT"
# concurrent start of the same zone
setsid "$KD" run personal --zones "$Z" --rootfs "$R" --passphrase-file /root/zt/personal.pass -- sh -c 'echo P2-UP; sleep 60' > "$LOG/personal-bg2.out" 2>&1 &
PBG2=$!
for _ in $(seq 1 40); do grep -q P2-UP "$LOG/personal-bg2.out" 2>/dev/null && break; sleep 0.5; done
zrun personal 20 --passphrase-file /root/zt/personal.pass -- sh -c 'echo SECOND-INSTANCE'
[[ "$ZRC" != 0 && "$ZOUT" != *SECOND-INSTANCE* ]] && pass "concurrent-start-refused" "$(grep -o 'already running.*' "$LOG/personal.err" | head -1)" || fail "concurrent-start-refused" "rc=$ZRC"
"$KD" stop personal >/dev/null 2>&1; wait "$PBG2" 2>/dev/null
# full volume
zrun personal 120 --passphrase-file /root/zt/personal.pass -- sh -c 'dd if=/dev/zero of="$HOME/fill" bs=1M 2>&1 | tail -1; echo FILL-RC=$?; rm -f "$HOME/fill"; cat "$HOME/keep"; echo FULL-SURVIVED'
[[ "$ZOUT" == *FULL-SURVIVED* && "$ZOUT" == *secret-data-1* ]] && pass "full-volume" "ENOSPC inside the volume; the zone and its data survived" || fail "full-volume" "$(tail -2 "$LOG/personal.err" | tr '\n' ' ')"
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
# the vault: encrypted, offline
printf 'vault-pass\n' > /root/zt/vault.pass; chmod 600 /root/zt/vault.pass
"$KD" volume init vault --size 64M --passphrase-file /root/zt/vault.pass > "$LOG/vol-vault.out" 2>&1 || fail "vault-volume" "$(tail -1 "$LOG/vol-vault.out")"
zrun vault 30 --passphrase-file /root/zt/vault.pass -- sh -c 'echo LINKS=$(ip -o link | grep -vc " lo:"); python3 /usr/lib/kryptik/guest-tests/icmp-echo.py 10.19.0.1 1 >/dev/null 2>&1 && echo VAULT-REACHED-BRIDGE || echo VAULT-ISOLATED; echo vault-secret > "$HOME/v" && echo VAULT-WROTE'
[[ "$ZOUT" == *VAULT-ISOLATED* && "$ZOUT" == *VAULT-WROTE* && "$ZOUT" == *LINKS=0* ]] && pass "vault-offline" "vault has loopback only, no path to the bridge, and keeps data" || fail "vault-offline" "$(tr '\n' ' ' <<<"$ZOUT") $(tail -1 "$LOG/vault.err")"
# No passphrase on any command line or in the registry. The [s] keeps this
# grep's own command line from matching.
if grep -rqs 'personal-pas[s]\|vault-pas[s]' /run/kryptik /proc/*/cmdline 2>/dev/null; then fail "no-passphrase-leak" "a passphrase appeared in the registry or a command line"; else pass "no-passphrase-leak" "no passphrase in /run/kryptik or any command line"; fi

# --- the system allocator (ADR-005), in zone 0 and in a zone -----------------------
grep -q /usr/lib/libhardened_malloc.so /proc/self/maps && pass "allocator-zone0" "zone 0 runs on hardened_malloc" || fail "allocator-zone0" "libhardened_malloc.so is not mapped in zone 0"
zrun untrusted 30 -- grep -c /usr/lib/libhardened_malloc.so /proc/self/maps
[[ "$ZRC" = 0 ]] && pass "allocator-zone" "a process in untrusted runs on it too" || fail "allocator-zone" "rc=$ZRC $(tail -1 "$LOG/untrusted.err")"

echo "ZT SUMMARY passed=$PASS failed=$FAIL"
echo "ZT END"
[[ "$FAIL" -eq 0 ]]
