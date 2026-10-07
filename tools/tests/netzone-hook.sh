#!/usr/bin/env bash
# Tests for dhcpcd's hook in the net zone (tools/net/dhcpcd-hook.py): the
# servers a lease, a DHCPv6 reply or a router advertisement names reach the
# zone's resolv.conf, a lease that ends takes them away, and nothing else that
# dhcpcd's unprivileged side could put in the environment reaches a file.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOK="${ROOT}/tools/net/dhcpcd-hook.py"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
same()  { if [[ "$2" == "$3" ]]; then green "$1"; else red "$1" "got '$(tr '\n' '|' <<<"$2")', want '$(tr '\n' '|' <<<"$3")'"; fi; }
command -v python3 >/dev/null 2>&1 || { echo "no python3 here"; exit 77; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/state" "$T/tmp"

# hook VAR=VALUE...: one event, as dhcpcd's helper runs it, with nothing else
# in the environment; prints the resolv.conf it leaves.
hook() {
    env -i "$@" python3 -I "$HOOK" --state "$T/state" --out "$T/tmp/resolv.conf"
    cat "$T/tmp/resolv.conf" 2>/dev/null
}

echo "-- what a network names"
same "a lease's servers" \
    "$(hook interface=eth0 protocol=dhcp reason=BOUND if_up=true new_domain_name_servers='10.0.2.3 192.0.2.53')" \
    "$(printf 'nameserver 10.0.2.3\nnameserver 192.0.2.53')"
same "a router advertisement's, beside them, while its lifetime runs" \
    "$(hook interface=eth0 protocol=ra reason=ROUTERADVERT nd1_rdnss1_servers='fec0::3' nd1_rdnss1_lifetime=3600)" \
    "$(printf 'nameserver 10.0.2.3\nnameserver 192.0.2.53\nnameserver fec0::3')"
same "a lifetime of 0 takes it away" \
    "$(hook interface=eth0 protocol=ra reason=ROUTERADVERT nd1_rdnss1_servers='fec0::3' nd1_rdnss1_lifetime=0)" \
    "$(printf 'nameserver 10.0.2.3\nnameserver 192.0.2.53')"
same "a lease that ends takes its servers with it" \
    "$(hook interface=eth0 protocol=dhcp reason=EXPIRE if_down=true)" ""
same "a link-local server keeps its scope only when it names the interface" \
    "$(hook interface=wlan0 protocol=dhcp6 reason=BOUND6 if_up=true new_dhcp6_name_servers='fe80::1%wlan0 fe80::2%eth9 2001:db8::53')" \
    "$(printf 'nameserver fe80::1%%wlan0\nnameserver 2001:db8::53')"
hook interface=wlan0 protocol=dhcp6 reason=STOP6 if_down=true > /dev/null

echo "-- what the unprivileged side could send instead"
same "words that are not addresses are dropped, and with them a second line" \
    "$(hook interface=eth0 protocol=dhcp reason=BOUND if_up=true new_domain_name_servers=$'10.0.2.3;\nsearch evil.example\n192.0.2.7 0.0.0.0 224.0.0.1')" \
    "nameserver 192.0.2.7"
before="$(cat "$T/tmp/resolv.conf")"
same "an interface name that is a path writes nothing" \
    "$(hook interface=../../etc protocol=dhcp reason=BOUND if_up=true new_domain_name_servers=192.0.2.66)" "$before"
same "a protocol not on the list writes nothing" \
    "$(hook interface=eth0 protocol=../x reason=BOUND if_up=true new_domain_name_servers=192.0.2.66)" "$before"
# "²", which str.isdigit() takes and int() refuses, as UTF-8 bytes whatever the locale.
env -i interface=eth0 protocol=ra reason=ROUTERADVERT nd1_rdnss1_servers=fec0::9 nd1_rdnss1_lifetime=$'\xc2\xb2' \
    python3 -I "$HOOK" --state "$T/state" --out "$T/tmp/resolv.conf" 2> "$T/err"; rc=$?
same "a lifetime that is not plain digits is no lifetime, and the hook does not fall over on it" \
    "rc=${rc} $(cat "$T/tmp/resolv.conf") $(head -1 "$T/err")" "rc=0 ${before} "
same "an event that is neither up nor down changes nothing" \
    "$(hook interface=eth0 protocol=dhcp reason=PREINIT new_domain_name_servers=192.0.2.66)" "$before"
[[ "$(ls -A "$T/state")" == "eth0.dhcp" ]] && green "the state holds one file per interface and protocol that passed, and no other" \
    || red "files in the state" "$(ls -A "$T/state" | tr '\n' ' ')"
printf '192.0.2.99\nnameserver 1.1.1.1\n../../x\n' > "$T/state/eth0.static"
same "a state file is checked again when read: a line that is not an address is no server" \
    "$(hook interface=eth0 protocol=dhcp reason=RENEW if_up=true new_domain_name_servers=192.0.2.7)" \
    "$(printf 'nameserver 192.0.2.7\nnameserver 192.0.2.99')"
same "the paths come from the command line alone: PYTHON* and the like change nothing" \
    "$(hook PYTHONPATH="$T" PYTHONSTARTUP=/dev/null interface=eth0 protocol=dhcp reason=RENEW if_up=true new_domain_name_servers=192.0.2.7)" \
    "$(printf 'nameserver 192.0.2.7\nnameserver 192.0.2.99')"
python3 -I "$HOOK" --nonsense > /dev/null 2>&1
[[ $? -eq 2 ]] && green "an argument it does not know is refused" || red "an unknown argument was taken"

echo "-- the net zone runs it"
grep -q -- '-c /usr/libexec/kryptik/dhcpcd-hook' "${ROOT}/tools/net/netzone-init.sh" \
    && green "netzone-init.sh starts dhcpcd with this hook" || red "netzone-init.sh does not name the hook"
grep -q 'dhcpcd-hook.py.*/usr/libexec/kryptik/dhcpcd-hook' "${ROOT}/build/recipes/netzone.sh" \
    && green "the recipe installs it where dhcpcd is told to look" || red "the recipe does not install the hook"

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
