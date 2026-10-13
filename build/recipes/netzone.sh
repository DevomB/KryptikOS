#!/usr/bin/env bash

# The net zone's startup program (docs/design/net-zone.md): DHCP, NAT and DNS beside the NIC.
s_netzone() {
    local src="${KRYPTIK_ROOT}/tools/net/netzone-init.sh"
    [[ -f "$src" ]] || { echo "no netzone-init at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    install -D -m 0755 "$src" /usr/libexec/kryptik/netzone-init.sh
    sh -n /usr/libexec/kryptik/netzone-init.sh || { echo "netzone-init does not parse under the target sh"; return 1; }
    # The SNTP query the net zone measures the clock with (docs/design/time.md).
    install -D -m 0755 "${KRYPTIK_ROOT}/tools/net/sntp-offset.py" /usr/libexec/kryptik/sntp-offset.py
    python3 -m py_compile /usr/libexec/kryptik/sntp-offset.py || { echo "sntp-offset.py does not compile under the target python"; return 1; }
    install -D -m 0755 "${KRYPTIK_ROOT}/tools/net/update-fetch.py" /usr/libexec/kryptik/update-fetch.py
    python3 -m py_compile /usr/libexec/kryptik/update-fetch.py || { echo "update-fetch.py does not compile under the target python"; return 1; }
    # dhcpcd's hook: its root helper runs it with what the unprivileged side sends.
    install -D -m 0755 "${KRYPTIK_ROOT}/tools/net/dhcpcd-hook.py" /usr/libexec/kryptik/dhcpcd-hook
    python3 -m py_compile /usr/libexec/kryptik/dhcpcd-hook || { echo "dhcpcd-hook does not compile under the target python"; return 1; }
    rm -rf /usr/libexec/kryptik/__pycache__
    for t in dhcpcd nft dnsmasq ip; do
        command -v "$t" >/dev/null 2>&1 && echo "  ok $t" || { echo "  MISSING $t"; return 1; }
    done
}
