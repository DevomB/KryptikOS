#!/usr/bin/env bash

# Early, with stage 01's localedef: perl's Configure probes LC_ALL, and glibc waits for python.
s_locales() {
    mkdir -p /usr/lib/locale
    localedef -i C -f UTF-8 C.UTF-8
    localedef -i en_US -f ISO-8859-1 en_US
    localedef -i en_US -f UTF-8 en_US.UTF-8
    localedef -i en_GB -f UTF-8 en_GB.UTF-8
    localedef -i de_DE -f UTF-8 de_DE.UTF-8
    localedef -i ja_JP -f UTF-8 ja_JP.UTF-8
    echo "locales generated:"
    # Read, then trim: no pipe into head, which can SIGPIPE under pipefail.
    local archived
    archived="$(localedef --list-archive 2>/dev/null || true)"
    printf '%s\n' "$archived" | sed -n '1,10p'

    # Minimal, sane defaults so the rest of the build is deterministic.
    cat > /etc/nsswitch.conf <<'NSS'
passwd: files
group: files
shadow: files
hosts: files dns
networks: files
protocols: files
services: files
ethers: files
rpc: files
NSS
}
