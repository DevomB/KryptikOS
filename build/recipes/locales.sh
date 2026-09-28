#!/usr/bin/env bash
# locales: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# Locales, with stage 01's localedef, first and apart from the glibc rebuild:
# perl needs them (Configure probes LC_ALL), and glibc's rebuild waits for
# python, which comes after perl.
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
