#!/usr/bin/env bash
# inetutils: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# inetutils' clients: hostname and ifconfig. --disable-servers: no telnetd,
# ftpd, rlogind and the rest, which nothing starts; ping is iputils'. traceroute
# is not built, and a sysroot from an earlier build still holds its setuid copy.
s_inetutils() {
    native_build "inetutils-${V_INETUTILS}.tar.gz" "inetutils-${V_INETUTILS}" --bindir=/usr/bin --localstatedir=/var \
        --disable-servers --disable-logger --disable-whois --disable-rlogin --disable-rsh --disable-rcp --disable-rexec \
        --disable-ping --disable-ping6 --disable-traceroute
    rm -f /usr/bin/traceroute
}
