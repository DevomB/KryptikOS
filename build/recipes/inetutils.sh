#!/usr/bin/env bash

# hostname and ifconfig; no servers, which nothing starts, and ping comes from iputils.
s_inetutils() {
    native_build "inetutils-${V_INETUTILS}.tar.gz" "inetutils-${V_INETUTILS}" --bindir=/usr/bin --localstatedir=/var \
        --disable-servers --disable-logger --disable-whois --disable-rlogin --disable-rsh --disable-rcp --disable-rexec \
        --disable-ping --disable-ping6 --disable-traceroute
    # A cached sysroot may still hold an old setuid traceroute.
    rm -f /usr/bin/traceroute
}
