#!/usr/bin/env bash

# hostname and ifconfig; no servers and no cleartext clients, which nothing runs, and ping comes from iputils.
s_inetutils() {
    native_build "inetutils-${V_INETUTILS}.tar.gz" "inetutils-${V_INETUTILS}" --bindir=/usr/bin --localstatedir=/var \
        --disable-servers --disable-logger --disable-whois --disable-rlogin --disable-rsh --disable-rcp --disable-rexec \
        --disable-ping --disable-ping6 --disable-traceroute --disable-ftp --disable-telnet --disable-tftp --disable-talk
    # A cached sysroot may still hold what an older build installed: a setuid traceroute, the clients.
    rm -f /usr/bin/{traceroute,ftp,telnet,tftp,talk} /usr/share/man/man1/{ftp,telnet,tftp,talk}.1
}
