#!/usr/bin/env bash

s_dnsmasq() {
    local src; src="$(unpack "dnsmasq-${V_DNSMASQ}.tar.xz" "dnsmasq-${V_DNSMASQ}")"
    cd "$src"
    # The Makefile sets CFLAGS and LDFLAGS over the environment, so they go on the command line.
    # NO_INOTIFY: a zone gets ENOSYS for inotify (seccomp.rs), and dnsmasq exits without it.
    local mk=(PREFIX=/usr COPTS="-DNO_DBUS -DNO_ID -DNO_INOTIFY" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS")
    make "${mk[@]}"
    # `install`, not `install-common`, which installs nothing with PREFIX set.
    make "${mk[@]}" install
    [[ -x /usr/sbin/dnsmasq ]] || { echo "FAIL: /usr/sbin/dnsmasq was not installed"; return 1; }
    local v; v="$(/usr/sbin/dnsmasq --version)"
    printf '%s\n' "$v" | sed -n 1,2p
    [[ "$v" == *no-inotify* ]] || { echo "FAIL: dnsmasq was built with inotify, which a zone is refused"; return 1; }
}
