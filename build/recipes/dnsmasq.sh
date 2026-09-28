#!/usr/bin/env bash
# dnsmasq: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_dnsmasq() {
    local src; src="$(unpack "dnsmasq-${V_DNSMASQ}.tar.xz" "dnsmasq-${V_DNSMASQ}")"
    cd "$src"
    # Its Makefile assigns CFLAGS and LDFLAGS, which beat the environment, so
    # the hardening goes on the command line. No inotify: a zone gets ENOSYS
    # for it (REFUSED_SOFTLY in seccomp.rs), dnsmasq exits when it cannot have
    # it, and the net zone runs it with --no-poll, which never watches anyway.
    local mk=(PREFIX=/usr COPTS="-DNO_DBUS -DNO_ID -DNO_INOTIFY" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS")
    make "${mk[@]}"
    # `install`, not `install-common`, which installs nothing with PREFIX set.
    make "${mk[@]}" install
    [[ -x /usr/sbin/dnsmasq ]] || { echo "FAIL: /usr/sbin/dnsmasq was not installed"; return 1; }
    local v; v="$(/usr/sbin/dnsmasq --version)"
    printf '%s\n' "$v" | sed -n 1,2p
    [[ "$v" == *no-inotify* ]] || { echo "FAIL: dnsmasq was built with inotify, which a zone is refused"; return 1; }
}
