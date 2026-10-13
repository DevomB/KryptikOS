#!/usr/bin/env bash

s_iproute2() {
    local src; src="$(unpack "iproute2-${V_IPROUTE2}.tar.xz" "iproute2-${V_IPROUTE2}")"
    cd "$src"
    # arpd needs Berkeley DB, which Kryptik does not ship.
    sed -i /ARPD/d Makefile
    rm -fv man/man8/arpd.8
    # Not the tools that come with libmnl (devlink, rdma, tipc and the rest), which nothing here
    # runs; ip and tc keep libmnl, with which they print the kernel's own error messages.
    sed -i '/^SUBDIRS += tipc devlink/d' Makefile
    if grep -q '^SUBDIRS.*devlink' Makefile; then echo "FAIL: iproute2 would still build devlink"; return 1; fi
    make NETNS_RUN_DIR=/run/netns
    make SBINDIR=/usr/sbin install
    # Their pages and completions install regardless, and a cached sysroot may hold the programs.
    local t
    for t in tipc devlink rdma dcb vdpa netshaper dpll; do
        rm -f "/usr/sbin/$t" "/usr/share/man/man8/$t.8" /usr/share/man/man8/"$t"-*.8 \
            "/usr/share/bash-completion/completions/$t"
    done
}
