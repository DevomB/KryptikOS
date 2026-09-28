#!/usr/bin/env bash
# iproute2: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_iproute2() {
    local src; src="$(unpack "iproute2-${V_IPROUTE2}.tar.xz" "iproute2-${V_IPROUTE2}")"
    cd "$src"
    # arpd needs Berkeley DB, which Kryptik does not ship.
    sed -i /ARPD/d Makefile
    rm -fv man/man8/arpd.8
    make NETNS_RUN_DIR=/run/netns
    make SBINDIR=/usr/sbin install
}
