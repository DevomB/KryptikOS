#!/usr/bin/env bash
# libaio: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_libaio() {
    local src; src="$(unpack "libaio-${V_LIBAIO}.tar.gz" "libaio-${V_LIBAIO}")"
    cd "$src"
    sed -i '/install.*libaio.a/s/^/#/' src/Makefile
    make
    make prefix=/usr install
}
