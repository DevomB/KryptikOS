#!/usr/bin/env bash

s_libaio() {
    local src; src="$(unpack "libaio-${V_LIBAIO}.tar.gz" "libaio-${V_LIBAIO}")"
    cd "$src"
    sed -i '/install.*libaio.a/s/^/#/' src/Makefile
    make
    make prefix=/usr install
}
