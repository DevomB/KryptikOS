#!/usr/bin/env bash

s_zstd() {
    local src; src="$(unpack "zstd-${V_ZSTD}.tar.gz" "zstd-${V_ZSTD}")"
    cd "$src"
    make prefix=/usr
    make prefix=/usr install
    rm -fv /usr/lib/libzstd.a
}
