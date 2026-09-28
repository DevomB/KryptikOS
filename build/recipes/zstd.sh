#!/usr/bin/env bash
# zstd: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_zstd() {
    local src; src="$(unpack "zstd-${V_ZSTD}.tar.gz" "zstd-${V_ZSTD}")"
    cd "$src"
    make prefix=/usr
    make prefix=/usr install
    rm -fv /usr/lib/libzstd.a
}
