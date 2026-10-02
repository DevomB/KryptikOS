#!/usr/bin/env bash

s_hwdata() {
    local src; src="$(unpack "hwdata-${V_HWDATA}.tar.gz" "hwdata-${V_HWDATA}")"
    cd "$src"
    ./configure --prefix=/usr --disable-blacklist
    make install
}
