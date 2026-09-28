#!/usr/bin/env bash
# hwdata: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_hwdata() {
    local src; src="$(unpack "hwdata-${V_HWDATA}.tar.gz" "hwdata-${V_HWDATA}")"
    cd "$src"
    ./configure --prefix=/usr --disable-blacklist
    make install
}
