#!/usr/bin/env bash
# openssl: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_openssl() {
    local src; src="$(unpack "openssl-${V_OPENSSL}.tar.gz" "openssl-${V_OPENSSL}")"
    cd "$src"
    # No enable-ktls: crypto in the kernel widens the surface a kernel bug
    # exposes to every zone at once (ADR-002).
    ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib \
        shared zlib-dynamic
    make
    make MANSUFFIX=ssl install
}
