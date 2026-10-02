#!/usr/bin/env bash

s_openssl() {
    local src; src="$(unpack "openssl-${V_OPENSSL}.tar.gz" "openssl-${V_OPENSSL}")"
    cd "$src"
    # No enable-ktls: kernel crypto widens what a kernel bug exposes to every zone (ADR-002).
    ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib \
        shared zlib-dynamic
    make
    make MANSUFFIX=ssl install
}
