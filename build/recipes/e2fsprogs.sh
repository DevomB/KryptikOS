#!/usr/bin/env bash

s_e2fsprogs() {
    local src; src="$(unpack "e2fsprogs-${V_E2FSPROGS}.tar.gz" "e2fsprogs-${V_E2FSPROGS}")"
    cd "$src"
    mkdir -p build && cd build
    # libblkid, libuuid, uuidd and fsck come from util-linux.
    ../configure --prefix=/usr --sysconfdir=/etc --enable-elf-shlibs \
        --disable-libblkid --disable-libuuid --disable-uuidd --disable-fsck
    make
    make install
    rm -fv /usr/lib/{libcom_err,libe2p,libext2fs,libss}.a
}
