#!/usr/bin/env bash

# Only device-mapper: libdevmapper for cryptsetup and dmsetup for an operator; no lvm or daemons.
s_lvm2() {
    local src; src="$(unpack "LVM2.${V_LVM2}.tgz" "LVM2.${V_LVM2}")"
    cd "$src"
    PATH="$PATH:/usr/sbin" ./configure --prefix=/usr --enable-pkgconfig \
        --disable-readline --disable-selinux --with-default-dm-run-dir=/run \
        --enable-udev_sync --disable-silent-rules
    make device-mapper
    # -j1: both sub-makes of the install rebuild dmsetup and race on dmsetup.o.
    make -j1 install_device-mapper
    # The library line proves it runs; the driver line needs the host's device-mapper.
    local out; out="$(dmsetup --version 2>&1 || true)"
    grep -m1 '^Library version:' <<<"$out" || { echo "dmsetup does not run: ${out}"; return 1; }
    [[ -f /usr/lib/pkgconfig/devmapper.pc ]] || { echo "no devmapper.pc"; return 1; }
}
