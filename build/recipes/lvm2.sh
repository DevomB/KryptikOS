#!/usr/bin/env bash
# lvm2: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# Only device-mapper from LVM2: libdevmapper for cryptsetup, dmsetup for an
# operator. No lvm binary, daemons or volume udev rules.
s_lvm2() {
    local src; src="$(unpack "LVM2.${V_LVM2}.tgz" "LVM2.${V_LVM2}")"
    cd "$src"
    PATH="$PATH:/usr/sbin" ./configure --prefix=/usr --enable-pkgconfig \
        --disable-readline --disable-selinux --with-default-dm-run-dir=/run \
        --enable-udev_sync --disable-silent-rules
    make device-mapper
    # -j1: the install target's two sub-makes both rebuild dmsetup, and in
    # parallel one links while the other rewrites dmsetup.o.
    make -j1 install_device-mapper
    # The library line shows the binary runs. The driver line after it needs
    # the build machine's device-mapper, and dmsetup fails without it.
    local out; out="$(dmsetup --version 2>&1 || true)"
    grep -m1 '^Library version:' <<<"$out" || { echo "dmsetup does not run: ${out}"; return 1; }
    [[ -f /usr/lib/pkgconfig/devmapper.pc ]] || { echo "no devmapper.pc"; return 1; }
}
