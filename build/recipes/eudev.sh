#!/usr/bin/env bash

s_eudev() {
    local src; src="$(unpack "eudev-${V_EUDEV}.tar.gz" "eudev-${V_EUDEV}")"
    cd "$src"
    ./configure --prefix=/usr --bindir=/usr/sbin --sysconfdir=/etc \
        --enable-manpages --disable-static
    make
    mkdir -pv /usr/lib/udev/rules.d
    mkdir -pv /etc/udev/rules.d
    make install
    # The hardware database the rules query (keyboard maps, mouse and touchpad fixes), compiled
    # onto the verified root: nothing on a booted system runs udevadm hwdb --update.
    udevadm hwdb --update --output=/usr/lib/udev/hwdb.bin
    local got; got="$(udevadm hwdb --test='usb:v1D6Bp0001' 2>&1 || true)"
    [[ "$got" == *ID_VENDOR_FROM_DATABASE=* ]] || { echo "FAIL: the hardware database does not answer: ${got}"; return 1; }
    printf 'hwdb.bin answers: %s\n' "$got"
}
