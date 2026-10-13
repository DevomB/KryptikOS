#!/usr/bin/env bash

# The operator's view of a radio (scan, link, reg), and a reference for kryptikd's nl80211 use.
s_iw() {
    local src; src="$(unpack "iw-${V_IW}.tar.xz" "iw-${V_IW}")"
    cd "$src"
    make PREFIX=/usr SBINDIR=/usr/sbin
    make PREFIX=/usr SBINDIR=/usr/sbin install
    [[ -x /usr/sbin/iw ]] || { echo "FAIL: /usr/sbin/iw was not installed"; return 1; }
    iw --version
}
