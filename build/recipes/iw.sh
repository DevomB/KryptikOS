#!/usr/bin/env bash
# iw: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# iw: the operator's view of a radio (scan, link, reg), and the reference for
# what kryptikd does with nl80211 itself.
s_iw() {
    local src; src="$(unpack "iw-${V_IW}.tar.xz" "iw-${V_IW}")"
    cd "$src"
    make PREFIX=/usr SBINDIR=/usr/sbin
    make PREFIX=/usr SBINDIR=/usr/sbin install
    [[ -x /usr/sbin/iw ]] || { echo "FAIL: /usr/sbin/iw was not installed"; return 1; }
    iw --version
}
