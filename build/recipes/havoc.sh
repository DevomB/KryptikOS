#!/usr/bin/env bash

s_havoc() {
    local src; src="$(unpack "havoc-${V_HAVOC}.tar.gz" "havoc-${V_HAVOC}")"
    cd "$src"
    make PREFIX=/usr
    make PREFIX=/usr install
    install -Dm644 havoc.cfg /usr/share/kryptik/havoc.cfg
    [[ -x /usr/bin/havoc ]] || { echo "no havoc binary"; return 1; }
}
