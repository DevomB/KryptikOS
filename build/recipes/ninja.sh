#!/usr/bin/env bash

s_ninja() {
    local src; src="$(unpack "ninja-${V_NINJA}.tar.gz" "ninja-${V_NINJA}")"
    cd "$src"
    python3 configure.py --bootstrap
    install -m 0755 ninja /usr/bin/ninja
    ninja --version
}
