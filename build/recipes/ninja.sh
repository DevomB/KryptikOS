#!/usr/bin/env bash
# ninja: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_ninja() {
    local src; src="$(unpack "ninja-${V_NINJA}.tar.gz" "ninja-${V_NINJA}")"
    cd "$src"
    python3 configure.py --bootstrap
    install -m 0755 ninja /usr/bin/ninja
    ninja --version
}
