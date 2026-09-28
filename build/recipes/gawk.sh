#!/usr/bin/env bash
# gawk: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# gawk's install links gawk-<version> only when the name is free, so stage
# 02's copy would stay under it. build/patches/gawk-5.3.0 (see its README)
# carries upstream's memory-safety fixes from 5.4.1.
s_gawk() {
    rm -f "/usr/bin/gawk-${V_GAWK}"
    local src; src="$(unpack "gawk-${V_GAWK}.tar.xz" "gawk-${V_GAWK}")"
    cd "$src"
    apply_repo_patches "gawk-${V_GAWK}"
    ./configure --prefix=/usr --disable-pma
    make
    make install
    cmp -s /usr/bin/gawk "/usr/bin/gawk-${V_GAWK}" \
        || { echo "FAIL: /usr/bin/gawk-${V_GAWK} is not the gawk just built"; return 1; }
}
