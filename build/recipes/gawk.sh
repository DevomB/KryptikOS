#!/usr/bin/env bash

s_gawk() {
    # Install links gawk-<version> only when the name is free, so stage 02's would stay.
    rm -f "/usr/bin/gawk-${V_GAWK}"
    local src; src="$(unpack "gawk-${V_GAWK}.tar.xz" "gawk-${V_GAWK}")"
    cd "$src"
    # Upstream's memory-safety fixes from 5.4.1 (see the patch set's README).
    apply_repo_patches "gawk-${V_GAWK}"
    ./configure --prefix=/usr --disable-pma
    make
    make install
    cmp -s /usr/bin/gawk "/usr/bin/gawk-${V_GAWK}" \
        || { echo "FAIL: /usr/bin/gawk-${V_GAWK} is not the gawk just built"; return 1; }
}
