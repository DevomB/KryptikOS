#!/usr/bin/env bash
# zlib: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_zlib() {
    local src; src="$(unpack "zlib-${V_ZLIB}.tar.gz" "zlib-${V_ZLIB}")"
    cd "$src"
    # 1.3.2's security fix without 1.3.2 (see the README).
    apply_repo_patches "zlib-${V_ZLIB}"
    ./configure --prefix=/usr
    make
    # The fix holds: a negative length gives 0, where 1.3.1 never returns.
    printf '%s\n' '#include "zlib.h"' \
        'int main(void) { return crc32_combine(1, 2, -1) != 0 || crc32_combine_gen(-1) != 0; }' > neg.c
    gcc -I. -o neg neg.c libz.a || return 1
    timeout 10 ./neg || { echo "FAIL: crc32_combine does not give 0 for a negative length"; return 1; }
    make install
    # .la files hardcode build paths and confuse libtool consumers later.
    rm -fv /usr/lib/libz.la
}
