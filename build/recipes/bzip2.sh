#!/usr/bin/env bash
# bzip2: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_bzip2() {
    local src; src="$(unpack "bzip2-${V_BZIP2}.tar.gz" "bzip2-${V_BZIP2}")"
    cd "$src"
    # bzip2 has no configure; its docs path and shared-lib build need patching.
    sed -i 's@\(ln -s -f \)$(PREFIX)/bin/@\1@' Makefile
    sed -i "s@(PREFIX)/man@(PREFIX)/share/man@g" Makefile
    # Both Makefiles assign CFLAGS, which beats the environment, and link the
    # library with neither CFLAGS nor LDFLAGS: the flags go on the command
    # line, with the -fPIC and large-file define theirs carried.
    sed -i -e 's/-shared -Wl,-soname/-shared $(LDFLAGS) -Wl,-soname/' \
        -e 's/$(CFLAGS) -o bzip2-shared/$(CFLAGS) $(LDFLAGS) -o bzip2-shared/' Makefile-libbz2_so
    [[ "$(grep -c 'LDFLAGS' Makefile-libbz2_so)" -eq 2 ]] || { echo "FAIL: Makefile-libbz2_so did not take LDFLAGS"; return 1; }
    make -f Makefile-libbz2_so CFLAGS="$CFLAGS -fPIC -D_FILE_OFFSET_BITS=64" LDFLAGS="$LDFLAGS"
    make clean
    make CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64" LDFLAGS="$LDFLAGS"
    make PREFIX=/usr CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64" LDFLAGS="$LDFLAGS" install
    cp -av libbz2.so.* /usr/lib
    ln -sfv "libbz2.so.${V_BZIP2}" /usr/lib/libbz2.so
    cp -v bzip2-shared /usr/bin/bzip2
    rm -fv /usr/lib/libbz2.a
}
