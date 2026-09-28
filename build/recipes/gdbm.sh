#!/usr/bin/env bash
# gdbm: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_gdbm() {
    # No --enable-libgdbm-compat: man-db uses gdbm's native interface, not ndbm.
    local src; src="$(unpack "gdbm-${V_GDBM}.tar.gz" "gdbm-${V_GDBM}")"
    cd "$src"
    ./configure --prefix=/usr --disable-static
    make
    make install
    rm -fv /usr/lib/libgdbm.la

    # The installed gdbm must store and return a key.
    echo "--- gdbm round trip ---"
    cat > /tmp/kryptik-gdbm-check.c <<'CEOF'
#include <gdbm.h>
#include <string.h>
#include <stdio.h>
int main(void)
{
    GDBM_FILE f = gdbm_open("/tmp/kryptik-gdbm-check.db", 0, GDBM_NEWDB, 0600, 0);
    if (!f) { puts("gdbm_open failed"); return 1; }
    datum k = { (char *) "kryptik", 7 }, v = { (char *) "works", 5 };
    if (gdbm_store(f, k, v, GDBM_INSERT)) { puts("gdbm_store failed"); return 2; }
    datum r = gdbm_fetch(f, k);
    if (!r.dptr || r.dsize != 5 || memcmp(r.dptr, "works", 5)) { puts("fetch mismatch"); return 3; }
    puts("gdbm stored and returned a key");
    gdbm_close(f);
    return 0;
}
CEOF
    gcc -O0 -o /tmp/kryptik-gdbm-check /tmp/kryptik-gdbm-check.c -lgdbm || {
        echo "FAIL: could not compile against the gdbm we just installed"; return 1; }
    /tmp/kryptik-gdbm-check || { echo "FAIL: gdbm cannot round-trip a key"; return 1; }
    rm -f /tmp/kryptik-gdbm-check /tmp/kryptik-gdbm-check.c /tmp/kryptik-gdbm-check.db
}
