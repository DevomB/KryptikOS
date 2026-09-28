#!/usr/bin/env bash
# man-db: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_man_db() {
    local src; src="$(unpack "man-db-${V_MANDB}.tar.xz" "man-db-${V_MANDB}")"
    cd "$src"

    # --disable-setuid: no setuid man parsing untrusted files for a page cache.
    # No browser/vgrind/grap paths: those programs are not on the system.
    ./configure --prefix=/usr \
        --docdir="/usr/share/doc/man-db-${V_MANDB}" \
        --sysconfdir=/etc \
        --disable-setuid \
        --enable-cache-owner=bin
    make
    make install

    # mandb must link gdbm: configure falls back to another interface silently.
    echo "--- which database interface did man-db link? ---"
    local dyn; dyn="$(readelf -dW /usr/bin/mandb 2>/dev/null || true)"
    if grep -q "libgdbm" <<<"$dyn"; then
        echo "  ok: mandb links libgdbm"
    else
        echo "FAIL: mandb does not link libgdbm."
        echo "      configure fell back to a different database interface, which"
        echo "      is exactly what pinning gdbm was meant to prevent."
        grep NEEDED <<<"$dyn" | sed 's/^/      /'
        return 1
    fi
    echo "--- man-db runs ---"
    man --version
    mandb --version
}
