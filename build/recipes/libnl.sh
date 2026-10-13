#!/usr/bin/env bash

# The library alone: wpa_supplicant and iw link it, and nothing runs its nl-* tools.
s_libnl() {
    native_build "libnl-${V_LIBNL}.tar.gz" "libnl-${V_LIBNL}" --sysconfdir=/etc --disable-static --disable-cli
    # A cached sysroot still holds what a build with the tools installed.
    rm -rf /usr/bin/nl-* /usr/bin/nf-* /usr/bin/genl-ctrl-list /usr/bin/idiag-socket-details \
        /usr/lib/libnl/cli /usr/lib/libnl-cli-3.* /usr/lib/pkgconfig/libnl-cli-3.0.pc \
        /usr/share/man/man8/genl-ctrl-list.8 /usr/share/man/man8/nl-*.8
    [[ ! -e /usr/bin/nl-link-list ]] || { echo "FAIL: libnl's tools are still installed"; return 1; }
}
