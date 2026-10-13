#!/usr/bin/env bash

# pkgconf has no option to install as pkg-config, which everything asks for: link it, as LFS does.
s_pkgconf() {
    native_build "pkgconf-${V_PKGCONF}.tar.xz" "pkgconf-${V_PKGCONF}" \
        --disable-static --docdir="/usr/share/doc/pkgconf-${V_PKGCONF}"

    ln -sfv pkgconf /usr/bin/pkg-config
    ln -sfv pkgconf.1 /usr/share/man/man1/pkg-config.1

    # The name must resolve and answer.
    pkg-config --version
}
