#!/usr/bin/env bash
# pkgconf: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# pkgconf installs as pkgconf and everything asks for pkg-config, with no
# configure option for the name: link it by hand, as LFS does.
s_pkgconf() {
    native_build "pkgconf-${V_PKGCONF}.tar.xz" "pkgconf-${V_PKGCONF}" \
        --disable-static --docdir="/usr/share/doc/pkgconf-${V_PKGCONF}"

    ln -sfv pkgconf /usr/bin/pkg-config
    ln -sfv pkgconf.1 /usr/share/man/man1/pkg-config.1

    # The name must resolve and answer.
    pkg-config --version
}
