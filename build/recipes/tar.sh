#!/usr/bin/env bash

# tar 1.35's private acl_*_at functions clash with libacl 2.4.0's; the patch set renames them.
s_tar() {
    local src; src="$(unpack "tar-${V_TAR}.tar.xz" "tar-${V_TAR}")"
    cd "$src"
    apply_repo_patches "tar-${V_TAR}"
    ./configure --prefix=/usr
    make
    make install
}
