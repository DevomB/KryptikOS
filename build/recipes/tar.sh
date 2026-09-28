#!/usr/bin/env bash
# tar: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# tar 1.35 defines private acl_*_at functions that libacl 2.4.0 now declares;
# build/patches/tar-1.35 (see its README) carries upstream's rename.
s_tar() {
    local src; src="$(unpack "tar-${V_TAR}.tar.xz" "tar-${V_TAR}")"
    cd "$src"
    apply_repo_patches "tar-${V_TAR}"
    ./configure --prefix=/usr
    make
    make install
}
