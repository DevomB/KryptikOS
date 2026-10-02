#!/usr/bin/env bash

s_shadow() {
    local src; src="$(unpack "shadow-${V_SHADOW}.tar.xz" "shadow-${V_SHADOW}")"
    cd "$src"
    # build/patches/shadow-4.16.0 (see its README): upstream's sgetgrent fix from 4.17.0.
    apply_repo_patches "shadow-${V_SHADOW}"
    # No groups(1) or its man page: coreutils provides groups.
    sed -i 's/groups$(EXEEXT) //' src/Makefile.in
    find man -name Makefile.in -exec sed -i 's/groups\.1 / /' {} \;

    # SHA512 rather than DES: password hashes leak and get cracked offline.
    sed -e 's:#ENCRYPT_METHOD DES:ENCRYPT_METHOD SHA512:' \
        -e 's:/var/spool/mail:/var/mail:' \
        -e '/PATH=/{s@/sbin:@@;s@/usr/sbin:@@}' \
        -i etc/login.defs

    ./configure --sysconfdir=/etc --disable-static --with-{b,yes}crypt \
        --without-libbsd --with-group-name-max-length=32
    make
    make exec_prefix=/usr install
    # Only su and passwd keep a setuid bit (build/config/setuid-allowlist.txt).
    chmod ug-s /usr/bin/{chage,chfn,chsh,expiry,gpasswd,newgidmap,newgrp,newuidmap}
}
