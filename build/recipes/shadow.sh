#!/usr/bin/env bash
# shadow: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_shadow() {
    local src; src="$(unpack "shadow-${V_SHADOW}.tar.xz" "shadow-${V_SHADOW}")"
    cd "$src"
    # build/patches/shadow-4.16.0 (see its README): upstream's sgetgrent fix from 4.17.0.
    apply_repo_patches "shadow-${V_SHADOW}"
    # Kryptik does not ship groups(1) or the *chage man pages that conflict
    # with coreutils/man-pages.
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
    # Privilege from a bit is su's and passwd's alone
    # (build/config/setuid-allowlist.txt); the rest run unprivileged or not at all.
    chmod ug-s /usr/bin/{chage,chfn,chsh,expiry,gpasswd,newgidmap,newgrp,newuidmap}
}
