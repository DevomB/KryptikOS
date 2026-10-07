#!/usr/bin/env bash

s_perl() {
    local src; src="$(unpack "perl-${V_PERL}.tar.xz" "perl-${V_PERL}")"
    cd "$src"
    # Configure ignores CFLAGS and LDFLAGS, so the hardening goes in as its own settings.
    # -shared: a given lddlflags replaces Configure's default instead of adding to it.
    # No GDBM_File: nothing needs it, and the build must not depend on a cached gdbm.
    sh Configure -des \
        -Dprefix=/usr \
        -Dvendorprefix=/usr \
        -Duseshrplib \
        -Dusethreads \
        -Doptimize="$KRYPTIK_OPT" \
        -Accflags="${CFLAGS#"$KRYPTIK_OPT"}" \
        -Dldflags="$LDFLAGS" \
        -Dlddlflags="-shared $LDFLAGS" \
        -Dnoextensions=GDBM_File
    make
    make install
    # A cached sysroot may hold the module from a build that saw gdbm; nothing else removes it.
    rm -rf /usr/lib/perl5/*/*/auto/GDBM_File /usr/lib/perl5/*/*/GDBM_File.pm
}
