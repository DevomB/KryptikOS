#!/usr/bin/env bash
# perl: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_perl() {
    local src; src="$(unpack "perl-${V_PERL}.tar.xz" "perl-${V_PERL}")"
    cd "$src"
    # Configure reads neither CFLAGS nor LDFLAGS, so the hardening goes in as
    # its own settings. lddlflags names -shared because a value given for it
    # replaces Configure's default instead of adding to it. No GDBM_File: perl
    # is built before gdbm, and nothing needs the binding, so the build must
    # not depend on whether an older sysroot has gdbm already.
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
    # A sysroot from an earlier build may hold the module a rebuild after gdbm
    # once made; nothing else removes what a step no longer installs.
    rm -rf /usr/lib/perl5/*/*/auto/GDBM_File /usr/lib/perl5/*/*/GDBM_File.pm
}
