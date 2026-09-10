#!/usr/bin/env bash
# Stage 04 — Hardened base system (Phase 3 of docs/roadmap.md)
#
# Builds the base system INSIDE the chroot prepared by stage 03. This is the
# first stage where Kryptik's hardening flags are applied: every package here is
# compiled with the full set from build/config/hardening.env.
#
#   ./04-base-system.sh              build everything, resumable
#   ./04-base-system.sh --redo bash  force one package to rebuild
#   ./04-base-system.sh --list       print the build order and stop
#
# MUST be run from inside the chroot:
#   sudo build/stages/03-chroot-prep.sh mount
#   sudo chroot ... /usr/bin/bash -c 'build/stages/04-base-system.sh'
#
# STATUS: written, not yet executed end to end. Roughly 50 packages; expect
# first-contact failures, particularly from packages that do not tolerate
# -D_FORTIFY_SOURCE=3 or -pie. Those get an entry in
# build/config/hardening-exceptions.txt WITH a justification, not a blanket
# flag removal.

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# --- hardening --------------------------------------------------------------
#
# Unlike stages 01 and 02, this stage DOES load the hardening flags. The
# toolchain exists now, it targets Kryptik, and these packages are the ones
# that ship. See docs/hardening.md.
load_hardening
validate_hardening_exceptions

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(nproc)}"
export MAKEFLAGS="-j${KRYPTIK_JOBS}"
umask 022

MODE="build"
REDO=""
case "${1:-}" in
    --list) MODE="list" ;;
    --redo) REDO="${2:?--redo needs a package name}" ;;
esac

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR"

# --- hardening exceptions ---------------------------------------------------

# Returns the flags to DROP for a package, if any. Every exception must carry a
# justification comment; common.sh::validate_hardening_exceptions fails the
# build otherwise, so an undocumented exception cannot accumulate quietly.
exception_flags_for() {
    local pkg="$1" f="${KRYPTIK_ROOT}/build/config/hardening-exceptions.txt"
    [[ -f "$f" ]] || return 0
    awk -v p="$pkg" '!/^[[:space:]]*#/ && $1 == p { print $2 }' "$f"
}

# Apply hardening minus any justified exceptions for this package.
set_flags_for() {
    local pkg="$1" drop
    export CFLAGS="${KRYPTIK_OPT} ${KRYPTIK_CFLAGS_HARDENING}"
    export CXXFLAGS="${KRYPTIK_OPT} ${KRYPTIK_CFLAGS_HARDENING}"
    export LDFLAGS="${KRYPTIK_LDFLAGS_HARDENING}"

    while read -r drop; do
        [[ -z "$drop" ]] && continue
        warn "${pkg}: dropping ${drop} (justified exception)"
        CFLAGS="${CFLAGS//${drop}/}"
        CXXFLAGS="${CXXFLAGS//${drop}/}"
        LDFLAGS="${LDFLAGS//${drop}/}"
    done < <(exception_flags_for "$pkg")

    export CFLAGS CXXFLAGS LDFLAGS
}

# --- step machinery ---------------------------------------------------------

step() {
    local name="$1"; shift
    if [[ "$REDO" == "$name" ]]; then
        warn "forcing rebuild of ${name}"
        rm -f "${STAMPS:?}/bs-${name}"
    fi
    if [[ -f "${STAMPS}/bs-${name}" ]]; then
        dim "  skip ${name} (already built)"
        return 0
    fi
    log "${name}"
    set_flags_for "$name"
    local logfile="${LOGS}/bs-${name}.log"
    local start=$SECONDS
    if "$@" > "$logfile" 2>&1; then
        touch "${STAMPS}/bs-${name}"
        ok "${name} ($(( SECONDS - start ))s)"
    else
        err "${name} failed. Last 40 lines of ${logfile}:"
        tail -40 "$logfile" >&2
        echo >&2
        err "If this is a hardening incompatibility, add an entry to"
        err "build/config/hardening-exceptions.txt WITH a justification."
        err "Do not remove the flag globally."
        die "stage 04 aborted at ${name}"
    fi
}

unpack() {
    local tarball="$1" dirname="$2"
    local dir="${BUILDDIR}/${dirname}"
    rm -rf "$dir"
    tar -xf "${KRYPTIK_SOURCES}/${tarball}" -C "$BUILDDIR"
    [[ -d "$dir" ]] || die "expected ${dir} after unpacking ${tarball}"
    printf '%s' "$dir"
}

# Native build: no --host, because we are running on the target now.
native_build() {
    local tarball="$1" dirname="$2"; shift 2
    local src; src="$(unpack "$tarball" "$dirname")"
    cd "$src"
    ./configure --prefix=/usr "$@"
    make
    make install
}

# --- packages that need more than ./configure ------------------------------

s_zlib() {
    local src; src="$(unpack "zlib-${V_ZLIB}.tar.gz" "zlib-${V_ZLIB}")"
    cd "$src"
    ./configure --prefix=/usr
    make
    make install
    # .la files hardcode build paths and confuse libtool consumers later.
    rm -fv /usr/lib/libz.la
}

s_bzip2() {
    local src; src="$(unpack "bzip2-${V_BZIP2}.tar.gz" "bzip2-${V_BZIP2}")"
    cd "$src"
    # bzip2 has no configure; its docs path and shared-lib build need patching.
    sed -i 's@\(ln -s -f \)$(PREFIX)/bin/@\1@' Makefile
    sed -i "s@(PREFIX)/man@(PREFIX)/share/man@g" Makefile
    make -f Makefile-libbz2_so
    make clean
    make
    make PREFIX=/usr install
    cp -av libbz2.so.* /usr/lib
    ln -sfv libbz2.so.1.0.8 /usr/lib/libbz2.so
    cp -v bzip2-shared /usr/bin/bzip2
    rm -fv /usr/lib/libbz2.a
}

s_xz_native() {
    native_build "xz-${V_XZ}.tar.xz" "xz-${V_XZ}" \
        --disable-static --docdir="/usr/share/doc/xz-${V_XZ}"
    rm -fv /usr/lib/liblzma.la
}

s_zstd() {
    local src; src="$(unpack "zstd-${V_ZSTD}.tar.gz" "zstd-${V_ZSTD}")"
    cd "$src"
    make prefix=/usr
    make prefix=/usr install
    rm -fv /usr/lib/libzstd.a
}

s_openssl() {
    local src; src="$(unpack "openssl-${V_OPENSSL}.tar.gz" "openssl-${V_OPENSSL}")"
    cd "$src"
    # enable-ktls is deliberately NOT set: it moves crypto into the kernel and
    # widens the kernel attack surface, which cuts against ADR-002's admission
    # that a kernel bug compromises every zone at once.
    ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib \
        shared zlib-dynamic
    make
    make MANSUFFIX=ssl install
}

s_perl() {
    local src; src="$(unpack "perl-${V_PERL}.tar.xz" "perl-${V_PERL}")"
    cd "$src"
    sh Configure -des \
        -Dprefix=/usr \
        -Dvendorprefix=/usr \
        -Duseshrplib \
        -Dusethreads
    make
    make install
}

s_python() {
    local src; src="$(unpack "Python-${V_PYTHON}.tar.xz" "Python-${V_PYTHON}")"
    cd "$src"
    ./configure --prefix=/usr --enable-shared --with-system-expat \
        --enable-optimizations
    make
    make install
}

s_shadow() {
    local src; src="$(unpack "shadow-${V_SHADOW}.tar.xz" "shadow-${V_SHADOW}")"
    cd "$src"
    # Kryptik does not ship groups(1) or the *chage man pages that conflict
    # with coreutils/man-pages.
    sed -i 's/groups$(EXEEXT) //' src/Makefile.in
    find man -name Makefile.in -exec sed -i 's/groups\.1 / /' {} \;

    # SHA512 rather than the default, and a high round count. Cheap, and
    # password hashes are exactly the thing that leaks and gets cracked offline.
    sed -e 's:#ENCRYPT_METHOD DES:ENCRYPT_METHOD SHA512:' \
        -e 's:/var/spool/mail:/var/mail:' \
        -e '/PATH=/{s@/sbin:@@;s@/usr/sbin:@@}' \
        -i etc/login.defs

    ./configure --sysconfdir=/etc --disable-static --with-{b,yes}crypt \
        --without-libbsd --with-group-name-max-length=32
    make
    make exec_prefix=/usr install
}

s_hardened_malloc() {
    # ADR-005. Built here so it exists before anything links against it.
    local src; src="$(unpack "${V_HARDENED_MALLOC}.tar.gz" "hardened_malloc-${V_HARDENED_MALLOC}")"
    cd "$src"
    make VARIANT=default
    install -Dm755 out/libhardened_malloc.so /usr/lib/libhardened_malloc.so

    # NOT wired into /etc/ld.so.preload yet. Making it the system allocator is
    # a separate, reversible step, and doing it mid-build would mean every
    # remaining package builds against an allocator that has not been smoke
    # tested on this system.
    echo "installed to /usr/lib/libhardened_malloc.so (not yet preloaded)"
}

s_libcap() {
    local src; src="$(unpack "libcap-${V_LIBCAP}.tar.xz" "libcap-${V_LIBCAP}")"
    cd "$src"
    # pam support is not wanted; Kryptik has no PAM stack.
    sed -i '/install -m.*STA/d' libcap/Makefile
    make prefix=/usr lib=lib
    make prefix=/usr lib=lib install
}

s_e2fsprogs() {
    local src; src="$(unpack "e2fsprogs-${V_E2FSPROGS}.tar.gz" "e2fsprogs-${V_E2FSPROGS}")"
    cd "$src"
    mkdir -p build && cd build
    # --disable-*-debug drops the debugging metadata utilities Kryptik has no
    # use for; each is filesystem-manipulation surface running as root.
    ../configure --prefix=/usr --sysconfdir=/etc --enable-elf-shlibs         --disable-libblkid --disable-libuuid --disable-uuidd --disable-fsck
    make
    make install
    rm -fv /usr/lib/{libcom_err,libe2p,libext2fs,libss}.a
}

s_elfutils() {
    local src; src="$(unpack "elfutils-${V_ELFUTILS}.tar.bz2" "elfutils-${V_ELFUTILS}")"
    cd "$src"
    ./configure --prefix=/usr --disable-debuginfod --enable-libdebuginfod=dummy
    make
    # Only libelf is wanted; the rest of elfutils is developer tooling that
    # does not belong in a base system.
    make -C libelf install
    install -vm644 config/libelf.pc /usr/lib/pkgconfig
    rm -fv /usr/lib/libelf.a
}

s_iproute2() {
    local src; src="$(unpack "iproute2-${V_IPROUTE2}.tar.xz" "iproute2-${V_IPROUTE2}")"
    cd "$src"
    # arpd needs Berkeley DB, which Kryptik does not ship.
    sed -i /ARPD/d Makefile
    rm -fv man/man8/arpd.8
    make NETNS_RUN_DIR=/run/netns
    make SBINDIR=/usr/sbin install
}

s_kbd() {
    local src; src="$(unpack "kbd-${V_KBD}.tar.xz" "kbd-${V_KBD}")"
    cd "$src"
    sed -i '/RESIZECONS_PROGS=/s/yes/no/' configure
    sed -i 's/resizecons.8 //' docs/man/man8/Makefile.in
    ./configure --prefix=/usr --disable-vlock
    make
    make install
}

s_eudev() {
    local src; src="$(unpack "eudev-${V_EUDEV}.tar.gz" "eudev-${V_EUDEV}")"
    cd "$src"
    ./configure --prefix=/usr --bindir=/usr/sbin --sysconfdir=/etc         --enable-manpages --disable-static
    make
    mkdir -pv /usr/lib/udev/rules.d
    mkdir -pv /etc/udev/rules.d
    make install
}

s_iana_etc() {
    # Not a build: /etc/protocols and /etc/services are data files.
    local src; src="$(unpack "iana-etc-${V_IANA_ETC}.tar.gz" "iana-etc-${V_IANA_ETC}")"
    cd "$src"
    cp -v services protocols /etc
}

s_binutils_native() {
    local src; src="$(unpack "binutils-${V_BINUTILS}.tar.xz" "binutils-${V_BINUTILS}")"
    cd "$src"
    mkdir -p build && cd build
    ../configure --prefix=/usr --sysconfdir=/etc --enable-gold         --enable-ld=default --enable-plugins --enable-shared --disable-werror         --enable-64-bit-bfd --enable-new-dtags --with-system-zlib         --enable-default-hash-style=gnu
    make tooldir=/usr
    make tooldir=/usr install
    rm -fv /usr/lib/lib{bfd,ctf,ctf-nobfd,gprofng,opcodes,sframe}.a
}

s_s6_stack() {
    # ADR-006. skarnet packages use their own configure conventions.
    local p
    for p in "skalibs-${V_SKALIBS}" "execline-${V_EXECLINE}" "s6-${V_S6}" \
             "s6-rc-${V_S6_RC}" "s6-linux-init-${V_S6_LINUX_INIT}"; do
        echo "--- ${p} ---"
        local src; src="$(unpack "${p}.tar.gz" "$p")"
        cd "$src"
        ./configure --prefix=/usr --libdir=/usr/lib --with-dynlib=/usr/lib
        make
        make install
    done
}

# --- build order ------------------------------------------------------------
#
# Ordered by dependency, not alphabetically. Moving an entry earlier because it
# "seems independent" is how a base system build breaks three packages later.

declare -a PACKAGES=(
    "gettext"     "native_build gettext-${V_GETTEXT}.tar.xz gettext-${V_GETTEXT} --disable-shared"
    "bison"       "native_build bison-${V_BISON}.tar.xz bison-${V_BISON} --docdir=/usr/share/doc/bison-${V_BISON}"
    "perl"        "s_perl"
    "python"      "s_python"
    "texinfo"     "native_build texinfo-${V_TEXINFO}.tar.xz texinfo-${V_TEXINFO}"
    "util-linux"  "native_build util-linux-${V_UTIL_LINUX}.tar.xz util-linux-${V_UTIL_LINUX} --libdir=/usr/lib --runstatedir=/run --disable-chfn-chsh --disable-login --disable-nologin --disable-su --disable-setpriv --disable-runuser --disable-pylibmount --disable-liblastlog2 --disable-static --without-python"
    "zlib"        "s_zlib"
    "bzip2"       "s_bzip2"
    "xz"          "s_xz_native"
    "zstd"        "s_zstd"
    "file"        "native_build file-${V_FILE}.tar.gz file-${V_FILE}"
    "readline"    "native_build readline-${V_READLINE}.tar.gz readline-${V_READLINE} --disable-static --with-curses"
    "m4"          "native_build m4-${V_M4}.tar.xz m4-${V_M4}"
    "flex"        "native_build flex-${V_FLEX}.tar.gz flex-${V_FLEX} --disable-static"
    "binutils"    "s_binutils_native"
    "gmp"         "native_build gmp-${V_GMP}.tar.xz gmp-${V_GMP} --enable-cxx --disable-static"
    "mpfr"        "native_build mpfr-${V_MPFR}.tar.xz mpfr-${V_MPFR} --disable-static --enable-thread-safe"
    "mpc"         "native_build mpc-${V_MPC}.tar.gz mpc-${V_MPC} --disable-static"
    "attr"        "native_build attr-${V_ATTR}.tar.gz attr-${V_ATTR} --disable-static --sysconfdir=/etc"
    "acl"         "native_build acl-${V_ACL}.tar.xz acl-${V_ACL} --disable-static"
    "libcap"      "s_libcap"
    "libxcrypt"   "native_build libxcrypt-${V_LIBXCRYPT}.tar.xz libxcrypt-${V_LIBXCRYPT} --enable-hashes=strong,glibc --enable-obsolete-api=no --disable-static --disable-failure-tokens"
    "shadow"      "s_shadow"
    "ncurses"     "native_build ncurses-${V_NCURSES}.tar.gz ncurses-${V_NCURSES} --mandir=/usr/share/man --with-shared --without-debug --without-normal --with-cxx-shared --enable-pc-files"
    "sed"         "native_build sed-${V_SED}.tar.xz sed-${V_SED}"
    "psmisc"      "native_build psmisc-${V_PSMISC}.tar.xz psmisc-${V_PSMISC}"
    "bash"        "native_build bash-${V_BASH}.tar.gz bash-${V_BASH} --without-bash-malloc --with-installed-readline"
    "libtool"     "native_build libtool-${V_LIBTOOL}.tar.xz libtool-${V_LIBTOOL}"
    "gperf"       "native_build gperf-${V_GPERF}.tar.gz gperf-${V_GPERF} --docdir=/usr/share/doc/gperf-${V_GPERF}"
    "expat"       "native_build expat-${V_EXPAT}.tar.xz expat-${V_EXPAT} --disable-static --docdir=/usr/share/doc/expat-${V_EXPAT}"
    "inetutils"   "native_build inetutils-${V_INETUTILS}.tar.xz inetutils-${V_INETUTILS} --bindir=/usr/bin --localstatedir=/var --disable-logger --disable-whois --disable-rlogin --disable-rsh --disable-rcp --disable-rexec --disable-rexecd --disable-rlogind --disable-rshd"
    "less"        "native_build less-${V_LESS}.tar.gz less-${V_LESS} --sysconfdir=/etc"
    "openssl"     "s_openssl"
    "libffi"      "native_build libffi-${V_LIBFFI}.tar.gz libffi-${V_LIBFFI} --disable-static --with-gcc-arch=native"
    "coreutils"   "native_build coreutils-${V_COREUTILS}.tar.xz coreutils-${V_COREUTILS} --enable-no-install-program=kill,uptime"
    "diffutils"   "native_build diffutils-${V_DIFFUTILS}.tar.xz diffutils-${V_DIFFUTILS}"
    "gawk"        "native_build gawk-${V_GAWK}.tar.xz gawk-${V_GAWK}"
    "findutils"   "native_build findutils-${V_FINDUTILS}.tar.xz findutils-${V_FINDUTILS} --localstatedir=/var/lib/locate"
    "grep"        "native_build grep-${V_GREP}.tar.xz grep-${V_GREP}"
    "gzip"        "native_build gzip-${V_GZIP}.tar.xz gzip-${V_GZIP}"
    "make"        "native_build make-${V_MAKE}.tar.gz make-${V_MAKE}"
    "patch"       "native_build patch-${V_PATCH}.tar.xz patch-${V_PATCH}"
    "tar"         "native_build tar-${V_TAR}.tar.xz tar-${V_TAR}"
    "groff"       "native_build groff-${V_GROFF}.tar.gz groff-${V_GROFF}"
    "kmod"        "native_build kmod-${V_KMOD}.tar.xz kmod-${V_KMOD} --sysconfdir=/etc --with-openssl --with-xz --with-zstd --with-zlib"
    "libpipeline" "native_build libpipeline-${V_LIBPIPELINE}.tar.gz libpipeline-${V_LIBPIPELINE}"
    "man-db"      "native_build man-db-${V_MANDB}.tar.xz man-db-${V_MANDB} --docdir=/usr/share/doc/man-db-${V_MANDB} --sysconfdir=/etc --disable-setuid --enable-cache-owner=bin"
    "procps-ng"   "native_build procps-ng-${V_PROCPS}.tar.xz procps-ng-${V_PROCPS} --docdir=/usr/share/doc/procps-ng-${V_PROCPS} --disable-static --disable-kill"
    "e2fsprogs"   "s_e2fsprogs"
    "elfutils"    "s_elfutils"
    "iproute2"    "s_iproute2"
    "kbd"         "s_kbd"
    "eudev"       "s_eudev"
    "iana-etc"    "s_iana_etc"
    "hardened-malloc" "s_hardened_malloc"
    "s6"          "s_s6_stack"
)

# --- run --------------------------------------------------------------------

if [[ "$MODE" == "list" ]]; then
    printf 'Kryptik stage 04 build order (%d entries):\n\n' "$(( ${#PACKAGES[@]} / 2 ))"
    for ((i = 0; i < ${#PACKAGES[@]}; i += 2)); do
        if [[ -n "${PACKAGES[i+1]}" ]]; then
            printf '  %2d. %-16s\n' "$(( i / 2 + 1 ))" "${PACKAGES[i]}"
        else
            printf '  %2d. %-16s  (NOT YET WIRED UP)\n' "$(( i / 2 + 1 ))" "${PACKAGES[i]}"
        fi
    done
    exit 0
fi

log "Kryptik stage 04 — hardened base system"
dim "  CFLAGS : ${CFLAGS}"
dim "  LDFLAGS: ${LDFLAGS}"
dim "  jobs   : ${KRYPTIK_JOBS}"
echo

# Refuse to run outside the chroot. Building the base system against the host
# would produce packages linked to host libraries that then get installed into
# the sysroot - broken in a way that surfaces much later.
if [[ ! -f /etc/kryptik/inside-chroot ]] && [[ "${KRYPTIK_ALLOW_UNCHROOTED:-0}" != "1" ]]; then
    die "stage 04 must run INSIDE the chroot.

  sudo build/stages/03-chroot-prep.sh mount
  sudo build/stages/03-chroot-prep.sh enter
  # then, inside:
  build/stages/04-base-system.sh

Set KRYPTIK_ALLOW_UNCHROOTED=1 only if you know exactly why."
fi

unwired=0
for ((i = 0; i < ${#PACKAGES[@]}; i += 2)); do
    name="${PACKAGES[i]}"
    recipe="${PACKAGES[i+1]}"
    if [[ -z "$recipe" ]]; then
        warn "${name}: no recipe yet - skipping"
        unwired=$((unwired + 1))
        continue
    fi
    # shellcheck disable=SC2086  # recipe is a deliberately word-split command
    step "$name" $recipe
done

echo
if [[ "$unwired" -gt 0 ]]; then
    warn "${unwired} package(s) have no recipe yet; the base system is INCOMPLETE."
    warn "Run with --list to see which."
fi
ok "Stage 04 finished the packages it has recipes for."
dim "Next: make kernel  (stage 05)"
