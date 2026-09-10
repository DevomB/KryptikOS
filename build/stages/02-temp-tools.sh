#!/usr/bin/env bash
# Stage 02 — Temporary tools (Phase 2 of docs/roadmap.md)
#
# Cross-compiles enough userland into the sysroot to enter a chroot and build
# the rest of the system from inside it. Everything here is built with the
# stage 01 cross toolchain and installed with DESTDIR=$LFS.
#
# Resumable via per-step stamps.
#   ./02-temp-tools.sh --redo ncurses
#
# STATUS: 16 of 17 packages verified building on 2026-09-10; gcc pass 2 was
# still running at time of writing. Per-step logs land in build/work/logs.

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# Same reasoning as stage 01: no hardening flags on a cross build. They go on
# at stage 04. See docs/hardening.md.
unset CFLAGS CXXFLAGS LDFLAGS CPPFLAGS LD_LIBRARY_PATH

export LFS="${KRYPTIK_WORK}/sysroot"
LFS_TGT="$(uname -m)-kryptik-linux-gnu"
export LFS_TGT
export PATH="${LFS}/tools/bin:${PATH}"
export CONFIG_SITE="${LFS}/usr/share/config.site"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(nproc)}"
export MAKEFLAGS="-j${KRYPTIK_JOBS}"
umask 022

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"

REDO=""
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR"

step() {
    local name="$1"; shift
    if [[ "$REDO" == "$name" ]]; then
        warn "forcing rebuild of ${name}"
        rm -f "${STAMPS:?}/tt-${name}"
    fi
    if [[ -f "${STAMPS}/tt-${name}" ]]; then
        dim "  skip ${name} (already built)"
        return 0
    fi
    log "${name}"
    local logfile="${LOGS}/tt-${name}.log"
    local start=$SECONDS
    # Run the build in a SUBSHELL with errexit active, and capture its status
    # without putting it in a condition.
    #
    # This was `if "$@" > "$logfile"; then`, which is silently broken: bash
    # suppresses set -e for any command in a condition context, AND that
    # suppression propagates into functions called from there. A build function
    # whose `make` failed therefore carried on to its remaining commands and
    # returned the status of the LAST one - so a package that never compiled
    # got stamped as successfully built.
    #
    # That is exactly how glibc came to be marked built after its configure
    # died with "critical programs are missing: python".
    local rc=0
    ( set -Eeuo pipefail; "$@" ) > "$logfile" 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        touch "${STAMPS}/tt-${name}"
        ok "${name} ($(( SECONDS - start ))s)"
    else
        err "${name} failed. Last 30 lines of ${logfile}:"
        tail -30 "$logfile" >&2
        die "stage 02 aborted at ${name}"
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

# config.guess lives in a different place in each project.
guess() {
    local d
    for d in build-aux/config.guess config.guess support/config.guess \
             build-aux/config.sub/config.guess; do
        [[ -f "$d" ]] && { sh "$d"; return; }
    done
    # Fall back to the toolchain's own idea of the build system.
    gcc -dumpmachine
}

# The common case: configure --host=cross, make, install into the sysroot.
cross_build() {
    local tarball="$1" dirname="$2"; shift 2
    local src; src="$(unpack "$tarball" "$dirname")"
    cd "$src"
    ./configure --prefix=/usr --host="$LFS_TGT" --build="$(guess)" "$@"
    make
    make DESTDIR="$LFS" install
}

# --- packages needing more than the common case ----------------------------

s_ncurses() {
    local src; src="$(unpack "ncurses-${V_NCURSES}.tar.gz" "ncurses-${V_NCURSES}")"
    cd "$src"

    # `tic` runs on the BUILD machine during install, so a native one is needed
    # before the cross build starts.
    mkdir -p build
    pushd build >/dev/null
    ../configure AWK=gawk
    make -C include
    make -C progs tic
    popd >/dev/null

    ./configure --prefix=/usr --host="$LFS_TGT" --build="$(guess)" \
        --mandir=/usr/share/man --with-manpage-format=normal \
        --with-shared --without-normal --with-cxx-shared \
        --without-debug --without-ada --disable-stripping AWK=gawk
    make
    make DESTDIR="$LFS" TIC_PATH="$(pwd)/build/progs/tic" install
    ln -sfv libncursesw.so "${LFS}/usr/lib/libncurses.so"
    sed -e 's/^#if.*XOPEN.*$/#if 1/' -i "${LFS}/usr/include/curses.h"
}

s_bash() {
    cross_build "bash-${V_BASH}.tar.gz" "bash-${V_BASH}" --without-bash-malloc
    ln -sfv bash "${LFS}/bin/sh"
}

s_coreutils() {
    local src; src="$(unpack "coreutils-${V_COREUTILS}.tar.xz" "coreutils-${V_COREUTILS}")"
    cd "$src"
    ./configure --prefix=/usr --host="$LFS_TGT" --build="$(guess)" \
        --enable-install-program=hostname \
        --enable-no-install-program=kill,uptime \
        gl_cv_macro_MB_CUR_MAX_good=y
    make
    make DESTDIR="$LFS" install

    # chroot is an admin tool; FHS puts it in sbin, and its man page follows.
    mv -v "${LFS}/usr/bin/chroot" "${LFS}/usr/sbin"
    mkdir -pv "${LFS}/usr/share/man/man8"
    if [[ -f "${LFS}/usr/share/man/man1/chroot.1" ]]; then
        mv -v "${LFS}/usr/share/man/man1/chroot.1" \
              "${LFS}/usr/share/man/man8/chroot.8"
        sed -i 's/"1"/"8"/' "${LFS}/usr/share/man/man8/chroot.8"
    fi
}

s_file() {
    local src; src="$(unpack "file-${V_FILE}.tar.gz" "file-${V_FILE}")"
    cd "$src"

    # Like tic, `file` is needed on the build machine to compile the magic db.
    mkdir -p build
    pushd build >/dev/null
    ../configure --disable-bzlib --disable-libseccomp \
                 --disable-xzlib --disable-zlib
    make
    popd >/dev/null

    ./configure --prefix=/usr --host="$LFS_TGT" --build="$(guess)"
    make FILE_COMPILE="$(pwd)/build/src/file"
    make DESTDIR="$LFS" install
    rm -vf "${LFS}/usr/lib/libmagic.la"
}

s_gawk() {
    local src; src="$(unpack "gawk-${V_GAWK}.tar.xz" "gawk-${V_GAWK}")"
    cd "$src"
    sed -i 's/extras//' Makefile.in
    ./configure --prefix=/usr --host="$LFS_TGT" --build="$(guess)"
    make
    make DESTDIR="$LFS" install
}

s_xz() {
    cross_build "xz-${V_XZ}.tar.xz" "xz-${V_XZ}" \
        --disable-static --docdir="/usr/share/doc/xz-${V_XZ}"
    rm -vf "${LFS}/usr/lib/liblzma.la"
}

s_binutils_pass2() {
    local src; src="$(unpack "binutils-${V_BINUTILS}.tar.xz" "binutils-${V_BINUTILS}")"
    cd "$src"

    # libtool accumulates an install-prefix -L path into the link line during
    # relink, which poisons a cross build. LFS patches this with a bare line
    # number (sed '6009s/$add_dir//'), which silently does nothing useful the
    # moment binutils shifts a line.
    #
    # The target line appears TWICE in ltmain.sh - once in each of two
    # branches - and only the second is the one LFS patches. So: locate both by
    # content, assert there are exactly two, and patch the second.
    #
    # If the count ever changes, FAIL rather than continue. An earlier version
    # of this matched a pattern that does not exist in binutils 2.43.1 at all
    # and fell through to a printed notice, which is how a silent no-op looks
    # right up until it matters.
    local -a lines
    mapfile -t lines < <(grep -n -F 'add_dir="$add_dir -L$inst_prefix_dir$libdir"' ltmain.sh | cut -d: -f1)

    if [[ "${#lines[@]}" -ne 2 ]]; then
        echo "ltmain.sh: expected 2 occurrences of the add_dir pattern, found ${#lines[@]}"
        echo "binutils ${V_BINUTILS} has changed shape; re-derive this patch"
        echo "against the LFS book before continuing."
        grep -n -F 'inst_prefix_dir' ltmain.sh || true
        return 1
    fi

    local target="${lines[1]}"
    echo "patching ltmain.sh line ${target} (second of ${#lines[@]} occurrences)"
    sed -i "${target}s/\$add_dir//" ltmain.sh

    # Prove it took.
    if sed -n "${target}p" ltmain.sh | grep -qF 'add_dir="$add_dir'; then
        echo "ltmain.sh patch did not apply"
        return 1
    fi
    echo "ltmain.sh line ${target} now: $(sed -n "${target}p" ltmain.sh)"

    mkdir -p build
    cd build
    ../configure --prefix=/usr --build="$(cd .. && guess)" --host="$LFS_TGT" \
        --disable-nls --enable-shared --enable-gprofng=no --disable-werror \
        --enable-64-bit-bfd --enable-new-dtags --enable-default-hash-style=gnu
    make
    make DESTDIR="$LFS" install
    rm -vf "${LFS}"/usr/lib/lib{bfd,ctf,ctf-nobfd,opcodes,sframe}.{a,la}
}

s_gcc_pass2() {
    local src; src="$(unpack "gcc-${V_GCC}.tar.xz" "gcc-${V_GCC}")"
    cd "$src"

    tar -xf "${KRYPTIK_SOURCES}/mpfr-${V_MPFR}.tar.xz" && mv "mpfr-${V_MPFR}" mpfr
    tar -xf "${KRYPTIK_SOURCES}/gmp-${V_GMP}.tar.xz"   && mv "gmp-${V_GMP}"   gmp
    tar -xf "${KRYPTIK_SOURCES}/mpc-${V_MPC}.tar.gz"   && mv "mpc-${V_MPC}"   mpc

    case "$(uname -m)" in
        x86_64) sed -e "/m64=/s/lib64/lib/" -i.orig gcc/config/i386/t-linux64 ;;
    esac

    # libgcc and libstdc++ can now be built with threads, but the generated
    # gthr header still points at the pass-1 placeholder.
    sed '/thread_header =/s/@.*@/gthr-posix.h/' \
        -i libgcc/Makefile.in libstdc++-v3/include/Makefile.in

    mkdir -p build
    cd build
    ../configure \
        --build="$(cd .. && guess)" \
        --host="$LFS_TGT" \
        --target="$LFS_TGT" \
        LDFLAGS_FOR_TARGET="-L${PWD}/${LFS_TGT}/libgcc" \
        --prefix=/usr \
        --with-build-sysroot="$LFS" \
        --enable-default-pie \
        --enable-default-ssp \
        --disable-nls \
        --disable-multilib \
        --disable-libatomic \
        --disable-libgomp \
        --disable-libquadmath \
        --disable-libsanitizer \
        --disable-libssp \
        --disable-libvtv \
        --enable-languages=c,c++
    make
    make DESTDIR="$LFS" install
    ln -sfv gcc "${LFS}/usr/bin/cc"
}

# Confirms the sysroot can actually host a chroot before stage 04 tries.
s_verify() {
    local missing=0 f
    for f in usr/bin/bash usr/bin/ls usr/bin/sed usr/bin/grep usr/bin/tar \
             usr/bin/gcc usr/bin/make bin/sh usr/sbin/chroot; do
        if [[ -e "${LFS}/${f}" ]]; then
            echo "  ok   /${f}"
        else
            echo "  MISSING /${f}"
            missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]] || { echo "${missing} required file(s) missing"; return 1; }

    # A binary that still points at the host loader means the cross toolchain
    # leaked, and stage 04 would build a system that only runs on this host.
    local interp
    interp="$(readelf -l "${LFS}/usr/bin/bash" 2>/dev/null \
              | grep 'Requesting program interpreter' || true)"
    echo "bash interpreter: ${interp}"
    if [[ "$interp" != *"/lib64/ld-linux-x86-64.so.2"* ]] \
    && [[ "$interp" != *"/lib/ld-linux.so.2"* ]]; then
        echo "FAIL: sysroot binaries do not use the target loader"
        return 1
    fi
    echo "PASS: sysroot binaries use the target loader"
}

# --- run -------------------------------------------------------------------

log "Kryptik stage 02 — temporary tools"
dim "  sysroot : ${LFS}"
dim "  target  : ${LFS_TGT}"
dim "  parallel: ${MAKEFLAGS}"
echo

[[ -x "${LFS}/tools/bin/${LFS_TGT}-gcc" ]] \
    || die "stage 01 has not completed - no cross compiler at ${LFS}/tools/bin
Run: make toolchain"

step m4         cross_build "m4-${V_M4}.tar.xz"               "m4-${V_M4}"
step ncurses    s_ncurses
step bash       s_bash
step coreutils  s_coreutils
step diffutils  cross_build "diffutils-${V_DIFFUTILS}.tar.xz" "diffutils-${V_DIFFUTILS}"
step file       s_file
step findutils  cross_build "findutils-${V_FINDUTILS}.tar.xz" "findutils-${V_FINDUTILS}" \
                    --localstatedir=/var/lib/locate
step gawk       s_gawk
step grep       cross_build "grep-${V_GREP}.tar.xz"           "grep-${V_GREP}"
step gzip       cross_build "gzip-${V_GZIP}.tar.xz"           "gzip-${V_GZIP}"
step make       cross_build "make-${V_MAKE}.tar.gz"           "make-${V_MAKE}" --without-guile
step patch      cross_build "patch-${V_PATCH}.tar.xz"         "patch-${V_PATCH}"
step sed        cross_build "sed-${V_SED}.tar.xz"             "sed-${V_SED}"
step tar        cross_build "tar-${V_TAR}.tar.xz"             "tar-${V_TAR}"
step xz         s_xz
step binutils2  s_binutils_pass2
step gcc2       s_gcc_pass2
step verify     s_verify

echo
ok "Stage 02 complete. Sysroot at ${LFS} can host a chroot."
dim "Next: make system  (stage 04 — not yet implemented)"
