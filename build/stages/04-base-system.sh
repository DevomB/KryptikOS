#!/usr/bin/env bash
# Stage 04: the hardened base system, built in the chroot with the full flag
# set from build/config/hardening.env.
# usage: make system   (or, in the chroot, 04-base-system.sh [--redo <step>])
#        04-base-system.sh --list   print the build order and stop

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# --- hardening --------------------------------------------------------------
# The first stage with hardening flags: these packages ship (docs/hardening.md).
load_hardening
validate_hardening_exceptions

# Built with the native target gcc, in the chroot.
stage_contract "${BASH_SOURCE[0]}" "bs-" gcc
# shellcheck disable=SC2034  # consumed by step() in common.sh
KRYPTIK_FAIL_TAIL=40

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(kryptik_default_jobs)}"

# The chroot builds as root, with no other user to drop to, and gnulib's
# configure (coreutils, tar) refuses to run as root. FORCE_UNSAFE_CONFIGURE=1
# is upstream's own switch for that check and affects nothing else.
export FORCE_UNSAFE_CONFIGURE=1

export MAKEFLAGS="-j${KRYPTIK_JOBS}"
umask 022

MODE="build"
REDO=""
# shellcheck disable=SC2034  # REDO is consumed by step() in common.sh
case "${1:-}" in
    --list) MODE="list" ;;
    --redo) REDO="${2:?--redo needs a package name}" ;;
esac

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR"

# tree_digest PATH...: one digest over each file's content and its path under
# the tree, so a renamed file changes it as an edited one does; a directory
# stands for every file below it, and a path that is neither is left out. For
# a step argument that stands for files the step reads by path.
tree_digest() {
    local f
    # if, not &&: a last path that is not there must not fail the loop, and
    # with it the stage's PACKAGES assignment.
    for f in "$@"; do
        if [[ -d "$f" ]]; then find "$f" -type f -print0
        elif [[ -f "$f" ]]; then printf '%s\0' "$f"
        fi
    done | LC_ALL=C sort -z | xargs -0r sha256sum | sed "s|  ${KRYPTIK_ROOT}/|  |" | sha256_of_stdin
}

# --- hardening exceptions ---------------------------------------------------

# The flags to drop for a package, from hardening-exceptions.txt.
exception_flags_for() {
    local pkg="$1" f="${KRYPTIK_ROOT}/build/config/hardening-exceptions.txt"
    [[ -f "$f" ]] || return 0
    awk -v p="$pkg" '!/^[[:space:]]*#/ && $1 == p { print $2 }' "$f"
}

# Hardening minus the package's exceptions; a -final row takes its package's.
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
    done < <(exception_flags_for "${pkg%-final}")

    export CFLAGS CXXFLAGS LDFLAGS
}

# --- step machinery ---------------------------------------------------------


# The shared step() calls this after printing the tail of a failed log.
step_failure_hint() {
    # Two locals: one `local` expands all its words before assigning any.
    local name="$1"
    local logfile="${LOGS}/${STAMP_PREFIX}${name}.log"

    # The error can be thousands of lines above the tail; show likely causes.
    if [[ -f "$logfile" ]]; then
        local hits
        hits="$(grep -nE '^(make(\[[0-9]+\])?: \*\*\*|.*: \*\*\* )|\[ERROR\]|undefined (symbol|reference)|No such file or directory|Permission denied|command not found|configure: error|fatal error|cannot find -l|ModuleNotFoundError|ImportError|^[A-Za-z_.]*Error:|Could not build' \
                "$logfile" 2>/dev/null | tail -15)"
        if [[ -n "$hits" ]]; then
            err ""
            err "Lines in ${logfile} that look like the actual cause:"
            printf '%s\n' "$hits" | sed 's/^/    /' >&2
        fi
    fi

    err ""
    err "Check the actual error before assuming it is the hardening flags."
    err "The first stage 04 failure looked like one and was not - it was a"
    err "missing native glibc and no generated locales."
    err ""
    err "If it IS a hardening incompatibility, add an entry to"
    err "build/config/hardening-exceptions.txt WITH a justification, so"
    err "only that flag is dropped and only for that package."
}

unpack() {
    local tarball="$1" dirname="$2"
    local dir="${BUILDDIR}/${dirname}"
    rm -rf "$dir"
    tar -xf "${KRYPTIK_SOURCES}/${tarball}" -C "$BUILDDIR"
    [[ -d "$dir" ]] || die "expected ${dir} after unpacking ${tarball}"
    printf '%s' "$dir"
}

# Native build: no --host, as this runs on the target.
native_build() {
    local tarball="$1" dirname="$2"; shift 2
    local src; src="$(unpack "$tarball" "$dirname")"
    cd "$src"
    ./configure --prefix=/usr "$@"
    make
    make install
}

# --- packages that need more than ./configure ------------------------------

# With the build/patches set (see its README): 2.42.3 does not compile against
# a glibc older than 2.43, and gets one flag wrong there.
s_util_linux() {
    local src; src="$(unpack "util-linux-${V_UTIL_LINUX}.tar.xz" "util-linux-${V_UTIL_LINUX}")"
    cd "$src"
    apply_repo_patches "util-linux-${V_UTIL_LINUX}"
    ./configure --prefix=/usr --libdir=/usr/lib --runstatedir=/run --disable-chfn-chsh --disable-login --disable-nologin --disable-su --disable-setpriv --disable-runuser --disable-pylibmount --disable-liblastlog2 --disable-static --without-python
    make
    make install
}


# Locales, with stage 01's localedef, first and apart from the glibc rebuild:
# perl needs them (Configure probes LC_ALL), and glibc's rebuild waits for
# python, which comes after perl.
s_locales() {
    mkdir -p /usr/lib/locale
    localedef -i C -f UTF-8 C.UTF-8
    localedef -i en_US -f ISO-8859-1 en_US
    localedef -i en_US -f UTF-8 en_US.UTF-8
    localedef -i en_GB -f UTF-8 en_GB.UTF-8
    localedef -i de_DE -f UTF-8 de_DE.UTF-8
    localedef -i ja_JP -f UTF-8 ja_JP.UTF-8
    echo "locales generated:"
    # Read, then trim: no pipe into head, which can SIGPIPE under pipefail.
    local archived
    archived="$(localedef --list-archive 2>/dev/null || true)"
    printf '%s\n' "$archived" | sed -n '1,10p'

    # Minimal, sane defaults so the rest of the build is deterministic.
    cat > /etc/nsswitch.conf <<'NSS'
passwd: files
group: files
shadow: files
hosts: files dns
networks: files
protocols: files
services: files
ethers: files
rpc: files
NSS
}

# glibc, rebuilt natively with the hardening flags (stage 01's was built
# without). After python, which glibc's configure requires.
s_glibc() {
    local src; src="$(unpack "glibc-${V_GLIBC}.tar.xz" "glibc-${V_GLIBC}")"
    cd "$src"

    local fhs="${KRYPTIK_SOURCES}/glibc-${V_GLIBC}-fhs-1.patch"
    [[ -f "$fhs" ]] && patch -Np1 -i "$fhs"

    # build/patches/glibc-2.40 (see its README): upstream's release/2.40/master
    # branch plus the bug 33088 fix, without which ld.so records its own map at
    # address 0 and unwinding aborts. The two checks below catch its return.
    apply_repo_patches "glibc-${V_GLIBC}"

    mkdir -p build
    cd build
    echo "rootsbindir=/usr/sbin" > configparms

    # --enable-stack-protector=strong: glibc builds its own stack protection.
    # --enable-cet: glibc compiles its CET support only when GCC defines __CET__
    # by default (Kryptik's does not), yet -fcf-protection=full in CFLAGS makes
    # rtld call it, so the link fails on _dl_cet_*. Dropping the flag instead
    # would leave the loader, which arms IBT and shadow stacks for everything,
    # without CET. Activation still depends on the CPU and kernel.
    ../configure \
        --prefix=/usr \
        --disable-werror \
        --enable-kernel=4.19 \
        --enable-stack-protector=strong \
        --enable-cet \
        --disable-nscd \
        libc_cv_slibdir=/usr/lib
    make

    # Upstream's check for bug 33088 (the test suite is not run): rtld must not
    # reach __ehdr_start or _end through a run-time relocation.
    echo "--- run-time relocations against __ehdr_start or _end in rtld.os ---"
    local rtld_relocs
    rtld_relocs="$(readelf -rW elf/rtld.os | grep -E 'R_X86_64_64.*(__ehdr_start|_end)' || true)"
    if [[ -n "$rtld_relocs" ]]; then
        printf '%s\n' "$rtld_relocs"
        echo "FAIL: rtld.os reaches __ehdr_start or _end through a relocated"
        echo "      constant (glibc bug 33088, GCC bug 120653); the loader"
        echo "      would record its own map as starting at address 0."
        return 1
    fi
    echo "  ok: none"

    # Skip glibc's test-installation script, as LFS does: it fails in a partly
    # built system.
    sed '/test-installation/s@$(PERL)@true@' -i ../Makefile
    touch /etc/ld.so.conf
    make install

    sed '/RTLDLIST=/s@/usr@@g' -i /usr/bin/ldd

    # Show the installed libc: a failed rebuild would leave stage 01's in place.
    echo "--- installed libc ---"
    ls -la /usr/lib/libc.so.6
    # grep reads the file itself: `strings | grep -m1` can fail on SIGPIPE.
    grep -a -m1 -o "GNU C Library.*" /usr/lib/libc.so.6 || \
        echo "(no GNU C Library banner found - check the install)"

    # Without the CET property note the loader arms IBT and shadow stacks for
    # nothing.
    echo "--- CET in the dynamic loader ---"
    local ldso=/usr/lib/ld-linux-x86-64.so.2
    if [[ -e "$ldso" ]]; then
        # No `readelf | grep -q`: the same SIGPIPE trap.
        local props
        props="$(readelf -n "$ldso" 2>/dev/null || true)"
        if [[ "$props" == *IBT* || "$props" == *SHSTK* ]]; then
            printf '%s\n' "$props" | sed -n '/IBT\|SHSTK/s/^/  /p'
            echo "  ok: the loader carries the CET property"
        else
            echo "FAIL: ${ldso} has no CET property note, but glibc was built"
            echo "      with -fcf-protection=full and --enable-cet."
            return 1
        fi
    else
        echo "FAIL: no dynamic loader at ${ldso}"
        return 1
    fi

    # The runtime form of that check: LD_TRACE_LOADED_OBJECTS (what ldd runs)
    # prints each map start, and with bug 33088 the loader's is 0.
    # tools/test-libc-unwind.sh tests the consequence on the whole system.
    echo "--- the loader's own map start ---"
    local trace ldso_start
    trace="$(LD_TRACE_LOADED_OBJECTS=1 /usr/bin/bash 2>&1 || true)"
    ldso_start="$(printf '%s\n' "$trace" | sed -n 's/.*ld-linux[^ ]* (0x\([0-9a-f]*\)).*/\1/p' | head -1)"
    if [[ -z "$ldso_start" ]]; then
        printf '%s\n' "$trace" | sed 's/^/  /'
        echo "FAIL: LD_TRACE_LOADED_OBJECTS did not report the loader's map start"
        return 1
    elif [[ "$ldso_start" =~ ^0+$ ]]; then
        printf '%s\n' "$trace" | sed 's/^/  /'
        echo "FAIL: the loader records its own map as starting at address 0"
        echo "      (glibc bug 33088); _dl_find_object would attribute every"
        echo "      later dlopen()ed object to ld.so and the unwinder would abort."
        return 1
    fi
    echo "  ok: ld.so at 0x${ldso_start}"
}

s_gdbm() {
    # No --enable-libgdbm-compat: man-db uses gdbm's native interface, not ndbm.
    local src; src="$(unpack "gdbm-${V_GDBM}.tar.gz" "gdbm-${V_GDBM}")"
    cd "$src"
    ./configure --prefix=/usr --disable-static
    make
    make install
    rm -fv /usr/lib/libgdbm.la

    # The installed gdbm must store and return a key.
    echo "--- gdbm round trip ---"
    cat > /tmp/kryptik-gdbm-check.c <<'CEOF'
#include <gdbm.h>
#include <string.h>
#include <stdio.h>
int main(void)
{
    GDBM_FILE f = gdbm_open("/tmp/kryptik-gdbm-check.db", 0, GDBM_NEWDB, 0600, 0);
    if (!f) { puts("gdbm_open failed"); return 1; }
    datum k = { (char *) "kryptik", 7 }, v = { (char *) "works", 5 };
    if (gdbm_store(f, k, v, GDBM_INSERT)) { puts("gdbm_store failed"); return 2; }
    datum r = gdbm_fetch(f, k);
    if (!r.dptr || r.dsize != 5 || memcmp(r.dptr, "works", 5)) { puts("fetch mismatch"); return 3; }
    puts("gdbm stored and returned a key");
    gdbm_close(f);
    return 0;
}
CEOF
    gcc -O0 -o /tmp/kryptik-gdbm-check /tmp/kryptik-gdbm-check.c -lgdbm || {
        echo "FAIL: could not compile against the gdbm we just installed"; return 1; }
    /tmp/kryptik-gdbm-check || { echo "FAIL: gdbm cannot round-trip a key"; return 1; }
    rm -f /tmp/kryptik-gdbm-check /tmp/kryptik-gdbm-check.c /tmp/kryptik-gdbm-check.db
}

s_man_db() {
    local src; src="$(unpack "man-db-${V_MANDB}.tar.xz" "man-db-${V_MANDB}")"
    cd "$src"

    # --disable-setuid: no setuid man parsing untrusted files for a page cache.
    # No browser/vgrind/grap paths: those programs are not on the system.
    ./configure --prefix=/usr \
        --docdir="/usr/share/doc/man-db-${V_MANDB}" \
        --sysconfdir=/etc \
        --disable-setuid \
        --enable-cache-owner=bin
    make
    make install

    # mandb must link gdbm: configure falls back to another interface silently.
    echo "--- which database interface did man-db link? ---"
    if readelf -dW /usr/bin/mandb 2>/dev/null | grep -q "libgdbm"; then
        echo "  ok: mandb links libgdbm"
    else
        echo "FAIL: mandb does not link libgdbm."
        echo "      configure fell back to a different database interface, which"
        echo "      is exactly what pinning gdbm was meant to prevent."
        readelf -dW /usr/bin/mandb 2>/dev/null | grep NEEDED | sed 's/^/      /'
        return 1
    fi
    echo "--- man-db runs ---"
    man --version
    mandb --version
}

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
    # Both Makefiles assign CFLAGS, which beats the environment, and link the
    # library with neither CFLAGS nor LDFLAGS: the flags go on the command
    # line, with the -fPIC and large-file define theirs carried.
    sed -i -e 's/-shared -Wl,-soname/-shared $(LDFLAGS) -Wl,-soname/' \
        -e 's/$(CFLAGS) -o bzip2-shared/$(CFLAGS) $(LDFLAGS) -o bzip2-shared/' Makefile-libbz2_so
    [[ "$(grep -c 'LDFLAGS' Makefile-libbz2_so)" -eq 2 ]] || { echo "FAIL: Makefile-libbz2_so did not take LDFLAGS"; return 1; }
    make -f Makefile-libbz2_so CFLAGS="$CFLAGS -fPIC -D_FILE_OFFSET_BITS=64" LDFLAGS="$LDFLAGS"
    make clean
    make CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64" LDFLAGS="$LDFLAGS"
    make PREFIX=/usr CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64" LDFLAGS="$LDFLAGS" install
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
    # No enable-ktls: crypto in the kernel widens the surface a kernel bug
    # exposes to every zone at once (ADR-002).
    ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib \
        shared zlib-dynamic
    make
    make MANSUFFIX=ssl install
}

s_perl() {
    local src; src="$(unpack "perl-${V_PERL}.tar.xz" "perl-${V_PERL}")"
    cd "$src"
    # Configure reads neither CFLAGS nor LDFLAGS, so the hardening goes in as
    # its own settings. lddlflags names -shared because a value given for it
    # replaces Configure's default instead of adding to it.
    sh Configure -des \
        -Dprefix=/usr \
        -Dvendorprefix=/usr \
        -Duseshrplib \
        -Dusethreads \
        -Doptimize="$KRYPTIK_OPT" \
        -Accflags="${CFLAGS#"$KRYPTIK_OPT"}" \
        -Dldflags="$LDFLAGS" \
        -Dlddlflags="-shared $LDFLAGS"
    make
    make install
}

s_python() {
    local src; src="$(unpack "Python-${V_PYTHON}.tar.xz" "Python-${V_PYTHON}")"
    cd "$src"
    # This python only serves glibc's configure. No --enable-optimizations: its
    # PGO pass fails to link (libgcov) and triples the build time. No
    # --with-system-expat: expat is not built yet.
    ./configure --prefix=/usr --enable-shared
    make
    make install
}

# The full python, rebuilt over the early one after libffi, openssl and expat.
# The step fails unless ctypes, ssl and pyexpat import.
s_python_final() {
    local src; src="$(unpack "Python-${V_PYTHON}.tar.xz" "Python-${V_PYTHON}")"
    cd "$src"
    ./configure --prefix=/usr --enable-shared --with-system-expat
    make
    make install
    local m
    for m in ctypes ssl pyexpat; do
        python3 -c "import ${m}" || { echo "FAIL: python3 was built without ${m}"; return 1; }
    done
    echo "python3 imports ctypes, ssl and pyexpat"
}

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
}

s_hardened_malloc() {
    # ADR-005. Built here so it exists before anything links against it.
    local src; src="$(unpack "${V_HARDENED_MALLOC}.tar.gz" "hardened_malloc-${V_HARDENED_MALLOC}")"
    cd "$src"

    # CONFIG_NATIVE=false overrides upstream's -march=native: in the system
    # allocator, an instruction an older CPU lacks kills every process.
    make VARIANT=default CONFIG_NATIVE=false

    # Check the command line beat config/default.mk.
    if grep -qE '^\s*CONFIG_NATIVE\s*:?=\s*true' config/default.mk; then
        echo "note: config/default.mk still says CONFIG_NATIVE := true;"
        echo "      the command line above overrides it."
    fi
    local hm_comment
    hm_comment="$(readelf -p .comment out/libhardened_malloc.so 2>/dev/null || true)"
    if [[ "$hm_comment" == *march=native* ]]; then
        echo "FAIL: libhardened_malloc.so was built with -march=native"
        return 1
    fi

    install -Dm755 out/libhardened_malloc.so /usr/lib/libhardened_malloc.so

    # Not preloaded here, or every later package would build on it: stage 06
    # writes /etc/ld.so.preload into the image's root only.
    echo "installed to /usr/lib/libhardened_malloc.so (not yet preloaded)"
}

s_libcap() {
    local src; src="$(unpack "libcap-${V_LIBCAP}.tar.xz" "libcap-${V_LIBCAP}")"
    cd "$src"
    # Do not install the static libraries.
    sed -i '/install -m.*STA/d' libcap/Makefile
    make prefix=/usr lib=lib
    make prefix=/usr lib=lib install
}

s_e2fsprogs() {
    local src; src="$(unpack "e2fsprogs-${V_E2FSPROGS}.tar.gz" "e2fsprogs-${V_E2FSPROGS}")"
    cd "$src"
    mkdir -p build && cd build
    # libblkid, libuuid, uuidd and fsck come from util-linux.
    ../configure --prefix=/usr --sysconfdir=/etc --enable-elf-shlibs \
        --disable-libblkid --disable-libuuid --disable-uuidd --disable-fsck
    make
    make install
    rm -fv /usr/lib/{libcom_err,libe2p,libext2fs,libss}.a
}

s_elfutils() {
    local src; src="$(unpack "elfutils-${V_ELFUTILS}.tar.bz2" "elfutils-${V_ELFUTILS}")"
    cd "$src"
    ./configure --prefix=/usr --disable-debuginfod --enable-libdebuginfod=dummy
    make
    # Only libelf; the rest of elfutils is developer tooling.
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

    # --disable-tests: generating the test suite needs autom4te, and there is no
    # autoconf here.
    ./configure --prefix=/usr --disable-vlock --disable-tests
    make
    make install
}

s_eudev() {
    local src; src="$(unpack "eudev-${V_EUDEV}.tar.gz" "eudev-${V_EUDEV}")"
    cd "$src"
    ./configure --prefix=/usr --bindir=/usr/sbin --sysconfdir=/etc \
        --enable-manpages --disable-static
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

# bc 1.07.1 builds libmath.h with an `ed` script (bc/fix-libmath_h) and no ed is
# pinned; as LFS does, the equivalent sed replaces it rather than pin an editor.
s_bc() {
    local src; src="$(unpack "bc-${V_BC}.tar.gz" "bc-${V_BC}")"
    cd "$src"

    # Only where the ed script is present: 1.08.2, the pinned version, ships
    # bc/fix-libmath.sed and needs no shim.
    if [[ -f bc/fix-libmath_h ]] && head -1 bc/fix-libmath_h | grep -qv '^#'; then
    cat > bc/fix-libmath_h <<'FIXEOF'
#! /bin/bash
# Replaces upstream's ed script. Wraps libmath.h into a C string array.
sed -e '1 s/^/{"/' \
    -e 's/$/",/' \
    -e '2,$ s/^/"/' \
    -e '$ d' \
    -i libmath.h
sed -e '$ s/$/0}/' -i libmath.h
FIXEOF
    chmod 0755 bc/fix-libmath_h
    fi

    ./configure --prefix=/usr --with-readline --mandir=/usr/share/man \
        --infodir=/usr/share/info
    make
    make install

    # The shape of linux/Kbuild's timeconst.h computation, which bc must answer.
    echo "--- bc answers ---"
    local got
    got="$(echo 'scale=0; 1000000000 / 250' | bc -q)"
    echo "  1000000000/250 = ${got}"
    [[ "$got" == "4000000" ]] || { echo "FAIL: bc computed ${got}, expected 4000000"; return 1; }

    # libmath is what fix-libmath_h exists for; -l loads it.
    got="$(echo 's(0)' | bc -q -l)"
    echo "  s(0) = ${got}"
    [[ "$got" == "0" || "$got" == ".00000000000000000000" ]] \
        || { echo "FAIL: bc -l (libmath) is broken: ${got}"; return 1; }
    echo "  ok: bc evaluates, and libmath loaded"
}

s_binutils_native() {
    local src; src="$(unpack "binutils-${V_BINUTILS}.tar.xz" "binutils-${V_BINUTILS}")"
    cd "$src"
    mkdir -p build && cd build
    # --with-stage1-ldflags= : the shared top-level configure would link the
    # programs with -static-libgcc -static-libstdc++, whose objects (stage
    # 02's) carry no CET note, and ld would drop it from ld, as and the rest.
    # No gprofng, a profiler nothing here uses.
    ../configure --prefix=/usr --sysconfdir=/etc --enable-gold \
        --enable-ld=default --enable-plugins --enable-shared --disable-werror \
        --enable-64-bit-bfd --enable-new-dtags --with-system-zlib \
        --enable-default-hash-style=gnu --with-stage1-ldflags= --enable-gprofng=no
    make tooldir=/usr
    make tooldir=/usr install
    rm -fv /usr/lib/lib{bfd,ctf,ctf-nobfd,opcodes,sframe}.a
    # Stage 02's binutils went into the target's tool directory, which gcc
    # searches before PATH; tooldir=/usr put these in /usr/bin instead.
    local t; t="$(gcc -dumpmachine)"
    rm -rf "/usr/${t:?}"
    local p
    for p in as ld; do
        [[ "$(gcc -print-prog-name="$p")" == "$p" ]] \
            || { echo "FAIL: gcc runs $(gcc -print-prog-name="$p"), not the ${p} on PATH"; return 1; }
    done
}

# shobj-conf links the libraries with an rpath to /usr/lib, where the loader
# looks anyway.
s_readline() {
    local src; src="$(unpack "readline-${V_READLINE}.tar.gz" "readline-${V_READLINE}")"
    cd "$src"
    sed -i 's/-Wl,-rpath,[^ ]*//' support/shobj-conf
    ./configure --prefix=/usr --disable-static --with-curses
    make
    make install
    if readelf -d "/usr/lib/libreadline.so.${V_READLINE}" | grep -q -E 'R(UN)?PATH'; then
        echo "FAIL: libreadline still carries an rpath"; return 1
    fi
}

# chroot goes to /usr/sbin, over the unhardened copy stage 02 put there.
s_coreutils() {
    native_build "coreutils-${V_COREUTILS}.tar.xz" "coreutils-${V_COREUTILS}" \
        --enable-no-install-program=kill,uptime
    mv -f /usr/bin/chroot /usr/sbin/chroot
    mkdir -p /usr/share/man/man8
    if [[ -f /usr/share/man/man1/chroot.1 ]]; then
        mv -f /usr/share/man/man1/chroot.1 /usr/share/man/man8/chroot.8
        sed -i 's/"1"/"8"/' /usr/share/man/man8/chroot.8
    fi
}

# gawk's install links gawk-<version> only when the name is free, so stage
# 02's copy would stay under it.
s_gawk() {
    rm -f "/usr/bin/gawk-${V_GAWK}"
    native_build "gawk-${V_GAWK}.tar.xz" "gawk-${V_GAWK}" --disable-pma
    cmp -s /usr/bin/gawk "/usr/bin/gawk-${V_GAWK}" \
        || { echo "FAIL: /usr/bin/gawk-${V_GAWK} is not the gawk just built"; return 1; }
}

# GCC again, in place of stage 02's temporary compiler, which set no flags:
# the same triplet and defaults, so stage 05 and the stamps see the same
# compiler, but now built with the hardening flags. Its binaries become PIE
# with BIND_NOW, and libgcc_s and libstdc++, which glibc's unwinder and every
# C++ program load, carry IBT and SHSTK.
s_gcc_native() {
    local src; src="$(unpack "gcc-${V_GCC}.tar.xz" "gcc-${V_GCC}")"
    cd "$src"
    case "$(uname -m)" in
        x86_64) sed -e '/m64=/s/lib64/lib/' -i.orig gcc/config/i386/t-linux64 ;;
    esac
    mkdir -p build && cd build
    # The target libraries take CFLAGS by themselves in a native build, but
    # not LDFLAGS: named, so libgcc_s and libstdc++ are linked with them too.
    # Without a bootstrap, cc1 and the drivers would link stage 02's static
    # libstdc++ and libgcc, which carry no CET note, and lose theirs; the
    # empty stage1 flags link the shared ones instead.
    local want; want="$(uname -m)-kryptik-linux-gnu"
    ../configure --build="$want" --prefix=/usr LD=ld LDFLAGS_FOR_TARGET="$LDFLAGS" \
        --with-stage1-ldflags= \
        --enable-languages=c,c++ --enable-default-pie --enable-default-ssp \
        --enable-host-pie --enable-host-bind-now --enable-cet \
        --disable-bootstrap --disable-fixincludes --disable-multilib --disable-nls \
        --disable-libatomic --disable-libgomp --disable-libquadmath \
        --disable-libsanitizer --disable-libssp --disable-libvtv \
        --with-system-zlib
    make
    # Stage 02's compiler ran fixincludes and this one does not, so its fixed
    # headers (searched before /usr/include) and its fixincl would stay.
    rm -rf "/usr/lib/gcc/${want}/${V_GCC}/include-fixed" "/usr/libexec/gcc/${want}/${V_GCC}/install-tools"
    make install

    local triple t lib
    triple="$(gcc -dumpmachine)"
    [[ "$triple" == "$want" ]] || { echo "FAIL: the new gcc targets ${triple}, not ${want}"; return 1; }
    t="$(mktemp -d)"
    printf '#include <stdio.h>\nint main(void) { puts("c ok"); return 0; }\n' > "$t/c.c"
    # A throw, so the unwinder in libgcc_s runs, which --enable-cet changes.
    printf '#include <iostream>\nint main() { try { throw 42; } catch (int e) { std::cout << "c++ ok " << e << std::endl; } }\n' > "$t/p.cc"
    # shellcheck disable=SC2086  # the flags are lists of words
    { gcc $CFLAGS $LDFLAGS -o "$t/c" "$t/c.c" && "$t/c" \
        && g++ $CXXFLAGS $LDFLAGS -o "$t/p" "$t/p.cc" && "$t/p"; } \
        || { rm -rf "$t"; echo "FAIL: the new compiler cannot build and run a C and a C++ program that throws"; return 1; }
    # Whole outputs, not pipes into grep -q, which can end readelf with SIGPIPE.
    # A program keeps the CET note only if every object it links has it: the
    # crt files, libc_nonshared and libgcc.a included.
    local out; out="$(readelf -h -n "$t/c")"; rm -rf "$t"
    [[ "$out" == *"Type:"*"DYN"* ]] || { echo "FAIL: its programs are not PIE"; return 1; }
    [[ "$out" == *"x86 feature: IBT, SHSTK"* ]] || { echo "FAIL: its programs carry no IBT and SHSTK: an object they link lacks the note"; return 1; }
    for lib in /usr/lib/libgcc_s.so.1 "$(readlink -f /usr/lib/libstdc++.so.6)"; do
        out="$(readelf -n "$lib")"
        [[ "$out" == *"x86 feature: IBT, SHSTK"* ]] || { echo "FAIL: ${lib} carries no IBT and SHSTK"; return 1; }
    done
    out="$(readelf -h -d "$(command -v gcc)")"
    [[ "$out" == *"Type:"*"DYN"* && ( "$out" == *BIND_NOW* || "$out" == *"Flags:"*" NOW"* ) ]] \
        || { echo "FAIL: gcc itself is not PIE with BIND_NOW"; return 1; }
    out="$(readelf -n "$(gcc -print-prog-name=cc1)")"
    [[ "$out" == *"x86 feature: IBT, SHSTK"* ]] || { echo "FAIL: cc1 carries no IBT and SHSTK"; return 1; }
    echo "ok: ${triple} gcc ${V_GCC}; libgcc_s, libstdc++ and cc1 carry IBT and SHSTK; gcc is PIE with BIND_NOW"
}

s_s6_stack() {
    # ADR-006. skarnet packages use their own configure conventions.
    local p
    for p in "skalibs-${V_SKALIBS}" "execline-${V_EXECLINE}" "s6-${V_S6}" \
             "s6-rc-${V_S6_RC}" "s6-linux-init-${V_S6_LINUX_INIT}"; do
        echo "--- ${p} ---"
        local src; src="$(unpack "${p}.tar.gz" "$p")"
        cd "$src"

        # --skeldir: with --prefix=/usr the skeleton would land in /usr/etc,
        # where s6-linux-init-maker does not look, leaving no stage 2 scripts.
        local extra=()
        case "$p" in
            s6-linux-init-*) extra=(--skeldir=/etc/s6-linux-init/skel) ;;
        esac

        ./configure --prefix=/usr --libdir=/usr/lib --with-dynlib=/usr/lib "${extra[@]}"
        make
        make install
    done
}

# --- system identity and boot configuration ---------------------------------

# /etc/os-release and friends. BUILD_ID, the commit that built the image, is
# added after the steps (at the end of this file): as this step's input it
# would re-fingerprint this step, and every step after it, on each commit.
s_etc() {
    cat > /etc/os-release <<'EOF'
NAME="Kryptik"
PRETTY_NAME="Kryptik (pre-alpha)"
ID=kryptik
ANSI_COLOR="0;36"
EOF

    echo "kryptik" > /etc/hostname

    # No root line: root comes from the kernel, and a wrong device name is
    # worse than none.
    cat > /etc/fstab <<'EOF'
# file system  mount point  type     options              dump  fsck
proc           /proc        proc     nosuid,noexec,nodev  0     0
sysfs          /sys         sysfs    nosuid,noexec,nodev  0     0
devpts         /dev/pts     devpts   gid=5,mode=620       0     0
tmpfs          /run         tmpfs    defaults             0     0
devtmpfs       /dev         devtmpfs mode=0755,nosuid     0     0
tmpfs          /dev/shm     tmpfs    nosuid,nodev         0     0
EOF

    cat > /etc/hosts <<'EOF'
127.0.0.1  localhost kryptik
::1        localhost ip6-localhost ip6-loopback
EOF

    # seat may talk to seatd (the compositor's user); kryptik may launch zones
    # through the trusted UI; the net zone's DHCP client drops to dhcpcd.
    local g
    for g in seat kryptik wheel; do
        getent group "$g" >/dev/null 2>&1 || groupadd -r "$g"
    done
    getent passwd dhcpcd >/dev/null 2>&1 || \
        useradd -r -g nogroup -d /var/lib/dhcpcd -s /usr/bin/false -c "dhcpcd privsep" dhcpcd 2>/dev/null || \
        useradd -r -d /var/lib/dhcpcd -s /usr/bin/false -c "dhcpcd privsep" dhcpcd
    install -d -m 0755 -o dhcpcd /var/lib/dhcpcd 2>/dev/null || install -d -m 0755 /var/lib/dhcpcd

    # root ships with no password ("*" matches nothing) until kryptik-firstboot
    # sets one, and the empty /etc/securetty keeps root off every terminal:
    # administration is su from wheel.
    [[ -f /etc/shadow ]] || pwconv
    usermod -p '*' root
    grep -q '^root:\*:' /etc/shadow && echo "root: no password" || { echo "FAIL: root has a password in the image"; return 1; }
    : > /etc/securetty
    if grep -q '^SU_WHEEL_ONLY' /etc/login.defs; then
        sed -i 's/^SU_WHEEL_ONLY.*/SU_WHEEL_ONLY yes/' /etc/login.defs
    else
        printf 'SU_WHEEL_ONLY yes\n' >> /etc/login.defs
    fi

    # Kernel interface names (eth0, wlan0), the same on every machine: eudev's
    # slot-naming rule is masked.
    install -d -m 0755 /etc/udev/rules.d
    ln -sf /dev/null /etc/udev/rules.d/80-net-name-slot.rules

    cat > /etc/kryptik/kryptik.conf <<'EOF'
# The kryptik command's defaults on an installed system.
zones_dir = /usr/lib/kryptik/zones
rootfs    = /var/lib/kryptik/zones
uid_base  = 100000
EOF

    # A tty1 login becomes the compositor session; any other tty stays a shell.
    install -d -m 0755 /etc/profile.d /etc/skel
    cat > /etc/profile.d/kryptik-session.sh <<'EOF'
# Start the zoned desktop from a tty1 login; every other login is a shell.
if [ -z "${WAYLAND_DISPLAY:-}" ] && [ "$(tty 2>/dev/null)" = /dev/tty1 ] \
   && [ -x /usr/bin/kryptik-session ] && [ "$(id -u)" -ne 0 ]; then
    exec /usr/bin/kryptik-session
fi
EOF
    cat > /etc/skel/.bash_profile <<'EOF'
[ -r /etc/profile ] && . /etc/profile
[ -r ~/.bashrc ] && . ~/.bashrc
EOF
    [[ -f /etc/profile ]] || cat > /etc/profile <<'EOF'
# Kryptik /etc/profile
export PATH=/usr/bin:/usr/sbin
umask 022
for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done
EOF
    grep -q 'profile.d' /etc/profile || printf '%s\n' 'for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done' >> /etc/profile
    printf '/bin/sh\n/bin/bash\n/usr/bin/bash\n' > /etc/shells

    echo "--- identity ---"
    cat /etc/os-release
    echo "--- groups ---"
    grep -E '^(seat|kryptik|wheel|dhcpcd):' /etc/group
}

# The net zone's startup program (docs/design/net-zone.md): dhcpcd, nftables
# NAT and dnsmasq in the zone that holds the NIC, run by the net-zone service.
s_netzone() {
    local src="${KRYPTIK_ROOT}/tools/net/netzone-init.sh"
    [[ -f "$src" ]] || { echo "no netzone-init at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    install -D -m 0755 "$src" /usr/libexec/kryptik/netzone-init.sh
    sh -n /usr/libexec/kryptik/netzone-init.sh || { echo "netzone-init does not parse under the target sh"; return 1; }
    # The SNTP query the net zone measures the clock with (docs/design/time.md).
    install -D -m 0755 "${KRYPTIK_ROOT}/tools/net/sntp-offset.py" /usr/libexec/kryptik/sntp-offset.py
    python3 -m py_compile /usr/libexec/kryptik/sntp-offset.py || { echo "sntp-offset.py does not compile under the target python"; return 1; }
    install -D -m 0755 "${KRYPTIK_ROOT}/tools/net/update-fetch.py" /usr/libexec/kryptik/update-fetch.py
    python3 -m py_compile /usr/libexec/kryptik/update-fetch.py || { echo "update-fetch.py does not compile under the target python"; return 1; }
    rm -rf /usr/libexec/kryptik/__pycache__
    for t in dhcpcd nft dnsmasq ip; do
        command -v "$t" >/dev/null 2>&1 && echo "  ok $t" || { echo "  MISSING $t"; return 1; }
    done
}

s_updater() {
    local src="${KRYPTIK_ROOT}/tools/update/kryptik-update"
    [[ -f "$src" ]] || { echo "no updater at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    install -D -m 0755 "$src" /usr/sbin/kryptik-update
    sh -n /usr/sbin/kryptik-update || { echo "the updater does not parse under the target sh"; return 1; }
    # Captured, not piped: the usage exits non-zero, which pipefail reports.
    local out
    out="$(/usr/sbin/kryptik-update 2>&1 || true)"
    case "$out" in *"apply DIR"*) echo "ok: kryptik-update runs" ;; *) echo "FAIL: kryptik-update does not run: ${out}"; return 1 ;; esac
    # The recovery path runs from the medium, which is this same image.
    local rec="${KRYPTIK_ROOT}/tools/update/kryptik-recover"
    [[ -f "$rec" ]] || { echo "no recover tool at ${rec}"; return 1; }
    echo "recover sha256: ${2:-unknown}"
    install -D -m 0755 "$rec" /usr/sbin/kryptik-recover
    sh -n /usr/sbin/kryptik-recover || { echo "the recover tool does not parse under the target sh"; return 1; }
    out="$(/usr/sbin/kryptik-recover --help 2>&1 || true)"
    case "$out" in *restore-slot*) echo "ok: kryptik-recover runs" ;; *) echo "FAIL: kryptik-recover does not run: ${out}"; return 1 ;; esac
}

# The firmware side of the A/B trial: writes Boot#### and BootNext through
# efivarfs. Its source hash is an argument, so a source change rebuilds it.
s_efiboot() {
    local src="${KRYPTIK_ROOT}/tools/efi/kryptik-efiboot.c"
    [[ -f "$src" ]] || { echo "no source at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    # shellcheck disable=SC2086  # CFLAGS/LDFLAGS are deliberately word-split
    gcc $CFLAGS $LDFLAGS -std=gnu11 -Wall -Wextra -o /usr/sbin/kryptik-efiboot "$src"
    local out
    out="$(/usr/sbin/kryptik-efiboot 2>&1 || true)"
    case "$out" in *usage*) echo "ok: kryptik-efiboot runs" ;; *) echo "FAIL: kryptik-efiboot does not run: ${out}"; return 1 ;; esac
}

# The console: a root shell on install media (agetty -n -l skips login), a
# login prompt otherwise. The device is the kernel's active console (ttyS0 on
# a -nographic VM, tty1 on hardware), not a guess.
s_console() {
    mkdir -p /usr/libexec
    cat > /usr/libexec/kryptik-console <<'EOF'
#!/bin/sh
# Start an interactive shell on the active kernel console.
#
# Called by the s6-linux-init early getty service. Takes an optional device
# name; otherwise asks the kernel which console it is using.

dev="$1"

# sysinit may be asking for the state passphrase on this console. It gets 30 s
# to start (a broken service database must still end in a console); once it
# has, the console is its own until it ends.
n=0
until [ -e /run/kryptik-sysinit ] || [ "$n" -ge 150 ]; do sleep 0.2; n=$((n + 1)); done
while [ "$(cat /run/kryptik-sysinit 2>/dev/null)" = running ]; do sleep 0.2; done

if [ -z "$dev" ]; then
    # /sys/class/tty/console/active lists the kernel-preferred console last.
    # With both video and serial consoles that is "tty0 ttyS0", so taking the
    # first field races rc.init's /sys mount and strands a headless login on tty0.
    if [ -r /sys/class/tty/console/active ]; then
        dev=$(awk '{print $NF}' < /sys/class/tty/console/active)
    fi
fi
[ -n "$dev" ] || dev=console

[ -e "/dev/$dev" ] || dev=console

if [ -x /usr/sbin/agetty ]; then
    # On an install medium (kryptik.media= is on the signed command line) the
    # serial console is the installer's root shell: -n -l skips login(1).
    # On an installed system it is an ordinary login prompt; root is locked,
    # so it admits the first-boot user, not root.
    if grep -qw 'kryptik\.media=[a-z]' /proc/cmdline 2>/dev/null; then
        exec /usr/sbin/agetty -n -l /usr/bin/bash --keep-baud \
             115200,57600,38400,9600 "$dev" vt220
    fi
    exec /usr/sbin/agetty --keep-baud 115200,57600,38400,9600 "$dev" vt220
fi

# No agetty: put a shell directly on the device. Less capable - no baud
# handling, no controlling-terminal setup beyond setsid - but a system whose
# console is unreachable cannot be debugged at all.
exec setsid -c /usr/bin/bash -l < "/dev/$dev" > "/dev/$dev" 2>&1
EOF
    chmod 0755 /usr/libexec/kryptik-console
    sh -n /usr/libexec/kryptik-console || { echo "console wrapper has a syntax error"; return 1; }
    echo "installed /usr/libexec/kryptik-console"
}

# s6-linux-init: /usr/lib/s6-linux-init/current and the /sbin entry points,
# under /usr/lib because the stage 2 scripts run as root first and must come
# from the verified root, not the /etc overlay. Upstream's skeleton scripts are
# all commented out, so ours replace them before the maker copies the skeldir.
s_init() {
    have() { command -v "$1" >/dev/null 2>&1; }
    have s6-linux-init-maker || { echo "s6-linux-init-maker not installed; s6 stack step failed?"; return 1; }
    have s6-svscan || { echo "s6-svscan not installed"; return 1; }

    local skel=/etc/s6-linux-init/skel
    mkdir -p "$skel"

    # Stage 2: runs once s6-svscan is pid 1.
    cat > "$skel/rc.init" <<'EOF'
#!/bin/sh -e
# Kryptik stage 2 init.

rl="$1"
shift

# s6-linux-init has already set up /run and, with -1, our console output.
# These are the mounts the rest of the system assumes exist. Each is guarded,
# because the kernel may have mounted some of them already (devtmpfs is
# automounted: CONFIG_DEVTMPFS_MOUNT=y).
mountpoint -q /proc     || mount -t proc     proc     /proc  -o nosuid,noexec,nodev
mountpoint -q /sys      || mount -t sysfs    sysfs    /sys   -o nosuid,noexec,nodev
mountpoint -q /dev      || mount -t devtmpfs devtmpfs /dev   -o mode=0755,nosuid
mkdir -p /dev/pts /dev/shm
mountpoint -q /dev/pts  || mount -t devpts devpts /dev/pts -o gid=5,mode=620,nosuid,noexec
mountpoint -q /dev/shm  || mount -t tmpfs  tmpfs  /dev/shm -o nosuid,nodev

[ -r /etc/hostname ] && hostname "$(cat /etc/hostname)" 2>/dev/null || true

# Kryptik's own state directories.
mkdir -p /run/kryptik /run/lock
chmod 0755 /run/kryptik

# The service manager, IF a compiled database exists.
#
# It deliberately does not exist yet: building an s6-rc source tree and
# compiling it belongs to the compositor and GUI isolation work. Saying so on the console is the point - a
# system that silently boots with no services and no explanation is
# indistinguishable from one whose service manager crashed.
if [ -d /usr/lib/kryptik/s6-rc/compiled ]; then
    s6-rc-init -c /usr/lib/kryptik/s6-rc/compiled /run/service
    s6-rc -v1 -up change "$rl"
else
    echo "kryptik: no compiled s6-rc database at /usr/lib/kryptik/s6-rc/compiled."
    echo "kryptik: booting with the early console only; no services will start."
    echo "kryptik: this is expected in a pre-alpha image - see docs/roadmap.md, compositor and GUI isolation."
fi
EOF

    # Shutdown: stop services and return; shutdownd unmounts and powers off.
    cat > "$skel/rc.shutdown" <<'EOF'
#!/bin/sh -e
# Kryptik shutdown. Bring services down and return; s6-linux-init-shutdownd
# performs the unmount and the hardware poweroff after this exits.

exec >/dev/console 2>&1

# Say so on the console at every step. Three boots could not distinguish
# "shutdownd never spawned this script" from "this script ran and hung", and
# the difference is the whole diagnosis: shutdownd waits for stage 3 to exit
# before it touches the hardware, so anything that blocks here looks exactly
# like a shutdown daemon that ignored the request.
echo "kryptik: rc.shutdown starting"

if [ -d /run/service ] && command -v s6-rc >/dev/null 2>&1; then
    echo "kryptik: bringing services down"
    # -t: a service that will not stop must not wedge the shutdown forever.
    # Without a timeout the only way out is the hardware, which is the outcome
    # this script exists to avoid.
    s6-rc -v2 -t 20000 -bDa change || echo "kryptik: s6-rc change exited $?"
    echo "kryptik: s6-rc returned"
else
    echo "kryptik: no service database to bring down"
fi
echo "kryptik: services stopped, handing back to shutdownd"
EOF

    cat > "$skel/rc.shutdown.final" <<'EOF'
#!/bin/sh -e
# Runs after every filesystem is unmounted. Kryptik needs nothing here, and
# upstream is emphatic that if you are unsure, the answer is nothing.
EOF

    cat > "$skel/runlevel" <<'EOF'
#!/bin/sh -e
test "$#" -gt 0 || { echo 'runlevel: fatal: too few arguments' 1>&2 ; exit 100 ; }
if [ -d /run/service ] && command -v s6-rc >/dev/null 2>&1; then
    exec s6-rc -v1 -up change "$1"
fi
echo "kryptik: no service database; runlevel '$1' has nothing to change" 1>&2
EOF

    chmod 0755 "$skel"/rc.init "$skel"/rc.shutdown "$skel"/rc.shutdown.final "$skel"/runlevel
    local s
    for s in rc.init rc.shutdown rc.shutdown.final runlevel; do
        sh -n "$skel/$s" || { echo "skeleton script $s has a syntax error"; return 1; }
    done

    # The maker will not write into an existing directory; build, then move.
    local tmp=/tmp/s6-linux-init-build.$$
    rm -rf "$tmp"

    #  -1  stage 2 output on /dev/console too, so a failed boot can be read
    #  -G  the early getty: our console wrapper
    #  -s  the envdir for the kernel command line's key=value pairs; under /run,
    #      since it is rewritten every boot and the root is read-only dm-verity
    #  -f  our skeleton
    # No -d /dev: the kernel mounts devtmpfs itself (CONFIG_DEVTMPFS_MOUNT=y).
    s6-linux-init-maker \
        -1 \
        -G "/usr/libexec/kryptik-console" \
        -p /usr/bin:/usr/sbin \
        -m 0022 \
        -c /usr/lib/s6-linux-init/current \
        -s /run/s6-linux-init/env \
        -f "$skel" \
        -D default \
        "$tmp"

    install -d -m 0755 /usr/lib/s6-linux-init
    rm -rf /usr/lib/s6-linux-init/current
    mv "$tmp" /usr/lib/s6-linux-init/current

    # /sbin/init and the rest; /sbin links to usr/sbin, and /sbin/init is where
    # the kernel looks.
    cp -a /usr/lib/s6-linux-init/current/bin/. /sbin/

    echo "--- /sbin entry points ---"
    ls -la /sbin/init /sbin/telinit /sbin/shutdown /sbin/halt /sbin/poweroff /sbin/reboot
}

# The installer runs inside a booted Kryptik system, onto a second disk; it is
# never run on the build host.
s_installer() {
    local src="${KRYPTIK_ROOT}/tools/install/kryptik-install.sh"
    [[ -f "$src" ]] || { echo "no installer at ${src}"; return 1; }

    install -D -m 0755 "$src" /usr/sbin/kryptik-install

    # Parsed by the target's sh, which is what runs it.
    sh -n /usr/sbin/kryptik-install || {
        echo "the installer does not parse under the target sh"
        return 1
    }
    echo "--- installer ---"
    ls -la /usr/sbin/kryptik-install
    /usr/sbin/kryptik-install --help
}

# The s6-rc database compiled from build/services, the scripts the services run
# (build/service-scripts) and the sysctl fragments, all on the verified root.
s_services() {
    local src="${KRYPTIK_ROOT}/build/services"
    [[ -d "$src" ]] || { echo "no service source tree at ${src}"; return 1; }

    # The scripts live outside the s6-rc source tree: s6-rc-compile reads every
    # directory there as a service.
    local scripts="${KRYPTIK_ROOT}/build/service-scripts"
    install -d -m 0755 /usr/libexec/kryptik
    install -m 0755 "$scripts"/*.sh /usr/libexec/kryptik/
    echo "--- boot scripts ---"
    ls -la /usr/libexec/kryptik/

    # sysinit applies these, never anything under /etc, which state can shadow.
    install -d -m 0755 /usr/lib/kryptik/sysctl.d
    if compgen -G "${KRYPTIK_ROOT}/build/config/sysctl.d/*.conf" > /dev/null; then
        install -m 0644 "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf /usr/lib/kryptik/sysctl.d/
        echo "--- sysctl.d ---"
        ls -la /usr/lib/kryptik/sysctl.d/
    else
        echo "no sysctl.d fragments to install"
    fi

    # s6-rc-compile will not overwrite: build beside and swap, as a half-written
    # database does not boot.
    local dbdir=/usr/lib/kryptik/s6-rc
    local tmpdb="$dbdir/compiled.new"
    rm -rf "$tmpdb"
    install -d -m 0755 "$dbdir"
    s6-rc-compile -v2 "$tmpdb" "$src"
    rm -rf "$dbdir/compiled.old"
    [[ -d "$dbdir/compiled" ]] && mv "$dbdir/compiled" "$dbdir/compiled.old"
    mv "$tmpdb" "$dbdir/compiled"
    rm -rf "$dbdir/compiled.old"

    # Read the database back: every service must be in it.
    echo "--- compiled database ---"
    local all
    all="$(s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled list all)"
    printf '%s\n' "$all" | sed 's/^/  /'

    local svc missing=0
    for svc in sysinit watchdog eudev eudev-trigger kryptikd-check time-floor kryptikd-serve firstboot seatd net-zone getty-tty1 boot-success boot-smoke default; do
        if ! printf '%s\n' "$all" | grep -qx "$svc"; then
            echo "MISSING from the database: ${svc}"; missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]] || { echo "${missing} service(s) did not compile in"; return 1; }

    # The dependency graph must be the declared one.
    echo "--- what 'default' pulls in, in order ---"
    s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled pipeline default 2>/dev/null || true
    s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled dependencies default | sed 's/^/  /'

    echo "--- eudev-trigger must depend on eudev ---"
    if s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled dependencies eudev-trigger | grep -qx eudev; then
        echo "  ok"
    else
        echo "  FAIL: eudev-trigger does not depend on eudev"
        return 1
    fi
    echo "service database compiled and verified"
}

# kryptikd, the zone supervisor: Rust, built outside as the sysroot has no Rust
# toolchain, and its absence is reported, not passed over. The path and the
# binary's hash are arguments, so the stamp covers them; an environment
# variable would not be.
s_kryptikd() {
    local src="$1" want_sha="${2:-absent}" zones_sha="${3:-nozones}"
    [[ "$src" == "none" ]] && src=""
    echo "requested: ${src:-<none>} (sha256 ${want_sha})"
    echo "zone definitions: ${zones_sha}"

    # Zone files and their policies live on the verified root, where every
    # privileged reader looks. /etc/kryptik/zones only links there for the
    # kryptik command: the /etc overlay could replace that link, and only that
    # unprivileged wrapper follows it.
    install -d -m 0755 /etc/kryptik /usr/lib/kryptik
    install -d -m 0755 /usr/lib/kryptik/zones /usr/lib/kryptik/zones/policy
    if [[ -d "${KRYPTIK_ROOT}/compartments/zones" ]]; then
        install -m 0644 "${KRYPTIK_ROOT}"/compartments/zones/*.toml /usr/lib/kryptik/zones/
        # The seccomp and Landlock policies the zone files name.
        install -m 0644 "${KRYPTIK_ROOT}"/compartments/zones/policy/* /usr/lib/kryptik/zones/policy/
        echo "installed zone definitions and policies:"
        ls -la /usr/lib/kryptik/zones/ /usr/lib/kryptik/zones/policy/
        local z p
        for z in /usr/lib/kryptik/zones/*.toml; do
            for p in $(sed -n 's/^[[:space:]]*\(seccomp\|landlock\)[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\2/p' "$z"); do
                [[ "$p" == /* ]] || p="/usr/lib/kryptik/zones/$p"
                [[ -f "$p" ]] || { echo "FAIL: $(basename "$z") names policy ${p}, which is not installed"; return 1; }
            done
        done
        echo "every policy a zone names is installed"
    else
        echo "no zone definitions at ${KRYPTIK_ROOT}/compartments/zones"
    fi
    if [[ -d /etc/kryptik/zones && ! -L /etc/kryptik/zones ]]; then
        rm -rf /etc/kryptik/zones
    fi
    ln -sfn /usr/lib/kryptik/zones /etc/kryptik/zones

    if [[ -z "$src" ]]; then
        echo "KRYPTIK_KRYPTIKD_BIN is not set: kryptikd was NOT installed."
        echo
        echo "This image has the zone definitions and none of the code that"
        echo "enforces them. Build a static kryptikd outside the chroot and"
        echo "point KRYPTIK_KRYPTIKD_BIN at it:"
        echo
        echo "  cd compartments/kryptikd"
        echo "  cargo build --release --target x86_64-unknown-linux-musl"
        echo "  KRYPTIK_KRYPTIKD_BIN=\$PWD/target/x86_64-unknown-linux-musl/release/kryptikd \\"
        echo "      make system"
        echo
        echo "Recorded as absent, not as installed."
        : > /etc/kryptik/kryptikd-absent
        return 0
    fi

    [[ -f "$src" ]] || { echo "KRYPTIK_KRYPTIKD_BIN=${src} does not exist"; return 1; }

    # The hash was taken outside the chroot; a mismatch means the file changed
    # under the build.
    local got_sha; got_sha="$(sha256_of "$src")"
    if [[ "$want_sha" != "absent" && "$got_sha" != "$want_sha" ]]; then
        echo "kryptikd binary changed during the build:"
        echo "  fingerprinted: ${want_sha}"
        echo "  now:           ${got_sha}"
        return 1
    fi
    echo "sha256: ${got_sha}"

    install -Dm755 "$src" /usr/bin/kryptikd
    rm -f /etc/kryptik/kryptikd-absent

    # It must run here: one linked against the host's libc installs fine and
    # fails at boot.
    echo "--- installed kryptikd ---"
    ls -la /usr/bin/kryptikd
    readelf -l /usr/bin/kryptikd 2>/dev/null | grep 'Requesting program interpreter' \
        || echo "  (static binary, no interpreter - good)"
    # --help is the one subcommand that exits 0 and touches nothing (--version
    # is not a subcommand); `check` would probe the build host's kernel.
    /usr/bin/kryptikd --help > /dev/null || {
        echo "FAIL: the installed kryptikd does not run inside the target."
        echo "A binary built against the host's libc installs fine and fails here."
        return 1
    }
    echo "kryptikd --help: ok"

    # And it must parse the zone definitions it will boot with.
    if /usr/bin/kryptikd list --zones /usr/lib/kryptik/zones; then
        echo "kryptikd parses the installed zone definitions"
    else
        echo "FAIL: kryptikd cannot read /usr/lib/kryptik/zones"
        return 1
    fi

    # The user's command (tools/kryptik), beside the daemon it wraps.
    install -m 0755 "${KRYPTIK_ROOT}/tools/kryptik" /usr/bin/kryptik
    bash -n /usr/bin/kryptik || { echo "FAIL: /usr/bin/kryptik has a syntax error"; return 1; }
    echo "installed /usr/bin/kryptik (sha256 ${4:-unknown})"
}

# The suites and guest checks, in the image, so the VM drivers run them as root
# on the installed kernel. They find their tree as $HERE/../.., hence
# /usr/lib/kryptik/compartments/tests beside a kryptikd link at their default.
s_tests() {
    echo "inputs digest: ${1:-none}"
    local base=/usr/lib/kryptik
    install -d -m 0755 "$base/compartments/tests" "$base/compartments/kryptikd/probes" \
        "$base/compartments/kryptikd/target/debug" "$base/compartments/kryptikd/src" "$base/guest-tests"
    local t
    for t in "${KRYPTIK_ROOT}"/compartments/tests/*.sh; do
        install -m 0755 "$t" "$base/compartments/tests/$(basename "$t")"
    done
    for t in "${KRYPTIK_ROOT}"/compartments/kryptikd/probes/*.sh; do
        install -m 0755 "$t" "$base/compartments/kryptikd/probes/$(basename "$t")"
    done
    # adversarial.sh checks its namespace set against isolate.rs and its proc
    # and sysfs mounts against rootfs.rs.
    for src in isolate.rs rootfs.rs; do
        install -m 0644 "${KRYPTIK_ROOT}/compartments/kryptikd/src/${src}" "$base/compartments/kryptikd/src/${src}"
    done
    ln -sfn /usr/bin/kryptikd "$base/compartments/kryptikd/target/debug/kryptikd"
    for t in "${KRYPTIK_ROOT}"/build/guest-tests/*.sh "${KRYPTIK_ROOT}"/build/guest-tests/*.py; do
        [[ -f "$t" ]] || continue
        install -m 0755 "$t" "$base/guest-tests/$(basename "$t")"
    done
    for t in "$base"/compartments/tests/*.sh "$base"/compartments/kryptikd/probes/*.sh "$base"/guest-tests/*.sh; do
        bash -n "$t" || { echo "FAIL: $t has a syntax error"; return 1; }
    done
    echo "--- installed ---"
    find "$base/compartments" "$base/guest-tests" -type f -o -type l | sort
}

# Every source's licence files, from its own tarball, under
# /usr/share/licenses/<source>/, and Kryptik's own under kryptik/. Beside the
# top-level files: the kernel's LICENSES/preferred and exceptions, which its
# COPYING points to, firmware's WHENCE, which says which licence covers which
# file, and a lowercase licence file (the microcode's). Acceptance checks that
# no shipped source is left without one (tools/check-image-licences.sh).
s_licences() {
    local more_re='^[^/]+/(license|WHENCE|LICENSES/(preferred|exceptions)/[^/]+)$'
    local name url f m dir tmp n=0 members
    while read -r name _ url; do
        [[ -n "$name" ]] || continue
        f="${KRYPTIK_SOURCES}/${url##*/}"
        [[ -f "$f" ]] || continue
        mapfile -t members < <(licence_members "$f" "$more_re")
        [[ "${#members[@]}" -gt 0 ]] || continue
        # One extraction for all of them: every tar run reads the whole
        # compressed stream, and linux-firmware has over a hundred.
        tmp="$(mktemp -d)"
        tar -xf "$f" -C "$tmp" -- "${members[@]}"
        dir="/usr/share/licenses/${name}"
        install -d -m 0755 "$dir"
        for m in "${members[@]}"; do
            # A link to a file not extracted would dangle: there is nothing to copy.
            if [[ -f "${tmp}/${m}" ]]; then
                install -m 0644 "${tmp}/${m}" "${dir}/${m##*/}"
                n=$((n + 1))
            fi
        done
        rm -rf "$tmp"
    done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
    install -Dm644 "${KRYPTIK_ROOT}/LICENSE" /usr/share/licenses/kryptik/LICENSE
    echo "${n} licence files in $(find /usr/share/licenses -mindepth 1 -maxdepth 1 -type d | wc -l) directories"
}

# Everything a boot needs, checked from the target's point of view.
s_boot_check() {
    local n=0
    chk() {  # chk <description> <path> [x]
        if [[ -e "$2" ]] && { [[ "${3:-}" != x ]] || [[ -x "$2" ]]; }; then
            printf '  ok      %s (%s)\n' "$1" "$2"
        else
            printf '  MISSING %s (%s)\n' "$1" "$2"; n=$((n + 1))
        fi
    }

    chk "init"              /sbin/init x
    chk "poweroff"          /sbin/poweroff x
    chk "reboot"            /sbin/reboot x
    chk "shutdown"          /sbin/shutdown x
    chk "s6-svscan"         /usr/bin/s6-svscan x
    chk "console wrapper"   /usr/libexec/kryptik-console x
    chk "stage 2 script"    /usr/lib/s6-linux-init/current/scripts/rc.init x
    chk "shutdown script"   /usr/lib/s6-linux-init/current/scripts/rc.shutdown x
    chk "shell"             /bin/sh x
    chk "bash"              /usr/bin/bash x
    chk "os-release"        /etc/os-release
    chk "fstab"             /etc/fstab
    chk "C library"         /usr/lib/libc.so.6
    chk "dynamic loader"    /usr/lib/ld-linux-x86-64.so.2
    # The desktop.
    chk "compositor"        /usr/bin/dwl x
    chk "terminal"          /usr/bin/havoc x
    chk "seatd"             /usr/bin/seatd x
    chk "kryptik-launch"    /usr/bin/kryptik-launch x
    chk "kryptik-session"   /usr/bin/kryptik-session x
    chk "kryptik-chrome"    /usr/bin/kryptik-chrome x
    chk "havoc font"        /usr/share/fonts/TTF/DejaVuSansMono.ttf
    chk "kryptik-wlproxy"   /usr/bin/kryptik-wlproxy x
    chk "kryptikd"          /usr/bin/kryptikd x
    # The net zone's Wi-Fi, and the regulatory database a radio needs before it
    # may transmit (compressed, like all of /lib/firmware).
    chk "wpa_supplicant"    /usr/sbin/wpa_supplicant x
    chk "wpa_cli"           /usr/sbin/wpa_cli x
    chk "iw"                /usr/sbin/iw x
    chk "CA bundle"         /etc/ssl/certs/ca-certificates.crt
    chk "regulatory.db"     /lib/firmware/regulatory.db.zst
    chk "regulatory.db.p7s" /lib/firmware/regulatory.db.p7s.zst

    # /sbin/init must be reachable by the exact path the kernel uses.
    if [[ -x /sbin/init ]]; then
        printf '  ok      /sbin/init resolves to %s\n' "$(readlink -f /sbin/init)"
    fi

    # Without the early getty the machine boots to silence.
    local svcdir=/usr/lib/s6-linux-init/current/run-image/service
    if [[ -d "$svcdir" ]]; then
        echo "  services in the boot image:"
        local s
        for s in "$svcdir"/*; do
            [[ -e "$s" ]] || continue
            printf '    %s\n' "$(basename "$s")"
        done
        if compgen -G "${svcdir}/*getty*" > /dev/null; then
            echo "  ok      an early getty service exists"
        else
            echo "  MISSING early getty service"; n=$((n + 1))
        fi
    else
        echo "  MISSING ${svcdir}"; n=$((n + 1))
    fi

    # Without the service database the machine boots to a bare console.
    if [[ -d /usr/lib/kryptik/s6-rc/compiled ]]; then
        local nsvc
        nsvc="$(s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled list all 2>/dev/null | grep -c . || echo 0)"
        printf '  ok      s6-rc database (%s services)\n' "$nsvc"
        if s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled list all 2>/dev/null | grep -qx default; then
            echo "  ok      a 'default' bundle exists for rc.init to bring up"
        else
            echo "  MISSING a 'default' bundle"; n=$((n + 1))
        fi
    else
        echo "  MISSING /usr/lib/kryptik/s6-rc/compiled - the image will boot to a bare console"
        n=$((n + 1))
    fi

    chk "sysctl fragments"  /usr/lib/kryptik/sysctl.d
    chk "zone definitions"  /usr/lib/kryptik/zones/work.toml
    chk "zone policies"     /usr/lib/kryptik/zones/policy/work.seccomp
    chk "device helper"     /usr/libexec/kryptik/devices.sh x
    chk "boot scripts"      /usr/libexec/kryptik/sysinit.sh x
    chk "test control helper" /usr/libexec/kryptik/testctl.sh
    chk "boot-success"      /usr/libexec/kryptik/boot-success.sh x
    chk "watchdog feeder"   /usr/libexec/kryptik/watchdog.sh x
    chk "first-boot setup"  /usr/libexec/kryptik/firstboot.sh x
    chk "login"             /usr/bin/login x
    chk "efiboot"           /usr/sbin/kryptik-efiboot x
    chk "updater"           /usr/sbin/kryptik-update x
    chk "recover"           /usr/sbin/kryptik-recover x
    chk "ssh-keygen"        /usr/bin/ssh-keygen x
    chk "cryptsetup"        /usr/sbin/cryptsetup x
    chk "seatd"             /usr/bin/seatd x

    if [[ -e /etc/kryptik/kryptikd-absent ]]; then
        echo "  NOTE    kryptikd is not installed in this image (see the kryptikd step)"
    fi

    [[ "$n" -eq 0 ]] || { echo "${n} boot prerequisite(s) missing"; return 1; }
    echo "the sysroot has what a boot needs"
}

# --- meson -------------------------------------------------------------------

# meson packages; the Wayland stack is meson-only. --buildtype=plain leaves the
# flags to the hardening CFLAGS (release adds -O3 and -DNDEBUG), and
# --wrap-mode=nodownload keeps a subproject from fetching unlocked sources.
meson_build() {
    local tarball="$1" dirname="$2"; shift 2
    local src; src="$(unpack "$tarball" "$dirname")"
    cd "$src"
    meson setup build --prefix=/usr --buildtype=plain --wrap-mode=nodownload "$@"
    ninja -C build
    ninja -C build install
}

# iputils' ping alone, without libcap, with no setuid bit or file capability:
# in a routed zone it sends over the ICMP datagram socket ping_group_range opens
# (netzone.rs), and the patch stops it making the id calls a zone refuses.
s_iputils() {
    local src; src="$(unpack "iputils-${V_IPUTILS}.tar.xz" "iputils-${V_IPUTILS}")"
    cd "$src"
    apply_repo_patches "iputils-${V_IPUTILS}"
    meson setup build --prefix=/usr --buildtype=plain --wrap-mode=nodownload \
        -DBUILD_PING=true -DBUILD_ARPING=false -DBUILD_CLOCKDIFF=false -DBUILD_TRACEPATH=false \
        -DUSE_CAP=false -DUSE_IDN=false -DUSE_GETTEXT=false -DNO_SETCAP_OR_SUID=true \
        -DBUILD_MANS=true -DBUILD_HTML_MANS=false -DSKIP_TESTS=true
    ninja -C build
    ninja -C build install
    # The tarball's prebuilt ping.8, installed without xsltproc, comes with an
    # HTML copy that nothing reads.
    rm -rf /usr/share/iputils
    [[ -f /usr/share/man/man8/ping.8 ]] || { echo "FAIL: ping.8 was not installed"; return 1; }
    local out; out="$(/usr/bin/ping -V)"
    printf '%s\n' "$out"
    [[ "$out" == *"libcap: no"* ]] || { echo "FAIL: ping was built with libcap"; return 1; }
    [[ "$(stat -c %a /usr/bin/ping)" == 755 ]] || { echo "FAIL: /usr/bin/ping is mode $(stat -c %a /usr/bin/ping), not 755"; return 1; }
    [[ ! -e /usr/bin/ping6 ]] || { echo "FAIL: a ping6 is installed beside ping"; return 1; }
}

# --- encrypted zone volumes -------------------------------------------------

# cmake only generates json-c's build files (cryptsetup needs json-c for LUKS2
# headers) and stays out of the image. The chroot runs Kitware's binary, pinned
# in sources.lock and never installed, instead of a long source build; where it
# cannot run, s_cmake builds from source with its bundled libraries. Unpacked
# on demand: the build tree is cleared between runs, and a resumed json-c step
# must not rely on a skipped cmake step.
prebuilt_cmake() {
    local dir="${BUILDDIR}/cmake-${V_CMAKE}-linux-x86_64"
    if [[ ! -x "${dir}/bin/cmake" ]]; then
        rm -rf "$dir"
        tar -xf "${KRYPTIK_SOURCES}/cmake-${V_CMAKE}-linux-x86_64.tar.gz" -C "$BUILDDIR"
    fi
    [[ -x "${dir}/bin/cmake" ]] || return 1
    "${dir}/bin/cmake" --version > /dev/null 2>&1 || return 1
    printf '%s' "${dir}/bin/cmake"
}

s_cmake() {
    local bin
    if bin="$(prebuilt_cmake)"; then
        echo "the prebuilt cmake runs in this chroot: ${bin}"
        "$bin" --version
        return 0
    fi
    warn "the prebuilt cmake does not run in this chroot; building cmake from source"
    local src; src="$(unpack "cmake-${V_CMAKE}.tar.gz" "cmake-${V_CMAKE}")"
    cd "$src"
    sed -i '/"lib64"/s/64//' Modules/GNUInstallDirs.cmake
    ./bootstrap --prefix=/usr --parallel="${KRYPTIK_JOBS}" --no-system-libs \
        --docdir=/share/doc/cmake -- -DCMAKE_USE_OPENSSL=OFF -DCMAKE_BUILD_TYPE=Release
    make
    make install
    cmake --version
}

s_json_c() {
    local cmake
    if ! cmake="$(prebuilt_cmake)"; then
        cmake="$(command -v cmake || true)"
        [[ -n "$cmake" ]] || die "json-c: no cmake - the prebuilt binary does not run here and none was built"
    fi
    echo "cmake: ${cmake}"
    local src; src="$(unpack "json-c-${V_JSON_C}.tar.gz" "json-c-json-c-${V_JSON_C}")"
    cd "$src"
    # CMAKE_POLICY_VERSION_MINIMUM: cmake 4 refuses projects whose minimum is
    # below 3.5, and json-c's test/app subdirectories still say 2.8/3.9.
    #
    # CMAKE_INSTALL_LIBDIR=lib: Kitware's binary, unlike the patched source
    # build, picks lib64 here, where nothing in this sysroot looks.
    "$cmake" -S . -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_STATIC_LIBS=OFF -DBUILD_TESTING=OFF -DBUILD_APPS=OFF \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    "$cmake" --build build
    "$cmake" --install build
    # cryptsetup's own check, made here where a failure names json-c (as s_lvm2
    # does for devmapper.pc).
    [[ -f /usr/lib/pkgconfig/json-c.pc ]] || { echo "no /usr/lib/pkgconfig/json-c.pc (installed under lib64?)"; return 1; }
    [[ -e /usr/lib64/libjson-c.so ]] && { echo "json-c installed into /usr/lib64, which this sysroot does not use"; return 1; }
    pkg-config --exists --print-errors json-c || return 1
    # It must round-trip a document; cryptsetup parses LUKS2 headers with it.
    cat > /tmp/jc.c <<'EOF'
#include <json.h>
#include <stdio.h>
#include <string.h>
int main(void){ struct json_object *o = json_tokener_parse("{\"a\":[1,2],\"b\":\"x\"}");
 if(!o) return 1; const char *s = json_object_to_json_string(o);
 return strcmp(s, "{ \"a\": [ 1, 2 ], \"b\": \"x\" }") == 0 ? 0 : 2; }
EOF
    # Through pkg-config, as cryptsetup's configure will find it.
    # shellcheck disable=SC2046
    gcc -o /tmp/jc /tmp/jc.c $(pkg-config --cflags --libs json-c)
    /tmp/jc || { echo "FAIL: json-c did not round-trip a document"; return 1; }
    rm -f /tmp/jc /tmp/jc.c
    echo "ok: json-c parses and prints"
}

s_libaio() {
    local src; src="$(unpack "libaio-${V_LIBAIO}.tar.gz" "libaio-${V_LIBAIO}")"
    cd "$src"
    sed -i '/install.*libaio.a/s/^/#/' src/Makefile
    make
    make prefix=/usr install
}

# Only device-mapper from LVM2: libdevmapper for cryptsetup, dmsetup for an
# operator. No lvm binary, daemons or volume udev rules.
s_lvm2() {
    local src; src="$(unpack "LVM2.${V_LVM2}.tgz" "LVM2.${V_LVM2}")"
    cd "$src"
    PATH="$PATH:/usr/sbin" ./configure --prefix=/usr --enable-pkgconfig \
        --disable-readline --disable-selinux --with-default-dm-run-dir=/run \
        --enable-udev_sync --disable-silent-rules
    make device-mapper
    # -j1: the install target's two sub-makes both rebuild dmsetup, and in
    # parallel one links while the other rewrites dmsetup.o.
    make -j1 install_device-mapper
    # The library line shows the binary runs. The driver line after it needs
    # the build machine's device-mapper, and dmsetup fails without it.
    local out; out="$(dmsetup --version 2>&1 || true)"
    grep -m1 '^Library version:' <<<"$out" || { echo "dmsetup does not run: ${out}"; return 1; }
    [[ -f /usr/lib/pkgconfig/devmapper.pc ]] || { echo "no devmapper.pc"; return 1; }
}

s_cryptsetup() {
    local src; src="$(unpack "cryptsetup-${V_CRYPTSETUP}.tar.xz" "cryptsetup-${V_CRYPTSETUP}")"
    cd "$src"
    ./configure --prefix=/usr --disable-ssh-token --disable-asciidoc \
        --disable-static --with-crypto_backend=openssl --enable-internal-argon2
    make
    make install
    echo "--- what shipped ---"
    cryptsetup --version
    veritysetup --version
    # LUKS2 is the contract (docs/design/encrypted-volumes.md). The help text is
    # captured, not piped into grep -q, which can SIGPIPE cryptsetup.
    cryptsetup benchmark --help >/dev/null 2>&1 || true
    local help; help="$(cryptsetup --help 2>&1 || true)"
    case "$help" in
        *luks2*) echo "ok: luks2 is a known type" ;;
        *) echo "FAIL: cryptsetup --help does not mention luks2"; return 1 ;;
    esac
}

# --- release manifests are verified by the installed system ---
# Only ssh-keygen, whose -Y verifies them; no sshd, ssh or host keys.
s_openssh() {
    local src; src="$(unpack "openssh-${V_OPENSSH}.tar.gz" "openssh-${V_OPENSSH}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/var/lib/sshd \
        --with-default-path=/usr/bin --with-superuser-path=/usr/sbin:/usr/bin \
        --with-pid-dir=/run --without-pam
    make ssh-keygen
    install -m 0755 ssh-keygen /usr/bin/ssh-keygen
    # Captured, not piped: the usage exits non-zero. Without -Y ssh-keygen says
    # "unknown option -- Y"; with it, it complains of missing arguments.
    local out
    out="$(ssh-keygen -Y verify 2>&1 || true)"
    case "$out" in
        *"unknown option"*|*"illegal option"*) echo "FAIL: ssh-keygen has no -Y: ${out}"; return 1 ;;
        *namespace*|*verify*|*usage*) echo "ok: ssh-keygen supports -Y (${out})" ;;
        *) echo "FAIL: unexpected ssh-keygen -Y verify output: ${out}"; return 1 ;;
    esac
}

# --- the net zone: NAT, resolver, DHCP client ------------------------------
s_dnsmasq() {
    local src; src="$(unpack "dnsmasq-${V_DNSMASQ}.tar.xz" "dnsmasq-${V_DNSMASQ}")"
    cd "$src"
    # Its Makefile assigns CFLAGS and LDFLAGS, which beat the environment, so
    # the hardening goes on the command line. No inotify: a zone gets ENOSYS
    # for it (REFUSED_SOFTLY in seccomp.rs), dnsmasq exits when it cannot have
    # it, and the net zone runs it with --no-poll, which never watches anyway.
    local mk=(PREFIX=/usr COPTS="-DNO_DBUS -DNO_ID -DNO_INOTIFY" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS")
    make "${mk[@]}"
    # `install`, not `install-common`, which installs nothing with PREFIX set.
    make "${mk[@]}" install
    [[ -x /usr/sbin/dnsmasq ]] || { echo "FAIL: /usr/sbin/dnsmasq was not installed"; return 1; }
    local v; v="$(/usr/sbin/dnsmasq --version)"
    printf '%s\n' "$v" | sed -n 1,2p
    [[ "$v" == *no-inotify* ]] || { echo "FAIL: dnsmasq was built with inotify, which a zone is refused"; return 1; }
}

s_dhcpcd() {
    local src; src="$(unpack "dhcpcd-${V_DHCPCD}.tar.xz" "dhcpcd-${V_DHCPCD}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib/dhcpcd \
        --dbdir=/var/lib/dhcpcd --runstatedir=/run --privsepuser=dhcpcd
    make
    make install
    dhcpcd --version | sed -n 1p
}

# --- the net zone's wireless uplink ------------------------------------------
# wpa_supplicant from its own .config: nl80211 through libnl, the unix control
# interface for wpa_cli (no D-Bus or readline), OpenSSL for WPA3-SAE, OWE, DPP
# and enterprise EAP, 802.11r and protected management frames. Its Makefile
# takes CFLAGS from the environment, so the hardening flags apply.
s_wpa_supplicant() {
    local src; src="$(unpack "wpa_supplicant-${V_WPA_SUPPLICANT}.tar.gz" "wpa_supplicant-${V_WPA_SUPPLICANT}")"
    cd "$src/wpa_supplicant"
    cat > .config <<'EOF'
CONFIG_DRIVER_NL80211=y
CONFIG_LIBNL32=y
CONFIG_CTRL_IFACE=y
CONFIG_BACKEND=file
CONFIG_TLS=openssl
CONFIG_IEEE80211W=y
CONFIG_IEEE80211R=y
CONFIG_SAE=y
CONFIG_OWE=y
CONFIG_DPP=y
CONFIG_EAP_TLS=y
CONFIG_EAP_PEAP=y
CONFIG_EAP_TTLS=y
CONFIG_EAP_MSCHAPV2=y
CONFIG_PKCS12=y
CONFIG_DEBUG_FILE=y
EOF
    make BINDIR=/usr/sbin LIBDIR=/usr/lib
    make BINDIR=/usr/sbin LIBDIR=/usr/lib install
    local b
    for b in wpa_supplicant wpa_cli wpa_passphrase; do
        [[ -x "/usr/sbin/$b" ]] || { echo "FAIL: /usr/sbin/$b was not installed"; return 1; }
    done
    wpa_supplicant -v 2>&1 | sed -n 1p
}

# iw: the operator's view of a radio (scan, link, reg), and the reference for
# what kryptikd does with nl80211 itself.
s_iw() {
    local src; src="$(unpack "iw-${V_IW}.tar.xz" "iw-${V_IW}")"
    cd "$src"
    make PREFIX=/usr SBINDIR=/usr/sbin
    make PREFIX=/usr SBINDIR=/usr/sbin install
    [[ -x /usr/sbin/iw ]] || { echo "FAIL: /usr/sbin/iw was not installed"; return 1; }
    iw --version
}

# Mozilla's CA bundle, where OpenSSL 3 and python's ssl look by default, on the
# verified root (zones see /etc/ssl/certs read-only). A release's authenticity
# rests on its signature, not TLS, but the downloader still verifies servers.
s_ca_bundle() {
    local pem="${KRYPTIK_SOURCES}/cacert-${V_CA_BUNDLE}.pem"
    [[ -f "$pem" ]] || { echo "FAIL: ${pem} was not fetched"; return 1; }
    local n; n="$(grep -c 'BEGIN CERTIFICATE' "$pem")"
    [[ "$n" -ge 100 ]] || { echo "FAIL: ${pem} holds ${n} certificates; expected Mozilla's set"; return 1; }
    install -D -m 0644 "$pem" "${KRYPTIK_DESTDIR}/etc/ssl/certs/ca-certificates.crt"
    ln -sfn certs/ca-certificates.crt "${KRYPTIK_DESTDIR}/etc/ssl/cert.pem"
    echo "installed ${n} certificates as /etc/ssl/certs/ca-certificates.crt"
    # The default lookup must find it, from both places the image speaks TLS.
    openssl version -d
    python3 -c 'import ssl; n = len(ssl.create_default_context().get_ca_certs()); print("python ssl default context:", n, "CAs"); raise SystemExit(0 if n >= 100 else 1)' \
        || { echo "FAIL: python's default TLS context does not find the bundle"; return 1; }
}

# --- device firmware (ADR-012) -----------------------------------------------
# copy-firmware.sh lays the pinned linux-firmware release out as the kernel
# names the files; build/config/firmware.list (format in its header) picks what
# ships, beside wireless-regdb. Files are zstd-compressed, as the kernel looks
# for name.zst (CONFIG_FW_LOADER_COMPRESS_ZSTD), and links are repointed.
s_firmware() {
    echo "list digest: ${1:-none}"
    local list="${KRYPTIK_ROOT}/build/config/firmware.list"
    [[ -f "$list" ]] || { echo "FAIL: ${list} is missing"; return 1; }
    local src; src="$(unpack "linux-firmware-${V_LINUX_FIRMWARE}.tar.xz" "linux-firmware-${V_LINUX_FIRMWARE}")"
    cd "$src"
    [[ -x ./copy-firmware.sh ]] || chmod +x ./copy-firmware.sh
    local tree="${src}/.installed"
    rm -rf "$tree"; mkdir -p "$tree"
    ./copy-firmware.sh -j"${KRYPTIK_JOBS:-$(nproc)}" "$tree" > /dev/null

    local dest="${KRYPTIK_DESTDIR}/lib/firmware"
    rm -rf "$dest"; mkdir -p "$dest"
    local line keep pattern matches n total=0 missing=0
    local selected="${src}/.selected"
    : > "$selected"
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        keep=0; pattern="$line"
        if [[ "$line" =~ ^newest[[:space:]]+([0-9]+)[[:space:]]+(.+)$ ]]; then
            keep="${BASH_REMATCH[1]}"; pattern="${BASH_REMATCH[2]}"
        fi
        matches="$(find "$tree" -path "${tree}/${pattern}" \( -type f -o -type l \) -print | sort)"
        if [[ "$keep" -gt 0 && -n "$matches" ]]; then
            # Group by the name with its trailing -NUMBER removed, keep the
            # highest NUMBERs of each group; a name without one is kept as is.
            matches="$(printf '%s\n' "$matches" | while IFS= read -r f; do
                b="${f##*/}"; stem="${b%.*}"; ext="${b##*.}"; ver="${stem##*-}"
                if [[ "$ver" =~ ^[0-9]+$ ]]; then
                    printf '%s\t%s\t%s\n' "${stem%-*}.${ext}" "$ver" "$f"
                else
                    printf '%s\t%s\t%s\n' "$b" 0 "$f"
                fi
            done | sort -t "$(printf '\t')" -k1,1 -k2,2nr | awk -F '\t' -v k="$keep" '{ if (++c[$1] <= k) print $3 }')"
        fi
        n="$(printf '%s\n' "$matches" | grep -c .)"
        if [[ "$n" -eq 0 ]]; then
            echo "  MISSING  ${pattern}: matches nothing in linux-firmware-${V_LINUX_FIRMWARE}"
            missing=$((missing + 1))
        else
            printf '%s\n' "$matches" >> "$selected"
            printf '  %5d  %s\n' "$n" "$line"
        fi
        total=$((total + n))
    done < "$list"
    if [[ "$missing" -gt 0 ]]; then
        echo "FAIL: ${missing} pattern(s) in firmware.list match nothing; the list must name what this release has"
        return 1
    fi
    # A symlink's target comes too, wherever it points inside the tree.
    local f t
    while IFS= read -r f; do
        [[ -L "$f" ]] || continue
        t="$(readlink -f "$f")"
        [[ "$t" == "${tree}/"* && -f "$t" ]] || { echo "FAIL: ${f#"${tree}/"} points outside the tree or at nothing (${t})"; return 1; }
        printf '%s\n' "$t"
    done < "$selected" >> "${selected}.targets"
    cat "${selected}.targets" >> "$selected"
    sort -u "$selected" | sed "s#^${tree}/##" > "${selected}.rel"
    echo "  $(wc -l < "${selected}.rel") files and links selected by ${total} matches"
    ( cd "$tree" && tr '\n' '\0' < "${selected}.rel" | xargs -0 cp -a --parents -t "$dest" )

    # regulatory.db and the signature cfg80211 checks with the kernel's key.
    local regdb; regdb="$(unpack "wireless-regdb-${V_WIRELESS_REGDB}.tar.xz" "wireless-regdb-${V_WIRELESS_REGDB}")"
    install -m 0644 "${regdb}/regulatory.db" "${regdb}/regulatory.db.p7s" "$dest/"

    # Compress the regular files, then repoint every symlink at the .zst.
    find "$dest" -type f ! -name '*.zst' -print0 | xargs -0 -r zstd -T0 -19 -q --rm
    while IFS= read -r -d '' f; do
        t="$(readlink "$f")"
        ln -sfn "${t}.zst" "${f}.zst"
        rm -f "$f"
    done < <(find "$dest" -type l -print0)
    if find "$dest" -type l ! -exec test -e {} \; -print | grep .; then
        echo "FAIL: dangling links under /lib/firmware (above)"; return 1
    fi
    chmod -R u=rwX,go=rX "$dest"
    echo "  /lib/firmware: $(find "$dest" -type f | wc -l) files, $(find "$dest" -type l | wc -l) links, $(du -sh "$dest" | cut -f1)"
    [[ -f "$dest/regulatory.db.zst" && -f "$dest/regulatory.db.p7s.zst" ]] || { echo "FAIL: the regulatory database did not land"; return 1; }
}

# --- the desktop -------------------------------------------------------------
# meson runs uninstalled from its own tree, avoiding the unpinned pip, wheel
# and setuptools.
s_meson() {
    local src; src="$(unpack "meson-${V_MESON}.tar.gz" "meson-${V_MESON}")"
    rm -rf /usr/lib/meson
    mkdir -p /usr/lib/meson
    cp -r "$src/mesonbuild" "$src/meson.py" /usr/lib/meson/
    cat > /usr/bin/meson <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/lib/meson/meson.py "$@"
EOF
    chmod 0755 /usr/bin/meson
    meson --version
}

s_ninja() {
    local src; src="$(unpack "ninja-${V_NINJA}.tar.gz" "ninja-${V_NINJA}")"
    cd "$src"
    python3 configure.py --bootstrap
    install -m 0755 ninja /usr/bin/ninja
    ninja --version
}

s_wayland() {
    meson_build "wayland-${V_WAYLAND}.tar.xz" "wayland-${V_WAYLAND}" \
        -Ddocumentation=false -Dtests=false -Ddtd_validation=false
    wayland-scanner --version 2>&1 | sed -n 1p
}

s_libxkbcommon() {
    meson_build "libxkbcommon-${V_LIBXKBCOMMON}.tar.gz" "libxkbcommon-xkbcommon-${V_LIBXKBCOMMON}" \
        -Denable-docs=false -Denable-x11=false -Denable-xkbregistry=false \
        -Denable-wayland=false -Denable-tools=false -Denable-bash-completion=false
}

s_libdrm() {
    meson_build "libdrm-${V_LIBDRM}.tar.xz" "libdrm-${V_LIBDRM}" \
        -Dudev=true -Dvalgrind=disabled -Dtests=false -Dcairo-tests=disabled \
        -Dman-pages=disabled -Dintel=disabled -Dradeon=disabled -Damdgpu=disabled \
        -Dnouveau=disabled -Dvmwgfx=disabled -Dfreedreno=disabled -Dvc4=disabled -Detnaviv=disabled
}

s_libinput() {
    meson_build "libinput-${V_LIBINPUT}.tar.gz" "libinput-${V_LIBINPUT}" \
        -Dlibwacom=false -Ddebug-gui=false -Dtests=false -Ddocumentation=false -Dzshcompletiondir=no
}

s_seatd() {
    meson_build "${V_SEATD}.tar.gz" "seatd-${V_SEATD}" \
        -Dlibseat-logind=disabled -Dlibseat-seatd=enabled -Dlibseat-builtin=disabled \
        -Dserver=enabled -Dexamples=disabled -Dman-pages=disabled
    seatd -v 2>&1 | head -1 || true
}

s_hwdata() {
    local src; src="$(unpack "hwdata-${V_HWDATA}.tar.gz" "hwdata-${V_HWDATA}")"
    cd "$src"
    ./configure --prefix=/usr --disable-blacklist
    make install
}

# wlroots with the pixman renderer only: GLES2, Vulkan and GBM need Mesa and
# LLVM. The DRM backend uses dumb buffers, which virtio-gpu and simpledrm have.
s_wlroots() {
    meson_build "wlroots-${V_WLROOTS}.tar.gz" "wlroots-${V_WLROOTS}" \
        -Dxwayland=disabled -Dexamples=false -Drenderers=[] -Dallocators=[] \
        -Dbackends=drm,libinput -Dsession=enabled -Dxcb-errors=disabled -Dlibliftoff=disabled
    pkg-config --modversion wlroots-0.19
}

# dwl with Kryptik's config.h: the keybindings are the trusted launcher, and
# border colours are the compositor-controlled zone identity. Its three inputs
# are digests in this step's arguments:
#   build/desktop/dwl-config.h        the configuration; includes the next
#   build/desktop/zone-colours.h      the zone -> border colour table
#   tools/desktop/dwl-zone-borders.py the change to dwl.c that draws them
# config.h uses `ZoneColor`, which only the patch adds: the three go together.
# Upstream fixes come first, from build/patches/dwl-0.8 (see its README).
s_dwl() {
    local cfg_sha="${1:-none}" colours_sha="${2:-none}" patch_sha="${3:-none}"
    local desk="${KRYPTIK_ROOT}/build/desktop"
    local cfg="${desk}/dwl-config.h" colours="${desk}/zone-colours.h"
    local patch="${KRYPTIK_ROOT}/tools/desktop/dwl-zone-borders.py"
    local f
    for f in "$cfg" "$colours" "$patch"; do
        [[ -f "$f" ]] || { echo "desktop input missing: ${f}"; return 1; }
    done
    # A digest mismatch means the inputs changed under the build.
    local got
    for f in "$cfg:$cfg_sha" "$colours:$colours_sha" "$patch:$patch_sha"; do
        got="$(sha256_of "${f%%:*}")"
        if [[ "${f##*:}" != "none" && "$got" != "${f##*:}" ]]; then
            echo "${f%%:*} changed during the build (fingerprinted ${f##*:}, now ${got})"
            return 1
        fi
    done
    echo "inputs: dwl-config.h ${cfg_sha}"
    echo "        zone-colours.h ${colours_sha}"
    echo "        dwl-zone-borders.py ${patch_sha}"

    local src; src="$(unpack "dwl-v${V_DWL}.tar.gz" "dwl-v${V_DWL}")"
    cd "$src"
    apply_repo_patches "dwl-${V_DWL}"
    # The patch makes exact-string edits and refuses any other dwl version.
    python3 "$patch" .
    grep -q 'zonecolors(Client \*c)' dwl.c || { echo "FAIL: the zone border change is not in dwl.c"; return 1; }
    cp "$colours" zone-colours.h
    cp "$cfg" config.h
    make PREFIX=/usr XWAYLAND= XLIBS=
    make PREFIX=/usr install
    # The installed binary must carry the change: the chooser's app_id prefix
    # is a literal in it.
    grep -aq 'kryptik\.' /usr/bin/dwl || { echo "FAIL: /usr/bin/dwl does not contain the zone chooser"; return 1; }
    echo "installed dwl with per-zone borders"
    dwl -v 2>&1 | head -1 || true
}

s_havoc() {
    local src; src="$(unpack "havoc-${V_HAVOC}.tar.gz" "havoc-${V_HAVOC}")"
    cd "$src"
    make PREFIX=/usr
    make PREFIX=/usr install
    install -Dm644 havoc.cfg /usr/share/kryptik/havoc.cfg
    [[ -x /usr/bin/havoc ]] || { echo "no havoc binary"; return 1; }
}

# havoc renders from the one TrueType file its config names
# (/usr/share/fonts/TTF/DejaVuSansMono.ttf); Sans and the bold faces come along.
# Licence: Bitstream Vera terms plus public-domain changes (LICENSE, installed).
s_fonts() {
    local src; src="$(unpack "dejavu-fonts-ttf-${V_DEJAVU_FONTS}.tar.bz2" "dejavu-fonts-ttf-${V_DEJAVU_FONTS}")"
    install -d -m 0755 /usr/share/fonts/TTF
    install -m 0644 "$src/ttf/DejaVuSansMono.ttf" "$src/ttf/DejaVuSansMono-Bold.ttf" \
        "$src/ttf/DejaVuSans.ttf" "$src/ttf/DejaVuSans-Bold.ttf" /usr/share/fonts/TTF/
    install -Dm644 "$src/LICENSE" /usr/share/licenses/dejavu-fonts/LICENSE
    local want; want="$(sed -n 's/^path=//p' /usr/share/kryptik/havoc.cfg | head -1)"
    [[ -s "${want:-/nonexistent}" ]] || { echo "havoc.cfg names ${want:-no font}, which is not installed"; return 1; }
    echo "havoc's font: ${want} ($(stat -c %s "$want") bytes)"
}

# --- the desktop's own pieces ------------------------------------------------
# kryptik-launch (the session's client of the launch daemon), the session and
# chrome scripts, and the per-zone Wayland proxy, built outside like kryptikd
# (KRYPTIK_WLPROXY_BIN). Every input is a digest argument of the step.
s_desktop() {
    local wl="$1" wl_sha="${2:-absent}" launch_sha="${3:-none}" session_sha="${4:-none}" chrome_sha="${5:-none}" probe_sha="${6:-none}"
    [[ "$wl" == "none" ]] && wl=""
    local d="${KRYPTIK_ROOT}/tools/desktop"
    echo "inputs: wlprobe.c ${probe_sha}"
    echo "        kryptik-launch.c ${launch_sha}"
    echo "        kryptik-session   ${session_sha}"
    echo "        kryptik-chrome    ${chrome_sha}"
    echo "        kryptik-wlproxy   ${wl:-<none>} (${wl_sha})"
    local f
    for f in kryptik-launch.c kryptik-session kryptik-chrome wlprobe.c; do
        [[ -f "$d/$f" ]] || { echo "missing ${d}/${f}"; return 1; }
    done
    install -d -m 0755 /usr/libexec/kryptik

    # The launch client, with the stage's hardening flags (step() set them).
    # shellcheck disable=SC2086
    gcc ${CFLAGS} ${LDFLAGS} -o /usr/bin/kryptik-launch "$d/kryptik-launch.c"
    chmod 0755 /usr/bin/kryptik-launch
    local out; out="$(/usr/bin/kryptik-launch 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: kryptik-launch does not run here: ${out}"; return 1; }
    echo "kryptik-launch: built and runs"

    # The Wayland probe the boundary tests run in zones and in zone 0: which
    # globals a client is offered, and what binding a hidden one gets.
    # shellcheck disable=SC2086
    gcc ${CFLAGS} ${LDFLAGS} -o /usr/libexec/kryptik/wlprobe "$d/wlprobe.c"
    chmod 0755 /usr/libexec/kryptik/wlprobe
    out="$(/usr/libexec/kryptik/wlprobe 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: wlprobe does not run here: ${out}"; return 1; }
    echo "wlprobe: built and runs"

    install -m 0755 "$d/kryptik-session" /usr/bin/kryptik-session
    install -m 0755 "$d/kryptik-chrome" /usr/bin/kryptik-chrome
    sh -n /usr/bin/kryptik-session || { echo "FAIL: kryptik-session has a syntax error"; return 1; }
    sh -n /usr/bin/kryptik-chrome || { echo "FAIL: kryptik-chrome has a syntax error"; return 1; }
    echo "kryptik-session, kryptik-chrome: installed"

    install -d -m 0755 /etc/kryptik
    if [[ -z "$wl" ]]; then
        echo "KRYPTIK_WLPROXY_BIN is not set: kryptik-wlproxy was NOT installed."
        echo "Zones cannot be given a display. Build it outside the chroot:"
        echo "  cd compositor && cargo build --release --target x86_64-unknown-linux-musl -p wlproxy --bin kryptik-wlproxy"
        echo "and pass KRYPTIK_WLPROXY_BIN=... to make system. Recorded as absent."
        : > /etc/kryptik/wlproxy-absent
        return 0
    fi
    [[ -f "$wl" ]] || { echo "KRYPTIK_WLPROXY_BIN=${wl} does not exist"; return 1; }
    local got_sha; got_sha="$(sha256_of "$wl")"
    if [[ "$wl_sha" != "absent" && "$got_sha" != "$wl_sha" ]]; then
        echo "kryptik-wlproxy changed during the build: fingerprinted ${wl_sha}, now ${got_sha}"
        return 1
    fi
    install -Dm755 "$wl" /usr/bin/kryptik-wlproxy
    rm -f /etc/kryptik/wlproxy-absent
    echo "--- installed kryptik-wlproxy (sha256 ${got_sha}) ---"
    readelf -l /usr/bin/kryptik-wlproxy 2>/dev/null | grep 'Requesting program interpreter' \
        || echo "  (static binary, no interpreter - good)"
    # It must run here; with no arguments it prints its usage and exits 2.
    out="$(/usr/bin/kryptik-wlproxy 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: the installed kryptik-wlproxy does not run here: ${out}"; return 1; }
    echo "kryptik-wlproxy: runs"
}

s_lynx() {
    local src; src="$(unpack "lynx${V_LYNX}.tar.bz2" "lynx${V_LYNX}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc/lynx --with-zlib --with-bzlib \
        --with-ssl --with-screen=ncursesw --enable-locale-charset \
        --datadir=/usr/share/doc/lynx
    make
    make install
    lynx -version | sed -n 1p
}

# With -fcf-protection=full a function must start with endbr64; gcc 14.2.0 put
# a loop's .p2align first (GCC PR target/116174, fixed in 14.3). This runs the
# bug's own test case with the image's flags; "plain" is the control.
s_compiler_check() {
    local d; d="$(mktemp -d)"
    printf '%s\n' 'char *f(char *d, const char *s) { while ((*d++ = *s++)) ; return --d; }' \
                  'int plain(int a) { return a + 1; }' > "$d/t.c"
    # shellcheck disable=SC2086  # CFLAGS is a list of words
    gcc ${CFLAGS:?hardening flags not loaded} -S -o "$d/t.s" "$d/t.c" || return 1
    local bad
    bad="$(awk '/^(f|plain):/ {fn=$1; next}
                fn && /endbr64/ {fn=""; n++; next}
                fn && !/^\.L|\.cfi_|^[ \t]*$/ {print fn, $0; fn=""}
                END {if (n != 2) print "landing pads found:", n+0}' "$d/t.s")"
    rm -rf "$d"
    [[ -z "$bad" ]] || { echo "FAIL: a function entry is not endbr64: ${bad}"; return 1; }
    echo "ok   $(gcc --version | sed -n 1p): function entries are landing pads"
}

# --- build order: by dependency, not alphabetical ----------------------------
PACKAGES=(
    "compiler-check" "s_compiler_check"
    "locales"     "s_locales"
    "gettext"     "native_build gettext-${V_GETTEXT}.tar.xz gettext-${V_GETTEXT} --disable-shared"
    "bison"       "native_build bison-${V_BISON}.tar.xz bison-${V_BISON} --docdir=/usr/share/doc/bison-${V_BISON}"
    "perl"        "s_perl"
    # After perl, which generates part of its source; before python, whose
    # _crypt module needs crypt(), gone from glibc since 2.39.
    "libxcrypt"   "native_build libxcrypt-${V_LIBXCRYPT}.tar.xz libxcrypt-${V_LIBXCRYPT} --enable-hashes=strong,glibc --enable-obsolete-api=no --disable-static --disable-failure-tokens"
    # Before python, whose install (ensurepip) unzips a bundled wheel.
    "zlib"        "s_zlib"
    "python"      "s_python"
    # No XS modules: texinfo links them without the hardening, and texi2any
    # runs as plain Perl without them.
    "texinfo"     "native_build texinfo-${V_TEXINFO}.tar.xz texinfo-${V_TEXINFO} --disable-perl-xs"
    "util-linux"  "s_util_linux"
    "glibc"       "s_glibc"
    "bzip2"       "s_bzip2"
    "xz"          "s_xz_native"
    "zstd"        "s_zstd"
    "file"        "native_build file-${V_FILE}.tar.gz file-${V_FILE}"
    "readline"    "s_readline"
    "m4"          "native_build m4-${V_M4}.tar.xz m4-${V_M4}"
    "flex"        "native_build flex-${V_FLEX}.tar.gz flex-${V_FLEX} --disable-static"
    # Before everything that asks pkg-config for its dependencies (e2fsprogs,
    # iproute2, kmod, eudev).
    "pkgconf"     "s_pkgconf"
    "binutils"    "s_binutils_native"
    "gmp"         "native_build gmp-${V_GMP}.tar.xz gmp-${V_GMP} --enable-cxx --disable-static"
    "mpfr"        "native_build mpfr-${V_MPFR}.tar.xz mpfr-${V_MPFR} --disable-static --enable-thread-safe"
    "mpc"         "native_build mpc-${V_MPC}.tar.gz mpc-${V_MPC} --disable-static"
    # After its libraries; everything below is built by it.
    "gcc"         "s_gcc_native"
    "attr"        "native_build attr-${V_ATTR}.tar.gz attr-${V_ATTR} --disable-static --sysconfdir=/etc"
    "acl"         "native_build acl-${V_ACL}.tar.xz acl-${V_ACL} --disable-static"
    "libcap"      "s_libcap"
    "shadow"      "s_shadow"
    # --enable-pc-files needs --with-pkg-config-libdir, or no .pc files are
    # installed and pkg-config finds no ncursesw.
    "ncurses"     "native_build ncurses-${V_NCURSES}.tar.gz ncurses-${V_NCURSES} --mandir=/usr/share/man --with-shared --without-debug --without-normal --with-cxx-shared --enable-pc-files --with-pkg-config-libdir=/usr/lib/pkgconfig"
    "sed"         "native_build sed-${V_SED}.tar.xz sed-${V_SED}"
    "psmisc"      "native_build psmisc-${V_PSMISC}.tar.xz psmisc-${V_PSMISC}"
    "bash"        "native_build bash-${V_BASH}.tar.gz bash-${V_BASH} --without-bash-malloc --with-installed-readline"
    "libtool"     "native_build libtool-${V_LIBTOOL}.tar.xz libtool-${V_LIBTOOL}"
    "gperf"       "native_build gperf-${V_GPERF}.tar.gz gperf-${V_GPERF} --docdir=/usr/share/doc/gperf-${V_GPERF}"
    "expat"       "native_build expat-${V_EXPAT}.tar.xz expat-${V_EXPAT} --disable-static --docdir=/usr/share/doc/expat-${V_EXPAT}"
    # --disable-servers: no telnetd, ftpd, rlogind and the rest, which nothing
    # starts; only the clients (hostname, traceroute, ifconfig); ping is iputils'.
    "inetutils"   "native_build inetutils-${V_INETUTILS}.tar.gz inetutils-${V_INETUTILS} --bindir=/usr/bin --localstatedir=/var --disable-servers --disable-logger --disable-whois --disable-rlogin --disable-rsh --disable-rcp --disable-rexec --disable-ping --disable-ping6"
    "less"        "native_build less-${V_LESS}.tar.gz less-${V_LESS} --sysconfdir=/etc"
    "openssl"     "s_openssl"
    # --with-gcc-arch=x86-64, not LFS's "native": inert while CFLAGS are set,
    # but the image must never be tuned to the build machine's CPU.
    "libffi"      "native_build libffi-${V_LIBFFI}.tar.gz libffi-${V_LIBFFI} --disable-static --with-gcc-arch=x86-64"
    "python-final" "s_python_final"
    "coreutils"   "s_coreutils"
    "diffutils"   "native_build diffutils-${V_DIFFUTILS}.tar.xz diffutils-${V_DIFFUTILS}"
    # No persistent-memory allocator: it needs a fixed-address, non-PIE gawk.
    "gawk"        "s_gawk"
    "findutils"   "native_build findutils-${V_FINDUTILS}.tar.xz findutils-${V_FINDUTILS} --localstatedir=/var/lib/locate"
    "grep"        "native_build grep-${V_GREP}.tar.xz grep-${V_GREP}"
    "gzip"        "native_build gzip-${V_GZIP}.tar.xz gzip-${V_GZIP}"
    "make"        "native_build make-${V_MAKE}.tar.gz make-${V_MAKE}"
    "patch"       "native_build patch-${V_PATCH}.tar.xz patch-${V_PATCH}"
    "tar"         "native_build tar-${V_TAR}.tar.xz tar-${V_TAR}"
    "groff"       "native_build groff-${V_GROFF}.tar.gz groff-${V_GROFF}"
    # For the kernel build, which generates timeconst.h with `bc -q`. After flex
    # and bison, which bc needs.
    "bc"          "s_bc"
    # --disable-manpages: kmod's man pages need scdoc, which is not pinned.
    "kmod"        "native_build kmod-${V_KMOD}.tar.xz kmod-${V_KMOD} --sysconfdir=/etc --with-openssl --with-xz --with-zstd --with-zlib --disable-manpages"
    "libpipeline" "native_build libpipeline-${V_LIBPIPELINE}.tar.gz libpipeline-${V_LIBPIPELINE}"
    # gdbm before man-db, whose configure otherwise picks another database
    # interface silently.
    "gdbm"        "s_gdbm"
    "man-db"      "s_man_db"
    "procps-ng"   "native_build procps-ng-${V_PROCPS}.tar.xz procps-ng-${V_PROCPS} --docdir=/usr/share/doc/procps-ng-${V_PROCPS} --disable-static --disable-kill"
    "e2fsprogs"   "s_e2fsprogs"
    "elfutils"    "s_elfutils"
    "iproute2"    "s_iproute2"
    "kbd"         "s_kbd"
    "eudev"       "s_eudev"
    "iana-etc"    "s_iana_etc"
    "hardened-malloc" "s_hardened_malloc"
    "s6"          "s_s6_stack"

    # --- encrypted volumes: cryptsetup, with libdevmapper (LVM2, which needs
    #     libaio), json-c (built with cmake) and popt.
    "cmake"       "s_cmake"
    "json-c"      "s_json_c"
    "popt"        "native_build popt-${V_POPT}.tar.gz popt-${V_POPT} --disable-static"
    "libaio"      "s_libaio"
    "lvm2"        "s_lvm2"
    "cryptsetup"  "s_cryptsetup"
    # --- updates: the installed system verifies update manifests itself.
    "openssh"     "s_openssh"
    # --- the net zone: NAT, a resolver and a DHCP client.
    "libmnl"      "native_build libmnl-${V_LIBMNL}.tar.bz2 libmnl-${V_LIBMNL} --disable-static"
    "libnftnl"    "native_build libnftnl-${V_LIBNFTNL}.tar.xz libnftnl-${V_LIBNFTNL} --disable-static"
    "nftables"    "native_build nftables-${V_NFTABLES}.tar.xz nftables-${V_NFTABLES} --without-cli --disable-man-doc --disable-python --with-json=no --disable-static"
    "dnsmasq"     "s_dnsmasq"
    "dhcpcd"      "s_dhcpcd"
    # --- the net zone's Wi-Fi (docs/design/net-zone.md).
    "libnl"       "native_build libnl-${V_LIBNL}.tar.gz libnl-${V_LIBNL} --sysconfdir=/etc --disable-static"
    "wpa-supplicant" "s_wpa_supplicant"
    "iw"          "s_iw"
    # --- what the net zone verifies a release server by.
    "ca-bundle"   "s_ca_bundle"
    # --- device firmware (ADR-012): what build/config/firmware.list names.
    "linux-firmware" "s_firmware $(sha256_of "${KRYPTIK_ROOT}/build/config/firmware.list" 2>/dev/null || echo none)"
    # --- the desktop: build tools, the Wayland stack, compositor, applications.
    "meson"       "s_meson"
    "ninja"       "s_ninja"
    # ping, which builds with meson; inetutils ships none.
    "iputils"     "s_iputils"
    "wayland"     "s_wayland"
    "wayland-protocols" "meson_build wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz wayland-protocols-${V_WAYLAND_PROTOCOLS} -Dtests=false"
    "xkeyboard-config"  "meson_build xkeyboard-config-${V_XKEYBOARD_CONFIG}.tar.xz xkeyboard-config-${V_XKEYBOARD_CONFIG}"
    "libxkbcommon" "s_libxkbcommon"
    "pixman"      "meson_build pixman-${V_PIXMAN}.tar.gz pixman-${V_PIXMAN} -Dtests=disabled -Ddemos=disabled -Dgtk=disabled -Dopenmp=disabled"
    "libdrm"      "s_libdrm"
    "libevdev"    "meson_build libevdev-${V_LIBEVDEV}.tar.xz libevdev-${V_LIBEVDEV} -Dtests=disabled -Ddocumentation=disabled"
    "mtdev"       "native_build mtdev-${V_MTDEV}.tar.bz2 mtdev-${V_MTDEV} --disable-static"
    "libinput"    "s_libinput"
    "seatd"       "s_seatd"
    "hwdata"      "s_hwdata"
    "libdisplay-info" "meson_build libdisplay-info-${V_LIBDISPLAY_INFO}.tar.xz libdisplay-info-${V_LIBDISPLAY_INFO}"
    "wlroots"     "s_wlroots"
    # dwl's three inputs are digests, so editing any of them rebuilds it.
    "dwl"         "s_dwl $(sha256_of "${KRYPTIK_ROOT}/build/desktop/dwl-config.h" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/build/desktop/zone-colours.h" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/dwl-zone-borders.py" 2>/dev/null || echo none)"
    "havoc"       "s_havoc"
    "fonts"       "s_fonts"
    "lynx"        "s_lynx"
    "nano"        "native_build nano-${V_NANO}.tar.xz nano-${V_NANO} --sysconfdir=/etc --enable-utf8"
    # The desktop's own pieces; the proxy's path and hash are arguments, as for
    # kryptikd.
    "desktop"     "s_desktop ${KRYPTIK_WLPROXY_BIN:-none} $([[ -f "${KRYPTIK_WLPROXY_BIN:-}" ]] && sha256_of "${KRYPTIK_WLPROXY_BIN}" || echo absent) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-launch.c" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-session" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-chrome" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/wlprobe.c" 2>/dev/null || echo none)"

    # From here the steps configure the system rather than build packages.
    "etc"         "s_etc"
    "console"     "s_console"
    "init"        "s_init"
    # After init, whose stage 2 scripts look for the database; before the
    # updater and efiboot, whose checks source the devices.sh it installs. The
    # digest covers the files the recipe reads by path, which declare -f cannot.
    "services" "s_services $(tree_digest "${KRYPTIK_ROOT}"/build/services/*/* "${KRYPTIK_ROOT}"/build/service-scripts/*.sh "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf)"
    # Before the updater, whose check runs kryptik-update, which needs efiboot.
    "efiboot"     "s_efiboot $(sha256_of "${KRYPTIK_ROOT}/tools/efi/kryptik-efiboot.c" 2>/dev/null || echo none)"
    "updater"     "s_updater $(sha256_of "${KRYPTIK_ROOT}/tools/update/kryptik-update" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/update/kryptik-recover" 2>/dev/null || echo none)"
    "netzone"     "s_netzone $(sha256_of "${KRYPTIK_ROOT}/tools/net/netzone-init.sh" 2>/dev/null || echo none)-$(sha256_of "${KRYPTIK_ROOT}/tools/net/sntp-offset.py" 2>/dev/null || echo none)-$(sha256_of "${KRYPTIK_ROOT}/tools/net/update-fetch.py" 2>/dev/null || echo none)"
    "installer"   "s_installer $(sha256_of "${KRYPTIK_ROOT}/tools/install/kryptik-install.sh" 2>/dev/null || echo none)"
    # The binary's path and hash, and a digest of the zone files: kryptikd
    # validates them at install time, so the two must move together.
    "kryptikd"    "s_kryptikd ${KRYPTIK_KRYPTIKD_BIN:-none} $([[ -f "${KRYPTIK_KRYPTIKD_BIN:-}" ]] && sha256_of "${KRYPTIK_KRYPTIKD_BIN}" || echo absent) $(tree_digest "${KRYPTIK_ROOT}"/compartments/zones/*.toml "${KRYPTIK_ROOT}"/compartments/zones/policy/*) $(sha256_of "${KRYPTIK_ROOT}/tools/kryptik" 2>/dev/null || echo none)"
    # The suites and guest checks the VM drivers run; every file is an input.
    "tests"       "s_tests $(tree_digest "${KRYPTIK_ROOT}"/compartments/tests/*.sh "${KRYPTIK_ROOT}"/compartments/kryptikd/probes/*.sh "${KRYPTIK_ROOT}"/compartments/kryptikd/src/isolate.rs "${KRYPTIK_ROOT}"/compartments/kryptikd/src/rootfs.rs "${KRYPTIK_ROOT}"/build/guest-tests/*.sh "${KRYPTIK_ROOT}"/build/guest-tests/*.py)"
    # The tarballs it reads are pinned by sources.lock and named by fetch-sources.
    "licences"    "s_licences $(sha256_of "${KRYPTIK_ROOT}/sources.lock") $(sha256_of "${KRYPTIK_ROOT}/tools/fetch-sources.sh") $(sha256_of "${KRYPTIK_ROOT}/LICENSE")"
    "boot-check"  "s_boot_check"
)

# Rows before glibc link stage 01's crt files, which carry no CET property, and
# ld marks a binary only when every input is marked. So each is built again by
# the same recipe right after glibc, unless it has its own -final row further
# down (python, which waits for its libraries).
rows=()
for ((i = 0; i < ${#PACKAGES[@]}; i += 2)); do
    rows+=("${PACKAGES[i]}" "${PACKAGES[i+1]}")
    [[ "${PACKAGES[i]}" == glibc ]] || continue
    for ((j = 0; j < i; j += 2)); do
        for ((k = i; k < ${#PACKAGES[@]}; k += 2)); do
            if [[ "${PACKAGES[k]}" == "${PACKAGES[j]}-final" ]]; then continue 2; fi
        done
        rows+=("${PACKAGES[j]}-final" "${PACKAGES[j+1]}")
    done
done
PACKAGES=("${rows[@]}")

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

# The commit that built this image, for /etc/os-release, passed in from outside
# (the chroot has no git): no commit is better than a wrong one.
KRYPTIK_BUILD_COMMIT="${KRYPTIK_BUILD_COMMIT:-unknown}"
export KRYPTIK_BUILD_COMMIT

log "Kryptik stage 04 — hardened base system"
dim "  CFLAGS : ${CFLAGS}"
dim "  LDFLAGS: ${LDFLAGS}"
dim "  jobs   : ${KRYPTIK_JOBS}"
echo

# Outside the chroot the packages would link against host libraries.
require_inside_chroot "stage 04" "system"

# Built by stage 02's toolchain: rebuilding it invalidates every stamp here.
stage_depends_on "tt-" verify

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

# Written on every run and by no step (see s_etc).
sed -i '/^BUILD_ID=/d' /etc/os-release
printf 'BUILD_ID=%s\n' "$KRYPTIK_BUILD_COMMIT" >> /etc/os-release

echo
if [[ "$unwired" -gt 0 ]]; then
    warn "${unwired} package(s) have no recipe yet; the base system is INCOMPLETE."
    warn "Run with --list to see which."
fi
ok "Stage 04 finished the packages it has recipes for."
dim "Next: make kernel  (stage 05)"
