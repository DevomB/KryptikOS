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

# Stage 04 runs inside the chroot and drives the native target compiler.
stage_contract "${BASH_SOURCE[0]}" "bs-" gcc
# shellcheck disable=SC2034  # consumed by step() in common.sh
KRYPTIK_FAIL_TAIL=40

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(kryptik_default_jobs)}"

# Every package in this stage configures and builds as root, and that is a
# property of the stage rather than a shortcut: stage 04 runs INSIDE the
# chroot, where root owns the whole filesystem and there is no unprivileged
# user to drop to. Creating one would mean inventing an account the target
# does not have.
#
# gnulib's configure probes "whether mknod can create a fifo without root
# privileges" and then refuses to continue, because as root the probe always
# succeeds and so answers nothing about the machine the binaries will run on.
# The check is aimed at someone building in their own shell, where running as
# root is a mistake. FORCE_UNSAFE_CONFIGURE=1 is upstream's own escape hatch,
# named in upstream's own error message, and it affects nothing but that probe.
#
# Set once for the stage rather than per package. coreutils and tar both
# refuse - and the first attempt to enumerate which packages refuse got tar
# wrong, because it piped `tar -xO` into `grep -q` with stderr discarded, so
# "could not read the tarball" and "the tarball is fine" produced the same
# answer. The condition here is the stage's, so the setting is the stage's.
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


# The shared step() calls this after printing the tail of a failed log.
step_failure_hint() {
    # Two locals, not one. An assignment in a `local` list is not visible to
    # the ones beside it, so ${name} would have been empty and this would
    # have opened the wrong file - silently, since the guard below just
    # skips a log it cannot find.
    local name="$1"
    local logfile="${LOGS}/${STAMP_PREFIX}${name}.log"

    # The tail is often the wrong forty lines.
    #
    # Python's install failed at line 1659 of a 6060-line log and then kept
    # going for another 4400 lines of "Compiling ...", so the tail showed
    # nothing but noise and the actual message - "undefined symbol: crypt" -
    # was four thousand lines above it. A log that hides its own error is
    # barely better than no log.
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

# Locale generation, using the localedef already installed by stage 01/02.
#
# Split out from the glibc rebuild and placed FIRST because of a dependency
# cycle that is easy to miss:
#
#   perl   needs locales  - without them Configure cannot probe LC_ALL, leaves
#                           PERL_LC_ALL_CATEGORY_POSITIONS_INIT undefined, and
#                           locale.c fails to compile with an error that looks
#                           nothing like its cause
#   glibc  needs python   - its configure calls python a critical program
#   python is built between the two
#
# So locales cannot wait for the glibc rebuild, and the glibc rebuild cannot
# come before python. Generating locales needs only localedef, which already
# exists, so it goes first on its own.
s_locales() {
    mkdir -p /usr/lib/locale
    localedef -i C -f UTF-8 C.UTF-8
    localedef -i en_US -f ISO-8859-1 en_US
    localedef -i en_US -f UTF-8 en_US.UTF-8
    localedef -i en_GB -f UTF-8 en_GB.UTF-8
    localedef -i de_DE -f UTF-8 de_DE.UTF-8
    localedef -i ja_JP -f UTF-8 ja_JP.UTF-8
    echo "locales generated:"
    # Read, then trim. `localedef | head` is small enough not to SIGPIPE
    # today, and that is a property of the data rather than of the code.
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

# glibc, rebuilt natively inside the chroot.
#
# Stage 01 built glibc with the cross toolchain and deliberately unsets
# CFLAGS/LDFLAGS there, because a pass-1 compiler cannot be built with the
# flags it implements. Nothing since has rebuilt it, so until this step runs
# the C library every binary links against is UNHARDENED - the single largest
# hole in the hardening story for a distribution built on the claim that
# hardening is a toolchain property.
#
# Positioned after python: glibc's configure treats python as a critical
# program and fails outright without it.
s_glibc() {
    local src; src="$(unpack "glibc-${V_GLIBC}.tar.xz" "glibc-${V_GLIBC}")"
    cd "$src"

    local fhs="${KRYPTIK_SOURCES}/glibc-${V_GLIBC}-fhs-1.patch"
    [[ -f "$fhs" ]] && patch -Np1 -i "$fhs"

    mkdir -p build
    cd build
    echo "rootsbindir=/usr/sbin" > configparms

    # glibc supplies its own stack protector rather than taking ours; see the
    # hardening exception for why external flags are dropped for this package.
    #
    # --enable-cet is not optional here, and the reason is a genuine
    # configure-vs-build mismatch rather than a preference.
    #
    # glibc decides whether to COMPILE its CET support from
    # libc_cv_compiler_default_cet - a test of whether the compiler defines
    # __CET__ *by default*. Kryptik's GCC is not built --enable-cet-default,
    # so that test says no and dl-cet.c is left out. The actual build then
    # runs with Kryptik's CFLAGS, which contain -fcf-protection=full, and that
    # DOES define __CET__ - so rtld.c and dl-open.c compile the CET code paths
    # and call into functions nobody compiled:
    #
    #   undefined reference to `_dl_cet_open_check'
    #   undefined reference to `_dl_cet_setup_features'
    #   undefined reference to `_dl_cet_check'
    #   hidden symbol `_dl_cet_open_check' isn't defined
    #   collect2: error: ld returned 1 exit status
    #
    # The alternative fix - dropping -fcf-protection for glibc via an
    # exception - also links, and gives a dynamic loader with no CET at all.
    # The loader is the single place CET matters most: it is what arms IBT and
    # the shadow stack for every process on the system. So the flag stays and
    # glibc is told to build the support that flag implies.
    #
    # Enabling it here does not force anything at runtime. Activation still
    # depends on the CPU and on kernel support; without those, glibc's CET
    # code detects their absence and stays out of the way.
    ../configure         --prefix=/usr         --disable-werror         --enable-kernel=4.19         --enable-stack-protector=strong         --enable-cet         --disable-nscd         libc_cv_slibdir=/usr/lib
    make

    # The install step runs a test-installation perl script that does not exist
    # yet - perl is built later, and cannot be built before glibc.
    sed '/test-installation/s@$(PERL)@true@' -i ../Makefile
    touch /etc/ld.so.conf
    make install

    sed '/RTLDLIST=/s@/usr@@g' -i /usr/bin/ldd

    # Prove the rebuild actually happened. A configure that dies early leaves
    # the stage 01 library in place, and the difference is invisible without
    # checking - which is precisely what happened the first time this ran.
    echo "--- installed libc ---"
    ls -la /usr/lib/libc.so.6
    # grep reads the file directly. Piping `strings` into `grep -m1` made
    # grep exit at the first match while strings still had 2.4MB to write,
    # so strings took SIGPIPE and pipefail reported 141 - failing the step
    # on a glibc that had just installed correctly.
    grep -a -m1 -o "GNU C Library.*" /usr/lib/libc.so.6 || \
        echo "(no GNU C Library banner found - check the install)"

    # And prove the CET support actually landed, rather than trusting that
    # --enable-cet was accepted. A loader without the property note is a
    # loader that will not arm IBT or the shadow stack for anything.
    echo "--- CET in the dynamic loader ---"
    local ldso=/usr/lib/ld-linux-x86-64.so.2
    if [[ -e "$ldso" ]]; then
        # Captured once, then matched in the shell. `readelf | grep -q` is the
        # same SIGPIPE trap as above.
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
    # Two flags deliberately NOT passed here, both of which were and both of
    # which were wrong at this point in the build.
    #
    # --enable-optimizations turns on PGO, whose instrumented first pass needs
    # libgcov on the link line and does not get it - the build died with a wall
    # of "undefined reference to __gcov_indirect_call" and similar. It is also
    # roughly a 3x build-time cost for a Python whose only job here is to
    # satisfy glibc's configure, which treats python as a critical program.
    #
    # --with-system-expat asks Python to link the system expat, which is built
    # 25 packages further down this same list. It would have silently fallen
    # back to the bundled copy, so the flag was describing something untrue -
    # the harder kind of wrong to notice, because nothing fails.
    ./configure --prefix=/usr --enable-shared
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

    # CONFIG_NATIVE=false, overriding config/default.mk.
    #
    # Upstream defaults it to true, which appends -march=native. That is the
    # right default for someone compiling an allocator for the machine in front
    # of them, and exactly wrong for a distribution: the .so would carry
    # whatever instruction set extensions THIS build host happens to have, and
    # on any older CPU the first hardened_malloc call executes an illegal
    # instruction.
    #
    # This is the system allocator (ADR-005). "Some instruction is unavailable"
    # in the allocator is not a degraded feature, it is every process on the
    # machine dying at startup, on hardware the build never saw.
    make VARIANT=default CONFIG_NATIVE=false

    # Prove the override took, rather than trusting that a make variable beat
    # an included .mk file.
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

    # --disable-tests: kbd ships tests/testsuite.at but no generated
    # tests/testsuite, so `make all` tries to produce one with autom4te and
    # dies with "command not found" - Kryptik installs no autoconf, and has no
    # reason to: the suite runs at build time and ships nothing.
    ./configure --prefix=/usr --disable-vlock --disable-tests
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

# pkgconf installs a binary called "pkgconf". Everything that looks for it
# looks for "pkg-config".
#
# There is no configure option for this - pkgconf offers --with-pkg-config-dir
# for where .pc files live, and nothing that creates the compatibility name -
# so the symlink is made by hand, which is what LFS does at this point too.
#
# Without it kmod's configure fails with "The pkg-config script could not be
# found or is too old", and e2fsprogs, elfutils, iproute2 and eudev would each
# have quietly configured without the dependencies they ask pkg-config about.
# The package was present and built; only the name everyone uses was missing.
s_pkgconf() {
    native_build "pkgconf-${V_PKGCONF}.tar.xz" "pkgconf-${V_PKGCONF}" \
        --disable-static --docdir="/usr/share/doc/pkgconf-${V_PKGCONF}"

    ln -sfv pkgconf /usr/bin/pkg-config
    ln -sfv pkgconf.1 /usr/share/man/man1/pkg-config.1

    # Prove the name resolves and answers, rather than just that a link exists.
    pkg-config --version
}

# GNU bc 1.07.1 generates libmath.h with an `ed` script, and Kryptik ships no
# ed:
#
#   ./fix-libmath_h: line 1: ed: command not found
#   make[2]: *** [Makefile:632: libmath.h] Error 127
#
# bc/fix-libmath_h wraps the text of libmath.b into a C string array. It is
# four line edits, and ed is simply the tool upstream reached for in 1991.
# Replacing it with the equivalent sed is what LFS does here, and it avoids
# pinning an entire editor to run four substitutions once.
#
# The alternative - adding `ed` to versions.env, fetch-sources.sh and an
# audited sources.lock line - buys a package that nothing else in the base
# system uses.
s_bc() {
    local src; src="$(unpack "bc-${V_BC}.tar.gz" "bc-${V_BC}")"
    cd "$src"

    # Upstream's fix-libmath_h is an `ed` script in 1.07.1, and Kryptik pins no
    # ed - so the build tab replaced it with a sed equivalent. 1.08.2, which is
    # the version provenance audited and this tree pins, ships
    # bc/fix-libmath.sed and needs no shim at all.
    #
    # Written only when the ed script is actually there, so the recipe works
    # for either version instead of being silently specific to the one it was
    # written against. An unconditional overwrite would put a bash script into
    # a tree whose build may not call it, which is the kind of inert difference
    # that is impossible to reason about later.
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

    # The kernel calls `bc -q` on a real program; prove this bc evaluates it,
    # not merely that a binary landed. This is the exact shape linux/Kbuild
    # uses to generate include/generated/timeconst.h.
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

        # s6-linux-init needs one extra argument, and it is not optional.
        #
        # Its --prefix defaults to "/" - not /usr - and --skeldir defaults to
        # PREFIX/etc/s6-linux-init/skel. Passing --prefix=/usr, which is right
        # for every other package here and right for this one's binaries, puts
        # the skeleton in /usr/etc/s6-linux-init/skel. s6-linux-init-maker then
        # looks in /etc/s6-linux-init/skel, finds nothing, and produces a boot
        # image with no stage 2 scripts.
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

# /etc/os-release and friends.
#
# This is not cosmetic. Integration has to answer "is the userspace I am
# looking at inside the VM the one this build produced, or the host's?", and
# the honest way to answer it is for the artifact to carry its own identity.
# KRYPTIK_BUILD_ID is the repository commit, so a booted system names the
# commit that built it.
s_etc() {
    local commit="${KRYPTIK_BUILD_COMMIT:-unknown}"

    cat > /etc/os-release <<EOF
NAME="Kryptik"
PRETTY_NAME="Kryptik (pre-alpha)"
ID=kryptik
BUILD_ID=${commit}
ANSI_COLOR="0;36"
EOF

    echo "kryptik" > /etc/hostname

    # Minimal and honest: the root filesystem is whatever the bootloader
    # handed us, and the kernel mounts devtmpfs itself
    # (CONFIG_DEVTMPFS_MOUNT=y). Nothing here should invent a device name -
    # a wrong root= line in fstab is worse than no fstab.
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

    echo "--- identity ---"
    cat /etc/os-release
}

# A console that works without login(1).
#
# util-linux is configured --disable-login (it is a setuid-adjacent surface
# Kryptik has no use for yet), so a plain getty would exec a /bin/login that
# does not exist and the console would be dead. agetty -n -l skips login
# entirely and execs the program named instead.
#
# The console DEVICE is discovered rather than guessed. A developer VM booted
# with -nographic uses ttyS0; the same image on hardware uses tty1; hardcoding
# either produces an image that boots to silence on the other. The kernel
# already knows which it is and publishes it.
s_console() {
    mkdir -p /usr/libexec
    cat > /usr/libexec/kryptik-console <<'EOF'
#!/bin/sh
# Start an interactive shell on the active kernel console.
#
# Called by the s6-linux-init early getty service. Takes an optional device
# name; otherwise asks the kernel which console it is using.

dev="$1"

if [ -z "$dev" ]; then
    # /sys/class/tty/console/active lists the active consoles, most recently
    # added first. "ttyS0" under QEMU -nographic, "tty1" on a normal display.
    if [ -r /sys/class/tty/console/active ]; then
        dev=$(cut -d' ' -f1 < /sys/class/tty/console/active)
    fi
fi
[ -n "$dev" ] || dev=console

[ -e "/dev/$dev" ] || dev=console

if [ -x /usr/sbin/agetty ]; then
    # -n: do not prompt for a login name.
    # -l: exec this program instead of /bin/login, which Kryptik does not ship.
    exec /usr/sbin/agetty -n -l /usr/bin/bash --keep-baud \
         115200,57600,38400,9600 "$dev" vt220
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

# s6-linux-init: generate /etc/s6-linux-init/current and the /sbin entry points.
#
# The upstream skeleton scripts are entirely commented out - they are a menu of
# "if your services are managed by X" options, not a working configuration. We
# replace them before running the maker, because the maker copies whatever is
# in the skeldir.
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
# compiling it is Phase 6 work. Saying so on the console is the point - a
# system that silently boots with no services and no explanation is
# indistinguishable from one whose service manager crashed.
if [ -d /etc/s6-rc/compiled ]; then
    s6-rc-init -c /etc/s6-rc/compiled /run/service
    s6-rc -v1 -up change "$rl"
else
    echo "kryptik: no compiled s6-rc database at /etc/s6-rc/compiled."
    echo "kryptik: booting with the early console only; no services will start."
    echo "kryptik: this is expected in a pre-alpha image - see docs/roadmap.md Phase 6."
fi
EOF

    # Shutdown: bring services down, then return. s6-linux-init-shutdownd does
    # the unmounting and the actual poweroff - rc.shutdown must NOT try to halt
    # the machine itself.
    cat > "$skel/rc.shutdown" <<'EOF'
#!/bin/sh -e
# Kryptik shutdown. Bring services down and return; s6-linux-init-shutdownd
# performs the unmount and the hardware poweroff after this exits.

exec >/dev/console 2>&1

if [ -d /run/service ] && command -v s6-rc >/dev/null 2>&1; then
    s6-rc -v1 -bDa change || true
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

    # The maker refuses to write into an existing directory, so build into a
    # fresh path and move it into place.
    local tmp=/tmp/s6-linux-init-build.$$
    rm -rf "$tmp"

    #  -1  stage 2 output also goes to /dev/console. Without it a boot failure
    #      is only visible in the catch-all log, which you cannot read because
    #      the machine did not boot.
    #  -G  the early getty: our console wrapper, supervised for the lifetime
    #      of the machine.
    #  -p  PATH for the init scripts. The host is not on it; there is no host.
    #  -s  kernel command line key=value pairs land in this envdir, so
    #      services can read them. It MUST be under /run: s6-linux-init-maker
    #      warns otherwise, and the reason bites Kryptik specifically. The
    #      store is rewritten at every boot, and Kryptik's kernel fragment
    #      enables dm-verity - a root filesystem that is read-only by design.
    #      Pointing this at /etc would mean init trying to write to a verified
    #      root on every boot.
    #  -f  our skeleton, not the commented-out upstream one.
    #
    # NOT passed: -d /dev. Upstream says to add it when devtmpfs is not
    # automounted by the kernel; Kryptik's kernel sets
    # CONFIG_DEVTMPFS_MOUNT=y, so passing it would mount devtmpfs a second
    # time over the kernel's own.
    s6-linux-init-maker \
        -1 \
        -G "/usr/libexec/kryptik-console" \
        -p /usr/bin:/usr/sbin \
        -m 0022 \
        -c /etc/s6-linux-init/current \
        -s /run/s6-linux-init/env \
        -f "$skel" \
        -D default \
        "$tmp"

    rm -rf /etc/s6-linux-init/current
    mv "$tmp" /etc/s6-linux-init/current

    # /sbin/init, plus telinit, shutdown, halt, poweroff and reboot. /sbin is a
    # symlink to usr/sbin in this layout, so these land in /usr/sbin and
    # /sbin/init resolves - which is the path the kernel looks for.
    cp -a /etc/s6-linux-init/current/bin/. /sbin/

    echo "--- /sbin entry points ---"
    ls -la /sbin/init /sbin/telinit /sbin/shutdown /sbin/halt /sbin/poweroff /sbin/reboot
}

# The service database, and the kernel tunables that were never installed.
#
# Until this step existed the image booted to a console and printed "no
# compiled s6-rc database ... no services will start", which was honest and
# not a system. s6-svscan was running as pid 1 supervising nothing but its own
# logger and the early getty.
#
# Two things get installed here that the build had been carrying and not
# shipping:
#
#   build/config/sysctl.d/99-kryptik-hardening.conf - present in the
#   repository since the beginning, referenced by docs/hardening.md, and never
#   copied into a target. Every tunable in it was inert.
#
#   build/services/       - the s6-rc source tree: service definitions ONLY
#   build/service-scripts/ - the shell the oneshots run, kept out of the
#                            source tree because s6-rc-compile reads every
#                            directory there as a service
#   rc.init looks for.
s_services() {
    local src="${KRYPTIK_ROOT}/build/services"
    [[ -d "$src" ]] || { echo "no service source tree at ${src}"; return 1; }

    # The scripts the oneshot `up` files name. They live outside the database
    # so they can be read, checked and run by hand on a machine that is not
    # booting properly - and outside the s6-rc SOURCE tree, which is the part
    # that matters here: s6-rc-compile treats every directory under the source
    # as a service definition, so a scripts/ directory in there made it stop
    # with "unable to read .../scripts/type: No such file or directory".
    local scripts="${KRYPTIK_ROOT}/build/service-scripts"
    install -d -m 0755 /usr/libexec/kryptik
    install -m 0755 "$scripts"/*.sh /usr/libexec/kryptik/
    echo "--- boot scripts ---"
    ls -la /usr/libexec/kryptik/

    # Kryptik's kernel tunables.
    install -d -m 0755 /etc/sysctl.d
    if compgen -G "${KRYPTIK_ROOT}/build/config/sysctl.d/*.conf" > /dev/null; then
        install -m 0644 "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf /etc/sysctl.d/
        echo "--- sysctl.d ---"
        ls -la /etc/sysctl.d/
    else
        echo "no sysctl.d fragments to install"
    fi

    # Compile the database. s6-rc-compile refuses to overwrite, so build
    # beside and swap: a half-written database is a machine that does not boot.
    local tmpdb=/etc/s6-rc/compiled.new
    rm -rf "$tmpdb"
    install -d -m 0755 /etc/s6-rc
    s6-rc-compile -v2 "$tmpdb" "$src"
    rm -rf /etc/s6-rc/compiled.old
    [[ -d /etc/s6-rc/compiled ]] && mv /etc/s6-rc/compiled /etc/s6-rc/compiled.old
    mv "$tmpdb" /etc/s6-rc/compiled
    rm -rf /etc/s6-rc/compiled.old

    # Read the database back. "s6-rc-compile exited 0" and "the database
    # describes the services we wrote" are different claims, and the second is
    # the one a boot depends on.
    echo "--- compiled database ---"
    local all
    all="$(s6-rc-db -c /etc/s6-rc/compiled list all)"
    printf '%s\n' "$all" | sed 's/^/  /'

    local svc missing=0
    for svc in sysinit eudev eudev-trigger kryptikd-check getty-tty1 default; do
        if ! printf '%s\n' "$all" | grep -qx "$svc"; then
            echo "MISSING from the database: ${svc}"; missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]] || { echo "${missing} service(s) did not compile in"; return 1; }

    # The dependency graph has to be the one we declared, or services start in
    # an order nobody chose.
    echo "--- what 'default' pulls in, in order ---"
    s6-rc-db -c /etc/s6-rc/compiled pipeline default 2>/dev/null || true
    s6-rc-db -c /etc/s6-rc/compiled dependencies default | sed 's/^/  /'

    echo "--- eudev-trigger must depend on eudev ---"
    if s6-rc-db -c /etc/s6-rc/compiled dependencies eudev-trigger | grep -qx eudev; then
        echo "  ok"
    else
        echo "  FAIL: eudev-trigger does not depend on eudev"
        return 1
    fi
    echo "service database compiled and verified"
}

# kryptikd, the zone supervisor.
#
# It is Rust, and the sysroot has no Rust toolchain - bootstrapping one into
# the target is a much larger piece of work than this stage. So the binary is
# built outside and installed here, and its ABSENCE is reported loudly rather
# than passed over: a Kryptik image without kryptikd is a Linux system with
# Kryptik's name on it.
# Takes its input as ARGUMENTS rather than reading the environment, and that
# is deliberate.
#
# step() fingerprints a step against its recipe and the arguments it was called
# with. An environment variable is invisible to that, so pointing
# KRYPTIK_KRYPTIKD_BIN at a binary after a run that had none would leave the
# stamp valid and the step skipped - the image would stay without kryptikd and
# the build would report success. Passing the path AND the binary's content
# hash makes both part of the step's identity.
s_kryptikd() {
    local src="$1" want_sha="${2:-absent}" zones_sha="${3:-nozones}"
    [[ "$src" == "none" ]] && src=""
    echo "requested: ${src:-<none>} (sha256 ${want_sha})"
    echo "zone definitions: ${zones_sha}"

    install -d -m 0755 /etc/kryptik
    install -d -m 0700 /etc/kryptik/zones
    if [[ -d "${KRYPTIK_ROOT}/compartments/zones" ]]; then
        install -m 0600 "${KRYPTIK_ROOT}"/compartments/zones/*.toml /etc/kryptik/zones/
        echo "installed zone definitions:"
        ls -la /etc/kryptik/zones/
    else
        echo "no zone definitions at ${KRYPTIK_ROOT}/compartments/zones"
    fi

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

    # The hash was taken when the build order was built, outside the chroot.
    # If it no longer matches, the file changed underneath the build and the
    # stamp about to be written would describe something else.
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

    # It must actually run here. A dynamically linked binary built against the
    # host's libc installs perfectly and then fails at boot with a missing
    # loader, which is exactly the kind of failure this stage exists to catch
    # before a VM does.
    echo "--- installed kryptikd ---"
    ls -la /usr/bin/kryptikd
    readelf -l /usr/bin/kryptikd 2>/dev/null | grep 'Requesting program interpreter' \
        || echo "  (static binary, no interpreter - good)"
    # It must actually RUN here, and --help is the only subcommand that both
    # exits 0 and touches nothing. (`--version` is not a kryptikd subcommand
    # at all: it prints usage and exits 2, which would fail this step on a
    # perfectly good binary.) `check` is deliberately not used - inside the
    # build chroot it would probe the BUILD host's kernel for Landlock and
    # seccomp and report an answer about the wrong machine.
    /usr/bin/kryptikd --help > /dev/null || {
        echo "FAIL: the installed kryptikd does not run inside the target."
        echo "A binary built against the host's libc installs fine and fails here."
        return 1
    }
    echo "kryptikd --help: ok"

    # And it must be able to read the zone definitions just installed. A zone
    # file this binary cannot parse is a boot-time failure discovered at boot.
    if /usr/bin/kryptikd list --zones /etc/kryptik/zones; then
        echo "kryptikd parses the installed zone definitions"
    else
        echo "FAIL: kryptikd cannot read /etc/kryptik/zones"
        return 1
    fi
}

# Everything a boot needs, checked from the target's own point of view.
#
# "make system finished" is not the same statement as "this tree can boot", and
# the gap between them is where an overnight build quietly wastes a morning.
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
    chk "stage 2 script"    /etc/s6-linux-init/current/scripts/rc.init x
    chk "shutdown script"   /etc/s6-linux-init/current/scripts/rc.shutdown x
    chk "shell"             /bin/sh x
    chk "bash"              /usr/bin/bash x
    chk "os-release"        /etc/os-release
    chk "fstab"             /etc/fstab
    chk "C library"         /usr/lib/libc.so.6
    chk "dynamic loader"    /usr/lib/ld-linux-x86-64.so.2

    # /sbin/init must be reachable by the exact path the kernel uses.
    if [[ -x /sbin/init ]]; then
        printf '  ok      /sbin/init resolves to %s\n' "$(readlink -f /sbin/init)"
    fi

    # The early getty is what turns a booted kernel into something you can
    # talk to. If the maker did not create it, the machine boots to silence.
    local svcdir=/etc/s6-linux-init/current/run-image/service
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

    # The service database. Without it the machine boots to a bare console,
    # which is a state worth distinguishing from a broken one.
    if [[ -d /etc/s6-rc/compiled ]]; then
        local nsvc
        nsvc="$(s6-rc-db -c /etc/s6-rc/compiled list all 2>/dev/null | grep -c . || echo 0)"
        printf '  ok      s6-rc database (%s services)\n' "$nsvc"
        if s6-rc-db -c /etc/s6-rc/compiled list all 2>/dev/null | grep -qx default; then
            echo "  ok      a 'default' bundle exists for rc.init to bring up"
        else
            echo "  MISSING a 'default' bundle"; n=$((n + 1))
        fi
    else
        echo "  MISSING /etc/s6-rc/compiled - the image will boot to a bare console"
        n=$((n + 1))
    fi

    chk "sysctl fragments"  /etc/sysctl.d
    chk "boot scripts"      /usr/libexec/kryptik/sysinit.sh x

    if [[ -e /etc/kryptik/kryptikd-absent ]]; then
        echo "  NOTE    kryptikd is not installed in this image (see the kryptikd step)"
    fi

    [[ "$n" -eq 0 ]] || { echo "${n} boot prerequisite(s) missing"; return 1; }
    echo "the sysroot has what a boot needs"
}

# --- build order ------------------------------------------------------------
#
# Ordered by dependency, not alphabetically. Moving an entry earlier because it
# "seems independent" is how a base system build breaks three packages later.

declare -a PACKAGES=(
    "locales"     "s_locales"
    "gettext"     "native_build gettext-${V_GETTEXT}.tar.xz gettext-${V_GETTEXT} --disable-shared"
    "bison"       "native_build bison-${V_BISON}.tar.xz bison-${V_BISON} --docdir=/usr/share/doc/bison-${V_BISON}"
    "perl"        "s_perl"
    # BEFORE python, and the ordering is not cosmetic.
    #
    # glibc no longer provides crypt(). It was split out years ago and
    # removed outright in 2.39; Kryptik pins 2.40, so nothing in this
    # sysroot defines the symbol until libxcrypt is built.
    #
    # Python links a _crypt module against it unconditionally. With
    # libxcrypt further down the list, that module built, failed to import
    # with "undefined symbol: crypt", was therefore not produced, and
    # `make install` died on a missing file:
    #
    #   install: cannot stat 'Modules/_crypt.cpython-312-...so'
    #   make: *** [Makefile:2066: sharedinstall] Error 1
    #
    # It has to come after perl, though, not before: libxcrypt generates
    # part of its own source with perl at build time. So this is the only
    # position that works - after perl, before python. LFS reaches the same
    # order for the same reason.
    "libxcrypt"   "native_build libxcrypt-${V_LIBXCRYPT}.tar.xz libxcrypt-${V_LIBXCRYPT} --enable-hashes=strong,glibc --enable-obsolete-api=no --disable-static --disable-failure-tokens"
    # BEFORE python, for the same class of reason as libxcrypt above.
    #
    # Python's `make install` runs ensurepip, which installs pip from a
    # bundled .whl - a zip archive - and so needs the zlib module to
    # decompress it. Without it the install died after twenty minutes of
    # work with a zipimport traceback:
    #
    #   ModuleNotFoundError: No module named 'zlib'
    #   zipimport.ZipImportError: can't decompress data; zlib not available
    #   make: *** [Makefile:2035: install] Error 1
    #
    # zlib needs nothing but a C compiler, so it can sit this early. It
    # links against the stage 01 glibc rather than the rebuilt one, which
    # is true of everything before the glibc step and is the same soname
    # and ABI - see the note on the dependency cycle above.
    "zlib"        "s_zlib"
    "python"      "s_python"
    "texinfo"     "native_build texinfo-${V_TEXINFO}.tar.xz texinfo-${V_TEXINFO}"
    "util-linux"  "native_build util-linux-${V_UTIL_LINUX}.tar.xz util-linux-${V_UTIL_LINUX} --libdir=/usr/lib --runstatedir=/run --disable-chfn-chsh --disable-login --disable-nologin --disable-su --disable-setpriv --disable-runuser --disable-pylibmount --disable-liblastlog2 --disable-static --without-python"
    "glibc"       "s_glibc"
    "bzip2"       "s_bzip2"
    "xz"          "s_xz_native"
    "zstd"        "s_zstd"
    "file"        "native_build file-${V_FILE}.tar.gz file-${V_FILE}"
    "readline"    "native_build readline-${V_READLINE}.tar.gz readline-${V_READLINE} --disable-static --with-curses"
    "m4"          "native_build m4-${V_M4}.tar.xz m4-${V_M4}"
    "flex"        "native_build flex-${V_FLEX}.tar.gz flex-${V_FLEX} --disable-static"
    # Before anything that probes for its dependencies. e2fsprogs, iproute2,
    # kmod and eudev all ask pkg-config where zlib, openssl, zstd and xz are;
    # without it kmod's --with-openssl --with-zstd --with-zlib --with-xz have
    # nothing to answer them and configure fails. The tarball was already
    # pinned in versions.env and fetched - the package simply had no recipe.
    "pkgconf"     "s_pkgconf"
    "binutils"    "s_binutils_native"
    "gmp"         "native_build gmp-${V_GMP}.tar.xz gmp-${V_GMP} --enable-cxx --disable-static"
    "mpfr"        "native_build mpfr-${V_MPFR}.tar.xz mpfr-${V_MPFR} --disable-static --enable-thread-safe"
    "mpc"         "native_build mpc-${V_MPC}.tar.gz mpc-${V_MPC} --disable-static"
    "attr"        "native_build attr-${V_ATTR}.tar.gz attr-${V_ATTR} --disable-static --sysconfdir=/etc"
    "acl"         "native_build acl-${V_ACL}.tar.xz acl-${V_ACL} --disable-static"
    "libcap"      "s_libcap"
    "shadow"      "s_shadow"
    # --enable-pc-files needs --with-pkg-config-libdir to go with it.
    #
    # Without the second flag ncurses has nowhere to put its .pc files and
    # installs none, silently. Everything that asks pkg-config for ncursesw
    # then gets "no": procps-ng stopped the stage with "ncurses support
    # missing/incomplete" while libncursesw.so.6.5 sat in /usr/lib, built
    # and working, twenty minutes earlier.
    #
    # It went unnoticed because ncurses was built BEFORE /usr/bin/pkg-config
    # existed - pkgconf installs under its own name, and the compatibility
    # symlink was a separate fix - so ncurses could not have located the
    # directory even to guess at it. Two absences that each hid the other.
    "ncurses"     "native_build ncurses-${V_NCURSES}.tar.gz ncurses-${V_NCURSES} --mandir=/usr/share/man --with-shared --without-debug --without-normal --with-cxx-shared --enable-pc-files --with-pkg-config-libdir=/usr/lib/pkgconfig"
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
    # --disable-manpages: kmod 33 generates its man pages with scdoc, which
    # Kryptik does not pin and which exists only to produce documentation.
    # The option is the one kmod's own error message names. man-db is not
    # built either (it needs gdbm, see the entry below), so this image has
    # no man infrastructure to read them with in any case.
    # A build-time requirement of the KERNEL, not a shipped convenience:
    # linux/Kbuild generates include/generated/timeconst.h with `bc -q`, and
    # arch/x86 asm-offsets depends on that header. Without it stage 05 dies at
    # "bc: command not found" - after the config step has already succeeded,
    # which is what made it look like a kernel problem rather than a missing
    # tool. Placed after flex and bison, which bc needs and which are earlier.
    #
    # --with-readline is deliberately NOT passed: the kernel only ever calls
    # `bc -q` non-interactively, and it would add a dependency to the one
    # package here that exists solely to compute two constants.
    "bc"          "s_bc"
    "kmod"        "native_build kmod-${V_KMOD}.tar.xz kmod-${V_KMOD} --sysconfdir=/etc --with-openssl --with-xz --with-zstd --with-zlib --disable-manpages"
    "libpipeline" "native_build libpipeline-${V_LIBPIPELINE}.tar.gz libpipeline-${V_LIBPIPELINE}"
    # man-db has NO RECIPE, deliberately, and the stage reports it as an
    # unwired package rather than pretending otherwise.
    #
    # Its configure requires a database library - gdbm, Berkeley db, or
    # ndbm - and hard-errors with "Fatal: no supported database
    # library/header found" when it finds none. Kryptik pins none of them,
    # and glibc does not provide ndbm (gdbm-ndbm.h ships with gdbm).
    #
    # Adding gdbm is an integration change: it needs a version in
    # versions.env, an entry in tools/fetch-sources.sh and an audited line
    # in sources.lock. Until then this package cannot build, and blocking
    # the kernel on a documentation tool would be the wrong trade - so it
    # is listed, unwired, and counted in the "base system is INCOMPLETE"
    # warning at the end of this stage.
    "man-db"      ""
    "procps-ng"   "native_build procps-ng-${V_PROCPS}.tar.xz procps-ng-${V_PROCPS} --docdir=/usr/share/doc/procps-ng-${V_PROCPS} --disable-static --disable-kill"
    "e2fsprogs"   "s_e2fsprogs"
    "elfutils"    "s_elfutils"
    "iproute2"    "s_iproute2"
    "kbd"         "s_kbd"
    "eudev"       "s_eudev"
    "iana-etc"    "s_iana_etc"
    "hardened-malloc" "s_hardened_malloc"
    "s6"          "s_s6_stack"

    # Past this line the stage stops compiling packages and starts making
    # the result bootable. These are ordinary steps - stamped, resumable
    # and fingerprinted like any other - because "configure the init
    # system" fails in exactly the same ways as "build a package", and
    # deserves the same machinery rather than a hand-rolled tail.
    "etc"         "s_etc"
    "console"     "s_console"
    "init"        "s_init"
    # After init: the database lives beside the stage 2 scripts that look
    # for it. Before kryptikd: boot-check verifies both together.
    # The service tree, the boot scripts and the sysctl fragments are inputs
    # to this step, and `declare -f s_services` cannot see a file the recipe
    # reads by path. Without their digest, editing sysinit.sh left the stamp
    # looking valid and the old script installed - which is exactly the
    # stale-stamp defect the kernel fragments had.
    "services"    "s_services $(cat "${KRYPTIK_ROOT}"/build/services/*/* \n                                    "${KRYPTIK_ROOT}"/build/service-scripts/*.sh \n                                    "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf \n                                2>/dev/null | sha256_of_stdin || echo nosvc)"
    # The path and the binary's content hash are arguments so that both are
    # part of this step's fingerprint; see s_kryptikd.
    # The zone definitions are an input too, not just the binary. kryptikd
    # validates them at install time, and the pair has to move together: a
    # newer kryptikd made "storage.size" mandatory for ephemeral zones and
    # rejected the definitions this branch was carrying. Hashing the directory
    # means changing a .toml re-runs this step instead of silently shipping a
    # binary that will not read its own config.
    "kryptikd"    "s_kryptikd ${KRYPTIK_KRYPTIKD_BIN:-none} $([[ -f "${KRYPTIK_KRYPTIKD_BIN:-}" ]] && sha256_of "${KRYPTIK_KRYPTIKD_BIN}" || echo absent) $(cat "${KRYPTIK_ROOT}"/compartments/zones/*.toml 2>/dev/null | sha256_of_stdin || echo nozones)"
    "boot-check"  "s_boot_check"
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

# The commit that produced this image, for /etc/os-release. Resolved out
# here because the chroot has no git, and passed in rather than guessed:
# an image that names the wrong commit is worse than one that names none.
KRYPTIK_BUILD_COMMIT="${KRYPTIK_BUILD_COMMIT:-unknown}"
export KRYPTIK_BUILD_COMMIT

log "Kryptik stage 04 — hardened base system"
dim "  CFLAGS : ${CFLAGS}"
dim "  LDFLAGS: ${LDFLAGS}"
dim "  jobs   : ${KRYPTIK_JOBS}"
echo

# Refuse to run outside the chroot. Building the base system against the
# host would produce packages linked to host libraries that then get
# installed into the sysroot - broken in a way that surfaces much later.
require_inside_chroot "stage 04" "system"

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
