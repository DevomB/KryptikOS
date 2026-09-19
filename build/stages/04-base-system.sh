#!/usr/bin/env bash
# Stage 04 — Hardened base system (docs/roadmap.md, Base system)
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

    # The loader defect recorded in docs/glibc-loader-defect.md - pthread_exit(),
    # pthread_cancel() and backtrace() aborting because _dl_find_object
    # attributed every object loaded after startup to ld.so itself - and
    # what fixes it. build/patches/glibc-2.40/ carries four upstream loader
    # fixes, with provenance in its README: the release/2.40/master fixes
    # for bug 31943 (a loader mapped with gaps, plus two prerequisites) and
    # the one that turned out to be Kryptik's actual defect, bug 33088: GCC
    # 14 at -O2 took the address of __ehdr_start for the loader's own map
    # bounds from a constant that is only right after self-relocation, so
    # ld.so recorded itself as starting at address 0. The two checks below
    # (rtld.os relocations, ldd's map start) fail this step if it returns.
    apply_repo_patches "glibc-${V_GLIBC}"

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

    # Upstream's make-check rule for bug 33088, run here because this build
    # does not run glibc's test suite: the loader's startup code must take
    # the addresses of __ehdr_start and _end without a run-time relocation,
    # or the values it stores before relocating itself are the link-time
    # ones (0 for __ehdr_start).
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

    # The runtime form of the rtld.os check above: LD_TRACE_LOADED_OBJECTS
    # (what ldd runs) prints each object's map start, and a loader with bug
    # 33088 prints its own as 0. tools/test-libc-unwind.sh then proves the
    # consequence - unwinding through a dlopen()ed libgcc_s - on the whole
    # system; this catches the cause at the step that builds it.
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
    # Provenance audited this pin and was explicit that it needs no extra
    # flags: man-db's configure.ac tries the gdbm NATIVE interface first
    # (gdbm.h plus gdbm_fetch in -lgdbm), so the ndbm compatibility layer that
    # --enable-libgdbm-compat would add is not what man-db reaches for.
    local src; src="$(unpack "gdbm-${V_GDBM}.tar.gz" "gdbm-${V_GDBM}")"
    cd "$src"
    ./configure --prefix=/usr --disable-static
    make
    make install
    rm -fv /usr/lib/libgdbm.la

    # "make install exited 0" and "this database can store and return a key"
    # are different claims, and man-db depends on the second.
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

    # --disable-setuid: man-db would otherwise install man setuid to a man
    # user so it can write a shared page cache. A setuid binary that parses
    # untrusted files is not a trade Kryptik makes for faster man pages.
    # The browser/vgrind/grap helpers are deliberately absent; naming paths to
    # programs this system does not have would only bake in dead references.
    ./configure --prefix=/usr                 --docdir="/usr/share/doc/man-db-${V_MANDB}"                 --sysconfdir=/etc                 --disable-setuid                 --enable-cache-owner=bin
    make
    make install

    # The whole reason gdbm was pinned. If configure quietly fell back to
    # another database interface then the pin bought nothing, and the failure
    # would otherwise only show up the first time someone ran mandb.
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

# The full Python, built again after the libraries it wants. The early build
# above exists to satisfy glibc's configure and is made before libffi,
# openssl and expat, so it went out without _ctypes and without ssl: the
# boundary suite's D1 probe died on `import ctypes` inside every zone on the
# first installed system, and reported a seccomp failure that was nothing of
# the kind. Same version, same prefix - this install overwrites the early
# one's files - and the step fails unless the modules it exists for import.
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
    # ed - so an earlier build replaced it with a sed equivalent. 1.08.2, which is
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
#
# The commit is an argument, not read from the environment here: the step's
# fingerprint covers its recipe and arguments, and a sysroot restored from
# the runner's cache would otherwise keep the os-release of the commit that
# filled the cache, stamped as up to date.
s_etc() {
    local commit="${1:-${KRYPTIK_BUILD_COMMIT:-unknown}}"

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

    # Groups and system accounts the boot-time services and the desktop
    # need. seat: who may talk to seatd (the compositor's user); kryptik:
    # who may launch zones through the trusted UI; dhcpcd: the net zone's
    # DHCP client drops privileges to it.
    local g
    for g in seat kryptik wheel; do
        getent group "$g" >/dev/null 2>&1 || groupadd -r "$g"
    done
    getent passwd dhcpcd >/dev/null 2>&1 || \
        useradd -r -g nogroup -d /var/lib/dhcpcd -s /usr/bin/false -c "dhcpcd privsep" dhcpcd 2>/dev/null || \
        useradd -r -d /var/lib/dhcpcd -s /usr/bin/false -c "dhcpcd privsep" dhcpcd
    install -d -m 0755 -o dhcpcd /var/lib/dhcpcd 2>/dev/null || install -d -m 0755 /var/lib/dhcpcd

    # root ships WITHOUT a password ("*": nothing hashes to it), so neither
    # login nor su can reach root until the first boot of an installed system
    # sets one (kryptik-firstboot). /etc/securetty is present and empty, so
    # root can never log in at a terminal even then; administration is su
    # from the wheel group. The install medium's console does not go through
    # login at all.
    [[ -f /etc/shadow ]] || pwconv
    usermod -p '*' root
    grep -q '^root:\*:' /etc/shadow && echo "root: no password" || { echo "FAIL: root has a password in the image"; return 1; }
    : > /etc/securetty
    if grep -q '^SU_WHEEL_ONLY' /etc/login.defs; then
        sed -i 's/^SU_WHEEL_ONLY.*/SU_WHEEL_ONLY yes/' /etc/login.defs
    else
        printf 'SU_WHEEL_ONLY yes\n' >> /etc/login.defs
    fi

    # Kernel interface names (eth0, not enp0s3): the shipped net zone names
    # its NIC `eth0`, and a name that depends on the bus slot would make
    # every machine's zone file different. eudev's slot-naming rule is masked.
    install -d -m 0755 /etc/udev/rules.d
    ln -sf /dev/null /etc/udev/rules.d/80-net-name-slot.rules

    cat > /etc/kryptik/kryptik.conf <<'EOF'
# The kryptik command's defaults on an installed system.
zones_dir = /usr/lib/kryptik/zones
rootfs    = /var/lib/kryptik/zones
uid_base  = 100000
EOF

    # The desktop session: a login on tty1 becomes the compositor session
    # when kryptik-session is installed. Any other tty stays a shell.
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

# The trust anchor for OS updates (docs/design/boot-and-updates.md). The release signing key is an
# OpenSSH key under ${KRYPTIK_WORK}/keys/release, generated once, never in
# Git and never in an image; only the allowed-signers line (its public half,
# principal kryptik-release) is installed. Stage 06 signs update manifests
# with the private half, so the image built here verifies what the same
# build signs - and nothing signed by any other key.
s_release_trust() {
    # Under /usr/share, on the verified root: /etc is overlaid with an
    # unauthenticated upper layer on the state partition (sysinit.sh, "the
    # trust boundary"), and the key that decides what may be booted next
    # must not be replaceable by whoever can write that partition.
    local keydir="${KRYPTIK_WORK}/keys/release"
    mkdir -p "$keydir"; chmod 0700 "$keydir"
    if [[ ! -f "$keydir/kryptik-release" ]]; then
        ssh-keygen -q -t ed25519 -N "" -C "kryptik-release (developer)" -f "$keydir/kryptik-release"
        chmod 0600 "$keydir/kryptik-release"
        echo "generated a new developer release signing key"
    fi
    install -d -m 0755 /usr/share/kryptik/trust
    printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 "$keydir/kryptik-release.pub")" \
        > /usr/share/kryptik/trust/release-signers
    chmod 0644 /usr/share/kryptik/trust/release-signers
    # Developer tier: the updater accepts development-role manifests. A
    # production image changes this file (and its key), deliberately.
    printf 'development\n' > /usr/share/kryptik/trust/required-role
    echo "--- trust anchor ---"; cat /usr/share/kryptik/trust/release-signers
    # Prove the anchor works end to end with the key beside it: sign a
    # scratch file and verify it through the installed signers file.
    local t; t="$(mktemp -d)"
    printf 'probe\n' > "$t/m"
    ssh-keygen -Y sign -f "$keydir/kryptik-release" -n kryptik-release "$t/m" >/dev/null 2>&1
    ssh-keygen -Y verify -f /usr/share/kryptik/trust/release-signers -I kryptik-release -n kryptik-release -s "$t/m.sig" < "$t/m" >/dev/null \
        && echo "ok: the anchor verifies a signature by the release key" || { echo "FAIL: anchor does not verify"; rm -rf "$t"; return 1; }
    # and refuses one by a different key (control). A SEPARATE file and
    # signature, and the signing step must succeed: the first version
    # re-signed m in place with its errors hidden, and when that signing
    # failed the release key's signature was still in m.sig, so the
    # "foreign key verified" verdict was about the wrong signature.
    ssh-keygen -q -t ed25519 -N "" -f "$t/other" >/dev/null 2>&1 || { echo "FAIL: could not generate the control key"; rm -rf "$t"; return 1; }
    printf 'probe by another key\n' > "$t/m2"
    ssh-keygen -Y sign -f "$t/other" -n kryptik-release "$t/m2" < /dev/null >/dev/null 2>"$t/sign.err" \
        || { echo "FAIL: signing with the control key failed: $(cat "$t/sign.err")"; rm -rf "$t"; return 1; }
    [[ -s "$t/m2.sig" ]] || { echo "FAIL: no m2.sig from the control key"; rm -rf "$t"; return 1; }
    if ssh-keygen -Y verify -f /usr/share/kryptik/trust/release-signers -I kryptik-release -n kryptik-release -s "$t/m2.sig" < "$t/m2" >/dev/null 2>&1; then
        echo "FAIL: a foreign key verified against the anchor"; rm -rf "$t"; return 1
    fi
    echo "ok: a foreign key is refused"
    rm -rf "$t"
}

# The net zone's own startup program (docs/design/net-zone.md): dhcpcd, nftables NAT and
# dnsmasq inside the zone that holds the NIC. Installed beside the boot
# scripts; run by the net-zone service through kryptikd.
s_netzone() {
    local src="${KRYPTIK_ROOT}/tools/net/netzone-init.sh"
    [[ -f "$src" ]] || { echo "no netzone-init at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    install -D -m 0755 "$src" /usr/libexec/kryptik/netzone-init.sh
    sh -n /usr/libexec/kryptik/netzone-init.sh || { echo "netzone-init does not parse under the target sh"; return 1; }
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
    # Captured, not piped into grep -q: the usage text comes with a non-zero
    # exit, which pipefail would report as this check failing.
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

# The firmware-side half of the A/B trial: a small C program that writes
# Boot#### and BootNext through efivarfs. Built here with the target
# toolchain and the hardening flags like everything else; its source hash is
# an argument so the step re-runs when the source changes.
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

# s6-linux-init: generate /usr/lib/s6-linux-init/current and the /sbin entry
# points. Under /usr/lib, not /etc: the stage 2 scripts run as root before
# anything else and must come from the verified root, not the /etc overlay.
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

    # Shutdown: bring services down, then return. s6-linux-init-shutdownd does
    # the unmounting and the actual poweroff - rc.shutdown must NOT try to halt
    # the machine itself.
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
        -c /usr/lib/s6-linux-init/current \
        -s /run/s6-linux-init/env \
        -f "$skel" \
        -D default \
        "$tmp"

    install -d -m 0755 /usr/lib/s6-linux-init
    rm -rf /usr/lib/s6-linux-init/current
    mv "$tmp" /usr/lib/s6-linux-init/current

    # /sbin/init, plus telinit, shutdown, halt, poweroff and reboot. /sbin is a
    # symlink to usr/sbin in this layout, so these land in /usr/sbin and
    # /sbin/init resolves - which is the path the kernel looks for.
    cp -a /usr/lib/s6-linux-init/current/bin/. /sbin/

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
s_installer() {
    # The installer runs INSIDE a booted Kryptik system, onto a second disk, so
    # it has to be in the image. It is never run on the build host and has no
    # business there - the host's disks are not something this project writes
    # to, and the installer's own refusals assume a guest.
    local src="${KRYPTIK_ROOT}/tools/install/kryptik-install.sh"
    [[ -f "$src" ]] || { echo "no installer at ${src}"; return 1; }

    install -D -m 0755 "$src" /usr/sbin/kryptik-install

    # It is /bin/sh, and the target's sh is the one that will run it. Parsing it
    # with the shell that will execute it is worth more than parsing it with the
    # build host's.
    sh -n /usr/sbin/kryptik-install || {
        echo "the installer does not parse under the target sh"
        return 1
    }
    echo "--- installer ---"
    ls -la /usr/sbin/kryptik-install
    /usr/sbin/kryptik-install --help
}

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

    # Kryptik's kernel tunables, on the verified root: sysinit applies these
    # and nothing under /etc, which the state partition can shadow.
    install -d -m 0755 /usr/lib/kryptik/sysctl.d
    if compgen -G "${KRYPTIK_ROOT}/build/config/sysctl.d/*.conf" > /dev/null; then
        install -m 0644 "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf /usr/lib/kryptik/sysctl.d/
        echo "--- sysctl.d ---"
        ls -la /usr/lib/kryptik/sysctl.d/
    else
        echo "no sysctl.d fragments to install"
    fi

    # Compile the database. s6-rc-compile refuses to overwrite, so build
    # beside and swap: a half-written database is a machine that does not boot.
    local dbdir=/usr/lib/kryptik/s6-rc
    local tmpdb="$dbdir/compiled.new"
    rm -rf "$tmpdb"
    install -d -m 0755 "$dbdir"
    s6-rc-compile -v2 "$tmpdb" "$src"
    rm -rf "$dbdir/compiled.old"
    [[ -d "$dbdir/compiled" ]] && mv "$dbdir/compiled" "$dbdir/compiled.old"
    mv "$tmpdb" "$dbdir/compiled"
    rm -rf "$dbdir/compiled.old"

    # Read the database back. "s6-rc-compile exited 0" and "the database
    # describes the services we wrote" are different claims, and the second is
    # the one a boot depends on.
    echo "--- compiled database ---"
    local all
    all="$(s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled list all)"
    printf '%s\n' "$all" | sed 's/^/  /'

    local svc missing=0
    for svc in sysinit eudev eudev-trigger kryptikd-check kryptikd-serve firstboot seatd net-zone getty-tty1 boot-success boot-smoke default; do
        if ! printf '%s\n' "$all" | grep -qx "$svc"; then
            echo "MISSING from the database: ${svc}"; missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]] || { echo "${missing} service(s) did not compile in"; return 1; }

    # The dependency graph has to be the one we declared, or services start in
    # an order nobody chose.
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

    # The zone definitions and the policy files they name live on the
    # verified root; every privileged consumer (the services, the launch
    # daemon, the net zone) reads them there. /etc/kryptik/zones is a symlink
    # to them for the kryptik command's default, and nothing more: the /etc
    # overlay could replace that link, and only the unprivileged wrapper
    # would follow it.
    install -d -m 0755 /etc/kryptik /usr/lib/kryptik
    install -d -m 0755 /usr/lib/kryptik/zones /usr/lib/kryptik/zones/policy
    if [[ -d "${KRYPTIK_ROOT}/compartments/zones" ]]; then
        install -m 0644 "${KRYPTIK_ROOT}"/compartments/zones/*.toml /usr/lib/kryptik/zones/
        # The seccomp/Landlock policies the zone files reference, relative
        # to the zone directory. The first version installed the .toml files
        # alone, so every zone would have failed to start on the target with
        # "policy/<zone>.seccomp: No such file".
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
    if /usr/bin/kryptikd list --zones /usr/lib/kryptik/zones; then
        echo "kryptikd parses the installed zone definitions"
    else
        echo "FAIL: kryptikd cannot read /usr/lib/kryptik/zones"
        return 1
    fi

    # The command a person types (tools/kryptik), beside the daemon it wraps.
    # It was never installed before: cli.sh in the image looked for it on
    # PATH and would have reported it missing.
    install -m 0755 "${KRYPTIK_ROOT}/tools/kryptik" /usr/bin/kryptik
    bash -n /usr/bin/kryptik || { echo "FAIL: /usr/bin/kryptik has a syntax error"; return 1; }
    echo "installed /usr/bin/kryptik (sha256 ${4:-unknown})"
}

# The suites and the guest-side checks, in the image, so the VM drivers can
# run the SAME isolation, launcher and CLI suites on the installed kernel as
# root - the [vm] rows those suites declare NOT RUN on a developer host.
# The layout matters: the suites locate their tree as $HERE/../.., so they
# sit at /usr/lib/kryptik/compartments/tests, next to a kryptikd symlink at
# the path they default to (see tools/vm/mkinitramfs.sh for the same rule).
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
    # adversarial.sh cross-checks its namespace set against isolate.rs and
    # the proc and sysfs mounts against rootfs.rs, where they are made. The
    # first target run after that check moved reported both mounts missing:
    # only isolate.rs had been shipped.
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

# Everything a boot needs, checked from the target's own point of view.
#
# "make system finished" is not the same statement as "this tree can boot", and
# the gap between them is where a build left running quietly wastes a morning.
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
    # The desktop: the compositor, the terminal, the launch
    # client, the session, the chrome, the per-zone proxy and the daemon.
    chk "compositor"        /usr/bin/dwl x
    chk "terminal"          /usr/bin/havoc x
    chk "seatd"             /usr/bin/seatd x
    chk "kryptik-launch"    /usr/bin/kryptik-launch x
    chk "kryptik-session"   /usr/bin/kryptik-session x
    chk "kryptik-chrome"    /usr/bin/kryptik-chrome x
    chk "havoc font"        /usr/share/fonts/TTF/DejaVuSansMono.ttf
    chk "kryptik-wlproxy"   /usr/bin/kryptik-wlproxy x
    chk "kryptikd"          /usr/bin/kryptikd x
    # The net zone's wireless uplink, and the regulatory database every
    # radio needs before it may transmit: the first firmware file the kernel
    # asks for, stored compressed like every file under /lib/firmware.
    chk "wpa_supplicant"    /usr/sbin/wpa_supplicant x
    chk "wpa_cli"           /usr/sbin/wpa_cli x
    chk "iw"                /usr/sbin/iw x
    chk "regulatory.db"     /lib/firmware/regulatory.db.zst
    chk "regulatory.db.p7s" /lib/firmware/regulatory.db.p7s.zst

    # /sbin/init must be reachable by the exact path the kernel uses.
    if [[ -x /sbin/init ]]; then
        printf '  ok      /sbin/init resolves to %s\n' "$(readlink -f /sbin/init)"
    fi

    # The early getty is what turns a booted kernel into something you can
    # talk to. If the maker did not create it, the machine boots to silence.
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

    # The service database. Without it the machine boots to a bare console,
    # which is a state worth distinguishing from a broken one.
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
    chk "device helper"     /usr/libexec/kryptik/devices.sh
    chk "boot scripts"      /usr/libexec/kryptik/sysinit.sh x
    chk "test control helper" /usr/libexec/kryptik/testctl.sh
    chk "boot-success"      /usr/libexec/kryptik/boot-success.sh x
    chk "first-boot setup"  /usr/libexec/kryptik/firstboot.sh x
    chk "login"             /usr/bin/login x
    chk "efiboot"           /usr/sbin/kryptik-efiboot x
    chk "updater"           /usr/sbin/kryptik-update x
    chk "recover"           /usr/sbin/kryptik-recover x
    chk "release trust"     /usr/share/kryptik/trust/release-signers
    chk "ssh-keygen"        /usr/bin/ssh-keygen x
    chk "cryptsetup"        /usr/sbin/cryptsetup x
    chk "seatd"             /usr/bin/seatd x

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

# ---------------------------------------------------------------------------
# meson-built packages. The Wayland stack is meson-only; there is no
# autotools alternative to reuse. --buildtype=plain so Kryptik's CFLAGS and
# LDFLAGS are the flags (release would add its own -O3 and -DNDEBUG), and
# --wrap-mode=nodownload so a subproject can never fetch a dependency the
# lock file has not seen (the chroot has no network, but the refusal should
# be the build system's, not the network's).
# ---------------------------------------------------------------------------
meson_build() {
    local tarball="$1" dirname="$2"; shift 2
    local src; src="$(unpack "$tarball" "$dirname")"
    cd "$src"
    meson setup build --prefix=/usr --buildtype=plain --wrap-mode=nodownload "$@"
    ninja -C build
    ninja -C build install
}

# --- encrypted zone volumes -------------------------------------------------

# cmake is here only because json-c has no other build system, and json-c
# is here only because LUKS2 headers are JSON and cryptsetup requires it.
# Bundled third-party libraries rather than system ones: the alternative is
# pinning curl, libarchive, libuv and nghttp2 for a tool that exists to run
# one cmake invocation. It is not part of the image (see the exclusions in
# stage 06).
# cmake is here only to generate json-c's build files, and stage 06 leaves it
# out of the image. Compiling it from source cost 13 of stage 04's 56 minutes
# on the runner: a large C++ tree plus bundled curl, libarchive and libuv, for
# one package's Makefiles. So the chroot runs Kitware's published Linux binary
# instead - pinned by hash in sources.lock like every other input, unpacked
# under the build tree, never installed. The binary writes Makefiles; json-c
# itself is still compiled by this stage's toolchain. Should the binary not
# run in this chroot (a loader or a libc it cannot find), s_cmake builds it
# from source as before, and the log says which path was taken.
#
# Unpacked on demand rather than once: the build tree is cleared between
# runs, and a resumed json-c step must not depend on a cmake step that was
# skipped as already built.
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
    # CMAKE_INSTALL_LIBDIR=lib: the source-built cmake had lib64 patched out
    # of GNUInstallDirs.cmake; Kitware's binary has not, and on a 64-bit host
    # with no /etc/debian_version it chooses lib64. The first run with the
    # binary put libjson-c.so and json-c.pc under /usr/lib64, where nothing
    # in this sysroot looks, and cryptsetup's configure then reported
    # "Package 'json-c' not found" two steps later. Kryptik has one library
    # directory and it is /usr/lib, so say so rather than trusting either
    # cmake's guess.
    "$cmake" -S . -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_STATIC_LIBS=OFF -DBUILD_TESTING=OFF -DBUILD_APPS=OFF \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    "$cmake" --build build
    "$cmake" --install build
    # The check cryptsetup will make, made here where the failure names the
    # package that caused it. Same shape as the devmapper.pc check in s_lvm2.
    [[ -f /usr/lib/pkgconfig/json-c.pc ]] || { echo "no /usr/lib/pkgconfig/json-c.pc (installed under lib64?)"; return 1; }
    [[ -e /usr/lib64/libjson-c.so ]] && { echo "json-c installed into /usr/lib64, which this sysroot does not use"; return 1; }
    pkg-config --exists --print-errors json-c || return 1
    # Prove the library round-trips a document; cryptsetup will parse LUKS2
    # headers with it.
    cat > /tmp/jc.c <<'EOF'
#include <json.h>
#include <stdio.h>
#include <string.h>
int main(void){ struct json_object *o = json_tokener_parse("{\"a\":[1,2],\"b\":\"x\"}");
 if(!o) return 1; const char *s = json_object_to_json_string(o);
 return strcmp(s, "{ \"a\": [ 1, 2 ], \"b\": \"x\" }") == 0 ? 0 : 2; }
EOF
    # Through pkg-config, not hand-written flags: the -I and -l that were here
    # passed on a tree where the .pc file was unfindable, and so proved nothing
    # about what cryptsetup's configure was about to ask.
    # shellcheck disable=SC2046
    gcc -o /tmp/jc /tmp/jc.c $(pkg-config --cflags --libs json-c) && /tmp/jc && echo "ok: json-c parses and prints"
    rm -f /tmp/jc /tmp/jc.c
}

s_libaio() {
    local src; src="$(unpack "libaio-${V_LIBAIO}.tar.gz" "libaio-${V_LIBAIO}")"
    cd "$src"
    sed -i '/install.*libaio.a/s/^/#/' src/Makefile
    make
    make prefix=/usr install
}

# Only device-mapper from LVM2: libdevmapper is what cryptsetup links, and
# dmsetup is what an operator uses to look at a mapping. No lvm binary, no
# daemons, no udev rules for volumes Kryptik does not create.
s_lvm2() {
    local src; src="$(unpack "LVM2.${V_LVM2}.tgz" "LVM2.${V_LVM2}")"
    cd "$src"
    PATH="$PATH:/usr/sbin" ./configure --prefix=/usr --enable-pkgconfig \
        --disable-readline --disable-selinux --with-default-dm-run-dir=/run \
        --enable-udev_sync --disable-silent-rules
    make device-mapper
    # The install target recurses into libdm and dm-tools with separate make
    # processes that both rebuild dmsetup; with the stage's -j4 they ran at
    # once, one relinking while the other recompiled dmsetup.o, and the link
    # saw no object at all ("undefined reference to `main'"). Serial here;
    # the parallel build above is where the time goes.
    make -j1 install_device-mapper
    dmsetup --version | head -1
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
    # LUKS2 with argon2id is the contract in docs/design/encrypted-volumes.md; prove the binary
    # offers it rather than trusting configure. The help text is captured,
    # not piped into grep -q: grep -q exits at its first match, cryptsetup
    # then dies of SIGPIPE, and under pipefail a successful match read as a
    # failed command (exit 141) - which is what stopped the 13:04 run right
    # after cryptsetup had installed.
    cryptsetup benchmark --help >/dev/null 2>&1 || true
    local help; help="$(cryptsetup --help 2>&1 || true)"
    case "$help" in
        *luks2*) echo "ok: luks2 is a known type" ;;
        *) echo "FAIL: cryptsetup --help does not mention luks2"; return 1 ;;
    esac
}

# --- release manifests are verified by the installed system ---
# ssh-keygen -Y is the verification primitive tools/release-manifest.sh uses;
# only that program is installed. No sshd, no ssh, no host keys.
s_openssh() {
    local src; src="$(unpack "openssh-${V_OPENSSH}.tar.gz" "openssh-${V_OPENSSH}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-privsep-path=/var/lib/sshd \
        --with-default-path=/usr/bin --with-superuser-path=/usr/sbin:/usr/bin \
        --with-pid-dir=/run --without-pam
    make ssh-keygen
    install -m 0755 ssh-keygen /usr/bin/ssh-keygen
    # Captured, not piped into grep -q: ssh-keygen prints its usage and exits
    # non-zero, and pipefail made that the step's status (the 13:08 stop).
    # A ssh-keygen that knows -Y complains about the missing namespace or
    # signature; one that does not says "unknown option -- Y".
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
    make PREFIX=/usr COPTS="-DNO_DBUS -DNO_ID"
    # `install`, not the internal `install-common`, which with PREFIX on the
    # command line had nothing to do and installed nothing (the 13:17 stop:
    # "dnsmasq: command not found" right after a successful build).
    make PREFIX=/usr install
    [[ -x /usr/sbin/dnsmasq ]] || { echo "FAIL: /usr/sbin/dnsmasq was not installed"; return 1; }
    /usr/sbin/dnsmasq --version | head -1
}

s_dhcpcd() {
    local src; src="$(unpack "dhcpcd-${V_DHCPCD}.tar.xz" "dhcpcd-${V_DHCPCD}")"
    cd "$src"
    ./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/lib/dhcpcd \
        --dbdir=/var/lib/dhcpcd --runstatedir=/run --privsepuser=dhcpcd
    make
    make install
    dhcpcd --version | head -1
}

# --- the net zone's wireless uplink ------------------------------------------
# wpa_supplicant from its own .config rather than the shipped defconfig: the
# nl80211 driver through libnl, the unix control interface (wpa_cli reaches
# it under /run/wpa_supplicant; no D-Bus, no readline), OpenSSL for WPA3-SAE,
# OWE, DPP and the EAP methods an enterprise network needs, roaming (802.11r)
# and protected management frames. The Makefile takes CFLAGS from the
# environment when they are set and adds none of its own, so the hardening
# flags apply to it as to everything else.
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
    wpa_supplicant -v 2>&1 | head -1
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

# --- device firmware (ADR-012) -----------------------------------------------
# The pinned linux-firmware release, unpacked once into the build tree; its
# own copy-firmware.sh lays the files out as the kernel names them (the
# WHENCE file's Link: entries become symlinks), and build/config/firmware.list
# says which of them ship: each line is a path pattern relative to that tree,
# as `find -path` matches it, or `newest N PATTERN` to keep only the N
# highest-numbered files per device among the pattern's matches (a driver
# asks for its newest supported firmware API and falls back a few versions).
# A selected symlink brings its target along. The regulatory database every
# radio needs before it transmits is a second, smaller pinned release,
# wireless-regdb. What ships is compressed with zstd on the way in (the
# kernel asks for name.zst when name is absent, CONFIG_FW_LOADER_COMPRESS_ZSTD)
# and a selected symlink is rewritten to point at the compressed target.
# Nothing outside the list reaches the image: that is how two gigabytes of
# vendor files become the couple of hundred megabytes the hardware list needs.
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

    # The regulatory database: regulatory.db and its detached signature, which
    # cfg80211 checks against the key built into the kernel before it uses it.
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
# meson runs from its own tree: python3 meson.py works uninstalled, and that
# avoids pip, wheel and setuptools - none of which this image pins.
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
    wayland-scanner --version 2>&1 | head -1
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

# wlroots with the pixman renderer only. No GLES2, no Vulkan, no GBM: those
# need Mesa, which needs LLVM, which is not what a verified base system
# should carry for a desktop that renders text and coloured borders. The
# DRM backend uses dumb buffers; virtio-gpu and simpledrm both provide them.
s_wlroots() {
    meson_build "wlroots-${V_WLROOTS}.tar.gz" "wlroots-${V_WLROOTS}" \
        -Dxwayland=disabled -Dexamples=false -Drenderers=[] -Dallocators=[] \
        -Dbackends=drm,libinput -Dsession=enabled -Dxcb-errors=disabled -Dlibliftoff=disabled
    pkg-config --modversion wlroots-0.19
}

# dwl: the compositor engine's smallest complete user. config.h is Kryptik's
# (build/desktop/dwl-config.h): the keybindings are the trusted launcher, and
# border colours are the compositor-controlled identity channel.
# Three Kryptik inputs go into dwl, and all three are fingerprints of this
# step (the dispatch passes their digests as arguments, like s_kryptikd):
#   build/desktop/dwl-config.h        the configuration; includes the next
#   build/desktop/zone-colours.h      the zone -> border colour table
#   tools/desktop/dwl-zone-borders.py the change to dwl.c that draws them
# config.h uses `ZoneColor`, which only the patch introduces, so copying the
# config without the header and the patch does not build - the first
# version did exactly that.
s_dwl() {
    local cfg_sha="${1:-none}" colours_sha="${2:-none}" patch_sha="${3:-none}"
    local desk="${KRYPTIK_ROOT}/build/desktop"
    local cfg="${desk}/dwl-config.h" colours="${desk}/zone-colours.h"
    local patch="${KRYPTIK_ROOT}/tools/desktop/dwl-zone-borders.py"
    local f
    for f in "$cfg" "$colours" "$patch"; do
        [[ -f "$f" ]] || { echo "desktop input missing: ${f}"; return 1; }
    done
    # The digests were taken when the build order was built. A mismatch
    # means the inputs changed under the build and the stamp about to be
    # written would describe something else.
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
    # The patch is exact-string edits and refuses if the pinned dwl is not
    # the one it was written for; that refusal is this step failing.
    python3 "$patch" .
    grep -q 'zonecolors(Client \*c)' dwl.c || { echo "FAIL: the zone border change is not in dwl.c"; return 1; }
    cp "$colours" zone-colours.h
    cp "$cfg" config.h
    make PREFIX=/usr XWAYLAND= XLIBS=
    make PREFIX=/usr install
    # The installed compositor must carry the change, not just the source
    # tree: the app_id prefix the chooser matches on is a literal in it.
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

# The terminal's font. havoc renders from ONE TrueType file, the path its
# config names (/usr/share/fonts/TTF/DejaVuSansMono.ttf, the upstream
# default), and the image shipped no font at all: the chrome's launcher
# window and every zone terminal died before drawing a glyph, and the first
# GUI run on installed media recorded "(no window)" for the whole session.
# DejaVu Sans Mono is the file that default names; Sans and the bold face
# come along for anything else that draws text. Licence: Bitstream Vera
# terms plus the public-domain DejaVu changes (LICENSE, installed).
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
#
# kryptik-launch (C: the session's client of the launch daemon), the session
# and the chrome (shell, tools/desktop/), and the per-zone Wayland proxy,
# which is Rust and built outside the chroot like kryptikd and handed in
# through KRYPTIK_WLPROXY_BIN. Every input is a digest argument of the step,
# so a change to any of them re-runs it and a binary that changed under the
# build is refused (as s_kryptikd does).
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

    # The raw-socket Wayland probe the boundary tests run inside zones and
    # in zone 0: what globals a client is offered, and what a bind of a
    # hidden one gets. Measured in the guest, not inferred from unit tests.
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
    # It must run on the target, not just install; without arguments it
    # prints its usage and exits 2, which is the one thing it does without
    # a compositor.
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
    lynx -version | head -1
}

PACKAGES=(
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
    "python-final" "s_python_final"
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
    # Adding gdbm is a change of pinned inputs: it needs a version in
    # versions.env, an entry in tools/fetch-sources.sh and an audited line
    # in sources.lock. Until then this package cannot build, and blocking
    # the kernel on a documentation tool would be the wrong trade - so it
    # is listed, unwired, and counted in the "base system is INCOMPLETE"
    # warning at the end of this stage.
    # gdbm before man-db: man-db's configure looks for the gdbm native
    # interface first, and silently picks a different one if it is absent.
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

    # Past this line the stage stops compiling packages and starts making
    # the result bootable. These are ordinary steps - stamped, resumable
    # and fingerprinted like any other - because "configure the init
    # system" fails in exactly the same ways as "build a package", and
    # deserves the same machinery rather than a hand-rolled tail.
    # --- encrypted volumes: LUKS2 zone volumes need cryptsetup, and cryptsetup needs
    #     libdevmapper (LVM2), json-c (cmake) and popt. libaio is LVM2's
    #     own hard requirement at configure time.
    "cmake"       "s_cmake"
    "json-c"      "s_json_c"
    "popt"        "native_build popt-${V_POPT}.tar.gz popt-${V_POPT} --disable-static"
    "libaio"      "s_libaio"
    "lvm2"        "s_lvm2"
    "cryptsetup"  "s_cryptsetup"
    # --- updates: the installed system verifies update manifests itself.
    "openssh"     "s_openssh"
    # --- the net zone: NAT and a resolver in the net zone, a DHCP client for
    #     the uplink.
    "libmnl"      "native_build libmnl-${V_LIBMNL}.tar.bz2 libmnl-${V_LIBMNL} --disable-static"
    "libnftnl"    "native_build libnftnl-${V_LIBNFTNL}.tar.xz libnftnl-${V_LIBNFTNL} --disable-static"
    "nftables"    "native_build nftables-${V_NFTABLES}.tar.xz nftables-${V_NFTABLES} --without-cli --disable-man-doc --disable-python --with-json=no --disable-static"
    "dnsmasq"     "s_dnsmasq"
    "dhcpcd"      "s_dhcpcd"
    # --- the net zone's wireless uplink: libnl (nl80211), wpa_supplicant with
    #     wpa_cli, iw. docs/design/net-zone.md.
    "libnl"       "native_build libnl-${V_LIBNL}.tar.gz libnl-${V_LIBNL} --sysconfdir=/etc --disable-static"
    "wpa-supplicant" "s_wpa_supplicant"
    "iw"          "s_iw"
    # --- device firmware (ADR-012): the files build/config/firmware.list names
    #     out of the pinned linux-firmware release, onto /lib/firmware.
    "linux-firmware" "s_firmware $(sha256_of "${KRYPTIK_ROOT}/build/config/firmware.list" 2>/dev/null || echo none)"
    # --- the desktop. meson and ninja first (build tools), then
    #     the Wayland stack in dependency order, then the compositor and the
    #     applications.
    "meson"       "s_meson"
    "ninja"       "s_ninja"
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
    # dwl takes its three Kryptik inputs as digests, so editing the config,
    # the colour table or the patch rebuilds it (see s_dwl).
    "dwl"         "s_dwl $(sha256_of "${KRYPTIK_ROOT}/build/desktop/dwl-config.h" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/build/desktop/zone-colours.h" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/dwl-zone-borders.py" 2>/dev/null || echo none)"
    "havoc"       "s_havoc"
    "fonts"       "s_fonts"
    "lynx"        "s_lynx"
    "nano"        "native_build nano-${V_NANO}.tar.xz nano-${V_NANO} --sysconfdir=/etc --enable-utf8"
    # The desktop's own pieces: the launch client, the session and the
    # chrome from this tree, and the proxy binary built outside (path and
    # content hash are the step's identity, as for kryptikd).
    "desktop"     "s_desktop ${KRYPTIK_WLPROXY_BIN:-none} $([[ -f "${KRYPTIK_WLPROXY_BIN:-}" ]] && sha256_of "${KRYPTIK_WLPROXY_BIN}" || echo absent) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-launch.c" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-session" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-chrome" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/wlprobe.c" 2>/dev/null || echo none)"

    "etc"         "s_etc ${KRYPTIK_BUILD_COMMIT:-unknown}"
    "console"     "s_console"
    "init"        "s_init"
    # After init: the database lives beside the stage 2 scripts that look
    # for it. Before kryptikd: boot-check verifies both together. Before
    # the updater and the EFI tool: their "does it run" checks source
    # /usr/libexec/kryptik/devices.sh, which this step installs.
    # These globs were separated by a literal backslash-n, which inside a
    # command substitution on one physical line is the FILENAME n, not a line
    # break. cat failed on it, and under pipefail the substitution would
    # collapse to nosvc - silently removing the input fingerprint this step
    # was added to have.
    "services" "s_services $(cat "${KRYPTIK_ROOT}"/build/services/*/* "${KRYPTIK_ROOT}"/build/service-scripts/*.sh "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf 2>/dev/null | sha256_of_stdin || echo nosvc)"
    # The service tree, the boot scripts and the sysctl fragments are inputs
    # to this step, and `declare -f s_services` cannot see a file the recipe
    # reads by path. Without their digest, editing sysinit.sh left the stamp
    # looking valid and the old script installed - which is exactly the
    # stale-stamp defect the kernel fragments had.
    # Its content is an argument so the step rebuilds when the installer
    # changes; the recipe reads it by path, which declare -f cannot see.
    "release-trust" "s_release_trust"
    # efiboot before the updater: the updater's "does it run" check runs
    # kryptik-update, which refuses to start without kryptik-efiboot.
    "efiboot"     "s_efiboot $(sha256_of "${KRYPTIK_ROOT}/tools/efi/kryptik-efiboot.c" 2>/dev/null || echo none)"
    "updater"     "s_updater $(sha256_of "${KRYPTIK_ROOT}/tools/update/kryptik-update" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/update/kryptik-recover" 2>/dev/null || echo none)"
    "netzone"     "s_netzone $(sha256_of "${KRYPTIK_ROOT}/tools/net/netzone-init.sh" 2>/dev/null || echo none)"
    "installer"   "s_installer $(sha256_of "${KRYPTIK_ROOT}/tools/install/kryptik-install.sh" 2>/dev/null || echo none)"
    # The path and the binary's content hash are arguments so that both are
    # part of this step's fingerprint; see s_kryptikd.
    # The zone definitions are an input too, not just the binary. kryptikd
    # validates them at install time, and the pair has to move together: a
    # newer kryptikd made "storage.size" mandatory for ephemeral zones and
    # rejected the definitions this branch was carrying. Hashing the directory
    # means changing a .toml re-runs this step instead of silently shipping a
    # binary that will not read its own config.
    "kryptikd"    "s_kryptikd ${KRYPTIK_KRYPTIKD_BIN:-none} $([[ -f "${KRYPTIK_KRYPTIKD_BIN:-}" ]] && sha256_of "${KRYPTIK_KRYPTIKD_BIN}" || echo absent) $(cat "${KRYPTIK_ROOT}"/compartments/zones/*.toml "${KRYPTIK_ROOT}"/compartments/zones/policy/* 2>/dev/null | sha256_of_stdin || echo nozones) $(sha256_of "${KRYPTIK_ROOT}/tools/kryptik" 2>/dev/null || echo none)"
    # The suites and guest checks the VM drivers run inside the installed
    # system; every file is an input.
    "tests"       "s_tests $(cat "${KRYPTIK_ROOT}"/compartments/tests/*.sh "${KRYPTIK_ROOT}"/compartments/kryptikd/probes/*.sh "${KRYPTIK_ROOT}"/compartments/kryptikd/src/isolate.rs "${KRYPTIK_ROOT}"/compartments/kryptikd/src/rootfs.rs "${KRYPTIK_ROOT}"/build/guest-tests/*.sh "${KRYPTIK_ROOT}"/build/guest-tests/*.py 2>/dev/null | sha256_of_stdin || echo none)"
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

# Every package here is compiled by stage 02's toolchain, so every stamp in
# this stage carries the fingerprint stage 02 finished on: rebuild the
# temporary tools and nothing built with them can claim to be unchanged.
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

echo
if [[ "$unwired" -gt 0 ]]; then
    warn "${unwired} package(s) have no recipe yet; the base system is INCOMPLETE."
    warn "Run with --list to see which."
fi
ok "Stage 04 finished the packages it has recipes for."
dim "Next: make kernel  (stage 05)"
