#!/usr/bin/env bash
# Stage 01 — Cross toolchain (Phase 1 of docs/roadmap.md)
#
# Builds a cross toolchain targeting $LFS_TGT against an isolated sysroot, so
# the host toolchain never contaminates the target. Follows the LFS chapter 5
# sequence with Kryptik's own configuration choices.
#
# Resumable: each step writes a stamp. Re-running skips completed steps.
# Force one step to rebuild with:  ./01-toolchain.sh --redo glibc

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# ---------------------------------------------------------------------------
# Hardening flags are deliberately NOT loaded here.
#
# Pass-1 GCC is the thing that *implements* -fstack-protector and friends; it
# cannot be built with them. Worse, an exported CFLAGS leaks host assumptions
# into a cross build and yields a toolchain that miscompiles in ways which do
# not surface until stage 04. LFS is explicit about this.
#
# Hardening is introduced at stage 04, where the target compiler builds target
# packages. See docs/hardening.md.
# ---------------------------------------------------------------------------
unset CFLAGS CXXFLAGS LDFLAGS CPPFLAGS LD_LIBRARY_PATH

export LFS="${KRYPTIK_WORK}/sysroot"
LFS_TGT="$(uname -m)-kryptik-linux-gnu"
export LFS_TGT
export PATH="${LFS}/tools/bin:${PATH}"
export CONFIG_SITE="${LFS}/usr/share/config.site"
export MAKEFLAGS="-j$(nproc)"
umask 022

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"

REDO=""
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR" "$LFS"

# --- step machinery --------------------------------------------------------

step() {
    local name="$1"; shift
    if [[ "$REDO" == "$name" ]]; then
        warn "forcing rebuild of ${name}"
        rm -f "${STAMPS:?}/${name}"
    fi
    if [[ -f "${STAMPS}/${name}" ]]; then
        dim "  skip ${name} (already built)"
        return 0
    fi
    log "${name}"
    local logfile="${LOGS}/${name}.log"
    local start=$SECONDS
    if "$@" > "$logfile" 2>&1; then
        touch "${STAMPS}/${name}"
        ok "${name} ($(( SECONDS - start ))s)"
    else
        err "${name} failed. Last 30 lines of ${logfile}:"
        tail -30 "$logfile" >&2
        die "stage 01 aborted at ${name}"
    fi
}

# Extract a tarball into $BUILDDIR under a caller-chosen directory name.
unpack() {
    local tarball="$1" srcdir="$2" destname="${3:-}"
    local dir="${BUILDDIR}/${destname:-$srcdir}"
    rm -rf "$dir"
    tar -xf "${KRYPTIK_SOURCES}/${tarball}" -C "$BUILDDIR"
    if [[ -n "$destname" && "$destname" != "$srcdir" ]]; then
        mv "${BUILDDIR}/${srcdir}" "$dir"
    fi
    [[ -d "$dir" ]] || die "expected ${dir} after unpacking ${tarball}"
    printf '%s' "$dir"
}

# --- steps -----------------------------------------------------------------

s_layout() {
    mkdir -pv "$LFS"/{etc,var,tools}
    mkdir -pv "$LFS"/usr/{bin,lib,sbin,share}
    local d
    for d in bin lib sbin; do
        [[ -e "${LFS}/${d}" ]] || ln -sv "usr/${d}" "${LFS}/${d}"
    done
    case "$(uname -m)" in
        x86_64) mkdir -pv "${LFS}/lib64" ;;
    esac
}

s_binutils_pass1() {
    local src
    src="$(unpack "binutils-${V_BINUTILS}.tar.xz" "binutils-${V_BINUTILS}")"
    mkdir -p "${src}/build"
    cd "${src}/build"
    ../configure \
        --prefix="${LFS}/tools" \
        --with-sysroot="$LFS" \
        --target="$LFS_TGT" \
        --disable-nls \
        --enable-gprofng=no \
        --disable-werror \
        --enable-new-dtags \
        --enable-default-hash-style=gnu
    make
    make install
}

s_gcc_pass1() {
    local src
    src="$(unpack "gcc-${V_GCC}.tar.xz" "gcc-${V_GCC}")"
    cd "$src"

    # GCC expects its math prerequisites unpacked in-tree under fixed names.
    tar -xf "${KRYPTIK_SOURCES}/mpfr-${V_MPFR}.tar.xz" && mv "mpfr-${V_MPFR}" mpfr
    tar -xf "${KRYPTIK_SOURCES}/gmp-${V_GMP}.tar.xz"   && mv "gmp-${V_GMP}"   gmp
    tar -xf "${KRYPTIK_SOURCES}/mpc-${V_MPC}.tar.gz"   && mv "mpc-${V_MPC}"   mpc

    # Kryptik uses /usr/lib, not /usr/lib64, on x86_64.
    case "$(uname -m)" in
        x86_64) sed -e "/m64=/s/lib64/lib/" -i.orig gcc/config/i386/t-linux64 ;;
    esac

    mkdir -p build
    cd build
    # --enable-default-pie and --enable-default-ssp bake two of Kryptik's
    # hardening guarantees into the compiler itself, so a package that forgets
    # the flags still gets them. See docs/hardening.md.
    ../configure \
        --target="$LFS_TGT" \
        --prefix="${LFS}/tools" \
        --with-glibc-version="${V_GLIBC}" \
        --with-sysroot="$LFS" \
        --with-newlib \
        --without-headers \
        --enable-default-pie \
        --enable-default-ssp \
        --disable-nls \
        --disable-shared \
        --disable-multilib \
        --disable-threads \
        --disable-libatomic \
        --disable-libgomp \
        --disable-libquadmath \
        --disable-libssp \
        --disable-libvtv \
        --disable-libstdcxx \
        --enable-languages=c,c++
    make
    make install

    # Pass-1 GCC ships an incomplete limits.h; assemble the full one.
    cd "$src"
    local libgcc_dir
    libgcc_dir="$(dirname "$("${LFS_TGT}-gcc" -print-libgcc-file-name)")"
    cat gcc/limitx.h gcc/glimits.h gcc/limity.h > "${libgcc_dir}/include/limits.h"
}

s_linux_headers() {
    local src
    src="$(unpack "linux-${V_LINUX}.tar.xz" "linux-${V_LINUX}")"
    cd "$src"
    make mrproper
    make headers
    find usr/include -type f ! -name "*.h" -delete
    cp -rv usr/include "${LFS}/usr"
}

s_glibc() {
    local src
    src="$(unpack "glibc-${V_GLIBC}.tar.xz" "glibc-${V_GLIBC}")"
    cd "$src"

    # The dynamic loader must be reachable at its canonical path.
    case "$(uname -m)" in
        i?86)
            ln -sfv ld-linux.so.2 "${LFS}/lib/ld-lsb.so.3"
            ;;
        x86_64)
            ln -sfv ../lib/ld-linux-x86-64.so.2 "${LFS}/lib64"
            ln -sfv ../lib/ld-linux-x86-64.so.2 "${LFS}/lib64/ld-lsb-x86-64.so.3"
            ;;
    esac

    # The LFS FHS patch relocates a few directories glibc still puts in legacy
    # places. Optional for chapter 5 — applied only when present.
    local fhs="${KRYPTIK_SOURCES}/glibc-${V_GLIBC}-fhs-1.patch"
    if [[ -f "$fhs" ]]; then
        patch -Np1 -i "$fhs"
    else
        echo "note: FHS patch absent, continuing without it"
    fi

    mkdir -p build
    cd build
    echo "rootsbindir=/usr/sbin" > configparms
    ../configure \
        --prefix=/usr \
        --host="$LFS_TGT" \
        --build="$(../scripts/config.guess)" \
        --enable-kernel=4.19 \
        --with-headers="${LFS}/usr/include" \
        --disable-nscd \
        libc_cv_slibdir=/usr/lib
    make
    make DESTDIR="$LFS" install

    # The ldd wrapper hardcodes a prefix that is wrong for a sysroot install.
    sed "/RTLDLIST=/s@/usr@@g" -i "${LFS}/usr/bin/ldd"
}

# The most important check in this stage: proves the cross compiler produces
# binaries linked against the TARGET loader, not the host's. If this passes
# for the wrong reason, everything downstream is silently host-contaminated.
s_sanity_check() {
    cd "$BUILDDIR"
    echo "int main(void){return 0;}" > sanity.c
    "${LFS_TGT}-gcc" -o sanity sanity.c

    local interp
    interp="$(readelf -l sanity | grep "Requesting program interpreter" || true)"
    echo "interpreter line: ${interp}"

    if [[ "$interp" != *"/lib64/ld-linux-x86-64.so.2"* ]] \
    && [[ "$interp" != *"/lib/ld-linux.so.2"* ]]; then
        echo "FAIL: unexpected program interpreter."
        echo "The toolchain is linking against the host loader, which means the"
        echo "sysroot is not isolated. Do NOT continue to stage 02."
        return 1
    fi
    echo "PASS: binaries link against the target loader."

    # Verifies --enable-default-pie actually took effect.
    if readelf -h sanity | grep -q "DYN (Position-Independent"; then
        echo "PASS: default-PIE active"
    else
        echo "FAIL: binaries are not position-independent by default"
        return 1
    fi

    rm -f sanity sanity.c
}

s_libstdcxx() {
    local src
    src="$(unpack "gcc-${V_GCC}.tar.xz" "gcc-${V_GCC}" "gcc-${V_GCC}-libstdcxx")"
    cd "$src"
    mkdir -p build
    cd build
    ../libstdc++-v3/configure \
        --host="$LFS_TGT" \
        --build="$(../config.guess)" \
        --prefix=/usr \
        --disable-multilib \
        --disable-nls \
        --disable-libstdcxx-pch \
        --with-gxx-include-dir="/tools/${LFS_TGT}/include/c++/${V_GCC}"
    make
    make DESTDIR="$LFS" install
    rm -vf "${LFS}"/usr/lib/lib{stdc++{,exp,fs},supc++}.la
}

# --- run -------------------------------------------------------------------

log "Kryptik stage 01 — cross toolchain"
dim "  sysroot : ${LFS}"
dim "  target  : ${LFS_TGT}"
dim "  parallel: ${MAKEFLAGS}"
dim "  logs    : ${LOGS}"
echo

[[ -d "$KRYPTIK_SOURCES" ]] || die "no sources found. Run: make sources"

# Preflight: confirm every tarball this stage needs is present BEFORE starting.
# A 40-minute build that dies at minute 35 on a missing file is a bad trade for
# the two seconds this costs.
preflight() {
    local missing=0 f
    for f in "binutils-${V_BINUTILS}.tar.xz" \
             "gcc-${V_GCC}.tar.xz" \
             "gmp-${V_GMP}.tar.xz" \
             "mpfr-${V_MPFR}.tar.xz" \
             "mpc-${V_MPC}.tar.gz" \
             "linux-${V_LINUX}.tar.xz" \
             "glibc-${V_GLIBC}.tar.xz"; do
        if [[ ! -f "${KRYPTIK_SOURCES}/${f}" ]]; then
            err "missing source: ${f}"
            missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]] || die "${missing} source tarball(s) missing. Run: make sources"

    # Host tools this stage invokes directly. The host checker covers these too,
    # but stage 01 can be run on its own.
    local t
    for t in tar make gcc g++ bison flex makeinfo patch readelf find sed; do
        have "$t" || die "required host tool not found: ${t}
Run 'make check' for the full host requirement list."
    done
    ok "preflight: sources and host tools present"
}
preflight

step layout          s_layout
step binutils-pass1  s_binutils_pass1
step gcc-pass1       s_gcc_pass1
step linux-headers   s_linux_headers
step glibc           s_glibc
step sanity-check    s_sanity_check
step libstdcxx       s_libstdcxx

echo
ok "Stage 01 complete. Cross toolchain is in ${LFS}/tools"
dim "Next: make temp-tools  (stage 02 — not yet implemented)"
