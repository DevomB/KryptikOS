#!/usr/bin/env bash
# Stage 01: cross toolchain for $LFS_TGT in an isolated sysroot (LFS chapter 5).
# usage: 01-toolchain.sh [--redo <step>]

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# No hardening flags: pass-1 GCC implements -fstack-protector and cannot be
# built with it, and host CFLAGS leak into a cross build. Hardening starts at
# stage 04 (docs/hardening.md).
unset CFLAGS CXXFLAGS LDFLAGS CPPFLAGS LD_LIBRARY_PATH

require_outside_chroot "stage 01"

export LFS="${KRYPTIK_SYSROOT}"
LFS_TGT="$(uname -m)-kryptik-linux-gnu"
export LFS_TGT
export PATH="${LFS}/tools/bin:${PATH}"
export CONFIG_SITE="${LFS}/usr/share/config.site"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(kryptik_default_jobs)}"
export MAKEFLAGS="-j${KRYPTIK_JOBS}"
umask 022

# The host gcc builds this stage.
stage_contract "${BASH_SOURCE[0]}" "" gcc

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"

REDO=""
# shellcheck disable=SC2034  # consumed by step() in common.sh
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR" "$LFS"



# unpack TARBALL TOPDIR [NAME]: extract into $BUILDDIR as NAME; print the path.
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
    # Default PIE and SSP are built into the compiler, so a package that
    # forgets the flags still gets them (docs/hardening.md).
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

    # Clear old headers first, or a V_LINUX bump leaves behind files the new
    # kernel dropped and glibc builds against a mix of two versions.
    rm -rf "${LFS}/usr/include"
    cp -rv usr/include "${LFS}/usr"

    if [[ -f "${LFS}/usr/include/linux/version.h" ]]; then
        echo "installed kernel headers:"
        grep -E "LINUX_VERSION_(MAJOR|PATCHLEVEL|SUBLEVEL)"             "${LFS}/usr/include/linux/version.h" || true
    fi
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

    # LFS's FHS patch moves a few legacy glibc paths; optional in chapter 5.
    local fhs="${KRYPTIK_SOURCES}/glibc-${V_GLIBC}-fhs-1.patch"
    if [[ -f "$fhs" ]]; then
        patch -Np1 -i "$fhs"
    else
        echo "note: FHS patch absent, continuing without it"
    fi

    # Upstream's release/2.40/master branch plus the bug 33088 fix, without
    # which GCC 14 makes ld.so record its own map at address 0 (see the patch
    # set's README). Stage 04 applies the same set to the final glibc.
    apply_repo_patches "glibc-${V_GLIBC}"

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

    # Upstream's check for bug 33088: rtld must not reach __ehdr_start or _end
    # through a run-time relocation, as it stores them before relocating itself.
    echo "--- run-time relocations against __ehdr_start or _end in rtld.os ---"
    local rtld_relocs
    rtld_relocs="$(readelf -rW elf/rtld.os | grep -E 'R_X86_64_64.*(__ehdr_start|_end)' || true)"
    if [[ -n "$rtld_relocs" ]]; then
        printf '%s\n' "$rtld_relocs"
        echo "FAIL: rtld.os takes the loader's own map bounds through a relocated"
        echo "      constant (glibc bug 33088); ld.so would record itself at 0."
        return 1
    fi
    echo "  ok: none"

    make DESTDIR="$LFS" install

    # The ldd wrapper hardcodes a prefix that is wrong for a sysroot install.
    sed "/RTLDLIST=/s@/usr@@g" -i "${LFS}/usr/bin/ldd"
}

# Cross-compiled binaries must request the target's loader, not the host's;
# otherwise everything downstream is silently host-contaminated.
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

    # --enable-default-pie took effect. No `readelf | grep -q`: under
    # pipefail, grep exiting on a match can fail the pipeline with SIGPIPE.
    local hdr
    hdr="$(readelf -h sanity 2>/dev/null || true)"
    if [[ "$hdr" == *"DYN (Position-Independent"* ]]; then
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

# Check every tarball and host tool is there before a long build starts.
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

    # The host check covers these too, but this stage can run on its own.
    local t
    for t in tar make gcc g++ bison flex makeinfo patch readelf find sed; do
        have "$t" || die "required host tool not found: ${t}
Run 'make check' for the full host requirement list."
    done
    ok "preflight: sources and host tools present"
}
preflight

# --- a cross toolchain is never rebuilt over another one's sysroot -------------
# Pass 1 expects a sysroot with no headers; over an older tree, fixincludes
# keeps copies of the old glibc headers, which no stamp hashes. So a tree built
# by another toolchain is cleared, stamps included. The record of which one
# built it stays out of the sysroot, which becomes the root image.
toolchain_id="$({ printf '%s\n' "$V_BINUTILS" "$V_GCC" "$V_GLIBC" "$V_LINUX" "$V_MPFR" "$V_GMP" "$V_MPC"
                  # `|| true`: not every package here has a patch set.
                  cat "${KRYPTIK_ROOT}"/build/patches/{glibc,gcc,binutils}-*/SHA256SUMS 2>/dev/null || true; } | sha256_of_stdin)"
toolchain_marker="${STAMPS}/toolchain-id"

# Anything mounted under DIR? Stage 03 binds this repository into the sysroot,
# and rm --one-file-system does not stop at a bind mount of the same filesystem.
# /proc/mounts has resolved paths with a space as \040 (ENVIRON, since awk -v
# would unescape it). Unreadable means yes.
mounted_under() {
    local real esc
    real="$(realpath -m -- "$1")" || return 0
    [[ -r /proc/mounts ]] || return 0
    esc="$(printf '%s' "$real" | sed -e 's/\\/\\134/g' -e 's/ /\\040/g' -e 's/\t/\\011/g')"
    P="${esc}/" awk 'index($2, ENVIRON["P"]) == 1 { found = 1 } END { exit !found }' /proc/mounts
}

if [[ -d "${LFS}/usr/include" && "$(cat "$toolchain_marker" 2>/dev/null)" != "$toolchain_id" ]]; then
    warn "the sysroot was built by a different toolchain (or by none this script recorded)."
    if mounted_under "$LFS"; then
        die "something is mounted under ${LFS}; unmount it (make chroot-umount), then run this again"
    fi
    # Stage 03's bind points are empty when unmounted.
    for d in kryptik kryptik-sources kryptik-work kryptik-kryptikd; do
        [[ -z "$(ls -A "${LFS}/${d}" 2>/dev/null)" ]] \
            || die "${LFS}/${d} is not empty: it looks mounted. Refusing to remove the sysroot"
    done
    old="${STAMPS}/legacy/toolchain-changed-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "$old"
    find "$STAMPS" -maxdepth 1 -type f -exec mv -f {} "$old/" \;
    rm -rf --one-file-system "${LFS:?}"
    mkdir -p "$LFS"
    warn "cleared ${LFS}; the stamps are archived under ${old}/. Everything is built again."
fi

# A tree with no headers is about to be built by this toolchain.
[[ -d "${LFS}/usr/include" ]] || { mkdir -p "$STAMPS"; printf '%s\n' "$toolchain_id" > "$toolchain_marker"; }

step layout          s_layout
step binutils-pass1  s_binutils_pass1
step gcc-pass1       s_gcc_pass1
step linux-headers   s_linux_headers
step glibc           s_glibc
step sanity-check    s_sanity_check
step libstdcxx       s_libstdcxx

echo
ok "Stage 01 complete. Cross toolchain is in ${LFS}/tools"
dim "Next: make temp-tools"
