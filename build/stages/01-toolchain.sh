#!/usr/bin/env bash
# Stage 01: cross toolchain for $LFS_TGT in an isolated sysroot (LFS chapter 5).
# usage: 01-toolchain.sh [--redo <step> | --toolchain-id]

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# No flags before stage 04: pass-1 GCC cannot build with the SSP it provides, and host flags leak in.
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

# The host gcc: the cross one exists only halfway through this stage.
stage_contract "${BASH_SOURCE[0]}" "" gcc

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"

REDO=""
# shellcheck disable=SC2034  # consumed by step() in common.sh
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR" "$LFS"

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

    gcc_prereqs

    # Kryptik uses /usr/lib, not /usr/lib64, on x86_64.
    case "$(uname -m)" in
        x86_64) sed -e "/m64=/s/lib64/lib/" -i.orig gcc/config/i386/t-linux64 ;;
    esac

    mkdir -p build
    cd build
    # Default PIE and SSP in the compiler, so a package that drops the flags still gets them.
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

    # Cleared first, or a V_LINUX bump leaves headers the new kernel dropped for glibc to mix in.
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

    # release/2.40 plus the bug 33088 fix (see the README); stage 04 applies the same set.
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

    # Upstream's bug 33088 check: rtld stores __ehdr_start and _end before relocating itself.
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

# Cross-compiled binaries must request the target's loader, or the host leaks into everything.
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

    # Default PIE took effect; no readelf | grep -q, which can SIGPIPE under pipefail.
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

# The steps, in order: walked once for the toolchain's identity, then run.
STEPS=(
    "layout s_layout"
    "binutils-pass1 s_binutils_pass1"
    "gcc-pass1 s_gcc_pass1"
    "linux-headers s_linux_headers"
    "glibc s_glibc"
    "sanity-check --check s_sanity_check"
    "libstdcxx s_libstdcxx"
)

# The toolchain's identity, walked before any step runs: no step argument may read build output.
toolchain_id="$(for row in "${STEPS[@]}"; do
                    read -ra s <<< "$row"
                    [[ "${s[1]}" != --check ]] || continue
                    if declare -F set_flags_for > /dev/null; then set_flags_for "${s[0]}"; fi
                    fp="$(stamp_fingerprint "${s[@]}")"
                    printf '%s %s\n' "${s[0]}" "$fp"
                    STAMP_DEPS="${STAMP_DEPS}${s[0]}=${fp};"
                done | sha256_of_stdin)"
if [[ "${1:-}" == --toolchain-id ]]; then printf '%s\n' "$toolchain_id"; exit 0; fi

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

# Kept out of the sysroot, which becomes the root image.
toolchain_marker="${STAMPS}/toolchain-id"

# Mounted under DIR (unreadable means yes)? rm --one-file-system crosses stage 03's binds.
mounted_under() {
    local real esc
    real="$(realpath -m -- "$1")" || return 0
    [[ -r /proc/mounts ]] || return 0
    # /proc/mounts writes a space as \040; ENVIRON, since awk -v would unescape it.
    esc="$(printf '%s' "$real" | sed -e 's/\\/\\134/g' -e 's/ /\\040/g' -e 's/\t/\\011/g')"
    P="${esc}/" awk 'index($2, ENVIRON["P"]) == 1 { found = 1 } END { exit !found }' /proc/mounts
}

# Over another toolchain's tree, fixincludes would keep old glibc headers that no stamp hashes.
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

for row in "${STEPS[@]}"; do
    read -ra s <<< "$row"
    step "${s[@]}"
done

echo
ok "Stage 01 complete. Cross toolchain is in ${LFS}/tools"
dim "Next: make temp-tools"
