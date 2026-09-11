#!/usr/bin/env bash
# Stage 05 — Hardened kernel (Phase 4 of docs/roadmap.md)
#
# Applies the linux-hardened patchset to the pinned LTS kernel (ADR-009), then
# builds it with Kryptik's two config fragments:
#
#   hardening.fragment   KSPP options that exist in vanilla Linux
#   hardened.fragment    options that exist ONLY with linux-hardened applied
#
# Runs INSIDE the chroot, like stage 04, and for the same reason: the kernel
# must be compiled by the native TARGET compiler, and must land in the target's
# own /boot and /lib/modules.
#
#   make kernel                      drives stage 03 to mount, run this, unmount
#   ./05-kernel.sh --redo patch      force one step to rerun (inside the chroot)
#
# ---------------------------------------------------------------------------
# Two things this stage used to get wrong, both worth keeping written down.
#
# 1. INSTALLATION DESTINATION.
#
#    It computed  LFS="${KRYPTIK_WORK}/sysroot"  and installed there. Inside
#    the chroot that is wrong. With the default KRYPTIK_WORK the path happened
#    to resolve, through the /kryptik bind mount, back to the chroot's own
#    root - right answer, by coincidence, from broken reasoning. With
#    KRYPTIK_WORK pointed at native storage (which any real build needs) the
#    path does not exist inside the chroot at all, and `cp` and
#    `modules_install` simply CREATE it: a nested, half-populated target tree
#    with the kernel several levels below the /boot anybody would look in.
#
#    The sysroot is now resolved by build/lib/common.sh, which knows which
#    side of the chroot boundary it is on. Inside, it is "/" and DESTDIR is
#    empty. Stage 03 additionally refuses to expose ${KRYPTIK_WORK}/sysroot
#    inside the chroot, so the old calculation cannot silently come back.
#
# 2. THE COMPILER.
#
#    It prepended ${LFS}/tools/bin to PATH - the stage 01 CROSS toolchain.
#    Inside the chroot that directory is either absent or, worse, present and
#    holding a compiler configured against a sysroot that is no longer where
#    it thinks it is. The kernel must be built by the native target compiler
#    that stage 02 installed and stage 04 builds against: /usr/bin/gcc,
#    reporting an x86_64-kryptik-linux-gnu triple.
#
#    s_compiler_check below asserts exactly that, before anything is compiled.
# ---------------------------------------------------------------------------

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

require_inside_chroot "stage 05" "kernel"

LFS_TGT="$(uname -m)-kryptik-linux-gnu"
export LFS_TGT

# No PATH surgery. Inside the chroot /usr/bin:/usr/sbin is the whole world,
# deliberately - a build that reaches anything else has escaped the chroot.

KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(nproc)}"
export MAKEFLAGS="-j${KRYPTIK_JOBS}"

# Contract for the shared step() in build/lib/common.sh.
STAGE_FILE="${BASH_SOURCE[0]}"
STAMP_PREFIX="kernel-"
STAMP_CC="gcc"

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"
KSRC="${BUILDDIR}/linux-${V_LINUX}"

# Where the kernel lands. Empty DESTDIR inside the chroot means "the live
# root", which is what every build system already understands.
BOOTDIR="${KRYPTIK_DESTDIR}/boot"
MODDIR="${KRYPTIK_DESTDIR}/lib/modules"

CONFIG_DIR="${KRYPTIK_ROOT}/build/config/kernel"
FRAG_BASE="${CONFIG_DIR}/hardening.fragment"
FRAG_HARDENED="${CONFIG_DIR}/hardened.fragment"

REDO=""
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR"

# --- steps -----------------------------------------------------------------

# The first thing this stage does, before unpacking 1.5GB of kernel source:
# prove the compiler about to build it is the right one.
#
# "Right" means three separate things, and a kernel can be built by the wrong
# compiler in all three ways without anything failing until it will not boot:
#
#   * a NATIVE compiler, not a cross compiler wrapped around a stale sysroot
#   * targeting Kryptik, not the host distribution
#   * the one stage 04 built the rest of userspace against
s_compiler_check() {
    local cc; cc="$(command -v gcc || true)"
    [[ -n "$cc" ]] || { echo "no gcc on PATH (${PATH})"; return 1; }
    echo "gcc          : ${cc}"
    echo "version      : $(gcc --version | head -1)"
    echo "target triple: $(gcc -dumpmachine)"
    echo "ld           : $(command -v ld || echo missing) ($(ld --version | head -1))"
    echo "PATH         : ${PATH}"

    # A compiler under /tools is the stage 01 cross toolchain. It has no
    # business building the kernel, and its presence here means PATH surgery
    # crept back in.
    case "$cc" in
        /tools/*|*/tools/bin/*)
            echo "FAIL: gcc resolves inside the stage 01 cross toolchain (${cc})."
            echo "The kernel must be built by the native target compiler in /usr/bin."
            return 1
            ;;
    esac

    local triple; triple="$(gcc -dumpmachine)"
    if [[ "$triple" != "$LFS_TGT" ]]; then
        echo "FAIL: gcc targets '${triple}', expected '${LFS_TGT}'."
        echo "This is the host's compiler or a differently-configured one; the"
        echo "kernel would not match the userspace stage 04 built."
        return 1
    fi
    echo "PASS: native target compiler"

    # It must also actually work, and produce target binaries.
    local t; t="$(mktemp -d)"
    # shellcheck disable=SC2064  # $t is wanted at trap-definition time
    trap "rm -rf '$t'" RETURN
    echo 'int main(void){return 0;}' > "$t/probe.c"
    gcc -o "$t/probe" "$t/probe.c" || { echo "FAIL: gcc cannot link"; return 1; }
    readelf -l "$t/probe" | grep "Requesting program interpreter" || true
    "$t/probe" || { echo "FAIL: gcc output does not run here"; return 1; }
    echo "PASS: compiler produces working native binaries"

    # The kernel build needs these; missing ones fail deep inside a 40-minute
    # compile rather than here.
    local missing=0 t2
    for t2 in make ld objcopy objdump ar nm perl bison flex openssl python3 \
              gawk tar xz gzip depmod; do
        if have "$t2"; then
            printf '  ok      %s\n' "$t2"
        else
            printf '  MISSING %s\n' "$t2"; missing=$((missing + 1))
        fi
    done
    # libelf is what objtool links against.
    if [[ -e /usr/lib/libelf.so || -e /usr/lib/libelf.a ]]; then
        echo "  ok      libelf"
    else
        echo "  MISSING libelf (objtool will not build)"; missing=$((missing + 1))
    fi
    [[ "$missing" -eq 0 ]] || { echo "${missing} kernel build prerequisite(s) missing"; return 1; }
}

s_unpack() {
    rm -rf "$KSRC"
    tar -xf "${KRYPTIK_SOURCES}/linux-${V_LINUX}.tar.xz" -C "$BUILDDIR"
    [[ -d "$KSRC" ]] || { echo "expected ${KSRC}"; return 1; }
    cd "$KSRC"
    make mrproper
}

# The patch is version-specific. A mismatch means a partially-patched tree,
# which is far worse than an unpatched one - so dry-run first and refuse to
# touch the tree unless the whole patch applies.
s_patch() {
    local patch="${KRYPTIK_SOURCES}/linux-hardened-v${V_LINUX_HARDENED}.patch"
    [[ -f "$patch" ]] || { echo "linux-hardened patch not fetched"; return 1; }
    cd "$KSRC"

    echo "--- dry run ---"
    if ! patch -Np1 --dry-run -i "$patch"; then
        echo
        echo "The linux-hardened patch does not apply cleanly to ${V_LINUX}."
        echo "V_LINUX and V_LINUX_HARDENED must name the same kernel version."
        echo "Check: https://github.com/anthraxx/linux-hardened/releases"
        return 1
    fi

    echo "--- applying ---"
    patch -Np1 -i "$patch"

    # A hardened-only symbol must now exist, or the patch did not do what the
    # filename claims.
    if ! grep -rq "config SLAB_CANARY" security/ mm/ 2>/dev/null \
    && ! grep -rq "SLAB_CANARY" security/Kconfig.hardening 2>/dev/null; then
        echo "WARNING: SLAB_CANARY not found after patching - verify the patch"
    fi
}

s_config() {
    cd "$KSRC"

    # Start from the architecture default, then layer Kryptik's fragments.
    make defconfig

    local merge="scripts/kconfig/merge_config.sh"
    [[ -x "$merge" ]] || { echo "merge_config.sh missing"; return 1; }

    # -m merges without running a config pass, so both fragments land before
    # dependency resolution happens once, here, at the end.
    "$merge" -m .config "$FRAG_BASE" "$FRAG_HARDENED"
    make olddefconfig

    # merge_config.sh silently drops symbols whose dependencies are unmet, so
    # verify the ones that carry Kryptik's actual guarantees actually survived.
    echo
    echo "--- verifying critical options survived ---"
    local missing=0 opt
    for opt in CONFIG_SECURITY_LANDLOCK \
               CONFIG_SECCOMP_FILTER \
               CONFIG_USER_NS \
               CONFIG_NET_NS \
               CONFIG_DM_VERITY \
               CONFIG_DM_CRYPT \
               CONFIG_MODULE_SIG_FORCE \
               CONFIG_SECURITY_LOCKDOWN_LSM \
               CONFIG_INIT_ON_ALLOC_DEFAULT_ON \
               CONFIG_SLAB_CANARY \
               CONFIG_MITIGATION_PAGE_TABLE_ISOLATION; do
        if grep -q "^${opt}=y" .config; then
            echo "  ok   ${opt}"
        else
            echo "  MISSING ${opt}"
            missing=$((missing + 1))
        fi
    done

    # Kryptik requires unprivileged user namespaces to be OFF: zones are
    # created by kryptikd, which is privileged. See hardened.fragment.
    if grep -q "^CONFIG_USER_NS_UNPRIVILEGED=y" .config; then
        echo "  WARNING: CONFIG_USER_NS_UNPRIVILEGED is enabled"
        echo "  Kryptik expects this off - zone creation is privileged."
    else
        echo "  ok   CONFIG_USER_NS_UNPRIVILEGED disabled"
    fi

    if [[ "$missing" -gt 0 ]]; then
        echo
        echo "${missing} critical option(s) did not survive config resolution."
        echo "These are not optional - the zone model and boot integrity"
        echo "depend on them. Investigate before building."
        return 1
    fi
}

s_build() {
    cd "$KSRC"
    make
    # Record what actually compiled this kernel, in the kernel. This string is
    # what ends up in /proc/version, and it is the only durable evidence of
    # which compiler built a given image.
    echo "--- linux_banner ---"
    strings vmlinux 2>/dev/null | grep -m1 "Linux version" || true
}

s_modules() {
    cd "$KSRC"
    # Empty INSTALL_MOD_PATH: inside the chroot the target IS the root. The
    # old value here was ${KRYPTIK_WORK}/sysroot, which is the nested-tree bug
    # described at the top of this file.
    make INSTALL_MOD_PATH="${KRYPTIK_DESTDIR}" modules_install
}

s_install() {
    cd "$KSRC"
    mkdir -p "$BOOTDIR"
    cp -v arch/x86/boot/bzImage "${BOOTDIR}/kryptik-${V_LINUX}"
    cp -v System.map "${BOOTDIR}/System.map-${V_LINUX}"
    cp -v .config "${BOOTDIR}/config-${V_LINUX}"
}

# Prove the kernel landed where a bootloader will look for it, and nowhere
# else. This is the check that would have caught the nested-tree bug.
s_verify_install() {
    local img="${BOOTDIR}/kryptik-${V_LINUX}"
    local n=0
    echo "--- installed kernel ---"
    ls -la "$img" "${BOOTDIR}/System.map-${V_LINUX}" "${BOOTDIR}/config-${V_LINUX}"
    file "$img" 2>/dev/null || true

    [[ -s "$img" ]] || { echo "FAIL: ${img} missing or empty"; n=$((n + 1)); }

    local modver="${MODDIR}/${V_LINUX}"
    if [[ -d "$modver" ]]; then
        echo "modules      : ${modver} ($(find "$modver" -name '*.ko*' | wc -l) objects)"
        [[ -f "${modver}/modules.dep" ]] || { echo "FAIL: depmod did not run"; n=$((n + 1)); }
    else
        echo "FAIL: no module tree at ${modver}"; n=$((n + 1))
    fi

    # There must be exactly one target tree. A ${KRYPTIK_WORK}/sysroot inside
    # the chroot is the nested-install signature.
    if [[ -e "${KRYPTIK_WORK}/sysroot" ]]; then
        echo "FAIL: ${KRYPTIK_WORK}/sysroot exists inside the chroot."
        echo "Something installed into a nested target tree. See the header of"
        echo "this file."
        n=$((n + 1))
    else
        echo "ok: no nested target tree under ${KRYPTIK_WORK}"
    fi

    echo "--- compiler recorded in the image ---"
    strings "$KSRC/vmlinux" 2>/dev/null | grep -m1 -i "gcc version" || \
        echo "(no GCC version string found in vmlinux)"

    [[ "$n" -eq 0 ]] || { echo "${n} installation problem(s)"; return 1; }
}

# --- run -------------------------------------------------------------------

log "Kryptik stage 05 — hardened kernel"
dim "  kernel   : linux-${V_LINUX} (longterm)"
dim "  patchset : linux-hardened v${V_LINUX_HARDENED}"
dim "  parallel : ${MAKEFLAGS}"
dim "  boot dir : ${BOOTDIR}"
dim "  modules  : ${MODDIR}"
dim "  work     : ${KRYPTIK_WORK}"
echo

[[ -f "${KRYPTIK_SOURCES}/linux-${V_LINUX}.tar.xz" ]] \
    || die "kernel source not fetched. Run: make sources"
[[ -f "$FRAG_BASE" ]]     || die "missing ${FRAG_BASE}"
[[ -f "$FRAG_HARDENED" ]] || die "missing ${FRAG_HARDENED}"

# Refuse to build an EOL kernel (ADR-009).
#
# `make kernel` runs this on the HOST before entering the chroot, where there
# is a network and kernel.org is reachable. Running it again here is cheap and
# covers a direct invocation; it degrades to a warning when offline, which
# inside the chroot it always is.
"${KRYPTIK_ROOT}/tools/check-kernel-eol.sh" || die "kernel EOL check failed"

step compiler-check  s_compiler_check
step unpack          s_unpack
step patch           s_patch
step config          s_config
step build           s_build
step modules         s_modules
step install         s_install
step verify-install  s_verify_install

echo
ok "Stage 05 complete."
dim "  kernel : ${BOOTDIR}/kryptik-${V_LINUX}"
dim "  modules: ${MODDIR}/${V_LINUX}"
dim "Verify hardening with: kernel-hardening-checker -c ${KSRC}/.config"
