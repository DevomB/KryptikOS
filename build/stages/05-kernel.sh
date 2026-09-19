#!/usr/bin/env bash
# Stage 05 — Hardened kernel (docs/roadmap.md, Hardened kernel)
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

# Stage 05 runs inside the chroot and drives the native target compiler.
stage_contract "${BASH_SOURCE[0]}" "kernel-" gcc

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
# What firmware boot, the verified root and the desktop need
# (docs/design/boot-and-updates.md).
FRAG_BOOT="${CONFIG_DIR}/boot.fragment"

REDO=""
# shellcheck disable=SC2034  # consumed by step() in common.sh
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
    # $1 is the digest of the two config fragments. It is not used in the
    # body: it exists so this step's fingerprint covers files the recipe
    # reads by path, which `declare -f` cannot see.
    echo "fragment digest: ${1:-none}"
    cd "$KSRC"

    # Start from the architecture default, then layer Kryptik's fragments.
    make defconfig

    local merge="scripts/kconfig/merge_config.sh"
    [[ -x "$merge" ]] || { echo "merge_config.sh missing"; return 1; }

    # -m merges without running a config pass, so both fragments land before
    # dependency resolution happens once, here, at the end.
    "$merge" -m .config "$FRAG_BASE" "$FRAG_HARDENED" "$FRAG_BOOT"
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
               CONFIG_EFI_STUB \
               CONFIG_CMDLINE_BOOL \
               CONFIG_CMDLINE_OVERRIDE \
               CONFIG_DM_INIT \
               CONFIG_EFIVAR_FS \
               CONFIG_OVERLAY_FS \
               CONFIG_DRM_VIRTIO_GPU \
               CONFIG_NFT_MASQ \
               CONFIG_DM_VERITY \
               CONFIG_DM_CRYPT \
               CONFIG_CRYPTO_XTS \
               CONFIG_FS_ENCRYPTION \
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

    # Every =y line in boot.fragment, not just the ones listed above. The
    # hardware drivers there are what a real machine's disk, network and
    # keyboard need, and one that kconfig drops for an unmet dependency is a
    # machine that boots into nothing, found only when someone tries.
    echo
    echo "--- verifying every boot.fragment option survived ---"
    local boot_opt boot_dropped=0
    while read -r boot_opt; do
        if ! grep -q "^${boot_opt}=y" .config; then
            echo "  DROPPED ${boot_opt} ($(grep -E "^${boot_opt}=|^# ${boot_opt} is not set" .config || echo absent))"
            boot_dropped=$((boot_dropped + 1))
        fi
    done < <(grep -oE '^CONFIG_[A-Z0-9_]+=y$' "$FRAG_BOOT" | cut -d= -f1)
    echo "  $(grep -cE '^CONFIG_[A-Z0-9_]+=y$' "$FRAG_BOOT") options, ${boot_dropped} dropped"
    missing=$((missing + boot_dropped))

    # Everything the fragments say must be OFF.
    #
    # s_config used to verify only the options that must be ON. An option can
    # fail to be off silently: a Kconfig `select` from any enabled symbol turns
    # one on unconditionally and overrides an explicit "is not set" without a
    # diagnostic. That is not hypothetical - CONFIG_DEBUG_FS was =y in a kernel
    # whose fragment asked for it off, because CONFIG_BLK_DEV_IO_TRACE from
    # defconfig selects it.
    #
    # A fragment that claims a mitigation the kernel does not have is worse
    # than one that never claimed it.
    echo
    echo "--- verifying the options the fragments say must be OFF ---"
    local off_violations=0 opt_off
    while read -r opt_off; do
        [[ -z "$opt_off" ]] && continue
        if grep -q "^${opt_off}=y" .config; then
            echo "  ON, BUT REQUESTED OFF: ${opt_off}"
            echo "      something enabled selects it; find it with"
            echo "      grep -rn 'select ${opt_off#CONFIG_}' ."
            off_violations=$((off_violations + 1))
        elif grep -q "^${opt_off}=m" .config; then
            echo "  MODULE, BUT REQUESTED OFF: ${opt_off}"
            off_violations=$((off_violations + 1))
        else
            echo "  ok   ${opt_off} is off"
        fi
    done < <(grep -hoE '^# CONFIG_[A-Z0-9_]+ is not set' "$FRAG_BASE" "$FRAG_HARDENED"              | awk '{print $2}' | sort -u)

    if [[ "$off_violations" -gt 0 ]]; then
        echo
        echo "${off_violations} option(s) the fragments disable are enabled anyway."
        echo "Each one is a mitigation this kernel does not have while the"
        echo "fragment says it does. Disable whatever selects them, or drop"
        echo "the claim from the fragment."
        return 1
    fi

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
    # $1 is HOSTLDFLAGS and $2 the digest of .config, both arguments so this
    # step's fingerprint covers them; see the step list.
    echo "host link flags: ${1:-none}"
    echo "config digest  : ${2:-none}"
    cd "$KSRC"
    make
    # Record what actually compiled this kernel, in the kernel. This string is
    # what ends up in /proc/version, and it is the only durable evidence of
    # which compiler built a given image.
    echo "--- linux_banner ---"
    strings vmlinux 2>/dev/null | grep -m1 "Linux version" || true
}

s_modules() {
    echo "config digest: ${1:-none}"
    cd "$KSRC"
    # Empty INSTALL_MOD_PATH: inside the chroot the target IS the root. The
    # old value here was ${KRYPTIK_WORK}/sysroot, which is the nested-tree bug
    # described at the top of this file.
    make INSTALL_MOD_PATH="${KRYPTIK_DESTDIR}" modules_install
}

s_install() {
    echo "config digest: ${1:-none}"
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

    # The module tree is named by the kernel RELEASE, not by the source
    # version - LOCALVERSION makes those differ. Looking under
    # ${MODDIR}/${V_LINUX} reported "no module tree at /lib/modules/6.18.50"
    # about a kernel whose modules had installed, signed and depmod'd perfectly
    # well into /lib/modules/6.18.50-hardened1. include/config/kernel.release
    # is the name the kernel's own build used, so ask it instead of rebuilding
    # the name from parts.
    local krel
    krel="$(cat "${KSRC}/include/config/kernel.release" 2>/dev/null || true)"
    [[ -n "$krel" ]] || krel="${V_LINUX}"
    echo "kernel release: ${krel}"
    local modver="${MODDIR}/${krel}"
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
    # This check was wrong twice over, and both ways said "no compiler here"
    # about a kernel that records one:
    #
    #   1. It searched for "gcc version". The kernel writes the compiler into
    #      linux_banner as "gcc (GCC) 14.2.0" - that text never appears.
    #   2. `strings | grep -m1` makes grep exit at the first match while
    #      strings still has megabytes to write, so strings dies of SIGPIPE and
    #      the || branch fires regardless. Same trap that once failed a good
    #      glibc.
    #
    # grep reads the file directly, and [ -~] stops at the NUL that ends the
    # banner. The compiler is the only durable evidence of what built an image,
    # so an absent banner is a failure, not a remark.
    local banner
    banner="$(grep -a -m1 -o 'Linux version [ -~]*' "$KSRC/vmlinux" 2>/dev/null || true)"
    if [[ -z "$banner" ]]; then
        echo "FAIL: vmlinux carries no Linux version banner - the image does"
        echo "      not record what compiled it."
        n=$((n + 1))
    else
        echo "  ${banner}"
        case "$banner" in
            *GCC*|*gcc*) : ;;
            *) echo "FAIL: the banner names no compiler: ${banner}"
               n=$((n + 1)) ;;
        esac
    fi

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

# Build-time host tools link libgcc_s.so.1 the ordinary way, when needed.
#
# Until 2026-09-13 this exported HOSTLDFLAGS="-Wl,--no-as-needed -lgcc_s" so
# that sorttable - which ends its sorter threads with pthread_exit() - did not
# abort on a loader that could not unwind through a dlopen()ed libgcc_s
# (docs/glibc-loader-defect.md, glibc bug 33088). The loader is fixed at its
# source (build/patches/glibc-2.40/0004-*.patch) and the workaround is gone on
# purpose: a kernel link that sorts its tables is now part of the proof.
# HOSTLDFLAGS is still an input to the build step below, so setting it in
# the environment still rebuilds rather than being silently ignored.

# The fragments and the host link flags are inputs to these steps, and
# `declare -f` cannot see a file read by path or a variable read from the
# environment. Passing their digests makes a change to either rebuild rather
# than silently reusing a stamp written under different inputs.
FRAG_DIGEST="$(cat "$FRAG_BASE" "$FRAG_HARDENED" "$FRAG_BOOT" | sha256_of_stdin)"

# The kernel is compiled by the toolchain stage 04 assembled - its glibc,
# binutils, the libraries its host tools link (openssl, libelf, zlib), and
# the tools it runs (bc, bison, flex, perl, kmod). elfutils is the last of
# those in stage 04's order, so seeding from it covers the whole closure
# without tying a kernel rebuild to eudev, s6 or the service tree, which
# the kernel never sees.
stage_depends_on "bs-" elfutils

step compiler-check  s_compiler_check
# The stamps record what was built; the tree records what is here. The build
# tree under work/build is not an output and gets removed to reclaim space,
# which leaves unpack, patch and config stamped as done for a tree that no
# longer exists; the next time a later step goes stale (a stage this one
# builds on changed) it dies in the middle with "cd: linux-...: No such file
# or directory" - which is how the first post-build after the tree was
# cleared ended. So: no tree, no tree stamps. They are archived together
# with the steps that read the tree, and all of them run again.
if [[ ! -d "$KSRC" && -f "${STAMPS}/${STAMP_PREFIX}unpack" ]]; then
    gone="${STAMPS}/legacy/kernel-tree-gone-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "$gone"
    for s in unpack patch config build modules install verify-install; do
        [[ -f "${STAMPS}/${STAMP_PREFIX}${s}" ]] && mv -f "${STAMPS}/${STAMP_PREFIX}${s}" "$gone/"
    done
    warn "the kernel tree ${KSRC} is gone but its steps were stamped as built;"
    warn "those stamps are archived under ${gone}/ and the tree is unpacked, patched, configured and built again."
fi

step unpack          s_unpack
step patch           s_patch
step config          s_config "$FRAG_DIGEST"

# .config is an input to every step after this one, and a step's fingerprint
# covers its own recipe and arguments - not the outputs of the steps before it.
# So editing a fragment rebuilt the config and then SKIPPED build, modules and
# install as "already built, inputs unchanged". The kernel in /boot stayed the
# previous one, and the boot proved it: the guest called securityfs an unknown
# filesystem type while the .config beside it said CONFIG_SECURITYFS=y.
#
# Evaluated here, after s_config has written the file, so it is the digest of
# the configuration these steps are about to build from.
CFG_DIGEST="$(sha256_of "${KSRC}/.config" 2>/dev/null || echo noconfig)"

step build           s_build "${HOSTLDFLAGS:-}" "$CFG_DIGEST"
step modules         s_modules "$CFG_DIGEST"
step install         s_install "$CFG_DIGEST"
step verify-install  s_verify_install "$CFG_DIGEST"

echo
ok "Stage 05 complete."
dim "  kernel : ${BOOTDIR}/kryptik-${V_LINUX}"
# The release, not the source version: they differ whenever LOCALVERSION
# is set, and a summary naming a directory that does not exist is the
# same defect the verify step had.
dim "  modules: ${MODDIR}/$(cat "${KSRC}/include/config/kernel.release" 2>/dev/null || echo "${V_LINUX}")"
dim "Verify hardening with: kernel-hardening-checker -c ${KSRC}/.config"
