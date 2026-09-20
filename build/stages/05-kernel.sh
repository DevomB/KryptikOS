#!/usr/bin/env bash
# Stage 05 — Hardened kernel (docs/roadmap.md, Hardened kernel)
#
# Applies the linux-hardened patchset to the pinned LTS kernel (ADR-009), then
# builds it with Kryptik's two config fragments:
#
#   hardening.fragment   KSPP options that exist in vanilla Linux
#   hardened.fragment    options that exist ONLY with linux-hardened applied
#   boot.fragment        firmware boot, the verified root, the desktop, the
#                        drivers real machines need
#
# and refuses to build a config that does not honour every line of them, or
# one that kernel-hardening-checker faults beyond the accepted list
# (build/config/kernel/checker-accepted.txt).
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
source "$(dirname "${BASH_SOURCE[0]}")/../lib/kconfig-check.sh"
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

    # GCC plugins. KSTACK_ERASE, RANDSTRUCT_FULL and LATENT_ENTROPY are
    # compiler plugins the kernel builds against this compiler's plugin
    # headers; without the headers kconfig drops all three and s_config will
    # refuse the config. This says why, first.
    local plugin_dir; plugin_dir="$(gcc -print-file-name=plugin)"
    if [[ -e "${plugin_dir}/include/plugin-version.h" ]]; then
        echo "PASS: gcc plugin headers at ${plugin_dir}/include"
    else
        echo "WARNING: no gcc plugin headers (${plugin_dir}/include/plugin-version.h is missing):"
        echo "         CONFIG_GCC_PLUGINS resolves to n and the fragment check in s_config will fail."
    fi

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

# CPU microcode, built into the kernel image. The early loader runs before any
# filesystem exists, and Kryptik has no initramfs to carry an update in, so the
# only microcode a Kryptik machine can ever load is what the signed kernel
# holds: CONFIG_EXTRA_FIRMWARE, with every file of Intel's release (the loader
# picks the one named for the running family-model-stepping) and AMD's
# containers from the pinned linux-firmware release. About 18 MB the image
# cannot shed, which is the price of CPU vulnerability fixes on a machine whose
# firmware vendor has stopped shipping them. Intel's "with caveats" directory
# stays out: those updates need a BIOS that expects them.
s_microcode() {
    echo "inputs: intel ${1:-none}, amd from linux-firmware ${2:-none}"
    # Inside the kernel tree, not beside it. Stage 06 links the kernel again
    # for each slot, from a tree that may have come out of a cache or an
    # artifact; both carry the tree and nothing next to it. Staged beside it,
    # the blobs were gone while this step's stamp said done, and the link
    # failed with "no rule to make target .../microcode_amd.bin".
    local dir="${KSRC}/kryptik-microcode"
    rm -rf "$dir"; mkdir -p "$dir"
    tar -xf "${KRYPTIK_SOURCES}/microcode-${V_INTEL_MICROCODE}.tar.gz" -C "$dir" \
        --strip-components=1 --wildcards '*/intel-ucode/*' '*/license'
    tar -xf "${KRYPTIK_SOURCES}/linux-firmware-${V_LINUX_FIRMWARE}.tar.xz" -C "$dir" \
        --strip-components=1 --wildcards '*/amd-ucode/microcode_amd*.bin'
    local n_intel n_amd
    n_intel="$(find "$dir/intel-ucode" -type f | wc -l)"
    n_amd="$(find "$dir/amd-ucode" -type f -name '*.bin' | wc -l)"
    echo "intel-ucode: ${n_intel} files, $(du -sh "$dir/intel-ucode" | cut -f1)"
    echo "amd-ucode  : ${n_amd} files, $(du -sh "$dir/amd-ucode" | cut -f1)"
    [[ "$n_intel" -gt 100 && "$n_amd" -ge 4 ]] \
        || { echo "FAIL: the microcode releases did not unpack as expected"; return 1; }
    # The value of CONFIG_EXTRA_FIRMWARE: every file, relative to the
    # directory, in a fixed order so the same inputs give the same .config.
    ( cd "$dir" && find intel-ucode amd-ucode -type f \( -path 'intel-ucode/*' -o -name '*.bin' \) \
        | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//' ) > "$dir/list"
    echo "list       : $(wc -w < "$dir/list") files"
}

s_config() {
    # $1 is the digest of the config fragments, $2 and $3 the microcode
    # releases. They are not used in the body: they exist so this step's
    # fingerprint covers inputs the recipe reads by path, which `declare -f`
    # cannot see.
    echo "fragment digest: ${1:-none}; microcode: ${2:-none} ${3:-none}"
    cd "$KSRC"

    # Start from the architecture default, then layer Kryptik's fragments.
    make defconfig

    local merge="scripts/kconfig/merge_config.sh"
    [[ -x "$merge" ]] || { echo "merge_config.sh missing"; return 1; }

    # -m merges without running a config pass, so both fragments land before
    # dependency resolution happens once, here, at the end.
    "$merge" -m .config "$FRAG_BASE" "$FRAG_HARDENED" "$FRAG_BOOT"

    # The microcode s_microcode staged goes in by name. It is not a fragment
    # line because its value is a list of some 160 files that changes with
    # every release of either vendor; it is checked below like one.
    local ucode="${KSRC}/kryptik-microcode"
    [[ -s "${ucode}/list" ]] || { echo "no ${ucode}/list: the microcode step has not run"; return 1; }
    scripts/config --set-str EXTRA_FIRMWARE "$(cat "${ucode}/list")" \
                   --set-str EXTRA_FIRMWARE_DIR "$ucode"
    make olddefconfig

    local fw; fw="$(sed -n 's/^CONFIG_EXTRA_FIRMWARE="\(.*\)"$/\1/p' .config)"
    if [[ "$fw" != "$(cat "${ucode}/list")" ]]; then
        echo "FAIL: CONFIG_EXTRA_FIRMWARE did not survive resolution ($(wc -w <<<"$fw") of $(wc -w < "${ucode}/list") files)"
        return 1
    fi
    echo "  ok   CONFIG_EXTRA_FIRMWARE names $(wc -w <<<"$fw") microcode files under ${ucode}"

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

    # Every line of every fragment, not just the ones listed above: an =value
    # line must come out with that value, an "is not set" line must come out
    # unset. kconfig drops a line without a word for an unmet dependency
    # (CONFIG_TIGON3 without PTP_1588_CLOCK_OPTIONAL), for a `select` from
    # something enabled (CONFIG_BLK_DEV_IO_TRACE from defconfig selected
    # DEBUG_FS back on, in a kernel whose fragment asked for it off) and for a
    # prompt that is invisible (every `if EXPERT` option, until EXPERT was
    # set). Each is a mitigation or a driver this kernel does not have while
    # the fragment says it does, which is worse than a fragment that never
    # claimed it. The check is build/lib/kconfig-check.sh, shared with
    # tools/resolve-kernel-config.sh so CI asks the same question of the same
    # fragments in minutes.
    echo
    echo "--- verifying every fragment line survived resolution ---"
    if ! kconfig_fragment_check .config "$FRAG_BASE" "$FRAG_HARDENED" "$FRAG_BOOT"; then
        echo
        echo "Fragment lines were not honoured. Fix the dependency, disable what"
        echo "selects the option, or drop the claim from the fragment."
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
    # The microcode is in the image, not merely in the config: the built-in
    # firmware table names each blob, so one name per vendor must be there.
    echo "--- built-in microcode ---"
    local blob
    for blob in "$(tr ' ' '\n' < "${KSRC}/kryptik-microcode/list" | grep -m1 '^intel-ucode/')" \
                amd-ucode/microcode_amd_fam19h.bin; do
        grep -a -q -F "$blob" vmlinux || { echo "FAIL: ${blob} is not built into vmlinux"; return 1; }
        echo "  ok   ${blob}"
    done
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

    # An UNSIGNED copy of one module, for the integrity suite. modules_install
    # signs what it installs (MODULE_SIG_ALL); the build tree's .ko is the
    # same object without the signature, and a kernel that enforces signing
    # has to refuse it. mac80211_hwsim is the module whose signed copy the
    # same suite loads, so one driver proves both directions.
    local hwsim="drivers/net/wireless/virtual/mac80211_hwsim.ko"
    [[ -f "$hwsim" ]] || { echo "FAIL: ${hwsim} was not built (CONFIG_MAC80211_HWSIM=m, boot.fragment)"; return 1; }
    if grep -q '~Module signature appended~' "$hwsim"; then
        echo "FAIL: the build tree's ${hwsim} carries a signature; the unsigned control needs one without"; return 1
    fi
    install -d -m 0755 "${KRYPTIK_DESTDIR}/usr/lib/kryptik/kernel"
    install -m 0644 "$hwsim" "${KRYPTIK_DESTDIR}/usr/lib/kryptik/kernel/mac80211_hwsim-unsigned.ko"
    echo "unsigned control module: /usr/lib/kryptik/kernel/mac80211_hwsim-unsigned.ko"
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
    for s in unpack patch microcode config hardening-check build modules install verify-install; do
        [[ -f "${STAMPS}/${STAMP_PREFIX}${s}" ]] && mv -f "${STAMPS}/${STAMP_PREFIX}${s}" "$gone/"
    done
    warn "the kernel tree ${KSRC} is gone but its steps were stamped as built;"
    warn "those stamps are archived under ${gone}/ and the tree is unpacked, patched, configured and built again."
fi

step unpack          s_unpack
step patch           s_patch
step microcode       s_microcode "$V_INTEL_MICROCODE" "$V_LINUX_FIRMWARE"
step config          s_config "$FRAG_DIGEST" "$V_INTEL_MICROCODE" "$V_LINUX_FIRMWARE"

# kernel-hardening-checker, the Kernel Self-Protection Project's reference
# list, on the .config that is about to be built and on the command line
# stage 06 compiles in (its COMMON_ARGS line). Every failure it reports is
# fixed in a fragment or accepted, with its reason, in
# build/config/kernel/checker-accepted.txt; tools/check-kernel-hardening.sh
# holds the result to that list and fails the stage otherwise. Until
# 2026-09-18 this stage ended with a suggestion to run the checker by hand,
# and nobody had: its first run found stack erasing and structure layout
# randomization absent from every kernel built so far, because the two
# fragment symbols that named them had become derived ones upstream.
#
# The inputs are the config, the accepted list and the command line, so a
# change to any of the three runs the check again.
s_hardening_check() {
    echo "config digest: ${1:-none}; accepted list digest: ${2:-none}; command line digest: ${3:-none}"
    "${KRYPTIK_ROOT}/tools/check-kernel-hardening.sh" --config "${KSRC}/.config"
}
ACCEPTED_LIST="${CONFIG_DIR}/checker-accepted.txt"
COMMON_ARGS_DIGEST="$(grep '^COMMON_ARGS=' "${KRYPTIK_ROOT}/build/stages/06-iso.sh" | sha256_of_stdin)"
step hardening-check s_hardening_check \
    "$(sha256_of "${KSRC}/.config" 2>/dev/null || echo noconfig)" \
    "$(sha256_of "$ACCEPTED_LIST")" "$COMMON_ARGS_DIGEST"

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
dim "  hardening: kernel-hardening-checker ran in the hardening-check step; what it still reports, and why, is build/config/kernel/checker-accepted.txt"
