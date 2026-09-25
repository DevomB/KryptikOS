#!/usr/bin/env bash
# Stage 05: the linux-hardened kernel (ADR-009), built in the chroot by the
# native target compiler from the fragments in build/config/kernel:
#   hardening.fragment   KSPP options in vanilla Linux
#   hardened.fragment    options that exist only with linux-hardened
#   boot.fragment        firmware boot, the verified root, the desktop, drivers
# It installs into the chroot's own /boot and /lib/modules. An install under
# ${KRYPTIK_WORK}/sysroot would be a nested, half-populated target tree.
# usage: make kernel   (or, inside the chroot, 05-kernel.sh [--redo <step>])

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/kconfig-check.sh"
load_config

require_inside_chroot "stage 05" "kernel"

LFS_TGT="$(uname -m)-kryptik-linux-gnu"
export LFS_TGT

# PATH stays the chroot's /usr/bin:/usr/sbin; never the /tools cross toolchain.

KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(nproc)}"
export MAKEFLAGS="-j${KRYPTIK_JOBS}"

stage_contract "${BASH_SOURCE[0]}" "kernel-" gcc

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"
KSRC="${BUILDDIR}/linux-${V_LINUX}"

# KRYPTIK_DESTDIR is empty inside the chroot: the live root.
BOOTDIR="${KRYPTIK_DESTDIR}/boot"
MODDIR="${KRYPTIK_DESTDIR}/lib/modules"

CONFIG_DIR="${KRYPTIK_ROOT}/build/config/kernel"
FRAG_BASE="${CONFIG_DIR}/hardening.fragment"
FRAG_HARDENED="${CONFIG_DIR}/hardened.fragment"
# See docs/design/boot-and-updates.md.
FRAG_BOOT="${CONFIG_DIR}/boot.fragment"

REDO=""
# shellcheck disable=SC2034  # consumed by step() in common.sh
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR"

# --- steps -----------------------------------------------------------------

# Before unpacking the source: gcc must be native (not the /tools cross
# compiler), target Kryptik, and be the one stage 04 built userspace with.
s_compiler_check() {
    local cc; cc="$(command -v gcc || true)"
    [[ -n "$cc" ]] || { echo "no gcc on PATH (${PATH})"; return 1; }
    echo "gcc          : ${cc}"
    echo "version      : $(gcc --version | head -1)"
    echo "target triple: $(gcc -dumpmachine)"
    echo "ld           : $(command -v ld || echo missing) ($(ld --version | head -1))"
    echo "PATH         : ${PATH}"

    # /tools holds the stage 01 cross toolchain.
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

    # KSTACK_ERASE, RANDSTRUCT_FULL and LATENT_ENTROPY are GCC plugins; without
    # the plugin headers kconfig drops them and s_config refuses the config.
    local plugin_dir; plugin_dir="$(gcc -print-file-name=plugin)"
    if [[ -e "${plugin_dir}/include/plugin-version.h" ]]; then
        echo "PASS: gcc plugin headers at ${plugin_dir}/include"
    else
        echo "WARNING: no gcc plugin headers (${plugin_dir}/include/plugin-version.h is missing):"
        echo "         CONFIG_GCC_PLUGINS resolves to n and the fragment check in s_config will fail."
    fi

    # And it must link binaries that run.
    local t; t="$(mktemp -d)"
    # shellcheck disable=SC2064  # $t is wanted at trap-definition time
    trap "rm -rf '$t'" RETURN
    echo 'int main(void){return 0;}' > "$t/probe.c"
    gcc -o "$t/probe" "$t/probe.c" || { echo "FAIL: gcc cannot link"; return 1; }
    readelf -l "$t/probe" | grep "Requesting program interpreter" || true
    "$t/probe" || { echo "FAIL: gcc output does not run here"; return 1; }
    echo "PASS: compiler produces working native binaries"

    # Kernel build prerequisites, checked before a long compile.
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

# Dry-run first: a partly applied patch is worse than none.
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

    # A hardened-only symbol must now exist.
    if ! grep -rq "config SLAB_CANARY" security/ mm/ 2>/dev/null \
    && ! grep -rq "SLAB_CANARY" security/Kconfig.hardening 2>/dev/null; then
        echo "WARNING: SLAB_CANARY not found after patching - verify the patch"
    fi
}

# CPU microcode, built into the signed kernel (CONFIG_EXTRA_FIRMWARE): with no
# initramfs, the early loader can find it nowhere else. All of Intel's files
# (it picks by family-model-stepping) and AMD's containers, about 18 MB. Intel's
# "with caveats" updates stay out; they need a BIOS that expects them.
s_microcode() {
    echo "inputs: intel ${1:-none}, amd from linux-firmware ${2:-none}"
    # Inside the kernel tree: stage 06 relinks from a cached or artifact copy
    # of the tree, which carries nothing beside it.
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
    # The CONFIG_EXTRA_FIRMWARE list, sorted so the .config is stable.
    ( cd "$dir" && find intel-ucode amd-ucode -type f \( -path 'intel-ucode/*' -o -name '*.bin' \) \
        | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//' ) > "$dir/list"
    echo "list       : $(wc -w < "$dir/list") files"
}

s_config() {
    # $1 fragment digest, $2 $3 microcode releases: arguments only so the
    # stamp covers inputs read by path.
    echo "fragment digest: ${1:-none}; microcode: ${2:-none} ${3:-none}"
    cd "$KSRC"

    # Start from the architecture default, then layer Kryptik's fragments.
    make defconfig

    local merge="scripts/kconfig/merge_config.sh"
    [[ -x "$merge" ]] || { echo "merge_config.sh missing"; return 1; }

    # -m merges without a config pass; olddefconfig resolves once, below.
    "$merge" -m .config "$FRAG_BASE" "$FRAG_HARDENED" "$FRAG_BOOT"

    # Not a fragment line: the file list changes with every vendor release.
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

    # Options Kryptik's guarantees rest on (build/lib/kconfig-check.sh).
    echo
    echo "--- verifying critical options survived ---"
    local missing=0
    kconfig_critical_check .config || missing=1

    # Every fragment line, since kconfig drops lines silently.
    echo
    echo "--- verifying every fragment line survived resolution ---"
    if ! kconfig_fragment_check .config "$FRAG_BASE" "$FRAG_HARDENED" "$FRAG_BOOT"; then
        echo
        echo "Fragment lines were not honoured. Fix the dependency, disable what"
        echo "selects the option, or drop the claim from the fragment."
        return 1
    fi

    # Unprivileged user namespaces stay off; kryptikd creates the zones.
    if grep -q "^CONFIG_USER_NS_UNPRIVILEGED=y" .config; then
        echo "  WARNING: CONFIG_USER_NS_UNPRIVILEGED is enabled"
        echo "  Kryptik expects this off - zone creation is privileged."
    else
        echo "  ok   CONFIG_USER_NS_UNPRIVILEGED disabled"
    fi

    if [[ "$missing" -gt 0 ]]; then
        echo
        echo "Critical option(s) did not survive config resolution (MISSING, above)."
        echo "These are not optional - the zone model and boot integrity"
        echo "depend on them. Investigate before building."
        return 1
    fi
}

s_build() {
    # $1 HOSTLDFLAGS, $2 .config digest: arguments so the stamp covers them.
    echo "host link flags: ${1:-none}"
    echo "config digest  : ${2:-none}"
    cd "$KSRC"
    make
    # The banner (/proc/version) records which compiler built the image.
    echo "--- linux_banner ---"
    strings vmlinux 2>/dev/null | grep -m1 "Linux version" || true
    # The built-in firmware table names each blob; check one per vendor.
    echo "--- built-in microcode ---"
    local blob
    for blob in "$(tr ' ' '\n' < "${KSRC}/kryptik-microcode/list" | grep -m1 '^intel-ucode/')" \
                amd-ucode/microcode_amd_fam19h.bin; do
        grep -a -q -F "$blob" vmlinux || { echo "FAIL: ${blob} is not built into vmlinux"; return 1; }
        echo "  ok   ${blob}"
    done
}

s_size() {
    # $1 .config digest, $2 budget digest: reruns when either changes.
    cd "$KSRC"
    local img_bytes ucode_bytes budget
    img_bytes="$(stat -c %s arch/x86/boot/bzImage)" || return 1
    ucode_bytes="$(du -sb kryptik-microcode 2>/dev/null | cut -f1)"
    budget="$(awk '$1 == "bzimage_max_bytes" {print $2}' "${CONFIG_DIR}/size-budget")"
    [[ "$budget" =~ ^[0-9]+$ ]] || { echo "FAIL: ${CONFIG_DIR}/size-budget names no bzimage_max_bytes"; return 1; }
    echo "bzImage ${img_bytes} bytes (microcode, which does not compress: ${ucode_bytes:-0}); budget ${budget}"
    echo "built in: $(grep -c '=y$' .config) options, modules: $(grep -c '=m$' .config)"
    [[ "$img_bytes" -le "$budget" ]] || { echo "FAIL: over budget by $(( img_bytes - budget )) bytes; make it a module or leave it out"; return 1; }
}

s_modules() {
    echo "config digest: ${1:-none}"
    cd "$KSRC"
    # KRYPTIK_DESTDIR is empty: inside the chroot the target is the root.
    make INSTALL_MOD_PATH="${KRYPTIK_DESTDIR}" modules_install
}

s_install() {
    echo "config digest: ${1:-none}"
    cd "$KSRC"
    mkdir -p "$BOOTDIR"
    cp -v arch/x86/boot/bzImage "${BOOTDIR}/kryptik-${V_LINUX}"
    cp -v System.map "${BOOTDIR}/System.map-${V_LINUX}"
    cp -v .config "${BOOTDIR}/config-${V_LINUX}"

    # The integrity suite loads the signed mac80211_hwsim and must see this
    # unsigned copy refused. modules_install signs; the build tree's .ko is not.
    local hwsim="drivers/net/wireless/virtual/mac80211_hwsim.ko"
    [[ -f "$hwsim" ]] || { echo "FAIL: ${hwsim} was not built (CONFIG_MAC80211_HWSIM=m, boot.fragment)"; return 1; }
    if grep -q '~Module signature appended~' "$hwsim"; then
        echo "FAIL: the build tree's ${hwsim} carries a signature; the unsigned control needs one without"; return 1
    fi
    install -d -m 0755 "${KRYPTIK_DESTDIR}/usr/lib/kryptik/kernel"
    install -m 0644 "$hwsim" "${KRYPTIK_DESTDIR}/usr/lib/kryptik/kernel/mac80211_hwsim-unsigned.ko"
    echo "unsigned control module: /usr/lib/kryptik/kernel/mac80211_hwsim-unsigned.ko"
}

# The kernel is where a bootloader will look, and nowhere else.
s_verify_install() {
    local img="${BOOTDIR}/kryptik-${V_LINUX}"
    local n=0
    echo "--- installed kernel ---"
    ls -la "$img" "${BOOTDIR}/System.map-${V_LINUX}" "${BOOTDIR}/config-${V_LINUX}"
    file "$img" 2>/dev/null || true

    [[ -s "$img" ]] || { echo "FAIL: ${img} missing or empty"; n=$((n + 1)); }

    # Modules live under the kernel release (include/config/kernel.release),
    # which LOCALVERSION makes differ from V_LINUX.
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

    # A ${KRYPTIK_WORK}/sysroot here means a nested install.
    if [[ -e "${KRYPTIK_WORK}/sysroot" ]]; then
        echo "FAIL: ${KRYPTIK_WORK}/sysroot exists inside the chroot."
        echo "Something installed into a nested target tree. See the header of"
        echo "this file."
        n=$((n + 1))
    else
        echo "ok: no nested target tree under ${KRYPTIK_WORK}"
    fi

    echo "--- compiler recorded in the image ---"
    # grep reads vmlinux itself: `strings | grep -m1` can fail on SIGPIPE.
    # [ -~] stops at the NUL ending the banner, which names the compiler.
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

# Refuse an EOL kernel (ADR-009). `make kernel` already ran this online on the
# host; here it covers a direct run, and offline it only warns.
"${KRYPTIK_ROOT}/tools/check-kernel-eol.sh" || die "kernel EOL check failed"

# No -lgcc_s workaround for sorttable's pthread_exit(): the patched glibc
# loader copes with it (build/patches/glibc-2.40/README.md), and this link
# tests that.

# Files read by path and variables from the environment are invisible to
# `declare -f`, so their digests are passed as step arguments.
FRAG_DIGEST="$(cat "$FRAG_BASE" "$FRAG_HARDENED" "$FRAG_BOOT" | sha256_of_stdin)"

# elfutils is the last of the kernel's build dependencies in stage 04's order,
# so this covers them without tying the kernel to later packages.
stage_depends_on "bs-" elfutils

step compiler-check  s_compiler_check
# The build tree may be deleted to reclaim space; then every step that reads
# it must run again, so their stamps are archived.
if [[ ! -d "$KSRC" && -f "${STAMPS}/${STAMP_PREFIX}unpack" ]]; then
    gone="${STAMPS}/legacy/kernel-tree-gone-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "$gone"
    for s in unpack patch microcode config hardening-check build size modules install verify-install; do
        [[ -f "${STAMPS}/${STAMP_PREFIX}${s}" ]] && mv -f "${STAMPS}/${STAMP_PREFIX}${s}" "$gone/"
    done
    warn "the kernel tree ${KSRC} is gone but its steps were stamped as built;"
    warn "those stamps are archived under ${gone}/ and the tree is unpacked, patched, configured and built again."
fi
# The module signing key never goes into the cache, which a pull request's run
# can restore. A tree without it builds again from `build`: kbuild makes a new
# key, and the kernel and its modules are signed as one pair.
if [[ -d "$KSRC" && ! -f "$KSRC/certs/signing_key.pem" && -f "${STAMPS}/${STAMP_PREFIX}build" ]]; then
    gone="${STAMPS}/legacy/kernel-key-gone-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "$gone"
    for s in build size modules install verify-install; do
        [[ -f "${STAMPS}/${STAMP_PREFIX}${s}" ]] && mv -f "${STAMPS}/${STAMP_PREFIX}${s}" "$gone/"
    done
    warn "the kernel tree has no module signing key; it is built and installed again with a new one"
fi

step unpack          s_unpack
step patch           s_patch
step microcode       s_microcode "$V_INTEL_MICROCODE" "$V_LINUX_FIRMWARE"
step config          s_config "$FRAG_DIGEST" "$V_INTEL_MICROCODE" "$V_LINUX_FIRMWARE"

# kernel-hardening-checker (KSPP) on this .config and on stage 06's COMMON_ARGS
# command line. Each finding must be fixed in a fragment or listed, with its
# reason, in build/config/kernel/checker-accepted.txt.
s_hardening_check() {
    echo "config digest: ${1:-none}; accepted list digest: ${2:-none}; command line digest: ${3:-none}"
    "${KRYPTIK_ROOT}/tools/check-kernel-hardening.sh" --config "${KSRC}/.config"
}
ACCEPTED_LIST="${CONFIG_DIR}/checker-accepted.txt"
COMMON_ARGS_DIGEST="$(grep '^COMMON_ARGS=' "${KRYPTIK_ROOT}/build/stages/06-iso.sh" | sha256_of_stdin)"
step hardening-check s_hardening_check \
    "$(sha256_of "${KSRC}/.config" 2>/dev/null || echo noconfig)" \
    "$(sha256_of "$ACCEPTED_LIST")" "$COMMON_ARGS_DIGEST"

# .config is an input of every later step, but a fingerprint covers only a
# step's recipe and arguments; hence this digest, taken after s_config wrote it.
CFG_DIGEST="$(sha256_of "${KSRC}/.config" 2>/dev/null || echo noconfig)"

step build           s_build "${HOSTLDFLAGS:-}" "$CFG_DIGEST"
step size            s_size "$CFG_DIGEST" "$(sha256_of "${CONFIG_DIR}/size-budget")"
step modules         s_modules "$CFG_DIGEST"
step install         s_install "$CFG_DIGEST"
step verify-install  s_verify_install "$CFG_DIGEST"

echo
ok "Stage 05 complete."
dim "  kernel : ${BOOTDIR}/kryptik-${V_LINUX}"
# The release, not V_LINUX: they differ under LOCALVERSION.
dim "  modules: ${MODDIR}/$(cat "${KSRC}/include/config/kernel.release" 2>/dev/null || echo "${V_LINUX}")"
dim "  hardening: kernel-hardening-checker ran in the hardening-check step; what it still reports, and why, is build/config/kernel/checker-accepted.txt"
