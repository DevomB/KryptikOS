#!/usr/bin/env bash
# Stage 05 — Hardened kernel (Phase 4 of docs/roadmap.md)
#
# Applies the linux-hardened patchset to the pinned LTS kernel (ADR-009), then
# builds it with Kryptik's two config fragments:
#
#   hardening.fragment   KSPP options that exist in vanilla Linux
#   hardened.fragment    options that exist ONLY with linux-hardened applied
#
# Resumable via per-step stamps, like stage 01.
#   ./05-kernel.sh --redo patch

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

export LFS="${KRYPTIK_WORK}/sysroot"
LFS_TGT="$(uname -m)-kryptik-linux-gnu"
export LFS_TGT
export PATH="${LFS}/tools/bin:${PATH}"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(nproc)}"
export MAKEFLAGS="-j${KRYPTIK_JOBS}"

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"
KSRC="${BUILDDIR}/linux-${V_LINUX}"

CONFIG_DIR="${KRYPTIK_ROOT}/build/config/kernel"
FRAG_BASE="${CONFIG_DIR}/hardening.fragment"
FRAG_HARDENED="${CONFIG_DIR}/hardened.fragment"

REDO=""
[[ "${1:-}" == "--redo" ]] && REDO="${2:?--redo needs a step name}"

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR"

step() {
    local name="kernel-$1"; shift
    if [[ "$REDO" == "${name#kernel-}" ]]; then
        warn "forcing rebuild of ${name}"
        rm -f "${STAMPS:?}/${name}"
    fi
    if [[ -f "${STAMPS}/${name}" ]]; then
        dim "  skip ${name} (already done)"
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
        die "stage 05 aborted at ${name}"
    fi
}

# --- steps -----------------------------------------------------------------

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

    # -m merges without running olddefconfig, so both fragments land before
    # dependency resolution happens once at the end.
    "$merge" -m .config "$FRAG_BASE" "$FRAG_HARDENED"
    make KCONFIG_ALLCONFIG=.config olddefconfig

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
}

s_modules() {
    cd "$KSRC"
    make INSTALL_MOD_PATH="$LFS" modules_install
}

s_install() {
    cd "$KSRC"
    mkdir -p "${LFS}/boot"
    cp -v arch/x86/boot/bzImage "${LFS}/boot/kryptik-${V_LINUX}"
    cp -v System.map "${LFS}/boot/System.map-${V_LINUX}"
    cp -v .config "${LFS}/boot/config-${V_LINUX}"
}

# --- run -------------------------------------------------------------------

log "Kryptik stage 05 — hardened kernel"
dim "  kernel   : linux-${V_LINUX} (longterm)"
dim "  patchset : linux-hardened v${V_LINUX_HARDENED}"
dim "  parallel : ${MAKEFLAGS}"
echo

[[ -f "${KRYPTIK_SOURCES}/linux-${V_LINUX}.tar.xz" ]] \
    || die "kernel source not fetched. Run: make sources"
[[ -f "$FRAG_BASE" ]]     || die "missing ${FRAG_BASE}"
[[ -f "$FRAG_HARDENED" ]] || die "missing ${FRAG_HARDENED}"

# Refuse to build an EOL kernel (ADR-009).
"${KRYPTIK_ROOT}/tools/check-kernel-eol.sh" || die "kernel EOL check failed"

step unpack   s_unpack
step patch    s_patch
step config   s_config
step build    s_build
step modules  s_modules
step install  s_install

echo
ok "Stage 05 complete. Kernel at ${LFS}/boot/kryptik-${V_LINUX}"
dim "Verify hardening with: kernel-hardening-checker -c ${KSRC}/.config"
