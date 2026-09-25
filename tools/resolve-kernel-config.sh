#!/usr/bin/env bash
# Resolve the kernel config on the host as stage 05 does in the chroot, and
# check that every fragment line survived.
#
#   ./tools/resolve-kernel-config.sh [OUT]
#
#   OUT   where the resolved .config is written;
#         default ${KRYPTIK_WORK}/kconfig-tree/kryptik.config
#
# validate-kernel-config.sh shows each symbol exists; this shows it survives
# resolution, which drops unmet dependencies as silently as typos. The host's
# gcc stands in for the chroot's, so CC_HAS_* and GCC plugin options can differ.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/kconfig-check.sh"
load_config

OUT="${1:-${KRYPTIK_WORK}/kconfig-tree/kryptik.config}"
TREE_DIR="${KRYPTIK_WORK}/kconfig-tree"
KSRC="${TREE_DIR}/linux-${V_LINUX}"
TARBALL="${KRYPTIK_SOURCES}/linux-${V_LINUX}.tar.xz"
PATCH="${KRYPTIK_SOURCES}/linux-hardened-v${V_LINUX_HARDENED}.patch"
CONFIG_DIR="${KRYPTIK_ROOT}/build/config/kernel"
FRAGMENTS=("${CONFIG_DIR}/hardening.fragment" "${CONFIG_DIR}/hardened.fragment" "${CONFIG_DIR}/boot.fragment")

for t in make gcc flex bison; do
    have "$t" || die "${t} is required to run kconfig"
done
[[ -f "$TARBALL" ]] || die "kernel source not fetched: ${TARBALL}. Run: make sources"
[[ -f "$PATCH" ]]   || die "linux-hardened patch not fetched: ${PATCH}. Run: make sources"

# Unpacked and patched once per linux-hardened version, which the stamp names.
stamp="${TREE_DIR}/.patched-${V_LINUX_HARDENED}"
if [[ ! -f "$stamp" ]]; then
    log "unpacking linux-${V_LINUX} (this is the whole tree, kconfig needs its Makefile and scripts)"
    rm -rf "$TREE_DIR"; mkdir -p "$TREE_DIR"
    tar -xf "$TARBALL" -C "$TREE_DIR"
    [[ -d "$KSRC" ]] || die "expected ${KSRC} after unpacking"
    log "applying linux-hardened ${V_LINUX_HARDENED}"
    ( cd "$KSRC" && patch -Np1 --dry-run -s -i "$PATCH" >/dev/null ) \
        || die "the linux-hardened patch does not apply to linux-${V_LINUX}"
    ( cd "$KSRC" && patch -Np1 -s -i "$PATCH" )
    : > "$stamp"
fi

cd "$KSRC"
make -s mrproper
log "make defconfig, merge the fragments, make olddefconfig"
make -s defconfig >/dev/null
scripts/kconfig/merge_config.sh -m .config "${FRAGMENTS[@]}" >/dev/null
make -s olddefconfig >/dev/null

# Say up front what the host compiler cannot answer.
plugin_dir="$(gcc -print-file-name=plugin 2>/dev/null || true)"
if [[ -e "${plugin_dir}/include/plugin-version.h" ]]; then
    dim "  host gcc $(gcc -dumpversion) has plugin headers: GCC plugin options resolve as in the chroot"
else
    warn "host gcc $(gcc -dumpversion) has no plugin headers (${plugin_dir}/include); every GCC_PLUGINS-dependent"
    warn "option will read as DROPPED here although the chroot's compiler has them. Install gcc-$(gcc -dumpversion | cut -d. -f1)-plugin-dev."
fi
dim "  =y: $(grep -c '=y$' .config)  =m: $(grep -c '=m$' .config)"

mkdir -p "$(dirname "$OUT")"
cp .config "$OUT"
ok "resolved config: ${OUT}"

echo
log "the options Kryptik's guarantees rest on"
kconfig_critical_check "$OUT" || die "a critical option did not survive resolution (MISSING, above)"

echo
log "every fragment line, against the resolved config"
if kconfig_fragment_check "$OUT" "${FRAGMENTS[@]}"; then
    ok "every fragment line survived resolution"
else
    echo
    die "fragment lines were not honoured. Each is a mitigation or a driver the built kernel would not have while the fragment says it does."
fi
