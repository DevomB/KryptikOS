#!/usr/bin/env bash
# Resolve Kryptik's kernel configuration on a host, the way stage 05 does it
# inside the chroot, and check that every fragment line survived.
#
#   ./tools/resolve-kernel-config.sh [OUT]
#
#   OUT   where the resolved .config is written;
#         default ${KRYPTIK_WORK}/kconfig-tree/kryptik.config
#
# The steps are stage 05's s_config: unpack the pinned kernel, apply the
# linux-hardened patch, `make defconfig`, merge the three fragments, `make
# olddefconfig`. tools/validate-kernel-config.sh proves each fragment symbol
# EXISTS in the pinned source; this proves each one SURVIVES resolution, which
# is the other half - kconfig drops a symbol for an unmet dependency, an
# invisible prompt or an overriding `select` just as quietly as for a typo.
#
# The host's compiler is not the chroot's, and kconfig asks the compiler
# questions: GCC plugin options need the plugin headers (gcc-N-plugin-dev on
# Debian and Ubuntu), and a handful of CC_HAS_* symbols depend on the exact
# version. So this is an approximation stage 05 refines; where the two can
# differ it says so below. It needs make, a C compiler, flex and bison.
#
# Exit status: 0 when every fragment line is honoured, 1 otherwise or when a
# prerequisite is missing.

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

# A tree is unpacked and patched once per pinned version; a later run reuses
# it. The stamp records which patch went in, so a version bump starts over.
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

# What the host compiler could and could not answer, stated rather than
# discovered from a puzzling DROPPED line.
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
log "every fragment line, against the resolved config"
if kconfig_fragment_check "$OUT" "${FRAGMENTS[@]}"; then
    ok "every fragment line survived resolution"
else
    echo
    die "fragment lines were not honoured. Each is a mitigation or a driver the built kernel would not have while the fragment says it does."
fi
