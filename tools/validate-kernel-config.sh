#!/usr/bin/env bash
# Validate the kernel hardening fragment against the pinned kernel source.
#
#   ./tools/validate-kernel-config.sh
#
# Kernel config symbols are renamed and removed between releases. A fragment
# referencing a symbol that no longer exists does not error at build time - the
# option is silently dropped and the hardening it was supposed to provide is
# simply absent. That is the worst possible failure mode for a security
# feature: it looks configured and is not.
#
# This checks every CONFIG_ symbol in the fragment against the `config` entries
# in the pinned kernel's Kconfig files, so a stale fragment fails loudly here
# rather than shipping a kernel that quietly lacks its mitigations.
#
# KNOWN LIMITATION: this proves a symbol EXISTS, not that its dependencies are
# satisfiable. CONFIG_CFI_CLANG exists in 6.18 but requires CC_IS_CLANG; set it
# while building with GCC and kconfig drops it just as silently as an unknown
# symbol. Catching that class properly means evaluating Kconfig dependency
# expressions, which is a kconfig-parser-sized job. Until then, verify the
# generated .config with kernel-hardening-checker after the kernel is built -
# that reads the real .config and sees what actually survived.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

FRAGMENT="${KRYPTIK_ROOT}/build/config/kernel/hardening.fragment"
KCONFIG_DIR="${KRYPTIK_WORK}/kconfig/linux-${V_LINUX}"
TARBALL="${KRYPTIK_SOURCES}/linux-${V_LINUX}.tar.xz"

[[ -f "$FRAGMENT" ]] || die "fragment not found: ${FRAGMENT}"

# Extract just the Kconfig files if we have not already.
if [[ ! -d "$KCONFIG_DIR" ]]; then
    [[ -f "$TARBALL" ]] || die "kernel source not fetched. Run: make sources"
    log "extracting Kconfig files from linux-${V_LINUX}"
    mkdir -p "${KRYPTIK_WORK}/kconfig"
    tar -xf "$TARBALL" -C "${KRYPTIK_WORK}/kconfig" --wildcards '*/Kconfig*'
fi

count="$(find "$KCONFIG_DIR" -name 'Kconfig*' | wc -l)"
[[ "$count" -gt 0 ]] || die "no Kconfig files found under ${KCONFIG_DIR}"
log "validating against linux-${V_LINUX} (${count} Kconfig files)"

# Build the set of every symbol the kernel actually defines.
SYMBOLS="${KRYPTIK_WORK}/kconfig/.symbols"
if [[ ! -s "$SYMBOLS" ]]; then
    find "$KCONFIG_DIR" -name 'Kconfig*' -print0 \
        | xargs -0 grep -hE '^[[:space:]]*(menu)?config[[:space:]]+[A-Za-z0-9_]+' \
        | sed -E 's/^[[:space:]]*(menu)?config[[:space:]]+([A-Za-z0-9_]+).*/\2/' \
        | sort -u > "$SYMBOLS"
fi
dim "  kernel defines $(wc -l < "$SYMBOLS") config symbols"
echo

KNOWN=0
UNKNOWN=0
declare -a UNKNOWN_LIST=()

while IFS= read -r line; do
    # Match both "CONFIG_FOO=y" and "# CONFIG_FOO is not set"
    if [[ "$line" =~ ^CONFIG_([A-Za-z0-9_]+)= ]]; then
        sym="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^#[[:space:]]*CONFIG_([A-Za-z0-9_]+)[[:space:]]+is[[:space:]]+not[[:space:]]+set ]]; then
        sym="${BASH_REMATCH[1]}"
    else
        continue
    fi

    if grep -qxF "$sym" "$SYMBOLS"; then
        KNOWN=$((KNOWN + 1))
    else
        err "CONFIG_${sym}: not defined in linux-${V_LINUX}"
        UNKNOWN=$((UNKNOWN + 1))
        UNKNOWN_LIST+=("$sym")
    fi
done < "$FRAGMENT"

echo
log "Summary"
ok "recognized: ${KNOWN}"

if [[ "$UNKNOWN" -gt 0 ]]; then
    err "unknown:    ${UNKNOWN}"
    echo
    dim "These symbols do not exist in the pinned kernel. Each was either renamed"
    dim "or removed upstream. merge_config.sh will DROP them silently, so the"
    dim "mitigation they name would simply not be present in the built kernel."
    echo
    for sym in "${UNKNOWN_LIST[@]}"; do
        # Offer likely replacements by fuzzy-matching the symbol name.
        local_matches="$(grep -iE "${sym#MITIGATION_}" "$SYMBOLS" 2>/dev/null | head -3 | tr '\n' ' ')"
        if [[ -n "$local_matches" ]]; then
            printf '  CONFIG_%s\n    possible replacements: %s\n' "$sym" "$local_matches"
        else
            printf '  CONFIG_%s\n    no similar symbol found\n' "$sym"
        fi
    done
    echo
    die "${UNKNOWN} stale config symbol(s). Fix the fragment before building a kernel."
fi

ok "every symbol in the fragment exists in linux-${V_LINUX}"
