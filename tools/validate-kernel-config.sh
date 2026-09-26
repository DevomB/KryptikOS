#!/usr/bin/env bash
# Check that a kernel fragment's CONFIG_ symbols all exist in the pinned source.
#
#   ./tools/validate-kernel-config.sh              hardening.fragment
#   ./tools/validate-kernel-config.sh --hardened   hardened.fragment
#   ./tools/validate-kernel-config.sh --boot       boot.fragment
#
# kconfig drops an unknown symbol silently. This checks existence only: one with
# unmet dependencies (CFI_CLANG under GCC) is dropped too, which
# tools/resolve-kernel-config.sh catches.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

HARDENED_MODE=0
BOOT_MODE=0
[[ "${1:-}" == "--hardened" ]] && HARDENED_MODE=1
[[ "${1:-}" == "--boot" ]] && BOOT_MODE=1

if [[ "$HARDENED_MODE" -eq 1 ]]; then
    FRAGMENT="${KRYPTIK_ROOT}/build/config/kernel/hardened.fragment"
elif [[ "$BOOT_MODE" -eq 1 ]]; then
    FRAGMENT="${KRYPTIK_ROOT}/build/config/kernel/boot.fragment"
else
    FRAGMENT="${KRYPTIK_ROOT}/build/config/kernel/hardening.fragment"
fi
KCONFIG_DIR="${KRYPTIK_WORK}/kconfig/linux-${V_LINUX}"
TARBALL="${KRYPTIK_SOURCES}/linux-${V_LINUX}.tar.xz"

[[ -f "$FRAGMENT" ]] || die "fragment not found: ${FRAGMENT}"

if [[ ! -d "$KCONFIG_DIR" ]]; then
    [[ -f "$TARBALL" ]] || die "kernel source not fetched. Run: make sources"
    log "extracting Kconfig files from linux-${V_LINUX}"
    mkdir -p "${KRYPTIK_WORK}/kconfig"
    tar -xf "$TARBALL" -C "${KRYPTIK_WORK}/kconfig" --wildcards '*/Kconfig*'
fi

count="$(find "$KCONFIG_DIR" -name 'Kconfig*' | wc -l)"
[[ "$count" -gt 0 ]] || die "no Kconfig files found under ${KCONFIG_DIR}"
log "validating against linux-${V_LINUX} (${count} Kconfig files)"

# Every symbol the kernel defines.
SYMBOLS="${KRYPTIK_WORK}/kconfig/.symbols"
if [[ ! -s "$SYMBOLS" ]]; then
    find "$KCONFIG_DIR" -name 'Kconfig*' -print0 \
        | xargs -0 grep -hE '^[[:space:]]*(menu)?config[[:space:]]+[A-Za-z0-9_]+' \
        | sed -E 's/^[[:space:]]*(menu)?config[[:space:]]+([A-Za-z0-9_]+).*/\2/' \
        | sort -u > "$SYMBOLS"
fi
dim "  kernel defines $(wc -l < "$SYMBOLS") config symbols"

# Plus those the linux-hardened patch adds ("+config X").
EFFECTIVE_SYMBOLS="$SYMBOLS"
if [[ "$HARDENED_MODE" -eq 1 ]]; then
    PATCH="${KRYPTIK_SOURCES}/linux-hardened-v${V_LINUX_HARDENED}.patch"
    [[ -f "$PATCH" ]] || die "linux-hardened patch not fetched. Run: make sources"
    EFFECTIVE_SYMBOLS="${KRYPTIK_WORK}/kconfig/.symbols-hardened"
    { cat "$SYMBOLS"
      grep -E "^\+config [A-Z_0-9]+" "$PATCH" | sed -E "s/^\+config //"
    } | sort -u > "$EFFECTIVE_SYMBOLS"
    added=$(( $(wc -l < "$EFFECTIVE_SYMBOLS") - $(wc -l < "$SYMBOLS") ))
    dim "  linux-hardened adds ${added} more"
fi
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

    if grep -qxF "$sym" "$EFFECTIVE_SYMBOLS"; then
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
        # Suggest similar names, ignoring any MITIGATION_ prefix.
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

ok "every symbol in $(basename "$FRAGMENT") exists in linux-${V_LINUX}$([[ "$HARDENED_MODE" -eq 1 ]] && printf " + linux-hardened")"
