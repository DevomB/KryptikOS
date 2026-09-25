# shellcheck shell=bash
# Does a resolved .config honour every line of the kernel config fragments?
# Used by stage 05 and tools/resolve-kernel-config.sh. merge_config.sh and
# olddefconfig drop a line silently on an unmet dependency, on a `select` that
# overrides "is not set", or when its prompt is hidden (e.g. behind EXPERT).

# The .config as KCONFIG_HAVE[option]=value, read once for both checks.
declare -gA KCONFIG_HAVE=()
_kconfig_load() {   # <.config>
    local line
    KCONFIG_HAVE=()
    while IFS= read -r line; do
        [[ "$line" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]] || continue
        [[ -v "KCONFIG_HAVE[${BASH_REMATCH[1]}]" ]] || KCONFIG_HAVE["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    done < "$1"
}

# Options Kryptik's guarantees rest on. They must be present at all, so that
# deleting one from a fragment is noticed; =y or =m is the fragment's choice.
KCONFIG_CRITICAL="CONFIG_SECURITY_LANDLOCK CONFIG_SECCOMP_FILTER CONFIG_USER_NS
CONFIG_NET_NS CONFIG_EFI_STUB CONFIG_CMDLINE_BOOL CONFIG_CMDLINE_OVERRIDE
CONFIG_DM_INIT CONFIG_EFIVAR_FS CONFIG_OVERLAY_FS CONFIG_DRM_VIRTIO_GPU
CONFIG_NFT_MASQ CONFIG_DM_VERITY CONFIG_DM_CRYPT CONFIG_CRYPTO_XTS
CONFIG_FS_ENCRYPTION CONFIG_MODULE_SIG_FORCE CONFIG_SECURITY_LOCKDOWN_LSM
CONFIG_INIT_ON_ALLOC_DEFAULT_ON CONFIG_SLAB_CANARY
CONFIG_MITIGATION_PAGE_TABLE_ISOLATION"

# kconfig_critical_check <.config>: 0 when every one of them is =y or =m.
kconfig_critical_check() {
    local opt missing=0
    _kconfig_load "$1"
    for opt in $KCONFIG_CRITICAL; do
        if [[ "${KCONFIG_HAVE[$opt]:-}" == [ym] ]]; then
            echo "  ok   ${opt}"
        else
            echo "  MISSING ${opt}"; missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]]
}

# kconfig_fragment_check <.config> <fragment>...
# Each =value line must come out with that value and each "is not set" line
# unset or absent. Prints the lines that did not; 0 when there are none.
kconfig_fragment_check() {
    local config="$1"; shift
    local frag line opt want got total=0 bad=0
    local -a lines
    _kconfig_load "$config"
    for frag in "$@"; do
        mapfile -t lines < "$frag"
        for line in "${lines[@]}"; do
            if [[ "$line" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
                opt="${BASH_REMATCH[1]}"; want="${BASH_REMATCH[2]}"
                total=$((total + 1))
                got="${KCONFIG_HAVE[$opt]:-}"
                if [[ "$got" != "$want" ]]; then
                    printf '  DROPPED   %-38s wanted %s, got %s  [%s]\n' \
                        "$opt" "$want" "${got:-nothing}" "$(basename "$frag")"
                    bad=$((bad + 1))
                fi
            elif [[ "$line" =~ ^#[[:space:]]+(CONFIG_[A-Za-z0-9_]+)[[:space:]]+is[[:space:]]+not[[:space:]]+set$ ]]; then
                opt="${BASH_REMATCH[1]}"
                total=$((total + 1))
                got="${KCONFIG_HAVE[$opt]:-}"
                if [[ "$got" == y || "$got" == m ]]; then
                    printf '  FORCED ON %-38s =%s although requested off  [%s]; find what selects it: grep -rn "select %s" .\n' \
                        "$opt" "$got" "$(basename "$frag")" "${opt#CONFIG_}"
                    bad=$((bad + 1))
                fi
            fi
        done
    done
    printf '  %d fragment lines checked, %d not honoured\n' "$total" "$bad"
    [[ "$bad" -eq 0 ]]
}
