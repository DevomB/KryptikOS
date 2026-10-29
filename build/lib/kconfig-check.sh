# shellcheck shell=bash
# Does a resolved .config honour every fragment line? Kconfig drops unmet ones silently.

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

# Options Kryptik's guarantees rest on, so deleting one from a fragment is noticed: a bare entry
# passes =y or =m, one written OPTION=y passes only built in. The =y entries are the keyboards
# sysinit's state passphrase prompt reads, before eudev loads any module: PS/2, USB through xHCI,
# and HID over I2C behind Intel's LPSS or AMD's DesignWare controller, with the pin controllers its
# interrupt comes through. SERIO_I8042, I2C_HID_CORE, PINCTRL_INTEL and USB_XHCI_PCI are not
# boot.fragment lines: ATKBD, I2C_HID_ACPI and the pin controllers select the first three, and
# xHCI brings the last by default. The two P-state drivers are bool only and default off: losing
# one leaves that maker's processors at a fixed clock with no energy preference.
KCONFIG_CRITICAL="CONFIG_SECURITY_LANDLOCK CONFIG_SECCOMP_FILTER CONFIG_USER_NS
CONFIG_NET_NS CONFIG_EFI_STUB CONFIG_CMDLINE_BOOL CONFIG_CMDLINE_OVERRIDE
CONFIG_DM_INIT CONFIG_EFIVAR_FS CONFIG_OVERLAY_FS CONFIG_DRM_VIRTIO_GPU
CONFIG_NFT_MASQ CONFIG_DM_VERITY CONFIG_DM_CRYPT CONFIG_CRYPTO_XTS
CONFIG_MODULE_SIG_FORCE CONFIG_SECURITY_LOCKDOWN_LSM
CONFIG_INIT_ON_ALLOC_DEFAULT_ON CONFIG_SLAB_CANARY
CONFIG_MITIGATION_PAGE_TABLE_ISOLATION
CONFIG_KEYBOARD_ATKBD=y CONFIG_SERIO_I8042=y CONFIG_USB_HID=y CONFIG_HID_GENERIC=y
CONFIG_USB_XHCI_HCD=y CONFIG_USB_XHCI_PCI=y
CONFIG_I2C_HID_ACPI=y CONFIG_I2C_HID_CORE=y CONFIG_I2C_DESIGNWARE_PLATFORM=y
CONFIG_X86_AMD_PLATFORM_DEVICE=y CONFIG_PINCTRL_AMD=y
CONFIG_MFD_INTEL_LPSS_PCI=y CONFIG_MFD_INTEL_LPSS_ACPI=y CONFIG_PINCTRL_INTEL=y
CONFIG_PINCTRL_SUNRISEPOINT=y CONFIG_PINCTRL_CANNONLAKE=y CONFIG_PINCTRL_ICELAKE=y
CONFIG_PINCTRL_JASPERLAKE=y CONFIG_PINCTRL_ELKHARTLAKE=y CONFIG_PINCTRL_LAKEFIELD=y
CONFIG_PINCTRL_TIGERLAKE=y CONFIG_PINCTRL_ALDERLAKE=y CONFIG_PINCTRL_METEORLAKE=y
CONFIG_PINCTRL_METEORPOINT=y CONFIG_PINCTRL_INTEL_PLATFORM=y
CONFIG_X86_INTEL_PSTATE=y CONFIG_X86_AMD_PSTATE=y"

# kconfig_critical_check <.config>: 0 when every bare entry is =y or =m and every OPTION=y one =y.
kconfig_critical_check() {
    local entry opt got missing=0
    _kconfig_load "$1"
    for entry in $KCONFIG_CRITICAL; do
        opt="${entry%=y}"; got="${KCONFIG_HAVE[$opt]:-}"
        if [[ "$got" == y || ( "$got" == m && "$entry" == "$opt" ) ]]; then
            echo "  ok   ${opt}"
        elif [[ "$got" == m ]]; then
            echo "  MODULE  ${opt}, which must be built in"; missing=$((missing + 1))
        else
            echo "  MISSING ${entry}${got:+, got =${got}}"; missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]]
}

# kconfig_fragment_check <.config> <fragment>...: print the lines not honoured; 0 when none.
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
