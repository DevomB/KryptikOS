#!/usr/bin/env bash
# kconfig_critical_check against a stand-in .config: a bare entry takes =y or =m, one written
# OPTION=y only =y, and either fails an option not set. Then the shipped list against
# boot.fragment: each entry it holds built in is a =y line there, but the four that are
# not boot.fragment lines (kconfig-check.sh says what brings them). Offline.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=build/lib/kconfig-check.sh
source "$ROOT/build/lib/kconfig-check.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf 'CONFIG_I2C_HID_ACPI=m\nCONFIG_HID=y\n# CONFIG_PINCTRL_INTEL is not set\n' > "$T/config"
shipped="$KCONFIG_CRITICAL"
passes() { KCONFIG_CRITICAL="$1"; kconfig_critical_check "$T/config" > /dev/null; }   # passes LIST
passes "CONFIG_I2C_HID_ACPI CONFIG_HID=y" && green "a bare entry takes =m, and one written =y takes =y" \
    || red "a bare entry refused =m, or one written =y refused =y"
passes "CONFIG_I2C_HID_ACPI=y" && red "a module passed an entry written =y" || green "a module fails an entry written =y"
passes "CONFIG_PINCTRL_INTEL=y" && red "an option not set passed an entry written =y" || green "an option not set fails an entry written =y"
passes "CONFIG_PINCTRL_INTEL" && red "an option not set passed a bare entry" || green "an option not set fails a bare entry"
said="$(KCONFIG_CRITICAL="CONFIG_I2C_HID_ACPI=y CONFIG_PINCTRL_INTEL=y"; kconfig_critical_check "$T/config")"
[[ "$said" == *"MODULE  CONFIG_I2C_HID_ACPI, which must be built in"* && "$said" == *"MISSING CONFIG_PINCTRL_INTEL=y"* ]] \
    && green "a module is named as one, an option not set as missing" || red "the check said: ${said//$'\n'/ | }"

frag="$ROOT/build/config/kernel/boot.fragment"
for entry in $shipped; do
    [[ "$entry" == *=y ]] || continue
    opt="${entry%=y}"
    case "$opt" in CONFIG_SERIO_I8042|CONFIG_I2C_HID_CORE|CONFIG_PINCTRL_INTEL|CONFIG_USB_XHCI_PCI) continue ;; esac
    grep -qx "${opt}=y" "$frag" && green "${opt} is built in by boot.fragment" \
        || red "${opt} is held built in, but boot.fragment does not set it =y"
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
