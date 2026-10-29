#!/bin/sh
# A line on the login prompt when the firmware did not check this kernel's signature: Secure Boot
# off, or the firmware in setup mode, where any program running as root can enrol keys of its
# own. The install medium's banner says which; without this the installed system never said.
# POSIX sh, sourced by sysinit.
#   secureboot_notice   write the notice when Secure Boot is not enforced, else remove it

SECUREBOOT_NOTICE="${SECUREBOOT_NOTICE:-/run/issue.d/kryptik-secureboot.issue}"
EFIVARS="${EFIVARS:-/sys/firmware/efi/efivars}"
IMAGE_JSON="${IMAGE_JSON:-/etc/kryptik-image.json}"

# A global EFI variable's value: the byte after its four of attributes, or nothing.
sb_var() { od -An -tu1 -j4 -N1 "$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c" 2>/dev/null | tr -d ' '; }

secureboot_notice() {
    sb="$(sb_var SecureBoot)"
    if [ "$(sb_var SetupMode)" = 1 ]; then
        said="the firmware did not check this kernel's signature, as it is in setup mode, where any program running as root can enrol keys of its own"
    elif [ "$sb" = 1 ]; then
        rm -f "$SECUREBOOT_NOTICE"
        return 0
    elif [ -z "$sb" ]; then
        said="the firmware gives no SecureBoot variable, so whether it checked this kernel's signature is unknown"
    else
        said="the firmware did not check this kernel's signature, as Secure Boot is off"
    fi
    # A development build's key is a test anchor, never enrolled in real firmware (release-keys.sh).
    if grep -q '"signed_boot": "production"' "$IMAGE_JSON" 2>/dev/null; then
        what="add kryptik-sb.der to the firmware's db and turn Secure Boot on (the guide's section 1)"
    else
        what="expected of a development build, whose key is never enrolled in real firmware"
    fi
    mkdir -p "${SECUREBOOT_NOTICE%/*}"
    echo "kryptik secure boot: ${said}: ${what}" > "$SECUREBOOT_NOTICE"
    echo "sysinit: Secure Boot is not enforced; the login prompt says so"
}
