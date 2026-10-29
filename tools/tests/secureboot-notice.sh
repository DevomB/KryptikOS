#!/usr/bin/env bash
# Tests for build/service-scripts/secureboot-notice.sh, sourced as sysinit sources it: the login
# prompt says when the firmware did not check the kernel's signature, with the advice a release
# build or a development build calls for, and says nothing once Secure Boot is enforced. Offline,
# with the firmware's variables and the image's identity stood in for.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/build/service-scripts/secureboot-notice.sh"
SYSINIT="${ROOT}/build/service-scripts/sysinit.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

GUID=8be4df61-93ca-11d2-aa0d-00e098032b8c
NOTICE="$T/issue.d/kryptik-secureboot.issue"
var() {   # var NAME 0|1: as efivarfs gives it, four bytes of attributes, then the value
    printf '\006\000\000\000' > "$T/efivars/$1-$GUID"
    if [[ "$2" == 1 ]]; then printf '\001'; else printf '\000'; fi >> "$T/efivars/$1-$GUID"
}
firmware() {   # firmware SECUREBOOT SETUPMODE
    rm -rf "$T/efivars"; mkdir -p "$T/efivars"
    var SecureBoot "$1"; var SetupMode "$2"
}
image() { printf '{\n  "version": "1.0.0",\n  "signed_boot": "%s",\n  "verity": true\n}\n' "$1" > "$T/image.json"; }
boot() {   # boot SHELL: secureboot_notice under SHELL
    EFIVARS="$T/efivars" IMAGE_JSON="$T/image.json" SECUREBOOT_NOTICE="$NOTICE" \
        "$1" -c '. "$1"; secureboot_notice' sh "$SCRIPT" > "$T/said" 2>&1
}
PREFIX="kryptik secure boot: the firmware did not check this kernel's signature"
DEV="expected of a development build, whose key is never enrolled in real firmware"
REL="add kryptik-sb.der to the firmware's db and turn Secure Boot on (the guide's section 1)"

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    echo "-- ${sh}"
    rm -rf "$T/issue.d"

    # No keys enrolled, as a clean OVMF store or a firmware whose keys were cleared.
    firmware 0 1; image developer; boot "$sh"; rc=$?
    if [[ "$rc" -eq 0 ]] && grep -qxF "${PREFIX}, as it is in setup mode, where any program running as root can enrol keys of its own: ${DEV}" "$NOTICE" 2>/dev/null \
       && grep -qxF 'sysinit: Secure Boot is not enforced; the login prompt says so' "$T/said"; then
        green "setup mode is named on the login prompt, with a development build's word"
    else
        red "setup mode" "exit ${rc}; notice: $(cat "$NOTICE" 2>&1); said: $(cat "$T/said")"
    fi

    # Keys enrolled and Secure Boot turned off, on a release build: the advice is to turn it on.
    firmware 0 0; image production; boot "$sh"; rc=$?
    if [[ "$rc" -eq 0 ]] && grep -qxF "${PREFIX}, as Secure Boot is off: ${REL}" "$NOTICE" 2>/dev/null; then
        green "Secure Boot off is named, with a release build's advice to enrol and turn it on"
    else
        red "Secure Boot off" "exit ${rc}; notice: $(cat "$NOTICE" 2>&1)"
    fi
    [[ "$(wc -l < "$NOTICE" 2>/dev/null)" -eq 1 ]] && green "one line" || red "one line" "$(cat "$NOTICE" 2>&1)"

    # Enforced: no notice, the last boot's goes, and the console says nothing.
    firmware 1 0; boot "$sh"; rc=$?
    [[ "$rc" -eq 0 && ! -e "$NOTICE" && ! -s "$T/said" ]] && green "Secure Boot enforced leaves no notice, and clears an old one" \
        || red "enforced" "exit ${rc}; notice: $(cat "$NOTICE" 2>&1); said: $(cat "$T/said")"

    # No variables to read, as with efivarfs unmounted: unknown, never called off or on.
    rm -rf "$T/efivars"; image developer; boot "$sh"; rc=$?
    if [[ "$rc" -eq 0 ]] && grep -qxF "kryptik secure boot: the firmware gives no SecureBoot variable, so whether it checked this kernel's signature is unknown: ${DEV}" "$NOTICE" 2>/dev/null; then
        green "no SecureBoot variable is said to be unknown"
    else
        red "no SecureBoot variable" "exit ${rc}; notice: $(cat "$NOTICE" 2>&1)"
    fi

    # An identity that does not say production gets the development build's word, never advice
    # to enrol a key that must not be.
    firmware 0 0; rm -f "$T/image.json"; boot "$sh"; rc=$?
    [[ "$rc" -eq 0 ]] && grep -qF ": ${DEV}" "$NOTICE" && ! grep -qF 'kryptik-sb.der' "$NOTICE" \
        && green "with no image identity, no advice to enrol a key" || red "no image identity" "$(cat "$NOTICE" 2>&1)"
done

# sysinit runs under sh -e: it sources the file and calls the function where a failure is let pass.
if grep -qxF '. /usr/libexec/kryptik/secureboot-notice.sh' "$SYSINIT" && grep -qxF 'secureboot_notice || true' "$SYSINIT"; then
    green "sysinit sources it and calls it before the first login prompt"
else
    red "sysinit does not source secureboot-notice.sh and call secureboot_notice || true"
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
