#!/usr/bin/env bash
# The install medium's console is a root shell: whoever boots it types
# kryptik-install there. Every suite installs through a control disk, so this
# is the one that types: a command runs as root, the installer and the
# recovery tool are found by name, and poweroff ends the session.
#
#   tools/image/medium-shell-test.sh (--usb IMG | --iso ISO)... [--timeout N]
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

MEDIA=(); TIMEOUT=300
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb|--iso) MEDIA+=("$1" "${2:?}"); shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ "${#MEDIA[@]}" -gt 0 ]] || die "--usb IMG or --iso ISO is required"
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"

for ((i = 0; i < ${#MEDIA[@]}; i += 2)); do
    kind="${MEDIA[i]#--}"; medium="${MEDIA[i+1]}"
    [[ -f "$medium" ]] || die "no such medium: ${medium}"
    step "the ${kind} medium's console"
    out="$("${SELF}/run-ovmf.sh" "--${kind}" "$medium" --mode serve --name "medium-shell-${kind}")"
    SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"
    [[ -S "$SER" ]] || die "no serial socket: ${out}"
    # The shell's own arithmetic and substitutions answer, never the echo of
    # what was typed; a getty drops its first second's input, so the first
    # line goes twice.
    python3 "$DRV" --serial "$SER" --timeout "$TIMEOUT" \
        "expect:KRYPTIK_SMOKE: END" "sleep:3" \
        'send:echo shell-$((6 * 7))' "sleep:2" 'send:echo shell-$((6 * 7))' "expect:shell-42" \
        'send:echo uid-$(id -u)' "expect:uid-0" \
        'send:echo found-$(command -v kryptik-install)-$(command -v kryptik-recover)' \
        "expect:found-/usr/sbin/kryptik-install-/usr/sbin/kryptik-recover" \
        "send:kryptik-install --help" "expect:usage: kryptik-install --target" \
        "send:poweroff" "expect:Power down" "wait-exit"
    drc=$?
    stop_vm
    [[ "$drc" -eq 0 ]] && green "${kind}: commands typed at the console ran as root, the installer is on its path, and poweroff took" \
        || red "${kind}: the console did not take commands (see above)"
    if txt | grep -q 'kryptik login:'; then red "${kind}: the medium's console asked for a login"; else green "${kind}: no login prompt on the medium"; fi
    if txt | grep -qE 'KRYPTIK_SMOKE: early_getty_pid=[0-9]+ comm=bash'; then green "${kind}: the console's process is the shell"; else red "${kind}: the console's process is not a shell: $(txt | grep -m1 -o 'early_getty_pid=.*' | cut -c1-80)"; fi
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
