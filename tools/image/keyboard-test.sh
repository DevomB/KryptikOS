#!/usr/bin/env bash
# The keyboard layout on an installed system (docs/design/keyboard-layout.md):
# named in a firmware variable, loaded before the state passphrase is asked,
# and handed to the desktop's session.
#
#   tools/image/keyboard-test.sh --usb IMG [--disk FILE] [--timeout N]
#
#   step 1  install with --keyboard de into a variable store that is kept
#   step 2  boot the disk alone: the layout is named before the question, and
#           the passphrase is pressed on the guest's keyboard, key by key
#           where a German keyboard has it; then the console's keymap, the
#           session's record, and `kryptik keyboard` changing it back
#   step 3  the next boot says us; a name this release lacks is put in the
#           variable
#   step 4  that boot says so, and asks under us
#
# Every disk and variable store is a file made here; no firmware is touched.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; DISK=""; TIMEOUT=600
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/keyboard.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/keyboard-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
# y, z and - sit on other keys of a German keyboard than of a US one.
export KRYPTIK_STATE_PASSPHRASE=lazy-zebra
VAR=/sys/firmware/efi/efivars/KryptikKeyboard-ec0aed97-b78d-446f-997d-10d0c35f5fb6

# ----------------------------------------------------------------- step 1 --
step "step 1: install with --keyboard de"
fresh_disk "$USB"
CTL="${VMDIR}/testctl-keyboard.img"
"${SELF}/mk-testctl.sh" --out "$CTL" --key "$TESTCTL_KEY" install_target=/dev/vda install_keyboard=de smoke_poweroff=1 install_wait=5 \
    "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}" \
    "state_passphrase=${KRYPTIK_STATE_PASSPHRASE}" > /dev/null || die "the install control disk"
smoke keyboard-install --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars-file "$VARSF" --timeout "$TIMEOUT" > /dev/null
T1="$(boot_txt)"
grep -q 'KRYPTIK_INSTALL: rc=0' <<<"$T1" && green "installed with --keyboard de" \
    || { red "install failed"; grep 'KRYPTIK_INSTALL: .*FAILED' <<<"$T1" | head -3 | sed 's/^/        /'; printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"; exit 1; }
grep -q 'KRYPTIK_INSTALL: kryptik-install: keyboard     de' <<<"$T1" && green "the installer named the layout the passphrase will be asked under" || red "the installer did not name the layout"

# ----------------------------------------------------------------- step 2 --
step "step 2: the passphrase pressed where a German keyboard has it"
start_vm keyboard-p2
# No answer on the serial line: the passphrase goes in through the keyboard.
# The Y key gives z, the Z key y, and the key right of the full stop gives -.
KRYPTIK_STATE_PASSPHRASE='' python3 "$DRV" --serial "$SER" --qmp "$QMP" --timeout 300 \
    "expect:sysinit: keyboard layout de" \
    "expect:passphrase for the state partition \(try 1 of 3\): " "sleep:2" \
    "key:l" "key:a" "key:y" "key:z" "key:slash" "key:y" "key:e" "key:b" "key:r" "key:a" "key:ret" \
    "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "run:grep -qx layout=de /run/kryptik-keyboard" \
    "run:sh -c '. /usr/libexec/kryptik/keyboard.sh; kb_export_xkb; test \"\$XKB_DEFAULT_LAYOUT\" = de'" \
    "run:kryptik keyboard | grep -qx '\\* de'" \
    "$(ROOTSH 'dumpkeys | grep -E "^keycode +21 = "; echo DUMPED-DE')" "expect:keycode +21 = \\+?z" "expect:DUMPED-DE" \
    "$(ROOTSH 'kryptik keyboard klingon; echo REFUSED-RC=$?')" "expect:no keyboard layout named klingon" "expect:REFUSED-RC=2" \
    "$(ROOTSH 'kryptik keyboard us && echo CHANGED-US')" "expect:CHANGED-US" \
    "$(ROOTSH 'dumpkeys | grep -E "^keycode +21 = "; echo DUMPED-US')" "expect:keycode +21 = \\+?y" "expect:DUMPED-US" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
T2="$(txt)"
[[ "$rc" -eq 0 ]] && green "the keys a German keyboard has for the passphrase opened the state; the console, the session's record and the change back all checked" || red "step 2 drive failed"
grep -q 'sysinit: keyboard layout de' <<<"$T2" && green "sysinit named the layout before it asked" || red "sysinit did not name the layout"
grep -q 'state=persistent' <<<"$T2" && green "the state partition was unlocked by the keyboard" || red "the state is not persistent"
grep -q 'STATE DEGRADED' <<<"$T2" && red "degraded: the passphrase typed under de was refused" || green "not degraded"
grep -qE 'keycode +21 = \+?z' <<<"$T2" && green "the console's Y key gives z under de" || red "the console keymap is not German"
grep -q 'no keyboard layout named klingon' <<<"$T2" && green "a name the table lacks is refused" || red "an unknown layout was not refused"
grep -qE 'keycode +21 = \+?y' <<<"$T2" && green "kryptik keyboard us put the console back" || red "the console keymap did not change back"

# ----------------------------------------------------------------- step 3 --
step "step 3: the next boot asks under us; then a name this release lacks goes into the variable"
start_vm keyboard-p3
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:grep -qx layout=us /run/kryptik-keyboard" \
    "$(ROOTSH "chattr -i ${VAR}; printf \"\\\\007\\\\000\\\\000\\\\000klingon\" > ${VAR} && echo PLANTED")" "expect:PLANTED" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "booted, logged in and wrote the variable" || red "step 3 drive failed"
txt | grep -q 'sysinit: keyboard layout us' && green "the change to us held across the boot" || red "the boot after the change did not say us"

# ----------------------------------------------------------------- step 4 --
step "step 4: a variable naming no layout of this release"
start_vm keyboard-p4
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:grep -qx layout=us /run/kryptik-keyboard" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "the machine boots and unlocks with an unknown name in the variable" || red "step 4 drive failed"
txt | grep -q 'sysinit: the firmware names a keyboard layout this release does not have' && green "sysinit says the name is not one it has" || red "sysinit did not report the unknown name"
txt | grep -q 'sysinit: keyboard layout us' && green "and asks under us" || red "it did not fall back to us"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
