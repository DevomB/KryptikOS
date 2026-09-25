#!/usr/bin/env bash
# The installed system's state partition: found on the system's own disk, and
# a boot that says so when it cannot use it (docs/design/boot-and-updates.md,
# sysinit.sh).
#
#   tools/image/state-test.sh --usb IMG [--disk FILE] [--timeout N]
#
#   step 1  install, first boot, a file on the state partition
#   step 2  a clone of the disk attached: its partitions are ignored; then
#           the clone boots alone
#   step 3  two kryptik-state partitions on the root disk: degraded
#   step 4  the LUKS2 header zeroed: degraded
#   step 5  no kryptik-state partition: degraded
#   step 6  the watchdog feeder stopped: the machine resets and comes back
#   step 7  three wrong passphrases: degraded; then the right one
#
# A degraded boot has no accounts, so only its console is checked; after each
# repair a login must find the user's file. Every disk is a file made here.
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
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sfdisk truncate dd; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/state.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"
CLONE="${VMDIR}/state-clone.img"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/state-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"


# A boot that must come up degraded. Nobody can log in to power it off, so it
# is stopped once its report ends, and only its transcript is checked: every
# line below comes before the report's END.
degraded_boot() {   # degraded_boot NAME REASON-REGEX
    start_vm "$1"
    DRIVE_TIMEOUT=150 drive "expect:KRYPTIK_SMOKE: END" > /dev/null
    stop_vm
    local t; t="$(txt)"
    grep -q 'sysinit: \*  STATE DEGRADED' <<<"$t" && green "$1: the console banner says STATE DEGRADED" || red "$1: no degraded banner"
    grep -qE "STATE DEGRADED: $2" <<<"$t" && green "$1: the reason is named ($2)" || { red "$1: reason not as expected"; grep 'STATE DEGRADED' <<<"$t" | head -2 | sed 's/^/        /'; }
    grep -q 'KRYPTIK_SMOKE: boot_identity=.*state=degraded' <<<"$t" && green "$1: boot identity records state=degraded" || red "$1: boot identity does not say degraded"
    grep -q 'KRYPTIK_SMOKE: var_source=tmpfs' <<<"$t" && green "$1: /var is a tmpfs" || red "$1: /var is not a tmpfs"
    grep -q 'kryptik-firstboot: state is DEGRADED' <<<"$t" && green "$1: first-boot setup refused to create accounts" || red "$1: first-boot did not refuse"
    grep -q 'kryptik-firstboot: created user' <<<"$t" && red "$1: an account was created on a tmpfs" || green "$1: no account created"
    grep -qE 'boot-success: .*state is degraded|boot-success: slot a is up but not fully usable' <<<"$t" && green "$1: boot-success reports the slot unhealthy" || red "$1: boot-success did not report unhealthy"
    grep -q 'KRYPTIK_SMOKE: END' <<<"$t" && green "$1: the machine still came up far enough to report (repairable)" || red "$1: the report never appeared"
    grep -q 'Kernel panic' <<<"$t" && red "$1: kernel panic" || green "$1: no panic"
}
# A boot that must be normal, with the user and the persisted file intact.
normal_boot() {   # normal_boot NAME
    start_vm "$1"
    drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
        "run:test -f /home/${TUSER}/state-marker" \
        "grab:ident:cat /run/kryptik/boot-identity" \
        "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
    local rc=$?; stop_vm
    [[ "$rc" -eq 0 ]] && green "$1: normal boot, login, persisted file present, clean poweroff" || red "$1: drive failed"
    txt | grep -q 'state=persistent' && green "$1: state=persistent" || red "$1: state is not persistent"
    txt | grep -q 'STATE DEGRADED' && red "$1: degraded banner on a healthy boot" || green "$1: no degraded banner"
}

# ----------------------------------------------------------------- step 1 --
step "step 1: install, first boot, a file on the state partition"
# Sized from the medium, not a constant: see test-disk-size.sh.
DISK_SIZE="$("${SELF}/test-disk-size.sh" --medium "$USB")" || die "could not size the test disk from the medium"
rm -f "$DISK"; truncate -s "$DISK_SIZE" "$DISK"
CTL="${VMDIR}/testctl-state.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "${PRESEED[@]}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars clean --mode smoke --timeout "$TIMEOUT" --name state-install > /dev/null
tr -d '\r' < "$LATEST" | grep -q 'KRYPTIK_INSTALL: rc=0' && green "installed" || { red "install failed"; exit 1; }
start_vm state-p1
drive "expect:KRYPTIK_SMOKE: END" "seen:kryptik-firstboot: created user '${TUSER}'" "login:${TUSER}:${TPASS}" \
    "run:echo state-marker > /home/${TUSER}/state-marker && sync" \
    "grab:ident:cat /run/kryptik/boot-identity" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "first boot: user created, file written" || { red "step 1 drive failed"; exit 1; }
txt | grep -q 'state=persistent' && green "state=persistent on the installed disk" || red "state not persistent"
txt | grep -q 'root_disk=/dev/vda' && green "root disk identified as /dev/vda" || red "root disk not identified"

# ----------------------------------------------------------------- step 2 --
step "step 2: a clone of the disk attached: the same labels twice"
cp --sparse=always "$DISK" "$CLONE"
start_vm state-p2 --disk "$CLONE"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:test -f /home/${TUSER}/state-marker" \
    "grab:ident:cat /run/kryptik/boot-identity" \
    "grab:mounts:awk '\$2==\"/var\"{print \$1}' /proc/mounts" \
    "grab:others:dmesg 2>/dev/null | grep -c . ; grep -c kryptik-state /proc/partitions" \
    "$(ROOTSH 'kryptik-update status')" "expect:running slot:     a" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "boots with a clone attached; login and the file work" || red "step 2 drive failed"
txt | grep -q 'KRYPTIK_SMOKE: var_source=/dev/mapper/kryptik-state ext4' && green "/var is the unlocked state partition" || red "/var is not the unlocked state partition"
txt | grep -q 'state_dev=/dev/vda4' && green "boot identity names /dev/vda4" || red "boot identity does not name vda4"
txt | grep -q 'sysinit: kryptik-state on other disks ignored: /dev/vdb4' && green "the clone's state partition was seen and ignored" || red "the clone's partition was not reported as ignored"
txt | grep -q 'STATE DEGRADED' && red "degraded with a clone attached (ambiguity wrongly detected)" || green "not degraded: the clone is not this installation"
txt | grep -q 'boot-success: slot a up, no trial pending' && green "boot-success: healthy" || red "boot-success not healthy with a clone attached"
# and the clone alone is a working system too (labels, not device names)
SAVED_DISK="$DISK"; DISK="$CLONE"
start_vm state-p2b
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" "run:test -f /home/${TUSER}/state-marker" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm; DISK="$SAVED_DISK"
[[ "$rc" -eq 0 ]] && green "the clone boots alone with its own copy of the state" || red "the clone did not boot alone"

# ----------------------------------------------------------------- step 3 --
step "step 3: two kryptik-state partitions on the same disk"
# partition 3 is kryptik-b; give it the state label from the host
sfdisk --part-label "$DISK" 3 kryptik-state >/dev/null 2>&1 || die "relabel"
degraded_boot state-p3 '2 partitions labelled kryptik-state'
sfdisk --part-label "$DISK" 3 kryptik-b >/dev/null 2>&1 || die "relabel back"
normal_boot state-p3b

# ----------------------------------------------------------------- step 4 --
step "step 4: a corrupt state partition"
S4_OFF=$(( $(part_start "$DISK" 4) * 512 ))
SAVE="${VMDIR}/state-super.bin"
# both copies of the LUKS2 header: the first 64 KiB of the partition
dd if="$DISK" of="$SAVE" bs=1 skip="$S4_OFF" count=65536 status=none
dd if=/dev/zero of="$DISK" bs=1 seek="$S4_OFF" count=65536 conv=notrunc status=none
degraded_boot state-p4 '/dev/vda4 carries no LUKS2 header'
dd if="$SAVE" of="$DISK" bs=1 seek="$S4_OFF" conv=notrunc status=none
normal_boot state-p4b

# ----------------------------------------------------------------- step 5 --
step "step 5: no state partition at all"
sfdisk --part-label "$DISK" 4 not-kryptik >/dev/null 2>&1 || die "relabel"
degraded_boot state-p5 'no partition labelled kryptik-state on /dev/vda'
sfdisk --part-label "$DISK" 4 kryptik-state >/dev/null 2>&1 || die "relabel back"
normal_boot state-p5b

# ----------------------------------------------------------------- step 6 --
# Stop the feeder rather than kill it (s6 would restart it): to the timer that
# is a hung userspace, and only the watchdog's reset can bring a second boot.
step "step 6: nothing feeds the watchdog: the machine resets itself and comes back with its data"
start_vm state-p6
p6=( "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}"
     "$(ROOTSH 's6-svc -p /run/service/watchdog && echo FEEDER-STOPPED')" "expect:FEEDER-STOPPED"
     "expect:KRYPTIK_SMOKE: BEGIN" "expect:KRYPTIK_SMOKE: END"
     "login:${TUSER}:${TPASS}" "run:test -f /home/${TUSER}/state-marker"
     "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit" )
drive "${p6[@]}"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "state-p6: reset without being asked, booted again, login, persisted file present, clean poweroff" || red "state-p6: drive failed"
boots="$(txt | grep -c 'KRYPTIK_SMOKE: BEGIN')"
[[ "$boots" -eq 2 ]] && green "state-p6: two boots in one transcript" || red "state-p6: ${boots} boot(s) in the transcript, wanted 2"
txt | grep -q 'KRYPTIK_SMOKE: svc_watchdog=up' && green "state-p6: the feeder is supervised and up" || red "state-p6: the feeder is not up"
txt | grep -qE 'KRYPTIK_SMOKE: watchdog watchdog[0-9]+: .* state=active .* nowayout=1' && green "state-p6: a watchdog is armed and cannot be closed off" || red "state-p6: no armed watchdog in the boot report"
if txt | grep -q 'softdog: Initiating system reboot'; then green "state-p6: the software watchdog named itself as the cause"
else echo "      note: no softdog line; the reset came from an emulated hardware timer"; fi
txt | grep -q 'Kernel panic' && red "state-p6: kernel panic" || green "state-p6: no panic"
txt | grep -q 'STATE DEGRADED' && red "state-p6: degraded after the reset" || green "state-p6: state is intact after the reset"

# ----------------------------------------------------------------- step 7 --
step "step 7: three wrong passphrases, then the right one"
KRYPTIK_STATE_PASSPHRASE=not-the-passphrase degraded_boot state-p7 '/dev/vda4 was not unlocked in three tries'
[[ "$(txt | grep -c 'passphrase for the state partition')" -eq 3 ]] && green "state-p7: asked three times and no more" || red "state-p7: not asked exactly three times"
normal_boot state-p7b

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
