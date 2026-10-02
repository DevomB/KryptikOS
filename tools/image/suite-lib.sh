#!/usr/bin/env bash
# Shared by the installed-system suites; source it after common.sh, with SELF set.
# start_vm reads DISK and VARSF, install_disk TIMEOUT and VMDIR, drive DRIVE_TIMEOUT.
# shellcheck disable=SC2034  # read by the suite that sources this

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
step()  { printf '\n==> %s\n' "$*"; }

# The plaintext exists only in the harness; the hashes are what lands on disk.
TUSER=tester; TPASS=tester-pw; RPASS=root-pw
TUSER_HASH="$(openssl passwd -6 "$TPASS")"; ROOT_HASH="$(openssl passwd -6 "$RPASS")"
# The installer reads it from the control disk; vm-drive.py answers sysinit with it (hence export).
export KRYPTIK_STATE_PASSPHRASE=state-pw
PRESEED=( "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}"
          "state_passphrase=${KRYPTIK_STATE_PASSPHRASE}" )
# The testctl key the medium's anchor lists signs the control disks; the developer one by default.
TESTCTL_KEY="${KRYPTIK_TESTCTL_KEY:-${KRYPTIK_WORK}/keys/release/kryptik-testctl}"

DRV="${SELF}/vm-drive.py"

# A smoke boot with its own transcript: ovmf-serial.latest.log may be another suite's boot.
BOOTS=0
smoke() {   # smoke NAME [run-ovmf args] -> BOOTLOG; run-ovmf.sh's status
    BOOTS=$((BOOTS + 1))
    BOOTLOG="${KRYPTIK_WORK}/logs/ovmf-serial.$1.$(date +%Y%m%dT%H%M%S).$$.${BOOTS}.log"
    "${SELF}/run-ovmf.sh" --mode smoke --name "$1" --log "$BOOTLOG" "${@:2}"
}
boot_txt() { tr -d '\r' < "$BOOTLOG"; }

# Every suite starts from a fresh install onto a DISK sized from the medium (test-disk-size.sh).
fresh_disk() {   # fresh_disk MEDIUM [test-disk-size.sh args]
    local size; size="$("${SELF}/test-disk-size.sh" --medium "$@")" || die "could not size the test disk from the medium"
    rm -f "$DISK"; truncate -s "$size" "$DISK"
}
install_disk() {   # install_disk NAME MEDIUM [run-ovmf args]; 0 when the installer reported success
    local ctl="${VMDIR}/testctl-$1.img"
    "${SELF}/mk-testctl.sh" --out "$ctl" --key "$TESTCTL_KEY" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
        "${PRESEED[@]}" > /dev/null || die "the install control disk"
    smoke "$1" --usb "$2" --disk "$DISK" --testctl "$ctl" --timeout "$TIMEOUT" "${@:3}" > /dev/null
    boot_txt | grep -q 'KRYPTIK_INSTALL: rc=0'
}

start_vm() {   # start_vm NAME [run-ovmf args] -> SER QMP PIDF LOG
    local name="$1"; shift
    local out; out="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name "$name" "$@")"
    SER="$(sed -n 's/^serial=//p' <<<"$out")"; QMP="$(sed -n 's/^qmp=//p' <<<"$out")"
    PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"
    [[ -S "$SER" ]] || die "no serial socket: ${out}"
}
stop_vm() { sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null; sleep 1; }
drive() { python3 "$DRV" --serial "$SER" --timeout "${DRIVE_TIMEOUT:-300}" "$@"; }
txt() { tr -d '\r' < "$LOG"; }
ROOTSH() { printf 'su:%s:%s' "$RPASS" "$1"; }   # a command as root, through su
# Where partition N of a disk file starts, in sectors, from its GPT.
part_start() { sfdisk -d "$1" 2>/dev/null | awk -v n="$2" -F'[ ,]+' '$1 ~ n"$" {for(i=1;i<=NF;i++) if($i=="start=") print $(i+1)}'; }
# A disk file's state partition, opened and mounted from the host.
open_state() {   # open_state DISK MNT
    STATE_LOOP="$(losetup --find --show --offset $(( $(part_start "$1" 4) * 512 )) "$1")" || return 1
    printf '%s' "$KRYPTIK_STATE_PASSPHRASE" | cryptsetup open --type luks2 --key-file=- "$STATE_LOOP" kryptik-suite-state \
        && mount /dev/mapper/kryptik-suite-state "$2" && return 0
    close_state "$2"; return 1
}
close_state() {   # close_state MNT
    sync; umount "$1" 2>/dev/null
    cryptsetup close kryptik-suite-state 2>/dev/null; losetup -d "$STATE_LOOP" 2>/dev/null
}
