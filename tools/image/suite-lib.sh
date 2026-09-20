#!/usr/bin/env bash
# What the installed-system suites share: the verdict, the accounts the
# preseed creates, and the plumbing around run-ovmf.sh and vm-drive.py.
# Sourced after common.sh with SELF set. start_vm reads DISK and VARSF; drive
# reads DRIVE_TIMEOUT.
# shellcheck disable=SC2034  # read by the suite that sources this

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
step()  { printf '\n==> %s\n' "$*"; }

# The plaintext exists only in the harness; the hashes are what lands on disk.
TUSER=tester; TPASS=tester-pw; RPASS=root-pw
TUSER_HASH="$(openssl passwd -6 "$TPASS")"; ROOT_HASH="$(openssl passwd -6 "$RPASS")"
PRESEED=( "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}" )

DRV="${SELF}/vm-drive.py"
LATEST="${KRYPTIK_WORK}/logs/ovmf-serial.latest.log"

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
