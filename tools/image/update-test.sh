#!/usr/bin/env bash
#
# OS updates on an installed system (Design 08, gate G9): install release A,
# update to release B, reboot into it, roll back, and prove the refusals.
#
#   tools/image/update-test.sh --usb-a IMG_A --payload-a DIR_A --payload-b DIR_B
#                              [--disk FILE] [--vars clean|enrolled] [--timeout N]
#
# A and B are two stage 06 releases of this tree (make media KRYPTIK_VERSION=...
# twice); B's VERSION_ID is the observable change, reported by the guest's
# own boot report and os-release. The payload reaches the guest as files on
# a plain ext4 disk image (fetching is out of scope here and out of zone 0
# by design). Guest-side mounts go under /run: the installed root is a
# read-only verity image, so /mnt cannot take a directory, which is how the
# first run of this driver failed at its first mkdir.
#
# Sequence, every step through firmware boots and the serial login:
#   1  install A onto a blank disk (control disk arms it), boot the disk
#      alone, create a zone volume and a file in the user's home
#   2  apply B: armed, reboot -> slot b running, version B, boot-success
#      committed it, zone volume and home file intact
#   3  refusals, on the running B: wrong key, modified image, truncated
#      kernel, unlisted extra file, an older release without --recovery,
#      a full state partition, a concurrent run; none arms a trial
#   4  authenticated recovery: apply A --recovery, reboot -> slot a, version A
#   5  rollback: arms b again, reboot -> slot b
#   6  interruption: apply A --recovery, kill the VM mid-write, boot: still
#      slot b, no trial; apply again succeeds; kill after arming: the
#      firmware consumes BootNext and boot-success commits a
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB_A=""; PAY_A=""; PAY_B=""; DISK=""; VARS="clean"; TIMEOUT=600
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb-a) USB_A="${2:?}"; shift 2 ;;
        --payload-a) PAY_A="${2:?}"; shift 2 ;;
        --payload-b) PAY_B="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --vars) VARS="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,27p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB_A" ]] || die "--usb-a IMG_A is required"
[[ -f "$PAY_A/manifest" && -f "$PAY_B/manifest" ]] || die "--payload-a and --payload-b must be stage 06 payload directories"
for t in python3 mkfs.ext4 truncate ssh-keygen sfdisk; do have "$t" || die "required tool not found: $t"; done
VA="$(awk -F': ' '$1=="version"{print $2}' "$PAY_A/manifest")"; VB="$(awk -F': ' '$1=="version"{print $2}' "$PAY_B/manifest")"
[[ "$VA" != "$VB" ]] || die "A and B are the same version (${VA})"
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/updated.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
phase() { printf '\n==> %s\n' "$*"; }
TUSER=tester; TPASS=tester-pw; RPASS=root-pw
TUSER_HASH="$(openssl passwd -6 "$TPASS")"; ROOT_HASH="$(openssl passwd -6 "$RPASS")"
DRV="${SELF}/vm-drive.py"
VARSF="${VMDIR}/updated-vars.fd"
[[ "$VARS" == "enrolled" ]] && cp "${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd" "$VARSF" || cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"

# A payload as a plain ext4 disk image the guest can mount read-only.
payload_disk() {   # payload_disk OUT DIR
    rm -f "$1"; local bytes; bytes="$(du -sb "$2" | cut -f1)"
    truncate -s $(( bytes + bytes / 10 + 64 * 1024 * 1024 )) "$1"
    mkfs.ext4 -q -F -d "$2" "$1" || die "payload image"
}
PA="${VMDIR}/payload-a.img"; PB="${VMDIR}/payload-b.img"
payload_disk "$PA" "$PAY_A"; payload_disk "$PB" "$PAY_B"

# Variants of B for the refusal cases.
BAD="${VMDIR}/bad"; rm -rf "$BAD"; mkdir -p "$BAD"
mk_variant() {   # mk_variant NAME  -> $BAD/NAME is a copy of payload B
    rm -rf "${BAD:?}/$1"; cp -a --sparse=always "$PAY_B" "$BAD/$1"
}
mk_variant wrongkey; ssh-keygen -q -t ed25519 -N "" -f "$BAD/otherkey" >/dev/null; rm -f "$BAD/wrongkey/manifest.sig"
ssh-keygen -Y sign -f "$BAD/otherkey" -n kryptik-release "$BAD/wrongkey/manifest" >/dev/null 2>&1
mk_variant modified; printf '\xff' | dd of="$BAD/modified/kryptik-root.img" bs=1 seek=$((4096*200+3)) conv=notrunc status=none
mk_variant truncated; truncate -s -1 "$BAD/truncated/kryptik-a.efi"
mk_variant extra; echo "ride along" > "$BAD/extra/extra.bin"
BADIMG="${VMDIR}/payload-bad.img"; payload_disk "$BADIMG" "$BAD"

# The guest side, as root through su.
ROOTSH() { printf 'su:%s:%s' "$RPASS" "$1"; }
start_vm() {   # start_vm NAME [extra run-ovmf args] -> sets SER PIDF LOG
    local name="$1"; shift
    local out; out="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name "$name" "$@")"
    SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"; QMP="$(sed -n 's/^qmp=//p' <<<"$out")"
    [[ -S "$SER" ]] || die "no serial socket: ${out}"
}
stop_vm() { sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null; sleep 1; }
drive() { python3 "$DRV" --serial "$SER" --timeout 420 "$@"; }
txt() { tr -d '\r' < "$LOG"; }
part_start_disk() { sfdisk -d "$1" 2>/dev/null | awk -v n="$2" -F'[ ,]+' '$1 ~ n"$" {for(i=1;i<=NF;i++) if($i=="start=") print $(i+1)}'; }

# ---------------------------------------------------------------- phase 1 --
phase "phase 1: install ${VA}, boot it, create zone data"
rm -f "$DISK"; truncate -s 12G "$DISK"
CTL="${VMDIR}/testctl-update.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB_A" --disk "$DISK" --testctl "$CTL" --vars "$VARS" --mode smoke --timeout "$TIMEOUT" --name update-install > /dev/null
tr -d '\r' < "${KRYPTIK_WORK}/logs/ovmf-serial.latest.log" | grep -q 'KRYPTIK_INSTALL: rc=0' && green "A installed" || { red "A did not install"; exit 1; }

start_vm update-p1 --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "grab:v1:grep ^VERSION_ID= /etc/os-release; cat /run/kryptik/boot-identity" \
    "run:echo before-update > /home/${TUSER}/marker && sync" \
    "$(ROOTSH 'printf zone-pw > /root/zp && chmod 600 /root/zp && kryptikd volume init work --size 64M --passphrase-file /root/zp && sha256sum /var/lib/kryptik/volumes/work.luks > /root/work.sha && echo VOL-OK')" \
    "expect:VOL-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "A boots, zone volume created (${VA})" || red "phase 1 drive failed"
txt | grep -q "version_id=${VA}" && green "guest reports version ${VA}" || red "guest did not report version ${VA}"

# ---------------------------------------------------------------- phase 2 --
phase "phase 2: apply ${VB}, reboot into slot b"
start_vm update-p2 --disk "$PB"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/p /var/lib/kryptik/updates/b && mount -o ro /dev/vdb /run/upd/p && cp -a /run/upd/p/. /var/lib/kryptik/updates/b/ && umount /run/upd/p && kryptik-update apply /var/lib/kryptik/updates/b && echo APPLY-OK')" \
    "expect:armed: the next boot tries slot b" "expect:APPLY-OK" \
    "$(ROOTSH 'kryptik-update status')" "expect:trial pending:    b" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "grab:v2:grep ^VERSION_ID= /etc/os-release; cat /run/kryptik/boot-identity; cat /var/lib/kryptik/boot/last-result" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = before-update" \
    "$(ROOTSH 'sha256sum -c /root/work.sha && kryptik-update status && echo B-OK')" "expect:B-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "B applied, rebooted into slot b, home file and zone volume intact" || red "phase 2 drive failed"
txt | grep -q "KRYPTIK_SMOKE: boot_identity=slot=b" && green "booted slot b" || red "did not boot slot b"
txt | grep -q "version_id=${VB}" && green "guest reports version ${VB}" || red "guest did not report ${VB}"
txt | grep -q "boot-success: trial slot b booted successfully; committing" && green "boot-success committed slot b" || red "no commit of slot b"
txt | grep -q "committed slot:   b" && green "status shows committed slot b" || red "committed slot is not b"

# ---------------------------------------------------------------- phase 3 --
phase "phase 3: refusals on the running ${VB}"
start_vm update-p3 --disk "$BADIMG" --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/p /run/upd/a && mount -o ro /dev/vdb /run/upd/p && mount -o ro /dev/vdc /run/upd/a && echo MNT-OK')" "expect:MNT-OK" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/wrongkey; echo RC=$?')" "expect:not enrolled" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/modified; echo RC=$?')" "expect:sha256 does not match" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/truncated; echo RC=$?')" "expect:truncated or altered" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/extra; echo RC=$?')" "expect:unlisted file" \
    "$(ROOTSH 'kryptik-update apply /run/upd/a; echo RC=$?')" "expect:older than the running" \
    "$(ROOTSH 'flock /run/kryptik/update.lock sleep 20 & sleep 1; kryptik-update apply /run/upd/a --recovery; echo RC=$?')" "expect:another update is in progress" \
    "$(ROOTSH 'fallocate -l 100G /var/filler 2>/dev/null || dd if=/dev/zero of=/var/filler bs=1M 2>/dev/null; cp -a /run/upd/a /var/lib/kryptik/updates/a-full 2>&1 | tail -1; kryptik-update apply /var/lib/kryptik/updates/a-full --recovery; echo RC=$?; rm -rf /var/filler /var/lib/kryptik/updates/a-full')" "expect:RC=1" \
    "$(ROOTSH 'kryptik-update status')" "expect:trial pending:    none" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "wrong key, modified image, truncated kernel, extra file, downgrade, concurrent run and full disk were all refused; no trial armed" || red "phase 3 drive failed"

# ---------------------------------------------------------------- phase 4 --
phase "phase 4: authenticated recovery to ${VA} with --recovery"
start_vm update-p4 --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/a /var/lib/kryptik/updates/a && mount -o ro /dev/vdb /run/upd/a && cp -a /run/upd/a/. /var/lib/kryptik/updates/a/ && umount /run/upd/a && kryptik-update apply /var/lib/kryptik/updates/a --recovery && echo REC-OK')" \
    "expect:accepted because --recovery" "expect:REC-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = before-update" \
    "$(ROOTSH 'sha256sum -c /root/work.sha && cat /var/lib/kryptik/boot/last-result && echo A-OK')" "expect:commit a" "expect:A-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "recovery to ${VA}: slot a booted and committed, data intact" || red "phase 4 drive failed"
txt | grep -q "version_id=${VA}" && green "guest reports ${VA} again" || red "guest did not report ${VA}"

# ---------------------------------------------------------------- phase 5 --
phase "phase 5: rollback arms the other slot (b) and it boots"
start_vm update-p5
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'kryptik-update rollback && echo RB-OK')" "expect:armed: the next boot tries slot b" "expect:RB-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity; cat /var/lib/kryptik/boot/last-result; echo RB2-OK')" "expect:slot=b" "expect:commit b" "expect:RB2-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "rollback: slot b armed, booted and committed" || red "phase 5 drive failed"
txt | grep -q "version_id=${VB}" && green "guest reports ${VB} after rollback" || red "guest did not report ${VB}"

# ---------------------------------------------------------------- phase 6 --
phase "phase 6: interruption during the slot write, then after arming"
start_vm update-p6 --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/a /var/lib/kryptik/updates/a && mount -o ro /dev/vdb /run/upd/a && cp -a /run/upd/a/. /var/lib/kryptik/updates/a/ && umount /run/upd/a && echo COPY-OK')" "expect:COPY-OK" \
    "send:su - root -c 'kryptik-update apply /var/lib/kryptik/updates/a --recovery'" "expect:Password: ?" "send:${RPASS}" \
    "expect:writing kryptik-a"
python3 - "$QMP" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1]); f = s.makefile("rwb", buffering=0)
f.readline(); f.write(b'{"execute":"qmp_capabilities"}\n'); f.readline(); f.write(b'{"execute":"quit"}\n'); f.readline()
PY
sleep 2; stop_vm
green "VM killed while slot a was being written (QMP quit, no clean shutdown)"
start_vm update-p6b --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity; kryptik-update status; echo P6-OK')" "expect:slot=b" "expect:trial pending:    none" "expect:P6-OK" \
    "$(ROOTSH 'kryptik-update apply /var/lib/kryptik/updates/a --recovery && echo ARMED-OK')" "expect:ARMED-OK"
rc=$?
[[ "$rc" -eq 0 ]] && green "after the interrupted write: still slot b, no trial; the apply succeeds again" || red "phase 6a drive failed"
# armed, now kill again before the reboot: the firmware consumes BootNext at the next boot
python3 - "$QMP" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1]); f = s.makefile("rwb", buffering=0)
f.readline(); f.write(b'{"execute":"qmp_capabilities"}\n'); f.readline(); f.write(b'{"execute":"quit"}\n'); f.readline()
PY
sleep 2; stop_vm
start_vm update-p6c
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity; cat /var/lib/kryptik/boot/last-result; echo P6C-OK')" "expect:slot=a" "expect:commit a" "expect:P6C-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "after a kill between arming and reboot: the trial boot happened and slot a was committed" || red "phase 6c drive failed"

# ---------------------------------------------------------------- phase 7 --
phase "phase 7: a deliberately broken trial falls back, is recorded, and is refused until retried"
# On slot a (committed in phase 6). Arm B, power off, corrupt slot b's root
# image from the host, boot: the firmware tries b (BootNext), dm-verity
# panics on the first bad block, panic=10 reboots, BootNext is spent, so the
# firmware loads BOOTX64.EFI - slot a - and boot-success records the failed
# trial. The updater then refuses the same payload without --retry; with it
# the slot is rewritten, verified, armed, and this time it comes up and is
# committed. Detection, fallback and recovery, on the real chain.
start_vm update-p7 --disk "$PB"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; mkdir -p /run/upd/p /var/lib/kryptik/updates/b2 && mount -o ro /dev/vdb /run/upd/p && cp -a /run/upd/p/. /var/lib/kryptik/updates/b2/ && umount /run/upd/p && kryptik-update apply /var/lib/kryptik/updates/b2 && echo ARM7-OK')" \
    "expect:slot=a" "expect:ARM7-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "B armed from slot a" || red "phase 7 arming failed"
B_OFF=$(( $(part_start_disk "$DISK" 3) * 512 ))
# The ext4 superblock's volume name: the first block a root mount reads, so
# the trial boot meets the corruption at once (a byte deep in the data area
# can sit in a block nothing reads at boot, and the trial would succeed).
printf '\xa5' | dd of="$DISK" bs=1 seek=$(( B_OFF + 1024 + 0x78 )) conv=notrunc status=none
green "slot b's root image corrupted from the host (one byte in the superblock)"
start_vm update-p7b
drive "expect:Linux version" \
    "expect:device-mapper: verity:.*(corrupt|mismatch|error)|dm-verity device corrupted" \
    "expect:Kernel panic" \
    "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; cat /var/lib/kryptik/boot/last-result; kryptik-update status; echo P7B-OK')" \
    "expect:slot=a" "expect:trial-failed b" "expect:P7B-OK" \
    "$(ROOTSH 'kryptik-update apply /var/lib/kryptik/updates/b2; echo RC=$?')" "expect:failed to boot" "expect:RC=1" \
    "$(ROOTSH 'kryptik-update apply /var/lib/kryptik/updates/b2 --retry && echo RETRY-OK')" "expect:slot b verifies after write" "expect:RETRY-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; cat /var/lib/kryptik/boot/last-result; echo P7C-OK')" "expect:slot=b" "expect:commit b" "expect:P7C-OK" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = before-update" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "broken trial: verity panic, fallback to a, trial-failed recorded, refused without --retry, rewritten and committed with it; data intact" || red "phase 7 drive failed"
txt | grep -q 'boot-success: trial slot b did NOT boot' && green "boot-success named the failed trial" || red "boot-success did not record the failed trial"
if [[ "$(txt | grep -c 'Linux version')" -ge 3 ]]; then green "three kernel starts in one session: the corrupt trial, the fallback, the retried trial" ; else red "expected three kernel starts"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Limits: the interruptions are QEMU process kills with cache=writeback and explicit fsyncs;"
echo "they exercise the recovery logic, not a storage controller's power-loss behaviour."
[[ "$FAIL" -eq 0 ]] || exit 1
