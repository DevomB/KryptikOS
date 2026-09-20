#!/usr/bin/env bash
#
# OS updates on an installed system (the update suite): install release A,
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
step() { printf '\n==> %s\n' "$*"; }
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

# Variants of A for the refusal cases, applied on the running B with
# --recovery: A is older, --recovery admits the version and leaves every
# later check to do its work. A variant of the RUNNING version is refused
# as "nothing to apply" before its defect is ever reached (the run on
# bae1de53 showed that with variants of B), which proves nothing about the
# check the variant was made for.
BAD="${VMDIR}/bad"; rm -rf "$BAD"; mkdir -p "$BAD"
mk_variant() {   # mk_variant NAME  -> $BAD/NAME is a copy of payload A
    rm -rf "${BAD:?}/$1"; cp -a --sparse=always "$PAY_A" "$BAD/$1"
}
mk_variant wrongkey; ssh-keygen -q -t ed25519 -N "" -f "$BAD/otherkey" >/dev/null; rm -f "$BAD/wrongkey/manifest.sig"
ssh-keygen -Y sign -f "$BAD/otherkey" -n kryptik-release "$BAD/wrongkey/manifest" >/dev/null 2>&1
mk_variant modified; printf '\xff' | dd of="$BAD/modified/kryptik-root.img" bs=1 seek=$((4096*200+3)) conv=notrunc status=none
mk_variant truncated; truncate -s -1 "$BAD/truncated/kryptik-a.efi"
mk_variant extra; echo "ride along" > "$BAD/extra/extra.bin"
# An empty lost+found is the medium's own and is passed over (step 2 applies
# a payload that is the root of an ext4 disk); one with something in it is not.
mk_variant hidden; mkdir -p "$BAD/hidden/lost+found"; echo "ride along" > "$BAD/hidden/lost+found/ride"
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

# Each step starts from the state the one before it leaves. When the copy in
# step 4 failed for want of disk space, steps 5 to 7 went on to roll back a
# slot that was never written and to arm a payload that was not there, and
# the last of them sat in a boot loop for fifty minutes to report eight
# failures that were all the first one. A step that fails ends the run, and
# the report then says the one thing that went wrong.
stop_unless_ok() {   # stop_unless_ok RC WHAT
    [[ "$1" -eq 0 ]] && return 0
    printf '\n  stopping: %s failed, and every later step starts from the state it leaves.\n' "$2"
    printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
    exit 1
}

# ----------------------------------------------------------------- step 1 --
step "step 1: install ${VA}, boot it, create zone data"
# Sized from the medium, with room on kryptik-state for the two payloads this
# suite keeps there at once: b from step 2 is still there when a arrives in
# step 4. On a fixed 12 GiB disk that stopped fitting when the image grew, and
# every later step failed for that reason and no other.
DISK_SIZE="$("${SELF}/test-disk-size.sh" --medium "$USB_A" --payloads 2)" || die "could not size the test disk from the medium"
rm -f "$DISK"; truncate -s "$DISK_SIZE" "$DISK"
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
[[ "$rc" -eq 0 ]] && green "A boots, zone volume created (${VA})" || red "step 1 drive failed"
stop_unless_ok "$rc" "step 1"
txt | grep -q "version_id=${VA}" && green "guest reports version ${VA}" || red "guest did not report version ${VA}"

# ----------------------------------------------------------------- step 2 --
step "step 2: apply ${VB}, reboot into slot b"
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
[[ "$rc" -eq 0 ]] && green "B applied, rebooted into slot b, home file and zone volume intact" || red "step 2 drive failed"
stop_unless_ok "$rc" "step 2"
txt | grep -q "KRYPTIK_SMOKE: boot_identity=slot=b" && green "booted slot b" || red "did not boot slot b"
txt | grep -q "version_id=${VB}" && green "guest reports version ${VB}" || red "guest did not report ${VB}"
txt | grep -q "boot-success: committed: BOOTX64.EFI is now slot b" && green "boot-success committed slot b" || red "no commit of slot b"
txt | grep -q "committed slot:   b" && green "status shows committed slot b" || red "committed slot is not b"

# ----------------------------------------------------------------- step 3 --
step "step 3: refusals on the running ${VB}"
start_vm update-p3 --disk "$BADIMG" --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/p /run/upd/a && mount -o ro /dev/vdb /run/upd/p && mount -o ro /dev/vdc /run/upd/a && echo MNT-OK')" "expect:MNT-OK" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/wrongkey; echo RC=$?')" "expect:not enrolled" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/modified --recovery; echo RC=$?')" "expect:sha256 does not match" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/truncated --recovery; echo RC=$?')" "expect:truncated or altered" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/extra --recovery; echo RC=$?')" "expect:unlisted file" \
    "$(ROOTSH 'kryptik-update apply /run/upd/p/hidden --recovery; echo RC=$?')" "expect:lost\\+found is not empty" \
    "$(ROOTSH 'kryptik-update apply /run/upd/a; echo RC=$?')" "expect:older than the running" \
    "$(ROOTSH 'flock /run/kryptik/update.lock sleep 20 & sleep 1; kryptik-update apply /run/upd/a --recovery; echo RC=$?')" "expect:another update is in progress" \
    "$(ROOTSH 'fallocate -l 100G /var/filler 2>/dev/null || dd if=/dev/zero of=/var/filler bs=1M 2>/dev/null; cp -a /run/upd/a /var/lib/kryptik/updates/a-full 2>&1 | tail -1; kryptik-update apply /var/lib/kryptik/updates/a-full --recovery; echo RC=$?; rm -rf /var/filler /var/lib/kryptik/updates/a-full')" "expect:RC=1" \
    "$(ROOTSH 'kryptik-update status')" "expect:trial pending:    none" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "wrong key, modified image, truncated kernel, extra file, downgrade, concurrent run and full disk were all refused; no trial armed" || red "step 3 drive failed"

# ----------------------------------------------------------------- step 4 --
step "step 4: authenticated recovery to ${VA} with --recovery"
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
[[ "$rc" -eq 0 ]] && green "recovery to ${VA}: slot a booted and committed, data intact" || red "step 4 drive failed"
stop_unless_ok "$rc" "step 4"
txt | grep -q "version_id=${VA}" && green "guest reports ${VA} again" || red "guest did not report ${VA}"

# ----------------------------------------------------------------- step 5 --
step "step 5: rollback arms the other slot (b) and it boots"
start_vm update-p5
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'kryptik-update rollback && echo RB-OK')" "expect:armed: the next boot tries slot b" "expect:RB-OK" \
    "$(ROOTSH 'reboot')" "expect:Linux version" "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity; cat /var/lib/kryptik/boot/last-result; echo RB2-OK')" "expect:slot=b" "expect:commit b" "expect:RB2-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "rollback: slot b armed, booted and committed" || red "step 5 drive failed"
stop_unless_ok "$rc" "step 5"
txt | grep -q "version_id=${VB}" && green "guest reports ${VB} after rollback" || red "guest did not report ${VB}"

# ----------------------------------------------------------------- step 6 --
step "step 6: interruption during the slot write, then after arming"
# The copy is synced before the updater starts. The kill below discards the
# guest's page cache, and on 55904d05 the copy had reached the disk only in
# part (kryptik-root.img 1666211840 of 2754519040 bytes), so the re-apply
# after the reboot refused its own payload as truncated. The interruption
# under test is the slot write, not the operator's copy.
start_vm update-p6 --disk "$PA"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'mkdir -p /run/upd/a /var/lib/kryptik/updates/a && mount -o ro /dev/vdb /run/upd/a && cp -a /run/upd/a/. /var/lib/kryptik/updates/a/ && umount /run/upd/a && sync && echo COPY-OK')" "expect:COPY-OK" \
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
[[ "$rc" -eq 0 ]] && green "after the interrupted write: still slot b, no trial; the apply succeeds again" || red "step 6a drive failed"
stop_unless_ok "$rc" "step 6a"
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
[[ "$rc" -eq 0 ]] && green "after a kill between arming and reboot: the trial boot happened and slot a was committed" || red "step 6c drive failed"
stop_unless_ok "$rc" "step 6c"

# ----------------------------------------------------------------- step 7 --
step "step 7: a deliberately broken trial falls back, is recorded, and is refused until retried"
# On slot a (committed in step 6). Arm B, power off, corrupt slot b's root
# image from the host, boot: the firmware tries b (BootNext), dm-verity
# panics on the first bad block, panic=10 reboots, BootNext is spent, so the
# firmware loads BOOTX64.EFI - slot a - and boot-success records the failed
# trial. The updater then refuses the same payload without --retry; with it
# the slot is rewritten, verified, armed, and this time it comes up and is
# committed. Detection, fallback and recovery, on the real chain.
#
# What a boot that dies before userspace looks like on the console: the
# command line carries loglevel=4, so the kernel's own "Linux version"
# banner (a notice) never reaches it; every "Linux version" the drivers
# see is boot-smoke's kernel_version_full line, printed from userspace.
# The corrupt trial therefore shows only the firmware's start line, the
# verity error and the panic - so that boot is read by those, and the
# session's boots are counted by the firmware's "BdsDxe: starting Boot"
# lines, one per boot, rather than by a banner only a booted userspace prints.
# The payload copies of steps 2 and 6 are still on the state partition,
# and a third one does not fit beside them (cp: No space left on device,
# on bae1de53); they have served, so they go before B is copied again.
start_vm update-p7 --disk "$PB"
drive "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "$(ROOTSH 'cat /run/kryptik/boot-identity | head -1; rm -rf /var/lib/kryptik/updates/a /var/lib/kryptik/updates/b; mkdir -p /run/upd/p /var/lib/kryptik/updates/b2 && mount -o ro /dev/vdb /run/upd/p && cp -a /run/upd/p/. /var/lib/kryptik/updates/b2/ && umount /run/upd/p && kryptik-update apply /var/lib/kryptik/updates/b2 && echo ARM7-OK')" \
    "expect:slot=a" "expect:ARM7-OK" \
    "$(ROOTSH 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; stop_vm
[[ "$rc" -eq 0 ]] && green "B armed from slot a" || red "step 7 arming failed"
stop_unless_ok "$rc" "step 7 arming"
B_OFF=$(( $(part_start_disk "$DISK" 3) * 512 ))
# The ext4 superblock's volume name: the first block a root mount reads, so
# the trial boot meets the corruption at once (a byte deep in the data area
# can sit in a block nothing reads at boot, and the trial would succeed).
printf '\xa5' | dd of="$DISK" bs=1 seek=$(( B_OFF + 1024 + 0x78 )) conv=notrunc status=none
green "slot b's root image corrupted from the host (one byte in the superblock)"
start_vm update-p7b
drive "expect:BdsDxe: starting Boot" \
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
[[ "$rc" -eq 0 ]] && green "broken trial: verity panic, fallback to a, trial-failed recorded, refused without --retry, rewritten and committed with it; data intact" || red "step 7 drive failed"
txt | grep -q 'boot-success: trial slot b did NOT boot' && green "boot-success named the failed trial" || red "boot-success did not record the failed trial"
starts="$(txt | grep -c 'BdsDxe: starting Boot')"; ups="$(txt | grep -c 'KRYPTIK_SMOKE: END')"; panics="$(txt | grep -c 'Kernel panic')"
if [[ "$starts" -ge 3 && "$ups" -ge 2 && "$panics" -ge 1 ]]; then green "three boots in one session: the corrupt trial (panicked), the fallback and the retried trial (both reached userspace)"; else red "expected three boots: firmware starts=${starts}, userspace ends=${ups}, panics=${panics}"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
echo "Limits: the interruptions are QEMU process kills with cache=writeback and explicit fsyncs;"
echo "they exercise the recovery logic, not a storage controller's power-loss behaviour."
[[ "$FAIL" -eq 0 ]] || exit 1
