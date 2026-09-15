#!/usr/bin/env bash
#
# Boot integrity on an installed disk (Design 08, gate G5): enforced Secure
# Boot with the developer key, an untrusted boot file refused by the firmware,
# root tampering refused by dm-verity before any userspace runs, and recovery
# from the medium afterwards.
#
#   tools/image/integrity-test.sh --usb IMG [--disk FILE] [--timeout N]
#
#   1  install (fresh disk, control disk) and boot it alone under the
#      ENROLLED variable store: Secure Boot on, the guest reports it
#   2  untrusted boot artifact: BOOTX64.EFI on the disk's ESP replaced by the
#      same kernel signed with a different key -> the firmware refuses it,
#      no kernel banner (the medium's own signed kernel still boots the same
#      firmware: positive control)
#   3  root tampering: the ESP restored, one data block of slot a flipped ->
#      the kernel panics on the verity mismatch before mounting root; no
#      "KRYPTIK_SMOKE" line, and the serial log names dm-verity
#   4  recovery: boot the medium with the disk attached, kryptik-recover
#      --restore-slot a from the medium; boot the disk alone: it comes up,
#      the user created at first boot is still there (state untouched)
#
# Every disk is a file made here. The firmware whose keys are enrolled is a
# copy of OVMF's variable store; no machine's firmware is touched.
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
        -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sbsign sbverify openssl mcopy mdel mdir sfdisk; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/integrity.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"
ENROLLED="${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd"
[[ -f "$ENROLLED" ]] || die "no enrolled variable store; run tools/image/ovmf-vars.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
phase() { printf '\n==> %s\n' "$*"; }
TUSER=tester; TPASS=tester-pw; RPASS=root-pw
TUSER_HASH="$(openssl passwd -6 "$TPASS")"; ROOT_HASH="$(openssl passwd -6 "$RPASS")"
DRV="${SELF}/vm-drive.py"
VARSF="${VMDIR}/integrity-vars.fd"; cp "$ENROLLED" "$VARSF"
LATEST="${KRYPTIK_WORK}/logs/ovmf-serial.latest.log"
txt_latest() { tr -d '\r' < "$LATEST"; }

# Partition offsets on the disk file, from its GPT, so the host can edit the
# ESP with mtools and flip bytes in slot a without mounting anything.
part_start() { sfdisk -d "$DISK" 2>/dev/null | awk -v n="$1" -F'[ ,]+' '$1 ~ n"$" {for(i=1;i<=NF;i++) if($i=="start=") print $(i+1)}'; }

# ---------------------------------------------------------------- phase 1 --
phase "phase 1: install, then boot alone with the developer key enrolled (Secure Boot on)"
rm -f "$DISK"; truncate -s 12G "$DISK"
CTL="${VMDIR}/testctl-integrity.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}" > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars enrolled --mode smoke --timeout "$TIMEOUT" --name integ-install > /dev/null
txt_latest | grep -q 'KRYPTIK_INSTALL: rc=0' && green "installed from the medium under Secure Boot" || { red "install failed"; exit 1; }
txt_latest | grep -q 'KRYPTIK_SMOKE: secureboot=1' && green "the medium itself booted with Secure Boot enforced" || red "medium did not report secureboot=1"

SERVE="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name integ-p1)"
SER="$(sed -n 's/^serial=//p' <<<"$SERVE")"; PIDF="$(sed -n 's/^pid=//p' <<<"$SERVE")"; LOG1="$(sed -n 's/^log=//p' <<<"$SERVE")"
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:test \"\$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d ' ')\" = 1" \
    "run:echo integrity-marker > /home/${TUSER}/marker && sync" \
    "su:${RPASS}:poweroff" "expect:Power down" "wait-exit"
rc=$?; sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
[[ "$rc" -eq 0 ]] && green "installed system boots with Secure Boot enforced (SecureBoot=1 inside the guest)" || red "phase 1 drive failed"
tr -d '\r' < "$LOG1" | grep -q 'KRYPTIK_SMOKE: verity_root=0 [0-9]* verity V' && green "dm-verity reports the root valid" || red "no valid verity root reported"

# ---------------------------------------------------------------- phase 2 --
phase "phase 2: an untrusted boot artifact is refused by the firmware"
ESP_OFF=$(( $(part_start 1) * 512 ))
ESPIMG="${VMDIR}/integrity-esp.img"
# lift the ESP out, keep a pristine copy, swap in a foreign-signed kernel
dd if="$DISK" of="$ESPIMG" bs=1M iflag=skip_bytes,count_bytes skip="$ESP_OFF" count=$((512*1024*1024)) status=none
cp "$ESPIMG" "${ESPIMG}.pristine"
TMPK="$(mktemp -d)"
mcopy -i "$ESPIMG" ::/EFI/BOOT/BOOTX64.EFI "$TMPK/good.efi"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=not kryptik/" -keyout "$TMPK/k" -out "$TMPK/c" >/dev/null 2>&1
# strip the developer signature, sign with the foreign key
sbattach --remove "$TMPK/good.efi" 2>/dev/null || true
sbsign --key "$TMPK/k" --cert "$TMPK/c" --output "$TMPK/foreign.efi" "$TMPK/good.efi" >/dev/null 2>&1
sbverify --cert "${KRYPTIK_WORK}/keys/sb/kryptik-sb.crt" "$TMPK/foreign.efi" >/dev/null 2>&1 && red "control: the foreign kernel verifies against our key" || green "control: the foreign-signed kernel does not verify against the developer key"
mdel -i "$ESPIMG" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$ESPIMG" "$TMPK/foreign.efi" ::/EFI/BOOT/BOOTX64.EFI
dd if="$ESPIMG" of="$DISK" bs=1M oflag=seek_bytes seek="$ESP_OFF" conv=notrunc status=none
cp "$ENROLLED" "$VARSF"
"${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode smoke --timeout 120 --name integ-p2 > /dev/null
T2="$(txt_latest)"
grep -q 'Linux version' <<<"$T2" && red "a foreign-signed kernel BOOTED under the enrolled key" || green "the firmware did not start the foreign-signed kernel"
grep -q 'KRYPTIK_SMOKE: BEGIN' <<<"$T2" && red "Kryptik userspace ran from an untrusted boot file" || green "no userspace ran"
# positive control: the same firmware and store boot the medium's signed kernel
"${SELF}/mk-testctl.sh" --out "${VMDIR}/testctl-smoke.img" smoke_poweroff=1 > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --testctl "${VMDIR}/testctl-smoke.img" --vars enrolled --mode smoke --timeout 300 --name integ-p2ctl > /dev/null 2>&1
txt_latest | grep -q 'Linux version' && green "control: the developer-signed medium boots under the same store" || red "control failed: the signed medium did not boot"
# restore the pristine ESP
dd if="${ESPIMG}.pristine" of="$DISK" bs=1M oflag=seek_bytes seek="$ESP_OFF" conv=notrunc status=none
rm -rf "$TMPK"

# ---------------------------------------------------------------- phase 3 --
phase "phase 3: a tampered root is refused by dm-verity before userspace"
A_OFF=$(( $(part_start 2) * 512 ))
# Flip a byte in the ext4 superblock (byte 1024 of the image, the volume
# name field at +0x78): the first thing a root mount reads, so dm-verity
# sees a block whose hash does not match before any userspace exists. A
# byte deep in the data area, which this used to flip, sits in a block
# nothing reads at boot, and the system came up as if untouched.
printf '\xa5' | dd of="$DISK" bs=1 seek=$(( A_OFF + 1024 + 0x78 )) conv=notrunc status=none
cp "$ENROLLED" "$VARSF"
"${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode smoke --timeout 300 --name integ-p3 > /dev/null
T3="$(txt_latest)"
# The kernel's banner is KERN_NOTICE and loglevel=4 keeps it off the console;
# a boot that panics before userspace prints no smoke report either. Its own
# timestamped console lines are the proof it started.
grep -qE '^\[ *[0-9]+\.[0-9]+\] |Linux version' <<<"$T3" && green "the (untampered) kernel still starts" || red "the kernel did not start after the root tamper"
# The kernel's own message, not the command line's "panic_on_corruption".
grep -qE 'device-mapper: verity:.*(corrupt|mismatch|error)|dm-verity device corrupted' <<<"$T3" && green "dm-verity named the corruption" || red "no dm-verity corruption report"
grep -q 'Kernel panic' <<<"$T3" && green "the kernel panicked on the verity failure (panic_on_corruption)" || red "no panic on a corrupted root"
grep -q 'KRYPTIK_SMOKE: BEGIN' <<<"$T3" && red "userspace ran on a tampered root" || green "no userspace ran on the tampered root"
grep -q 'login:' <<<"$T3" && red "a login prompt appeared on a tampered root" || green "no login prompt on the tampered root"

# ---------------------------------------------------------------- phase 4 --
phase "phase 4: recovery from the medium restores slot a; state survives"
CTLR="${VMDIR}/testctl-recover.img"
"${SELF}/mk-testctl.sh" --out "$CTLR" recover_disk=/dev/vda recover_slot=a recover_mode=restore smoke_poweroff=1 install_wait=5 > /dev/null
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTLR" --vars enrolled --mode smoke --timeout "$TIMEOUT" --name integ-p4 > /dev/null
txt_latest | grep -q 'KRYPTIK_RECOVER: rc=0' && green "kryptik-recover --restore-slot a succeeded from the medium" || { red "recovery did not report success"; txt_latest | grep 'KRYPTIK_RECOVER' | tail -5 | sed 's/^/        /'; }
cp "$ENROLLED" "$VARSF"
SERVE="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name integ-p4b)"
SER="$(sed -n 's/^serial=//p' <<<"$SERVE")"; PIDF="$(sed -n 's/^pid=//p' <<<"$SERVE")"; LOG4="$(sed -n 's/^log=//p' <<<"$SERVE")"
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = integrity-marker" \
    "su:${RPASS}:poweroff" "expect:Power down" "wait-exit"
rc=$?; sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
[[ "$rc" -eq 0 ]] && green "the recovered disk boots alone under Secure Boot; the user and the home file survived" || red "phase 4 drive failed"
tr -d '\r' < "$LOG4" | grep -q 'KRYPTIK_SMOKE: verity_root=0 [0-9]* verity V' && green "dm-verity reports the restored root valid" || red "restored root not reported valid"
tr -d '\r' < "$LOG4" | grep -q 'kryptik-firstboot: created user' && red "first-boot setup ran again (state was lost)" || green "first-boot setup did not run again"

# ---------------------------------------------------------------- phase 5 --
phase "phase 5: offline tampering of the state partition does not reach privileged startup"
# The state partition is mutable and unauthenticated by design (sysinit.sh,
# "the trust boundary"). Someone with the disk in hand can put anything
# under /etc through the overlay's upper layer. What they must NOT gain:
# a trust anchor of their own for updates, a zone definition the launch
# daemon will honour, a kernel tunable applied at boot. Plant all three from
# the host, boot, and measure each from inside the guest.
S_OFF=$(( $(part_start 4) * 512 ))
TMPK="$(mktemp -d)"; MNT="$TMPK/state"; mkdir -p "$MNT"
ssh-keygen -q -t ed25519 -N "" -f "$TMPK/attacker" >/dev/null
if mount -o loop,offset="$S_OFF" "$DISK" "$MNT" 2>/dev/null; then
    up="$MNT/lib/kryptik/etc/upper"
    mkdir -p "$up/kryptik/trust" "$up/kryptik/zones" "$up/sysctl.d"
    printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 "$TMPK/attacker.pub")" > "$up/kryptik/trust/release-signers"
    printf 'development\n' > "$up/kryptik/trust/required-role"
    # a zone directory in the upper layer replaces the verified symlink under /etc
    cat > "$up/kryptik/zones/evil.toml" <<'EOF'
[zone]
name = "evil"
[network]
mode = "none"
[storage]
mode = "ephemeral"
size = "64M"
[identity]
uid_base = 1310720
[ui]
border_color = "#000001"
EOF
    printf 'kernel.kptr_restrict = 0\n' > "$up/sysctl.d/99-evil.conf"
    # And the names root honours without asking: a preload library for every
    # process, a udev rule that RUNs as root, both pointing at the state
    # partition. Plus one change the system MAY keep (a subuid line), which
    # proves the overlay still works for what is allowed.
    mkdir -p "$up/udev/rules.d" "$MNT/lib/kryptik"
    printf '/var/lib/kryptik/evil.so\n' > "$up/ld.so.preload"
    printf 'ACTION=="add", RUN+="/var/lib/kryptik/evil.sh"\n' > "$up/udev/rules.d/99-evil.rules"
    printf '#!/bin/sh\ntouch /var/lib/kryptik/evil-ran\n' > "$MNT/lib/kryptik/evil.sh"; chmod 0755 "$MNT/lib/kryptik/evil.sh"
    printf 'planted:1310720:65536\n' > "$up/subuid"
    sync; umount "$MNT"
    green "planted a trust anchor, a zone definition, a sysctl fragment, a preload library and a udev rule under the state's /etc upper layer, and one allowed change"
else
    red "could not mount the state partition from the host (loop/offset); phase 5 not performed"
fi
# A payload signed with the attacker's key: valid against the planted anchor,
# not against the image's.
PAYDIR="${KRYPTIK_WORK}/images/payload-$(sed -n 's/^  "version": "\([^"]*\)".*/\1/p' "${KRYPTIK_WORK}/images/root.json" 2>/dev/null)"
if [[ -f "$PAYDIR/manifest" ]]; then
    rm -rf "$TMPK/pay"; cp -a --sparse=always "$PAYDIR" "$TMPK/pay"; rm -f "$TMPK/pay/manifest.sig"
    ssh-keygen -Y sign -f "$TMPK/attacker" -n kryptik-release "$TMPK/pay/manifest" >/dev/null 2>&1
    PAYIMG="${VMDIR}/integrity-attacker-payload.img"; rm -f "$PAYIMG"
    bytes="$(du -sb "$TMPK/pay" | cut -f1)"; truncate -s $(( bytes + bytes / 10 + 64 * 1024 * 1024 )) "$PAYIMG"
    mkfs.ext4 -q -F -d "$TMPK/pay" "$PAYIMG"
    EXTRA=(--disk "$PAYIMG")
else
    red "no stage 06 payload under ${KRYPTIK_WORK}/images; the attacker-signed update case cannot run"
    EXTRA=()
fi
cp "$ENROLLED" "$VARSF"
SERVE="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name integ-p5 "${EXTRA[@]}")"
SER="$(sed -n 's/^serial=//p' <<<"$SERVE")"; PIDF="$(sed -n 's/^pid=//p' <<<"$SERVE")"; LOG5="$(sed -n 's/^log=//p' <<<"$SERVE")"
# What the guest must show: the planted kryptik/ directory (anchor and zone)
# is in the quarantine and gone from /etc, and the anchor the updater reads -
# /usr/share/kryptik/trust/release-signers, on the verified root - still
# names the release key. (/etc/kryptik/trust never existed in the lower
# layer; only the planted copy put it there.)
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "grab:overlay:ls /etc/kryptik/ /var/lib/kryptik/etc/quarantine/ 2>&1 | head -12" \
    "run:test ! -e /etc/kryptik/trust/release-signers" \
    "run:grep -q '^kryptik-release ' /usr/share/kryptik/trust/release-signers" \
    "run:ls /var/lib/kryptik/etc/quarantine/ | grep -q '^kryptik'" \
    "run:test ! -e /etc/kryptik/zones/evil.toml" \
    "run:test ! -e /etc/ld.so.preload" \
    "run:test ! -e /etc/udev/rules.d/99-evil.rules" \
    "run:test ! -e /var/lib/kryptik/evil-ran" \
    "run:ls /var/lib/kryptik/etc/quarantine/ | grep -q '^ld.so.preload'" \
    "run:ls /var/lib/kryptik/etc/quarantine/ | grep -q '^udev'" \
    "run:grep -q '^planted:' /etc/subuid" \
    "run:test \"\$(sysctl -n kernel.kptr_restrict)\" = 2" \
    "run!:kryptik-launch --info evil; echo EVIL-RC=\$?" "seen:no zone named \"evil\"" \
    "run:kryptik-launch --info work" \
    "$(printf 'su:%s:%s' "$RPASS" 'kryptikd list --zones /usr/lib/kryptik/zones | grep -c evil; echo LIST-DONE')" "expect:LIST-DONE" \
    ${EXTRA:+"$(printf 'su:%s:%s' "$RPASS" 'mkdir -p /run/upd/x && mount -o ro /dev/vdb /run/upd/x && kryptik-update apply /run/upd/x; echo UPD-RC=$?')"} \
    ${EXTRA:+"expect:not enrolled"} \
    "$(printf 'su:%s:%s' "$RPASS" 'poweroff')" "expect:Power down" "wait-exit"
rc=$?; sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
T5="$(tr -d '\r' < "$LOG5")"
[[ "$rc" -eq 0 ]] && green "the planted /etc content was quarantined before the overlay was mounted (preload, udev rule, zone, anchor, sysctl), the allowed change is in effect, and nothing planted ran" || red "phase 5 drive failed"
grep -q 'no zone named "evil"' <<<"$T5" && green "the launch daemon does not know the planted zone (it reads /usr/lib/kryptik/zones)" || red "the daemon honoured a planted zone"
if [[ -n "${EXTRA[*]:-}" ]]; then
    grep -q 'not enrolled' <<<"$T5" && green "an update signed by the planted anchor's key is refused (the anchor is read from the verified root)" || red "an attacker-signed update was not refused"
fi
grep -q 'KRYPTIK_SMOKE: sysctl kernel.kptr_restrict=2' <<<"$T5" && green "the planted sysctl fragment was not applied" || red "the planted sysctl was applied"
grep -q 'KRYPTIK_SMOKE: var_source=/dev/vda4' <<<"$T5" && green "state stayed persistent through the tamper (this is a repairable machine, not a bricked one)" || red "state not persistent in phase 5"
# undo the planting so later runs start clean
if mount -o loop,offset="$S_OFF" "$DISK" "$MNT" 2>/dev/null; then
    rm -rf "$MNT/lib/kryptik/etc/upper/kryptik/trust" "$MNT/lib/kryptik/etc/upper/kryptik/zones" "$MNT/lib/kryptik/etc/upper/sysctl.d" \
           "$MNT/lib/kryptik/etc/upper/ld.so.preload" "$MNT/lib/kryptik/etc/upper/udev" "$MNT/lib/kryptik/etc/upper/subuid" \
           "$MNT/lib/kryptik/etc/quarantine" "$MNT/lib/kryptik/evil.sh" "$MNT/lib/kryptik/evil-ran"
    sync; umount "$MNT"
fi
rm -rf "$TMPK"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
