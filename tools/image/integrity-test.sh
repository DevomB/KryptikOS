#!/usr/bin/env bash
# Boot integrity on an installed disk: Secure Boot enforced with the developer
# key, a foreign-signed boot file refused, a tampered root stopped by dm-verity
# before userspace, recovery from the medium, and offline tampering of the
# state partition kept away from privileged startup.
#
#   tools/image/integrity-test.sh --usb IMG [--disk FILE] [--timeout N]
#
#   step 1  install and boot alone under the enrolled store; lockdown and
#           module signing checked from inside
#   step 2  BOOTX64.EFI re-signed with a foreign key: the firmware refuses it
#           (control: the signed medium boots under the same store); then
#           kryptik-recover --commit-slot a puts the signed kernel back
#   step 3  a byte of slot a's root flipped: dm-verity stops the boot
#   step 4  kryptik-recover --restore-slot a refuses a medium whose root is
#           not the one its signed kernel names, then restores slot a from the
#           medium; its records on the ESP are whole, and the user's data survives
#   step 5  an anchor, zone, sysctl, preload library and udev rule planted in
#           the state's /etc layer: none takes effect
#   step 6  the state header saved, wiped and restored by kryptik-recover
#           from the medium: the disk unlocks and the user's data is there
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
        -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -f "$USB" ]] || die "--usb IMG is required"
for t in python3 sbsign sbverify sbattach openssl mcopy mdel mdir mtype sfdisk cryptsetup losetup debugfs; do have "$t" || die "required tool not found: $t"; done
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/integrity.img}"
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} is not a regular file"
ENROLLED="${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd"
[[ -f "$ENROLLED" ]] || die "no enrolled variable store; run tools/image/ovmf-vars.sh"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
VARSF="${VMDIR}/integrity-vars.fd"; cp "$ENROLLED" "$VARSF"

# ----------------------------------------------------------------- step 1 --
step "step 1: install, then boot alone with the developer key enrolled (Secure Boot on)"
fresh_disk "$USB"
install_disk integ-install "$USB" --vars enrolled && green "installed from the medium under Secure Boot" || { red "install failed"; exit 1; }
boot_txt | grep -q 'KRYPTIK_SMOKE: secureboot=1' && green "the medium itself booted with Secure Boot enforced" || red "medium did not report secureboot=1"

start_vm integ-p1; LOG1="$LOG"
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:test \"\$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | tr -d ' ')\" = 1" \
    "run:echo integrity-marker > /home/${TUSER}/marker && sync" \
    "$(printf 'su:%s:%s' "$RPASS" 'grep -q "\[confidentiality\]" /sys/kernel/security/lockdown && echo LOCKDOWN=confidentiality')" "expect:LOCKDOWN=confidentiality" \
    "$(printf 'su:%s:%s' "$RPASS" 'insmod /usr/lib/kryptik/kernel/mac80211_hwsim-unsigned.ko 2>&1; echo UNSIGNED-RC=$?; test ! -d /sys/module/mac80211_hwsim && echo UNSIGNED=refused')" "expect:UNSIGNED=refused" \
    "$(printf 'su:%s:%s' "$RPASS" 'modprobe mac80211_hwsim radios=0 && test -d /sys/module/mac80211_hwsim && echo SIGNED=loaded')" "expect:SIGNED=loaded" \
    "su:${RPASS}:poweroff" "expect:Power down" "wait-exit"
rc=$?; sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
[[ "$rc" -eq 0 ]] && green "installed system boots with Secure Boot enforced (SecureBoot=1 inside the guest)" || red "step 1 drive failed"
T1="$(tr -d '\r' < "$LOG1")"
grep -q 'KRYPTIK_SMOKE: verity_root=0 [0-9]* verity V' <<<"$T1" && green "dm-verity reports the root valid" || red "no valid verity root reported"
# Lockdown in confidentiality mode, and module signing both ways: stage 05's
# unsigned copy of a driver is refused with the kernel's reason, the signed one loads.
grep -q 'LOCKDOWN=confidentiality' <<<"$T1" && green "lockdown reports confidentiality" || red "lockdown is not in confidentiality mode"
if grep -q 'UNSIGNED=refused' <<<"$T1" && grep -q 'Key was rejected by service\|Required key not available' <<<"$T1"; then
    green "an unsigned module is refused (Key was rejected by service)"
else
    red "an unsigned module was not refused for its missing signature"
fi
grep -q 'SIGNED=loaded' <<<"$T1" && green "the module signed by the build loads" || red "the build's own signed module did not load"

# ----------------------------------------------------------------- step 2 --
step "step 2: an untrusted boot artifact is refused by the firmware"
ESP_OFF=$(( $(part_start "$DISK" 1) * 512 ))
ESPIMG="${VMDIR}/integrity-esp.img"
# lift the ESP out, keep a pristine copy, swap in a foreign-signed kernel
dd if="$DISK" of="$ESPIMG" bs=1M iflag=skip_bytes,count_bytes skip="$ESP_OFF" count=$((512*1024*1024)) status=none
cp "$ESPIMG" "${ESPIMG}.pristine"
TMPK="$(mktemp -d)"
mcopy -i "$ESPIMG" ::/EFI/BOOT/BOOTX64.EFI "$TMPK/good.efi"
# The certificate the medium carries, which signed the kernel it installed.
mtype -i "${USB}@@$(( $(part_start "$USB" 1) * 512 ))" ::/kryptik/kryptik-sb.crt > "$TMPK/medium.crt" 2>/dev/null
sbverify --cert "$TMPK/medium.crt" "$TMPK/good.efi" >/dev/null 2>&1 && green "control: the medium's certificate verifies the installed kernel" || red "control: the medium's certificate does not verify the installed kernel"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=not kryptik/" -keyout "$TMPK/k" -out "$TMPK/c" >/dev/null 2>&1
# Strip the signature, sign with the foreign key. The result must verify
# against the foreign certificate and not the medium's: a file sbsign never
# wrote verifies against neither, and one that kept the medium's signature
# verifies against both.
sbattach --remove "$TMPK/good.efi" >/dev/null 2>&1
sbsign --key "$TMPK/k" --cert "$TMPK/c" --output "$TMPK/foreign.efi" "$TMPK/good.efi" >/dev/null 2>&1
if sbverify --cert "$TMPK/c" "$TMPK/foreign.efi" >/dev/null 2>&1 && ! sbverify --cert "$TMPK/medium.crt" "$TMPK/foreign.efi" >/dev/null 2>&1; then
    green "control: the boot file now carries the foreign key's signature and not the medium's"
else
    red "control: the boot file was not re-signed with the foreign key alone"
fi
mdel -i "$ESPIMG" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$ESPIMG" "$TMPK/foreign.efi" ::/EFI/BOOT/BOOTX64.EFI
dd if="$ESPIMG" of="$DISK" bs=1M oflag=seek_bytes seek="$ESP_OFF" conv=notrunc status=none
cp "$ENROLLED" "$VARSF"
smoke integ-p2 --no-media --disk "$DISK" --vars-file "$VARSF" --timeout 120 \
    --until 'Access Denied|Security Violation' > /dev/null
T2="$(boot_txt)"
# A disk the firmware never tried would pass the absences below; the refusal must be seen.
grep -qE 'Access Denied|Security Violation' <<<"$T2" && green "the firmware refused the boot file for its signature" || red "the firmware reported no refusal"
grep -q 'Linux version' <<<"$T2" && red "a foreign-signed kernel BOOTED under the enrolled key" || green "the firmware did not start the foreign-signed kernel"
grep -q 'KRYPTIK_SMOKE: BEGIN' <<<"$T2" && red "Kryptik userspace ran from an untrusted boot file" || green "no userspace ran"
# positive control: the same firmware and store boot the medium's signed kernel
"${SELF}/mk-testctl.sh" --out "${VMDIR}/testctl-smoke.img" --key "$TESTCTL_KEY" smoke_poweroff=1 > /dev/null
smoke integ-p2ctl --usb "$USB" --testctl "${VMDIR}/testctl-smoke.img" --vars enrolled --timeout 300 > /dev/null 2>&1
boot_txt | grep -q 'Linux version' && green "control: the developer-signed medium boots under the same store" || red "control failed: the signed medium did not boot"
# The repair a user has: --commit-slot from the medium makes slot a's signed
# kernel the boot file again.
CTLC="${VMDIR}/testctl-commit.img"
"${SELF}/mk-testctl.sh" --out "$CTLC" --key "$TESTCTL_KEY" recover_disk=/dev/vda recover_slot=a recover_mode=commit smoke_poweroff=1 install_wait=5 > /dev/null
smoke integ-p2r --usb "$USB" --disk "$DISK" --testctl "$CTLC" --vars enrolled --timeout "$TIMEOUT" > /dev/null
boot_txt | grep -q 'KRYPTIK_RECOVER: rc=0' && green "kryptik-recover --commit-slot a succeeded from the medium" || { red "--commit-slot did not report success"; boot_txt | grep 'KRYPTIK_RECOVER' | tail -5 | sed 's/^/        /'; }
dd if="$DISK" of="$ESPIMG" bs=1M iflag=skip_bytes,count_bytes skip="$ESP_OFF" count=$((512*1024*1024)) status=none
mcopy -n -i "$ESPIMG" ::/EFI/BOOT/BOOTX64.EFI "$TMPK/committed.efi" 2>/dev/null
mcopy -n -i "${ESPIMG}.pristine" ::/EFI/BOOT/BOOTX64.EFI "$TMPK/installed.efi" 2>/dev/null
cmp -s "$TMPK/committed.efi" "$TMPK/installed.efi" && green "the boot file is the kernel the install wrote, byte for byte" || red "the boot file is not the kernel the install wrote"
sbverify --cert "$TMPK/medium.crt" "$TMPK/committed.efi" >/dev/null 2>&1 && green "the medium's certificate verifies the boot file again" || red "the medium's certificate does not verify the committed boot file"
[[ "$(mtype -i "$ESPIMG" ::/kryptik/committed-slot 2>/dev/null)" == a ]] && green "the ESP records slot a as committed" || red "the ESP does not record slot a as committed"
# restore the pristine ESP
dd if="${ESPIMG}.pristine" of="$DISK" bs=1M oflag=seek_bytes seek="$ESP_OFF" conv=notrunc status=none
rm -rf "$TMPK"

# ----------------------------------------------------------------- step 3 --
step "step 3: a tampered root is refused by dm-verity before userspace"
A_OFF=$(( $(part_start "$DISK" 2) * 512 ))
# Flip a byte of the ext4 superblock (the volume name, 1024 + 0x78): mounting
# the root reads it first, so dm-verity fails before userspace. A block that
# nothing reads at boot would go unnoticed.
printf '\xa5' | dd of="$DISK" bs=1 seek=$(( A_OFF + 1024 + 0x78 )) conv=notrunc status=none
cp "$ENROLLED" "$VARSF"
smoke integ-p3 --no-media --disk "$DISK" --vars-file "$VARSF" --timeout 300 > /dev/null
T3="$(boot_txt)"
# loglevel=4 hides the KERN_NOTICE banner, so the kernel's timestamped console
# lines are the proof it started.
grep -qE '^\[ *[0-9]+\.[0-9]+\] |Linux version' <<<"$T3" && green "the (untampered) kernel still starts" || red "the kernel did not start after the root tamper"
# The kernel's own message, not the command line's "panic_on_corruption".
grep -qE 'device-mapper: verity:.*(corrupt|mismatch|error)|dm-verity device corrupted' <<<"$T3" && green "dm-verity named the corruption" || red "no dm-verity corruption report"
grep -q 'Kernel panic' <<<"$T3" && green "the kernel panicked on the verity failure (panic_on_corruption)" || red "no panic on a corrupted root"
grep -q 'KRYPTIK_SMOKE: BEGIN' <<<"$T3" && red "userspace ran on a tampered root" || green "no userspace ran on the tampered root"
grep -q 'login:' <<<"$T3" && red "a login prompt appeared on a tampered root" || green "no login prompt on the tampered root"

# ----------------------------------------------------------------- step 4 --
step "step 4: recovery from the medium restores slot a; state survives"
CTLR="${VMDIR}/testctl-recover.img"
"${SELF}/mk-testctl.sh" --out "$CTLR" --key "$TESTCTL_KEY" recover_disk=/dev/vda recover_slot=a recover_mode=restore smoke_poweroff=1 install_wait=5 > /dev/null
# First a medium altered as whoever can write to it could alter it: a byte of a
# root block nothing reads at boot, and root.json rewritten to match. Slot a
# reads back as that record says; only the signed root hash tells.
ALT="$(mktemp -d)"; ALTUSB="${VMDIR}/integrity-altered-usb.img"
cp --sparse=always "$USB" "$ALTUSB"
U_ESP=$(( $(part_start "$ALTUSB" 1) * 512 )); U_ROOT=$(( $(part_start "$ALTUSB" 2) * 512 ))
mtype -i "${ALTUSB}@@${U_ESP}" ::/kryptik/root.json > "$ALT/root.json"
A_BLOCKS="$(sed -n 's/^  "data_blocks": \([0-9]*\).*/\1/p' "$ALT/root.json")"
A_BYTES="$(sed -n 's/^  "total_bytes": \([0-9]*\).*/\1/p' "$ALT/root.json")"
# A free block from the middle of the root's ext4: never read, still verified.
A_FREE=""
if [[ -n "$A_BLOCKS" ]] && A_LOOP="$(losetup --find --show --read-only --offset "$U_ROOT" --sizelimit $(( A_BLOCKS * 4096 )) "$ALTUSB")"; then
    A_FREE="$(debugfs -R "ffb 1 $(( A_BLOCKS / 2 ))" "$A_LOOP" 2>/dev/null | sed -n 's/^Free blocks found: \([0-9][0-9]*\).*/\1/p')"
    losetup -d "$A_LOOP"
fi
if [[ -n "$A_FREE" && -n "$A_BYTES" ]]; then
    printf '\x5a' | dd of="$ALTUSB" bs=1 seek=$(( U_ROOT + A_FREE * 4096 + 100 )) conv=notrunc status=none
    A_SHA="$(dd if="$ALTUSB" bs=4M iflag=skip_bytes,count_bytes skip="$U_ROOT" count="$A_BYTES" status=none | sha256sum | cut -c1-64)"
    sed -i "s/^  \"sha256\": \"[0-9a-f]*\"/  \"sha256\": \"${A_SHA}\"/" "$ALT/root.json"
    mcopy -o -i "${ALTUSB}@@${U_ESP}" "$ALT/root.json" ::/kryptik/root.json
    smoke integ-p4a --usb "$ALTUSB" --disk "$DISK" --testctl "$CTLR" --vars enrolled --timeout "$TIMEOUT" > /dev/null
    T4A="$(boot_txt)"
    if grep -q 'KRYPTIK_RECOVER: rc=1' <<<"$T4A" && grep -q 'does not verify against the root hash' <<<"$T4A"; then
        green "a medium whose root is not the one its signed kernel names is refused, though its root.json was rewritten to match"
    else
        red "the altered medium's root was not refused"; grep 'KRYPTIK_RECOVER' <<<"$T4A" | tail -5 | sed 's/^/        /'
    fi
    dd if="$DISK" of="$ESPIMG" bs=1M iflag=skip_bytes,count_bytes skip="$ESP_OFF" count=$((512*1024*1024)) status=none
    mtype -i "$ESPIMG" ::/EFI/kryptik/kryptik-a.efi >/dev/null 2>&1 \
        && red "the refused restore left a kernel for slot a on the ESP" \
        || green "the refused restore left the ESP naming no kernel for slot a, so --commit-slot a takes nothing"
else
    red "could not alter a copy of the medium (free block '${A_FREE}', total_bytes '${A_BYTES}')"
fi
rm -rf "$ALT" "$ALTUSB"
smoke integ-p4 --usb "$USB" --disk "$DISK" --testctl "$CTLR" --vars enrolled --timeout "$TIMEOUT" > /dev/null
boot_txt | grep -q 'KRYPTIK_RECOVER: rc=0' && green "kryptik-recover --restore-slot a succeeded from the medium" || { red "recovery did not report success"; boot_txt | grep 'KRYPTIK_RECOVER' | tail -5 | sed 's/^/        /'; }
# The records recovery wrote on the ESP, read from the host: whole, and
# nothing written through a .new left behind.
dd if="$DISK" of="$ESPIMG" bs=1M iflag=skip_bytes,count_bytes skip="$ESP_OFF" count=$((512*1024*1024)) status=none
MVER="$(basename "$USB")"; MVER="${MVER#kryptik-}"; MVER="${MVER%-usb.img}"
CSLOT="$(mtype -i "$ESPIMG" ::/kryptik/committed-slot 2>/dev/null)"; CVER="$(mtype -i "$ESPIMG" ::/kryptik/version-a 2>/dev/null)"
[[ "$CSLOT" == a && "$CVER" == "$MVER" ]] && green "the ESP records slot a as committed, at the medium's version" \
    || red "the ESP records committed slot '${CSLOT}', slot a version '${CVER}' (want a, ${MVER})"
LEFT="$(mdir -/ -b -i "$ESPIMG" ::/ 2>/dev/null | grep -i '\.new$' | tr '\n' ' ')"
[[ -z "$LEFT" ]] && green "recovery left no .new file on the ESP" || red "recovery left ${LEFT}on the ESP"
cp "$ENROLLED" "$VARSF"
start_vm integ-p4b; LOG4="$LOG"
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = integrity-marker" \
    "su:${RPASS}:poweroff" "expect:Power down" "wait-exit"
rc=$?; sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
[[ "$rc" -eq 0 ]] && green "the recovered disk boots alone under Secure Boot; the user and the home file survived" || red "step 4 drive failed"
tr -d '\r' < "$LOG4" | grep -q 'KRYPTIK_SMOKE: verity_root=0 [0-9]* verity V' && green "dm-verity reports the restored root valid" || red "restored root not reported valid"
tr -d '\r' < "$LOG4" | grep -q 'kryptik-firstboot: created user' && red "first-boot setup ran again (state was lost)" || green "first-boot setup did not run again"

# ----------------------------------------------------------------- step 5 --
step "step 5: offline tampering of the state partition does not reach privileged startup"
# The state partition is unauthenticated (sysinit.sh, "the trust boundary"):
# plant an update anchor, a zone and a sysctl in its /etc layer from the host,
# and check from inside the guest that none takes effect.
TMPK="$(mktemp -d)"; MNT="$TMPK/state"; mkdir -p "$MNT"
ssh-keygen -q -t ed25519 -N "" -f "$TMPK/attacker" >/dev/null
if open_state "$DISK" "$MNT" 2>/dev/null; then
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
    # Also a preload library and a udev rule run as root, both pointing at the
    # state partition, and one allowed change (a subuid line) as a control.
    mkdir -p "$up/udev/rules.d" "$MNT/lib/kryptik"
    printf '/var/lib/kryptik/evil.so\n' > "$up/ld.so.preload"
    printf 'ACTION=="add", RUN+="/var/lib/kryptik/evil.sh"\n' > "$up/udev/rules.d/99-evil.rules"
    printf '#!/bin/sh\ntouch /var/lib/kryptik/evil-ran\n' > "$MNT/lib/kryptik/evil.sh"; chmod 0755 "$MNT/lib/kryptik/evil.sh"
    printf 'planted:1310720:65536\n' > "$up/subuid"
    close_state "$MNT"
    green "planted a trust anchor, a zone definition, a sysctl fragment, a preload library and a udev rule under the state's /etc upper layer, and one allowed change"
else
    red "could not mount the state partition from the host (loop/offset); step 5 not performed"
fi
# A payload signed with the attacker's key: valid against the planted anchor,
# not against the image's. Its manifest alone, since the updater checks the
# signature before it reads a file the manifest lists.
PAYDIR="${KRYPTIK_WORK}/images/payload-$(sed -n 's/^  "version": "\([^"]*\)".*/\1/p' "${KRYPTIK_WORK}/images/root.json" 2>/dev/null)"
if [[ -f "$PAYDIR/manifest" ]]; then
    rm -rf "$TMPK/pay"; mkdir -p "$TMPK/pay"; cp "$PAYDIR/manifest" "$TMPK/pay/"
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
start_vm integ-p5 "${EXTRA[@]}"; LOG5="$LOG"
# The planted kryptik/ directory must be quarantined and gone from /etc, and
# the updater's anchor on the verified root must still name the release key.
# The root has an ld.so.preload of its own (the allocator), so the planted
# library is looked for by name.
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "grab:overlay:ls /etc/kryptik/ /var/lib/kryptik/etc/quarantine/ 2>&1 | head -12" \
    "run:test ! -e /etc/kryptik/trust/release-signers" \
    "run:grep -q '^kryptik-release ' /usr/share/kryptik/trust/release-signers" \
    "run:ls /var/lib/kryptik/etc/quarantine/ | grep -q '^kryptik'" \
    "run:test ! -e /etc/kryptik/zones/evil.toml" \
    "run:! grep -q evil /etc/ld.so.preload" \
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
[[ "$rc" -eq 0 ]] && green "the planted /etc content was quarantined before the overlay was mounted (preload, udev rule, zone, anchor, sysctl), the allowed change is in effect, and nothing planted ran" || red "step 5 drive failed"
grep -q 'no zone named "evil"' <<<"$T5" && green "the launch daemon does not know the planted zone (it reads /usr/lib/kryptik/zones)" || red "the daemon honoured a planted zone"
if [[ -n "${EXTRA[*]:-}" ]]; then
    grep -q 'not enrolled' <<<"$T5" && green "an update signed by the planted anchor's key is refused (the anchor is read from the verified root)" || red "an attacker-signed update was not refused"
fi
grep -q 'KRYPTIK_SMOKE: sysctl kernel.kptr_restrict=2' <<<"$T5" && green "the planted sysctl fragment was not applied" || red "the planted sysctl was applied"
grep -q 'KRYPTIK_SMOKE: var_source=/dev/mapper/kryptik-state' <<<"$T5" && green "state stayed persistent through the tamper (this is a repairable machine, not a bricked one)" || red "state not persistent in step 5"
# undo the planting so later runs start clean
if open_state "$DISK" "$MNT" 2>/dev/null; then
    rm -rf "$MNT/lib/kryptik/etc/upper/kryptik/trust" "$MNT/lib/kryptik/etc/upper/kryptik/zones" "$MNT/lib/kryptik/etc/upper/sysctl.d" \
           "$MNT/lib/kryptik/etc/upper/ld.so.preload" "$MNT/lib/kryptik/etc/upper/udev" "$MNT/lib/kryptik/etc/upper/subuid" \
           "$MNT/lib/kryptik/etc/quarantine" "$MNT/lib/kryptik/evil.sh" "$MNT/lib/kryptik/evil-ran"
    close_state "$MNT"
fi
rm -rf "$TMPK"

# ----------------------------------------------------------------- step 6 --
step "step 6: the state partition's header saved, wiped and restored from the medium"
CTLH="${VMDIR}/testctl-header.img"
"${SELF}/mk-testctl.sh" --out "$CTLH" --key "$TESTCTL_KEY" recover_disk=/dev/vda recover_mode=header smoke_poweroff=1 install_wait=5 > /dev/null
smoke integ-p6 --usb "$USB" --disk "$DISK" --testctl "$CTLH" --vars enrolled --timeout "$TIMEOUT" > /dev/null
T6="$(boot_txt)"
grep -q 'KRYPTIK_RECOVER: header: wiped [0-9]* bytes, and /dev/vda4 is no longer LUKS' <<<"$T6" \
    && green "--backup-state-header saved the header; wiped on the disk, the partition is no longer LUKS" || red "the header was not saved and wiped"
if grep -q 'KRYPTIK_RECOVER: header: restored' <<<"$T6" && grep -q 'KRYPTIK_RECOVER: rc=0' <<<"$T6"; then
    green "--restore-state-header put it back: the partition reads back as the backup"
else
    red "the header was not restored"; grep 'KRYPTIK_RECOVER' <<<"$T6" | tail -6 | sed 's/^/        /'
fi
cp "$ENROLLED" "$VARSF"
start_vm integ-p6b; LOG6="$LOG"
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:test \"\$(cat /home/${TUSER}/marker)\" = integrity-marker" \
    "su:${RPASS}:poweroff" "expect:Power down" "wait-exit"
rc=$?; sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
[[ "$rc" -eq 0 ]] && green "the disk unlocks with the restored header; the user and the home file are there" || red "step 6 drive failed"
tr -d '\r' < "$LOG6" | grep -q 'STATE DEGRADED' && red "degraded after the header was restored" || green "the state is not degraded after the restore"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
