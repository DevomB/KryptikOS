#!/usr/bin/env bash
# Install from the medium, boot the result from firmware alone (medium gone,
# variables reset), and check that the installer's refusals refuse.
#
#   tools/image/install-test.sh --usb IMG [--disk FILE] [--size 12G]
#                               [--vars clean|enrolled] [--timeout N] [--quick]
#
#   step 1  install unattended onto a blank disk; check the transcript and,
#           from the host, the partition table
#   step 2  boot the disk alone: first boot, login, reboot, login, poweroff
#   step 3  cold boot it again (not with --quick)
#   step 4  a disk too small, a read-only disk, and an I/O error in the root
#           image copy (not with --quick): each must fail, installing nothing
#
# Every disk is a file this script creates; no device is touched.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; DISK=""; SIZE=""; VARS="clean"; TIMEOUT=600; QUICK=0
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --size) SIZE="${2:?}"; shift 2 ;;
        --vars) VARS="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$USB" && -f "$USB" ]] || die "--usb IMG is required and must exist"
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/installed.img}"
case "$DISK" in /dev/*|/sys/*|/proc/*) die "refusing to use ${DISK} as a target disk" ;; esac
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} exists and is not a regular file"
for t in python3 sfdisk blkid truncate; do have "$t" || die "required tool not found: $t"; done

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
want()  { if grep -qE "$2" "$1"; then green "$3"; else red "$3"; fi; }
deny()  { if grep -qE "$2" "$1"; then red "$3"; else green "$3"; fi; }
txt_of() { tr -d '\r' < "$1"; }


# ----------------------------------------------------------------- step 1 --
step "step 1: install from the medium onto a blank ${SIZE} disk"
# --size wins; without it the disk is sized from the medium (test-disk-size.sh).
if [[ -z "$SIZE" ]]; then SIZE="$("${SELF}/test-disk-size.sh" --medium "$USB")" || die "could not size the test disk from the medium"; fi
rm -f "$DISK"; truncate -s "$SIZE" "$DISK"
CTL="${VMDIR}/testctl-install.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "${PRESEED[@]}" > /dev/null || die "control disk"
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars "$VARS" --mode smoke --timeout "$TIMEOUT" --name install-p1
qrc=$?
P1="${VMDIR}/install-p1.txt"; txt_of "${KRYPTIK_WORK}/logs/ovmf-serial.latest.log" > "$P1"
echo "  transcript: ${KRYPTIK_WORK}/logs/ovmf-serial.latest.log ($(grep -c '' < "$P1") lines, qemu ${qrc})"
want "$P1" 'KRYPTIK_INSTALL: BEGIN target=/dev/vda'      "the installer was armed and ran"
want "$P1" 'KRYPTIK_INSTALL: rc=0'                       "the installer exited 0"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-esp=/dev/vda1 type=vfat'   "partition 1 is the ESP"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-a=/dev/vda2'  "partition 2 is kryptik-a"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-b=/dev/vda3'  "partition 3 is kryptik-b"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-state=/dev/vda4 type=crypto_LUKS' "partition 4 is the state partition, and it is LUKS"
want "$P1" 'KRYPTIK_INSTALL: verify: esp_files=.*EFI/BOOT/BOOTX64.EFI' "the ESP has the removable-media boot file"
want "$P1" 'KRYPTIK_INSTALL: verify: install_json=yes'   "install.json was written"
want "$P1" 'KRYPTIK_INSTALL: verify: preseed=present'    "the first-boot preseed was written"
want "$P1" 'KRYPTIK_INSTALL: .*kryptik-a verifies'       "the root image was read back and verified"
deny "$P1" 'KRYPTIK_INSTALL: FAILED'                     "the installer reported no failure"
want "$P1" 'Power down'                                  "the medium powered off afterwards"
deny "$P1" 'Kernel panic|Oops:'                          "no panic during the install boot"
# From the host side: the partition table the guest wrote.
sfdisk -l "$DISK" 2>/dev/null | grep -E '^/|Disklabel' | sed 's/^/        /'
if [[ "$(sfdisk -l "$DISK" 2>/dev/null | grep -c "^${DISK}")" -eq 4 ]]; then green "host sees four partitions on the target"; else red "host does not see four partitions"; fi
lbls="$(blkid -p -O 0 "$DISK" >/dev/null 2>&1; sfdisk -d "$DISK" 2>/dev/null | grep -o 'name="[^"]*"' | tr '\n' ' ')"
if [[ "$lbls" == *kryptik-esp* && "$lbls" == *kryptik-a* && "$lbls" == *kryptik-b* && "$lbls" == *kryptik-state* ]]; then
    green "host sees the four partition labels"; else red "host labels: ${lbls}"; fi
if [[ "$FAIL" -ne 0 ]]; then printf '\nphase 1 failed; not booting the result.\n%d passed, %d failed\n' "$PASS" "$FAIL"; exit 1; fi

# ----------------------------------------------------------------- step 2 --
step "step 2: boot the installed disk alone, medium detached, variables reset"
VARSF="${VMDIR}/installed-vars.fd"
cp "/usr/share/OVMF/OVMF_VARS_4M.fd" "$VARSF"
[[ "$VARS" == "enrolled" ]] && cp "${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd" "$VARSF"
SERVE="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name install-p2)"
SER="$(sed -n 's/^serial=//p' <<<"$SERVE")"; PIDF="$(sed -n 's/^pid=//p' <<<"$SERVE")"; LOG2="$(sed -n 's/^log=//p' <<<"$SERVE")"
[[ -S "$SER" ]] || die "no serial socket from run-ovmf: ${SERVE}"
REC="${VMDIR}/install-p2.json"
python3 "$DRV" --serial "$SER" --timeout 300 --record "$REC" \
    "expect:KRYPTIK_SMOKE: END" \
    "seen:kryptik-firstboot: created user '${TUSER}'" \
    "login:${TUSER}:${TPASS}" \
    "grab:identity:cat /run/kryptik/boot-identity; grep -E '^(ID|VERSION_ID)=' /etc/os-release" \
    "grab:mounts:awk '\$2==\"/\"||\$2==\"/var\"||\$2==\"/etc\"||\$2==\"/home\" {print \$2, \$1, \$3, \$4}' /proc/mounts" \
    "grab:secureboot:od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null || echo none" \
    "grab:bootresult:cat /var/lib/kryptik/boot/last-result" \
    "run:echo KRYPTIK-CLEAR-MARKER-7f3a91 > /home/${TUSER}/persisted-p2 && sync" \
    "$(ROOTSH "grep -rqa state[-]pw /proc/[0-9]*/cmdline /run /etc 2>/dev/null && echo PW-LEAK || echo PW-NOLEAK")" "expect:PW-NOLEAK" \
    "su:${RPASS}:reboot" \
    "expect:Linux version" \
    "expect:KRYPTIK_SMOKE: END" \
    "login:${TUSER}:${TPASS}" \
    "run:test -f /home/${TUSER}/persisted-p2" \
    "grab:bootresult2:cat /var/lib/kryptik/boot/last-result" \
    "su:${RPASS}:poweroff" \
    "expect:Power down" \
    "wait-exit"
drc=$?
sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
P2="${VMDIR}/install-p2.txt"; txt_of "$LOG2" > "$P2"
echo "  transcript: ${LOG2}"
[[ "$drc" -eq 0 ]] && green "first boot, login, reboot, second login and clean poweroff all happened" || red "the serial drive failed (see above)"
want "$P2" 'KRYPTIK_SMOKE: root_source=/dev/dm-0 ext4 ro'   "installed root is the verity device"
want "$P2" 'KRYPTIK_SMOKE: boot_identity=slot=a media='      "booted slot a"
want "$P2" 'KRYPTIK_SMOKE: var_source=/dev/mapper/kryptik-state ext4' "the unlocked state partition is mounted on /var"
want "$P2" 'passphrase for the state partition \(try 1 of 3\)' "sysinit asked for the state passphrase on the console"
deny "$P2" "$KRYPTIK_STATE_PASSPHRASE"                       "the passphrase is nowhere in the transcript"
# From the host: partition 4 is a LUKS header and ciphertext.
S4=$(( $(part_start "$DISK" 4) * 512 ))
magic() { dd if="$DISK" bs=1 skip="$1" count="$2" status=none | od -An -tx1 | tr -d ' \n'; }
[[ "$(magic "$S4" 6)" == 4c554b53babe ]] && green "partition 4 starts with a LUKS header" || red "partition 4 does not start with a LUKS header"
[[ "$(magic $(( S4 + 1080 )) 2)" != 53ef ]] && green "no ext4 superblock in the clear" || red "an ext4 superblock is readable on partition 4"
if tail -c +$(( S4 + 1 )) "$DISK" | LC_ALL=C grep -aq 'KRYPTIK-CLEAR-MARKER-7f3a91'; then red "a file written under /home is readable from the raw partition"
else green "a file written under /home is not readable from the raw partition"; fi
want "$P2" 'KRYPTIK_SMOKE: etc_source=overlay'               "/etc is an overlay"
want "$P2" 'KRYPTIK_SMOKE: root_writable=no'                 "the verified root is not writable"
want "$P2" 'boot-success: slot a up'                         "boot-success recorded slot a"
want "$P2" 'reboot: Restarting system'                       "the guest rebooted itself"
if [[ "$(grep -c 'Linux version' "$P2")" -ge 2 ]]; then green "two kernel boots in one session (reboot worked)"; else red "expected two kernel boots"; fi
want "$P2" 'Power down'                                      "the guest powered off from inside"
deny "$P2" 'Kernel panic|Oops:|POWEROFF_DID_NOT_TAKE_EFFECT' "no panic, no forced poweroff"
if [[ -f "$REC" ]]; then echo "  recorded:"; sed 's/^/    /' "$REC" | head -30; fi

# ----------------------------------------------------------------- step 3 --
if [[ "$QUICK" -eq 0 ]]; then
step "step 3: cold boot the installed disk again"
SERVE="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name install-p3)"
SER="$(sed -n 's/^serial=//p' <<<"$SERVE")"; PIDF="$(sed -n 's/^pid=//p' <<<"$SERVE")"; LOG3="$(sed -n 's/^log=//p' <<<"$SERVE")"
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "login:${TUSER}:${TPASS}" \
    "run:test -f /home/${TUSER}/persisted-p2" \
    "su:${RPASS}:poweroff" "expect:Power down" "wait-exit"
drc=$?
sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
[[ "$drc" -eq 0 ]] && green "cold boot: login, persisted file present, clean poweroff" || red "cold boot drive failed"
P3="${VMDIR}/install-p3.txt"; txt_of "$LOG3" > "$P3"
deny "$P3" 'kryptik-firstboot: created user'  "first-boot setup did not run again"
fi

# ----------------------------------------------------------------- step 4 --
step "step 4: refusals and failures report as failures"
refusal_case() {   # refusal_case NAME DISK-SIZE EXTRA-RUN-ARGS... ; expects rc!=0 and FAILED, no kryptik-a
    local name="$1" size="$2"; shift 2
    local d="${VMDIR}/refuse-${name}.img"; rm -f "$d"; truncate -s "$size" "$d"
    local ctl="${VMDIR}/testctl-${name}.img"
    "${SELF}/mk-testctl.sh" --out "$ctl" install_target=/dev/vda smoke_poweroff=1 install_wait=5 > /dev/null
    "${SELF}/run-ovmf.sh" --usb "$USB" --disk "$d" --testctl "$ctl" --vars "$VARS" --mode smoke --timeout "$TIMEOUT" --name "refuse-${name}" "$@" > /dev/null
    local t="${VMDIR}/refuse-${name}.txt"; txt_of "${KRYPTIK_WORK}/logs/ovmf-serial.latest.log" > "$t"
    want "$t" 'KRYPTIK_INSTALL: BEGIN'            "${name}: the installer ran"
    want "$t" 'KRYPTIK_INSTALL: rc=[1-9]'         "${name}: reported a non-zero status"
    want "$t" 'KRYPTIK_INSTALL: .*FAILED'         "${name}: said FAILED and why"
    deny "$t" 'KRYPTIK_INSTALL: rc=0'             "${name}: never reported success"
    if sfdisk -d "$d" 2>/dev/null | grep -q 'name="kryptik-a"' && [[ "$name" != "ioerror" ]]; then
        red "${name}: a kryptik-a partition was written anyway"
    else
        green "${name}: no completed installation on the disk"
    fi
    grep -E 'KRYPTIK_INSTALL: .*FAILED' "$t" | head -2 | sed 's/^/        /'
}
refusal_case toosmall 1G
refusal_case readonly "$SIZE" --disk-readonly
# An I/O error in the root image copy, after the partition table is written;
# the runner must report that failure.
if [[ "$QUICK" -eq 0 ]]; then
    cat > "${VMDIR}/blkdebug.conf" <<'EOF'
[inject-error]
event = "write_aio"
errno = "5"
sector = "1400000"
once = "off"
EOF
    refusal_case ioerror "$SIZE" --blkdebug "${VMDIR}/blkdebug.conf"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
