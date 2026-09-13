#!/usr/bin/env bash
#
# Prove the installer works, by installing from the medium and then BOOTING
# what it produced - through firmware, with the medium gone and the variable
# store reset - and by proving its refusals refuse.
#
#   tools/image/install-test.sh --usb IMG [--disk FILE] [--size 12G]
#                               [--vars clean|enrolled] [--timeout N] [--quick]
#
# Phases:
#   1  blank disk + control disk (install_target, preseed): boot the medium,
#      the installer runs unattended, the guest powers off; assert on its
#      transcript and on the target's partition table from the host side.
#   2  boot the disk ALONE with a fresh variable store: first boot creates
#      the preseeded user; log in over serial, check identity, reboot from
#      inside, log in again, power off from inside.
#   3  cold boot the disk again: it comes up, log in, power off.
#   4  refusals: a disk too small; a read-only disk; a copy that fails with
#      an I/O error injected under the root image write. Each must report
#      rc!=0 and "FAILED", and the not-installed disk must have no
#      kryptik-a partition afterwards.
#
# Every disk here is a file created by this script. Nothing touches a device.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; DISK=""; SIZE="12G"; VARS="clean"; TIMEOUT=600; QUICK=0
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --disk) DISK="${2:?}"; shift 2 ;;
        --size) SIZE="${2:?}"; shift 2 ;;
        --vars) VARS="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$USB" && -f "$USB" ]] || die "--usb IMG is required and must exist"
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
DISK="${DISK:-${VMDIR}/installed.img}"
case "$DISK" in /dev/*|/sys/*|/proc/*) die "refusing to use ${DISK} as a target disk" ;; esac
[[ -e "$DISK" && ! -f "$DISK" ]] && die "refusing: ${DISK} exists and is not a regular file"
for t in python3 sfdisk blkid truncate; do have "$t" || die "required tool not found: $t"; done

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
want()  { if grep -qE "$2" "$1"; then green "$3"; else red "$3"; fi; }
deny()  { if grep -qE "$2" "$1"; then red "$3"; else green "$3"; fi; }
phase() { printf '\n==> %s\n' "$*"; }
txt_of() { tr -d '\r' < "$1"; }

# The test account and root password the preseed creates. The hashes are
# what lands on disk; the plaintext exists only in this harness.
TUSER=tester; TPASS=tester-pw; RPASS=root-pw
hash_of() { openssl passwd -6 "$1"; }
TUSER_HASH="$(hash_of "$TPASS")"; ROOT_HASH="$(hash_of "$RPASS")"

# ---------------------------------------------------------------- phase 1 --
phase "phase 1: install from the medium onto a blank ${SIZE} disk"
rm -f "$DISK"; truncate -s "$SIZE" "$DISK"
CTL="${VMDIR}/testctl-install.img"
"${SELF}/mk-testctl.sh" --out "$CTL" install_target=/dev/vda smoke_poweroff=1 install_wait=5 \
    "preseed_user=${TUSER}" "preseed_password_hash=${TUSER_HASH}" "preseed_root_hash=${ROOT_HASH}" > /dev/null || die "control disk"
"${SELF}/run-ovmf.sh" --usb "$USB" --disk "$DISK" --testctl "$CTL" --vars "$VARS" --mode smoke --timeout "$TIMEOUT" --name install-p1
qrc=$?
P1="${VMDIR}/install-p1.txt"; txt_of "${KRYPTIK_WORK}/logs/ovmf-serial.latest.log" > "$P1"
echo "  transcript: ${KRYPTIK_WORK}/logs/ovmf-serial.latest.log ($(grep -c '' < "$P1") lines, qemu ${qrc})"
want "$P1" 'KRYPTIK_INSTALL: BEGIN target=/dev/vda'      "the installer was armed and ran"
want "$P1" 'KRYPTIK_INSTALL: rc=0'                       "the installer exited 0"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-esp=/dev/vda1 type=vfat'   "partition 1 is the ESP"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-a=/dev/vda2'  "partition 2 is kryptik-a"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-b=/dev/vda3'  "partition 3 is kryptik-b"
want "$P1" 'KRYPTIK_INSTALL: verify: kryptik-state=/dev/vda4 type=ext4' "partition 4 is the state partition"
want "$P1" 'KRYPTIK_INSTALL: verify: esp_files=.*EFI/BOOT/BOOTX64.EFI' "the ESP has the removable-media boot file"
want "$P1" 'KRYPTIK_INSTALL: verify: install_json=yes'   "install.json was written"
want "$P1" 'KRYPTIK_INSTALL: verify: preseed=present'    "the first-boot preseed was written"
want "$P1" 'KRYPTIK_INSTALL: kryptik-a verifies'         "the root image was read back and verified"
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

# ---------------------------------------------------------------- phase 2 --
phase "phase 2: boot the installed disk alone, medium detached, variables reset"
VARSF="${VMDIR}/installed-vars.fd"
cp "/usr/share/OVMF/OVMF_VARS_4M.fd" "$VARSF"
[[ "$VARS" == "enrolled" ]] && cp "${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd" "$VARSF"
SERVE="$("${SELF}/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name install-p2)"
SER="$(sed -n 's/^serial=//p' <<<"$SERVE")"; PIDF="$(sed -n 's/^pid=//p' <<<"$SERVE")"; LOG2="$(sed -n 's/^log=//p' <<<"$SERVE")"
[[ -S "$SER" ]] || die "no serial socket from run-ovmf: ${SERVE}"
DRV="${SELF}/vm-drive.py"
REC="${VMDIR}/install-p2.json"
python3 "$DRV" --serial "$SER" --timeout 300 --record "$REC" \
    "expect:KRYPTIK_SMOKE: END" \
    "expect:kryptik-firstboot: created user '${TUSER}'" \
    "login:${TUSER}:${TPASS}" \
    "grab:identity:cat /run/kryptik/boot-identity; grep -E '^(ID|VERSION_ID)=' /etc/os-release" \
    "grab:mounts:awk '\$2==\"/\"||\$2==\"/var\"||\$2==\"/etc\"||\$2==\"/home\" {print \$2, \$1, \$3, \$4}' /proc/mounts" \
    "grab:secureboot:od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null || echo none" \
    "grab:bootresult:cat /var/lib/kryptik/boot/last-result" \
    "run:touch /home/${TUSER}/persisted-p2 && sync" \
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
want "$P2" 'KRYPTIK_SMOKE: var_source=/dev/vda4 ext4'       "state partition mounted on /var"
want "$P2" 'KRYPTIK_SMOKE: etc_source=overlay'               "/etc is an overlay"
want "$P2" 'KRYPTIK_SMOKE: root_writable=no'                 "the verified root is not writable"
want "$P2" 'boot-success: slot a up'                         "boot-success recorded slot a"
want "$P2" 'reboot: Restarting system'                       "the guest rebooted itself"
if [[ "$(grep -c 'Linux version' "$P2")" -ge 2 ]]; then green "two kernel boots in one session (reboot worked)"; else red "expected two kernel boots"; fi
want "$P2" 'Power down'                                      "the guest powered off from inside"
deny "$P2" 'Kernel panic|Oops:|POWEROFF_DID_NOT_TAKE_EFFECT' "no panic, no forced poweroff"
if [[ -f "$REC" ]]; then echo "  recorded:"; sed 's/^/    /' "$REC" | head -30; fi

# ---------------------------------------------------------------- phase 3 --
if [[ "$QUICK" -eq 0 ]]; then
phase "phase 3: cold boot the installed disk again"
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

# ---------------------------------------------------------------- phase 4 --
phase "phase 4: refusals and failures report as failures"
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
# An I/O error under the root image copy: the partition table is written,
# the copy fails, and that failure must be what the runner reports.
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
