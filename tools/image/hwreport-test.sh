#!/usr/bin/env bash
# The hardware report on the USB medium (tools/install/kryptik-hwreport.sh):
# written only onto a stick that asks for one, or by the command; whole;
# naming the machine's parts and nothing that is the machine's alone; and
# left behind by the installer.
#
#   tools/image/hwreport-test.sh --usb IMG [--timeout N]
#
#   step 1  a stick nobody prepared, booted writable: not a byte changes
#   step 2  a stick with a kryptik-report directory: report-1.txt at boot, the
#           filesystem clean and the boot file as it was; the next boot adds
#           report-2.txt
#   step 3  that stick write-protected: no report, and the boot says why
#   step 4  an install from that stick: a third report on it, none on the
#           installed disk
#   step 5  kryptik-hwreport --save at the medium's root shell, on a stick
#           nobody prepared
#
# Every boot is of a copy this script makes; the medium itself is only read.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

USB=""; TIMEOUT=600
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb) USB="${2:?}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,19p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$USB" && -f "$USB" ]] || die "--usb IMG is required and must exist"
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"
for t in python3 sfdisk mmd mtype mdir fsck.vfat truncate; do have "$t" || die "required tool not found: $t"; done

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"
want() { if grep -qE -- "$2" "$1"; then green "$3"; else red "$3"; fi; }
deny() { if grep -qE -- "$2" "$1"; then red "$3"; else green "$3"; fi; }
part_size() { sfdisk -d "$1" 2>/dev/null | awk -v n="$2" -F'[ ,]+' '$1 ~ n"$" {for(i=1;i<=NF;i++) if($i=="size=") print $(i+1)}'; }
sha() { sha256sum "$1" | cut -c1-64; }

# The stick's first partition, as mtools addresses it inside an image.
export MTOOLS_SKIP_CHECK=1
ESP_START="$(part_start "$USB" 1)"; ESP_SECTORS="$(part_size "$USB" 1)"
[[ -n "$ESP_START" && -n "$ESP_SECTORS" ]] || die "could not read the medium's partition table"
esp_of() { printf '%s@@%s' "$1" "$(( ESP_START * 512 ))"; }
report_of() { mtype -i "$(esp_of "$1")" "::/kryptik-report/report-$2.txt" 2>/dev/null; }   # report_of IMAGE N
fsck_esp() {   # fsck_esp IMAGE: its first partition, checked and not repaired
    dd if="$1" of="${VMDIR}/hwreport-esp.img" bs=512 skip="$ESP_START" count="$ESP_SECTORS" status=none \
        && fsck.vfat -n "${VMDIR}/hwreport-esp.img" > "${VMDIR}/hwreport-fsck.txt" 2>&1
}

PLAIN="${VMDIR}/hwreport-plain.img"       # a copy nobody prepared
ASKED="${VMDIR}/hwreport-asked.img"       # a copy with the directory
CTL="${VMDIR}/testctl-hwreport.img"
"${SELF}/mk-testctl.sh" --out "$CTL" --key "$TESTCTL_KEY" smoke_poweroff=1 > /dev/null || die "could not make the control disk"
BOOT_FILE="$(mtype -i "$(esp_of "$USB")" ::/EFI/BOOT/BOOTX64.EFI | sha256sum | cut -c1-64)"
fsck_esp "$USB"; PRISTINE_FSCK=$?

# ----------------------------------------------------------------- step 1 --
step "step 1: a stick nobody prepared is not written, though it could be"
cp --sparse=always "$USB" "$PLAIN" || die "could not copy the medium"
smoke hwreport-plain --usb "$PLAIN" --usb-writable --testctl "$CTL" --timeout "$TIMEOUT" > /dev/null
P1="${VMDIR}/hwreport-p1.txt"; boot_txt > "$P1"
want "$P1" 'KRYPTIK_SMOKE: END'              "the medium booted"
want "$P1" 'Power down'                      "and powered off"
deny "$P1" 'hw-report: this stick|kryptik-hwreport: |hardware report' "no report was offered or written"
if cmp -s "$USB" "$PLAIN"; then green "the stick is byte for byte what it was"; else red "the stick changed, and nobody asked"; fi

# ----------------------------------------------------------------- step 2 --
step "step 2: a stick with a kryptik-report directory gets a report at boot"
cp --sparse=always "$USB" "$ASKED" || die "could not copy the medium"
mmd -i "$(esp_of "$ASKED")" ::/kryptik-report || die "could not make the directory on the copy"
smoke hwreport-asked --usb "$ASKED" --usb-writable --testctl "$CTL" --net user --timeout "$TIMEOUT" > /dev/null
P2="${VMDIR}/hwreport-p2.txt"; boot_txt > "$P2"
want "$P2" 'hw-report: this stick asks for a hardware report'             "the boot saw the request"
want "$P2" 'kryptik-hwreport: written kryptik-report/report-1\.txt'      "and said what it wrote"
want "$P2" 'Power down'                                                   "the medium powered off afterwards"
R1="${VMDIR}/hwreport-1.txt"; report_of "$ASKED" 1 > "$R1"
[[ "$(head -1 "$R1")" == "kryptik-hwreport 1" ]] && green "report-1.txt is on the stick, whole" || red "no report-1.txt on the stick, or not a report"
want "$R1" '^booted: the usb medium$'                         "it says what booted"
want "$R1" '^sys_vendor: QEMU'                                "the machine, by its maker"
want "$R1" '^secure boot: off$'                               "Secure Boot as the firmware has it"
want "$R1" '^microcode: '                                     "the processor's microcode"
want "$R1" ' class 0c0330 .* driver xhci_hcd'                 "a PCI device with the driver that took it"
want "$R1" ' interface class 08/06/50 driver usb-storage$'    "the stick's own interface, by its driver"
want "$R1" '^sd[a-z] .*\(the root is here\).*usb-storage \(built in\)' "the disk the root is on, through built-in drivers"
want "$R1" '^== missing ==$'                                  "what the image lacks has its place"
want "$R1" '^== kernel log ==$'                               "the kernel log is there"
want "$R1" 'Linux version .*hardened'                         "from its first line"
deny "$R1" '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'               "no hardware address"
deny "$R1" '[Ss]erial ?[Nn]umber[:=] ?[^< ]'                  "no serial number"
deny "$R1" '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "no UUID"
if [[ "$PRISTINE_FSCK" -eq 0 ]]; then
    if fsck_esp "$ASKED"; then green "the stick's filesystem is clean after the write"
    else red "the stick's filesystem is not clean after the write"; sed 's/^/        /' "${VMDIR}/hwreport-fsck.txt" | head -8; fi
else
    echo "        (fsck.vfat faults the medium's own partition here, so it is not asked about the copy)"
fi
[[ "$(mtype -i "$(esp_of "$ASKED")" ::/EFI/BOOT/BOOTX64.EFI | sha256sum | cut -c1-64)" == "$BOOT_FILE" ]] \
    && green "the signed boot file is as it was" || red "the boot file changed"
smoke hwreport-again --usb "$ASKED" --usb-writable --testctl "$CTL" --timeout "$TIMEOUT" > /dev/null
want "$BOOTLOG" 'kryptik-hwreport: written kryptik-report/report-2\.txt' "the next boot writes report-2.txt"
if [[ "$(report_of "$ASKED" 2 | head -1)" == "kryptik-hwreport 1" ]] && report_of "$ASKED" 1 | cmp -s - "$R1"; then
    green "beside report-1.txt, which is as it was"
else
    red "the second report is missing, or the first changed"
fi

# ----------------------------------------------------------------- step 3 --
step "step 3: the same stick, write-protected"
before="$(sha "$ASKED")"
smoke hwreport-protected --usb "$ASKED" --testctl "$CTL" --timeout "$TIMEOUT" > /dev/null
want "$BOOTLOG" 'kryptik-hwreport: FAILED: the stick is write-protected' "the boot says the stick is write-protected"
want "$BOOTLOG" 'No hardware report was written'                         "and that no report was written"
want "$BOOTLOG" 'KRYPTIK_SMOKE: END'                                     "and goes on"
[[ "$(sha "$ASKED")" == "$before" ]] && green "nothing on the stick changed" || red "a write-protected stick changed"

# ----------------------------------------------------------------- step 4 --
step "step 4: the installer leaves the reports on the stick"
DISK="${VMDIR}/hwreport-installed.img"
fresh_disk "$USB"
if install_disk hwreport-install "$ASKED" --usb-writable; then green "an install from the stick succeeded"; else red "the install from the stick failed"; fi
P4="${VMDIR}/hwreport-p4.txt"; boot_txt > "$P4"
want "$P4" 'kryptik-hwreport: written kryptik-report/report-3\.txt'  "the report was on the stick before the installer copied its partition"
want "$P4" 'KRYPTIK_INSTALL: verify: esp_files=.*EFI/BOOT/BOOTX64.EFI' "the installed ESP has its boot file"
deny "$P4" 'KRYPTIK_INSTALL: verify: esp_files=.*kryptik-report'      "and no report among its files"
TESP="${DISK}@@$(( $(part_start "$DISK" 1) * 512 ))"
if mdir -i "$TESP" ::/kryptik > /dev/null 2>&1 && ! mdir -i "$TESP" ::/kryptik-report > /dev/null 2>&1; then
    green "from the host: the installed disk carries no kryptik-report"
else
    red "from the host: the installed disk carries kryptik-report, or its ESP cannot be read"
fi
[[ "$(report_of "$ASKED" 3 | head -1)" == "kryptik-hwreport 1" ]] && green "the stick keeps all three" || red "report-3.txt is not on the stick"

# ----------------------------------------------------------------- step 5 --
step "step 5: kryptik-hwreport --save at the medium's root shell"
cp --sparse=always "$USB" "$PLAIN" || die "could not copy the medium"
out="$("${SELF}/run-ovmf.sh" --usb "$PLAIN" --usb-writable --mode serve --name hwreport-shell)"
SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"
[[ -S "$SER" ]] || die "no serial socket: ${out}"
# The shell's own arithmetic shows it is listening; a getty drops what is
# typed in its first second, so the line goes twice.
python3 "$DRV" --serial "$SER" --timeout 300 \
    "expect:KRYPTIK_SMOKE: END" "sleep:3" \
    'send:echo shell-$((6 * 7))' "sleep:2" 'send:echo shell-$((6 * 7))' "expect:shell-42" \
    "send:kryptik-hwreport --save" "expect:kryptik-hwreport: written kryptik-report/report-1\.txt" \
    "send:poweroff" "expect:Power down" "wait-exit"
drc=$?
stop_vm
[[ "$drc" -eq 0 ]] && green "the command wrote a report and said where" || red "the serial drive failed (see above)"
[[ "$(report_of "$PLAIN" 1 | head -1)" == "kryptik-hwreport 1" ]] && green "and it is on the stick" || red "no report on the stick"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
