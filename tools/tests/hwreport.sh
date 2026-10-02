#!/usr/bin/env bash
# Tests for tools/install/kryptik-hwreport.sh on a made-up machine: a tree
# shaped like /sys and /proc and a kernel log, with a serial number, hardware
# addresses and a UUID in the places a real machine has them. Offline.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/tools/install/kryptik-hwreport.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
OUT="$W/report.txt"
want() { if grep -qE -- "$2" "$OUT"; then green "$1"; else red "$1"; fi; }
deny() { if grep -qE -- "$2" "$OUT"; then red "$1"; else green "$1"; fi; }
put()  { mkdir -p "$(dirname "$W/$1")"; printf '%s\n' "$2" > "$W/$1"; }

# --- the machine ------------------------------------------------------------
put etc/os-release 'VERSION_ID="0.1.20261002.abcdef12"'
echo 'BUILD_ID=abcdef1234' >> "$W/etc/os-release"
put proc/sys/kernel/osrelease 6.18.53-hardened1
put run/kryptik/boot-identity 'slot='
printf 'media=usb\nstate=tmpfs\nstate_dev=\nroot_disk=/dev/sdb\n' >> "$W/run/kryptik/boot-identity"
put sys/class/dmi/id/sys_vendor LENOVO
put sys/class/dmi/id/product_name 20XWCTO1WW
put sys/class/dmi/id/product_version 'ThinkPad X1 Carbon Gen 9'
put sys/class/dmi/id/product_serial PF-SECRET-1
put sys/class/dmi/id/product_uuid 4c4c4544-0042-3010-8051-b4c04f595931
put sys/class/dmi/id/board_serial L1-SECRET-2
put sys/firmware/efi/fw_platform_size 64
mkdir -p "$W/sys/firmware/efi/efivars"
printf '\006\000\000\000\001' > "$W/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
printf '\006\000\000\000\000' > "$W/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
put sys/kernel/security/lockdown 'none integrity [confidentiality]'
put sys/class/tpm/tpm0/tpm_version_major 2
for n in 0 1; do
    printf 'processor\t: %s\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 140\nmodel name\t: 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz\nstepping\t: 1\nmicrocode\t: 0xa4\nflags\t\t: fpu nx smep smap umip ibt rdrand aes\n\n' "$n"
done > "$W/proc/cpuinfo"
put sys/devices/system/cpu/present 0-7
put sys/devices/system/cpu/online 0-3
put sys/devices/system/cpu/smt/control off
put sys/devices/system/cpu/vulnerabilities/meltdown 'Not affected'
put proc/meminfo 'MemTotal:       16284420 kB'


# --- devices: an Ethernet card on a module, a radio and a host bridge with no
#     driver, a SATA controller whose driver is a module, and the stick. The
#     links are absolute, which the tool resolves as it does sysfs's own. ------
driver() {   # driver BUS NAME [module]: loadable with "module", else built in
    mkdir -p "$W/sys/bus/$1/drivers/$2"
    [[ "${3:-}" == module ]] || return 0
    put "sys/module/$2/initstate" live
    ln -s "$W/sys/module/$2" "$W/sys/bus/$1/drivers/$2/module"
}
pci() {   # pci ADDRESS CLASS VENDOR DEVICE [DRIVER]
    local d="sys/devices/pci0000:00/$1"
    put "$d/class" "$2"; put "$d/vendor" "0x$3"; put "$d/device" "0x$4"
    put "$d/subsystem_vendor" 0x17aa; put "$d/subsystem_device" 0x22b8; put "$d/revision" 0x20
    put "$d/modalias" "pci:v0000${3}d0000${4}sv000017AAsd000022B8bc00sc00i00"
    mkdir -p "$W/sys/bus/pci/devices"
    ln -s "$W/$d" "$W/sys/bus/pci/devices/$1"
    [[ -z "${5:-}" ]] || ln -s "$W/sys/bus/pci/drivers/$5" "$W/$d/driver"
}
disk() {   # disk NAME UNDER SIZE REMOVABLE MODEL: a SCSI disk below the device UNDER
    local s="$2/host0/target0:0:0/0:0:0:0"
    put "$s/model" "$5"
    ln -s "$W/sys/bus/scsi/drivers/sd" "$W/$s/driver"
    put "$s/block/$1/size" "$3"; put "$s/block/$1/removable" "$4"
    ln -s "$W/$s" "$W/$s/block/$1/device"
    mkdir -p "$W/sys/block"
    ln -s "$W/$s/block/$1" "$W/sys/block/$1"
}
driver pci e1000e module; driver pci ahci module; driver pci xhci_hcd; driver scsi sd; driver usb usb-storage
pci 0000:00:00.0 0x060000 8086 9a14
pci 0000:00:14.0 0x0c0330 8086 a0ed xhci_hcd
pci 0000:00:14.3 0x028000 8086 a0f0
pci 0000:00:17.0 0x010601 8086 a0d3 ahci
pci 0000:00:1f.6 0x020000 8086 15fb e1000e
disk sda sys/devices/pci0000:00/0000:00:17.0/ata1 1000215216 0 'Samsung SSD 860   '

stick=sys/devices/pci0000:00/0000:00:14.0/usb1/1-2
put "$stick/idVendor" 0781; put "$stick/idProduct" 5581; put "$stick/speed" 5000
put "$stick/manufacturer" SanDisk; put "$stick/product" Ultra; put "$stick/serial" 4C530001230506115281
put "$stick/1-2:1.0/bInterfaceClass" 08; put "$stick/1-2:1.0/bInterfaceSubClass" 06; put "$stick/1-2:1.0/bInterfaceProtocol" 50
ln -s "$W/sys/bus/usb/drivers/usb-storage" "$W/$stick/1-2:1.0/driver"
disk sdb "$stick/1-2:1.0" 30031872 1 Ultra
radio=sys/devices/pci0000:00/0000:00:14.0/usb1/1-3
put "$radio/1-3:1.0/bInterfaceClass" e0; put "$radio/1-3:1.0/bInterfaceSubClass" 01; put "$radio/1-3:1.0/bInterfaceProtocol" 01
put "$radio/1-3:1.0/modalias" usb:v8087p0026d0002dcE0dsc01dp01icE0isc01ip01in00
mkdir -p "$W/sys/bus/usb/devices"
ln -s "$W/$stick" "$W/sys/bus/usb/devices/1-2"
ln -s "$W/$stick/1-2:1.0" "$W/sys/bus/usb/devices/1-2:1.0"
ln -s "$W/$radio/1-3:1.0" "$W/sys/bus/usb/devices/1-3:1.0"

mkdir -p "$W/usr/share/hwdata"
printf '# a comment\n8086  Intel Corporation\n\t15fb  Ethernet Connection (13) I219-LM\n\ta0f0  Wi-Fi 6 AX201\n\t\t8086 0074  a subsystem line\n\ta0d3  Tiger Lake-LP SATA Controller\n10ec  Realtek\n\ta0f0  not this vendor\nC 01  Mass storage controller\n\t06  SATA controller\n\t\t01  AHCI 1.0\nC 02  Network controller\n\t00  Ethernet controller\n\t80  Network controller\nC 06  Bridge\n' > "$W/usr/share/hwdata/pci.ids"

put run/kryptik/zones/net/init.pid '4242 9876'
mkdir -p "$W/netzone"
cat > "$W/netzone/ip-link" <<'EOF'
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 allmulti 0 minmtu 0 maxmtu 0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff promiscuity 0 allmulti 0 minmtu 68 maxmtu 9194 parentbus pci parentdev 0000:00:1f.6
3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DORMANT group default qlen 1000\    link/ether 52:54:00:65:43:21 brd ff:ff:ff:ff:ff:ff promiscuity 0 allmulti 0 minmtu 256 maxmtu 2304
4: kzbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:00:00:01 brd ff:ff:ff:ff:ff:ff promiscuity 0 allmulti 0 minmtu 68 maxmtu 65535 \    bridge forward_delay 1500 hello_time 200
5: vz-untrusted@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master kzbr0 state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:00:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 1 promiscuity 1 allmulti 1 minmtu 68 maxmtu 65535 \    veth \    bridge_slave state forwarding
EOF
printf 'phy#0\n\tInterface wlan0\n\t\tifindex 3\n\t\taddr 52:54:00:65:43:21\n\t\ttype managed\n' > "$W/netzone/iw-dev"
put netzone/ip-route 'default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 1002'

cat > "$W/dmesg" <<'EOF'
[    0.000000] Linux version 6.18.53-hardened1 (kryptik@build)
[    0.100000] microcode: Current revision: 0x000000a4
[    1.200000] pci 0000:00:1f.6: [8086:15fb] type 00 class 0x020000
[    1.300000] e1000e 0000:00:1f.6 eth0: (PCI Express:2.5GT/s:Width x1) 8c:16:45:aa:bb:cc
[    1.400000] usb 1-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[    1.400100] usb 1-2: SerialNumber: 4C530001230506115281
[    2.000000] iwlwifi 0000:00:14.3: Direct firmware load for iwlwifi-QuZ-a0-hr-b0-77.ucode failed with error -2
[    2.100000] r8169 0000:03:00.0: Unable to load firmware rtl_nic/rtl8168h-2.fw (-2)
[    2.200000] brcmfmac 0000:02:00.0: Direct firmware load for brcm/brcmfmac4350-pcie.Dell Inc.-XPS 13 9350.bin failed with error -2
[    3.000000] EXT4-fs (sdc1): mounted filesystem 0a1b2c3d-1111-2222-3333-444455556666 ro with ordered data mode
[    3.100000] wlan0: authenticate with 00:11:22:33:44:55 (local address=66:77:88:99:aa:bb)
EOF

KRYPTIK_HWREPORT_ROOT="$W" sh "$TOOL" > "$OUT" 2> "$W/err"; rc=$?
[[ "$rc" -eq 0 && ! -s "$W/err" ]] && green "the report is made without a complaint" || { red "exit ${rc}: $(head -3 "$W/err")"; }

echo "-- what the machine is"
[[ "$(head -1 "$OUT")" == "kryptik-hwreport 1" ]] && green "it opens with its name and format" || red "first line: $(head -1 "$OUT")"
want "the release and the kernel"           '^kryptik: 0\.1\.20261002\.abcdef12 \(build abcdef1234\)$'
want "what booted"                          '^booted: the usb medium$'
want "whether its state is kept"            '^state: tmpfs$'
want "the maker and the model"              '^product_version: ThinkPad X1 Carbon Gen 9$'
want "Secure Boot, read from the firmware"  '^secure boot: on$'
want "the lockdown in force"                '^lockdown: confidentiality$'
want "the TPM"                              '^tpm: version 2$'
want "the processor"                        '^vendor, family/model/stepping: GenuineIntel, 6/140/1$'
want "its microcode, and what loaded it"    '^microcode: 0xa4$'
want "the loader's own line"            '^microcode: Current revision: 0x000000a4$'
want "the features that matter here"        '^of note: nx smep smap umip ibt rdrand aes$'
want "a mitigation as the kernel states it" '^meltdown: Not affected$'
want "the memory"                           '^memory: 15902 MiB$'

echo "-- devices and drivers"
want "a device, its driver and its name"    '^0000:00:1f\.6 class 020000 8086:15fb sub 17aa:22b8 rev 20 driver e1000e \| Ethernet controller \| Intel Corporation Ethernet Connection \(13\) I219-LM$'
want "a device with no driver"              '^0000:00:14\.3 class 028000 8086:a0f0 .* driver - \| Network controller \| Intel Corporation Wi-Fi 6 AX201$'
want "a USB device by its own strings"      '^1-2 0781:5581 speed 5000 \| SanDisk Ultra$'
want "a USB interface and its driver"       '^1-2:1\.0 interface class 08/06/50 driver usb-storage$'
want "an interface nothing drives, with what would" '^usb 1-3:1\.0 usb:v8087p0026'
want "the disk, through its drivers"        '^sda 476\.9 GiB \| Samsung SSD 860 \| sd \(built in\), ahci \(module\)$'
want "the stick the root is on"             '^sdb 14\.3 GiB removable \(the root is here\) \| Ultra \| sd \(built in\), usb-storage \(built in\), xhci_hcd \(built in\)$'

echo "-- the interfaces the net zone holds"
want "a wired one, by its flags"            '^  eth0 wired <BROADCAST,MULTICAST,UP,LOWER_UP>$'
want "a radio, known from iw"               '^  wlan0 wireless <NO-CARRIER,BROADCAST,MULTICAST,UP>$'
want "the zones' bridge is not the machine's" '^  kzbr0 virtual '
want "nor a zone's link, named without its peer" '^  vz-untrusted virtual '
want "where the default route leaves"       '^  default route by eth0$'
deny "no address of the network it is on"   '10\.0\.2\.'

echo "-- what the image lacks"
missing="$(sed -n '/^== missing ==$/,/^== pci ==$/p' "$OUT")"
has() { if grep -qF -- "$2" <<<"$missing"; then green "$1"; else red "$1"; fi; }
has "firmware the kernel named"             '  iwlwifi-QuZ-a0-hr-b0-77.ucode'
has "a driver's own wording of it"      '  rtl_nic/rtl8168h-2.fw'
has "a name with spaces, whole"             '  brcm/brcmfmac4350-pcie.Dell Inc.-XPS 13 9350.bin'
has "the radio that wants a driver"         '  0000:00:14.3 class 028000 8086:a0f0'
has "the disk a root cannot sit on yet"     '  sda: ahci'
if grep -qF '0000:00:00.0' <<<"$missing"; then red "a host bridge is listed as wanting a driver"; else green "a host bridge wants none"; fi
if grep -qF 'sdb:' <<<"$missing"; then red "the stick is listed as behind a module"; else green "a disk behind built-in drivers is not listed"; fi

echo "-- what stays on the machine"
deny "no hardware address"                  '8c:16:45|00:11:22:33:44:55|66:77:88:99:aa:bb|52:54:00'
want "each struck where it stood"           'eth0: \(PCI Express:2\.5GT/s:Width x1\) xx:xx:xx:xx:xx:xx$'
want "two on one line, both"                'authenticate with xx:xx:xx:xx:xx:xx \(local address=xx:xx:xx:xx:xx:xx\)$'
deny "no serial number from the log or sysfs" '4C530001230506115281|PF-SECRET-1|L1-SECRET-2'
want "the log line kept, the number gone"   'usb 1-2: SerialNumber: <removed>$'
deny "no UUID"                              '0a1b2c3d-1111|4c4c4544-0042'
want "the filesystem line kept"             'mounted filesystem <uuid> ro'
want "a PCI address is not an address to strike" 'pci 0000:00:1f\.6: \[8086:15fb\] type 00 class 0x020000$'

echo "-- the listing it carries"
LISTING="$(bash "${ROOT}/tools/check-hardware.sh" "$OUT" 2>&1)"; rc=$?
[[ "$rc" -eq 0 ]] && grep -q '^  carries    reported; short of certified:$' <<<"$LISTING" \
    && green "check-hardware.sh reads it: reported" || { red "check-hardware.sh on the report: exit ${rc}"; sed 's/^/        /' <<<"$LISTING" | tail -8; }
grep -qF '      not taken on an installed system (booted: the usb medium)' <<<"$LISTING" && green "short of certified for booting the medium" || red "no word on the medium"
grep -qF '      firmware the kernel did not find: iwlwifi-QuZ-a0-hr-b0-77.ucode' <<<"$LISTING" && green "and for the firmware it lacks" || red "no word on the firmware"
grep -qF '  network    wired eth0' <<<"$LISTING" && green "the network path is read from it" || red "network line: $(grep '^  network' <<<"$LISTING")"

echo "-- where it may be written"
sed -i 's/^media=usb$/media=/' "$W/run/kryptik/boot-identity"
KRYPTIK_HWREPORT_ROOT="$W" sh "$TOOL" --save > "$W/save.out" 2>&1; rc=$?
if [[ "$rc" -ne 0 ]] && grep -q 'this is not one' "$W/save.out"; then green "--save refuses anywhere but a USB medium"; else red "--save off a medium: exit ${rc}: $(head -2 "$W/save.out")"; fi
KRYPTIK_HWREPORT_ROOT="$W" sh "$TOOL" --elsewhere > "$W/save.out" 2>&1; rc=$?
[[ "$rc" -ne 0 ]] && green "an unknown argument is refused" || red "an unknown argument was taken"

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
