#!/usr/bin/env bash
# Tests for tools/check-hardware.sh: what a report must show to carry a
# listing, each reason it falls short, and the list held to its reports.
# Offline; the reports are written here in kryptik-hwreport's form.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/tools/check-hardware.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

# An installed release on a laptop, with nothing wanting.
cat > "$W/good.txt" <<'EOF'
kryptik-hwreport 1

== system ==
kryptik: 1.0.0 (build 91c3238aabbccddeeff00112233445566778899a)
kernel: 6.18.53-hardened1
booted: slot a, installed
state: persistent
taken: 2026-10-14T09:12Z

== machine ==
sys_vendor: LENOVO
product_name: 20XWCTO1WW
product_version: ThinkPad X1 Carbon Gen 9
bios_version: N32ET75W (1.51 )
bios_date: 12/02/2021
chassis_type: 10

== firmware ==
uefi: yes, 64-bit
secure boot: on
setup mode: 0
lockdown: confidentiality
tpm: version 2

== cpu ==
model: 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz
vendor, family/model/stepping: GenuineIntel, 6/140/1
microcode: 0xa4
threads running: 4
present: 0-7, online: 0-3, smt: off
microcode: Current revision: 0x000000a4
memory: 15902 MiB

== missing ==
firmware the kernel asked for and did not find, each a line for build/config/firmware.list:
  (none)
devices with no driver, each wanting its driver's line in build/config/kernel/boot.fragment:
  (none)
disks behind a driver that is a module, which boot.fragment must build in before a root can sit there:
  (none)

== pci ==
0000:00:02.0 class 030000 8086:9a49 sub 17aa:22b8 rev 01 driver i915 | VGA compatible controller | Intel Corporation TigerLake-LP GT2 [Iris Xe Graphics]
0000:00:14.3 class 028000 8086:a0f0 sub 8086:0074 rev 20 driver iwlwifi | Network controller | Intel Corporation Wi-Fi 6 AX201

== usb ==

== no driver ==

== storage ==
nvme0n1 476.9 GiB (the root is here) | SAMSUNG MZVLB512HBJQ-000L7 | nvme (built in)

== display ==
card0 driver i915
card0-eDP-1 connected 1920x1200
card0-DP-1 disconnected

== network ==
rfkill0 wlan phy0 soft 0 hard 0
in the net zone:
  wlan0 wireless <BROADCAST,MULTICAST,UP,LOWER_UP>
  kzbr0 virtual <BROADCAST,MULTICAST,UP,LOWER_UP>
  default route by wlan0

== input ==
"AT Translated Set 2 keyboard" | kbd event0

== modules ==
i915 iwlmvm iwlwifi

== firmware messages ==

== kernel log ==
[    0.000000] Linux version 6.18.53-hardened1
[    1.400100] usb 1-2: SerialNumber: <removed>
[    3.100000] wlan0: authenticate with xx:xx:xx:xx:xx:xx
EOF

# see FILE: the tool's words on it in OUT, its status in RC.
see() { OUT="$(bash "$TOOL" "$1" 2>&1)"; RC=$?; }
# vary NAME SED-SCRIPT: the good report, changed, as $W/NAME.txt.
vary() { sed "$2" "$W/good.txt" > "$W/$1.txt"; }
# short NAME SED-SCRIPT REASON: that change leaves a reported listing, for REASON.
short() {
    vary "$1" "$2"; see "$W/$1.txt"
    if [[ "$RC" -eq 0 ]] && grep -q '^  carries    reported; short of certified:$' <<<"$OUT" && grep -qF -- "      $3" <<<"$OUT"; then
        green "short of certified: $3"
    else
        red "$1: wanted reported, for '$3'"; sed 's/^/        /' <<<"$OUT" | tail -6
    fi
}
# unfit NAME SED-SCRIPT REASON: that change leaves no listing at all.
unfit() {
    vary "$1" "$2"; see "$W/$1.txt"
    if [[ "$RC" -ne 0 ]] && grep -q '^  carries    no listing:$' <<<"$OUT" && grep -qF -- "      $3" <<<"$OUT"; then
        green "no listing: $3"
    else
        red "$1: wanted no listing, for '$3'"; sed 's/^/        /' <<<"$OUT" | tail -6
    fi
}

echo "-- a report that carries a certified listing"
see "$W/good.txt"
[[ "$RC" -eq 0 ]] && grep -q '^  carries    certified$' <<<"$OUT" && green "an installed release with nothing wanting is certified" \
    || { red "the good report: exit ${RC}"; sed 's/^/        /' <<<"$OUT"; }
grep -qF '  machine    LENOVO 20XWCTO1WW (ThinkPad X1 Carbon Gen 9), firmware N32ET75W (1.51 ) 12/02/2021' <<<"$OUT" \
    && green "the machine, by maker, model and firmware" || red "machine line: $(grep machine <<<"$OUT")"
grep -qF '  release    1.0.0, kernel 6.18.53-hardened1' <<<"$OUT" && green "the release and kernel" || red "release line"
grep -qF '  display    i915: eDP-1 1920x1200' <<<"$OUT" && green "the display driver and the connected output" || red "display line: $(grep display <<<"$OUT")"
grep -qF '  network    wireless wlan0' <<<"$OUT" && green "the interface the default route leaves by" || red "network line: $(grep network <<<"$OUT")"

echo "-- each thing a certified listing needs"
short medium    's/^booted: .*/booted: the usb medium/'           "not taken on an installed system (booted: the usb medium)"
short degraded  's/^state: .*/state: degraded/'                   "the state partition is not in use (state: degraded)"
short dated     's/^kryptik: 1\.0\.0/kryptik: 0.1.20261014.91c3238a/' "0.1.20261014.91c3238a is not a release (a dated build, or none)"
short sboff     's/^secure boot: on/secure boot: off/'            "Secure Boot is off"
short lockdown  's/^lockdown: .*/lockdown: integrity/'            "lockdown is integrity, not confidentiality"
short firmware  '/^firmware the kernel asked/{n;s/.*/  iwlwifi-QuZ-a0-hr-b0-77.ucode/}' "firmware the kernel did not find: iwlwifi-QuZ-a0-hr-b0-77.ucode"
short undriven  '/^devices with no driver/{n;s/.*/  0000:00:1f.6 class 020000 8086:15fb sub 17aa:22b8 rev 20 driver - | Ethernet controller/}' "no driver for 0000:00:1f.6 class 020000 8086:15fb"
short modular   '/^disks behind a driver/{n;s/.*/  sda: ahci/}'    "a disk behind a module: sda: ahci"
short dark      's/^card0-eDP-1 connected.*/card0-eDP-1 disconnected /' "no display the compositor can use"
short nocarrier 's/^  wlan0 wireless <.*/  wlan0 wireless <NO-CARRIER,BROADCAST,MULTICAST,UP>/' "no network path"
short noroute   '/^  default route by /d'                         "no network path"
short elsewhere 's/^  default route by .*/  default route by kzbr0/' "no network path"

echo "-- what leaves no listing at all"
unfit other     '1s/.*/a hardware report/'                        "not a report this tool reads"
unfit cut       '/^== storage ==$/d'                              "cut short: no 'storage' section"
unfit nameless  's/^sys_vendor: .*/sys_vendor: /'                 "does not name its machine"
line() { grep -n -- "$1" "$W/good.txt" | cut -d: -f1; }   # the good report's line holding $1
unfit address   's/authenticate with xx:xx:xx:xx:xx:xx/authenticate with 00:11:22:33:44:55/' "holds a hardware address, a UUID or a serial number: line(s) $(line 'authenticate with')"
grep -q '00:11:22:33:44:55' <<<"$OUT" && red "the address itself is printed" || green "the line is named, never what it holds"
unfit serial    's/SerialNumber: <removed>/SerialNumber: 4C530001230506115281/' "holds a hardware address, a UUID or a serial number: line(s) $(line 'SerialNumber: ')"
unfit uuid      's/^\[    0\.000000\] Linux.*/[    3.0] EXT4-fs (sda2): mounted filesystem 0a1b2c3d-1111-2222-3333-444455556666 ro/' "holds a hardware address, a UUID or a serial number: line(s) $(line 'Linux version')"

echo "-- the list, held to its reports"
L="$W/list"; mkdir -p "$L"
lists() { OUT="$(KRYPTIK_HARDWARE_DIR="$L" bash "$TOOL" --list 2>&1)"; RC=$?; }
rows() { printf '# report  level  who  day  note\n' > "$L/list.tsv"; printf '%s\n' "$@" >> "$L/list.tsv"; }
bad() {   # bad WHAT WORDS: the list as it stands is refused, in WORDS
    lists
    if [[ "$RC" -ne 0 ]] && grep -qF -- "$2" <<<"$OUT"; then green "$1"; else red "$1"; sed 's/^/        /' <<<"$OUT" | tail -5; fi
}
cp "$W/good.txt" "$L/lenovo-thinkpad-x1-carbon-gen-9.txt"
sed 's/^taken: 2026-10-14/taken: 2026-10-15/' "$W/medium.txt" > "$L/dell-xps-13-9310.txt"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-14  on its own screen" \
     "dell-xps-13-9310.txt  reported  DevomB  2026-10-15"
lists
[[ "$RC" -eq 0 ]] && grep -q '^ok: 2 machine(s) listed' <<<"$OUT" && green "a certified row and a reported one, each carried by its report" \
    || { red "the good list: exit ${RC}"; sed 's/^/        /' <<<"$OUT"; }
grep -qF '  ok    certified  LENOVO 20XWCTO1WW (ThinkPad X1 Carbon Gen 9), 1.0.0 (DevomB, 2026-10-14)' <<<"$OUT" \
    && green "each row says what it lists" || red "row line: $(grep certified <<<"$OUT")"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-14" "dell-xps-13-9310.txt  certified  DevomB  2026-10-15"
bad "a row cannot claim certified on a report short of it" "dell-xps-13-9310.txt: listed certified, and its report is short of that:"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-14"
bad "a report beside the list needs a row" "dell-xps-13-9310.txt: a report with no row in the list"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-14" "dell-xps-13-9310.txt  reported  DevomB  2026-10-15" \
     "hp-elitebook-845.txt  reported  DevomB  2026-10-16"
bad "a row needs its report" "hp-elitebook-845.txt: no such report beside the list"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  tested  DevomB  2026-10-14" "dell-xps-13-9310.txt  reported  DevomB  2026-10-15"
bad "a level is reported or certified" "the level is reported or certified, not 'tested'"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-14" "dell-xps-13-9310.txt  reported  DevomB  2026-10-15" \
     "dell-xps-13-9310.txt  reported  DevomB  2026-10-16"
bad "a report is listed once" "dell-xps-13-9310.txt: listed twice"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  October" "dell-xps-13-9310.txt  reported  DevomB  2026-10-15"
bad "a row names who vouches and the day" "a row names who vouches and the day (YYYY-MM-DD)"
cp "$W/address.txt" "$L/acer-swift-3.txt"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-14" "dell-xps-13-9310.txt  reported  DevomB  2026-10-15" \
     "acer-swift-3.txt  reported  DevomB  2026-10-16"
bad "a report holding an address is not listed" "acer-swift-3.txt: carries no listing:"
rm "$L/acer-swift-3.txt"
# The processor's own word for it: a report whole in every other way.
sed '/^threads running/a of note: nx smep smap hypervisor' "$W/good.txt" > "$L/qemu-standard-pc.txt"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-14" "dell-xps-13-9310.txt  reported  DevomB  2026-10-15" \
     "qemu-standard-pc.txt  certified  DevomB  2026-10-14"
bad "a report taken in a virtual machine is not listed" "qemu-standard-pc.txt: taken in a virtual machine"
rm "$L/qemu-standard-pc.txt"
rows "lenovo-thinkpad-x1-carbon-gen-9.txt  certified  DevomB  2026-10-13" "dell-xps-13-9310.txt  reported  DevomB  2026-10-15"
bad "a row's day is the day its report was taken" "lenovo-thinkpad-x1-carbon-gen-9.txt: its row says 2026-10-13, and the report was taken 2026-10-14T09:12Z"

echo "-- the tree's own list"
OUT="$(bash "$TOOL" --list 2>&1)"; RC=$?
[[ "$RC" -eq 0 ]] && green "docs/hardware/list.tsv: $(tail -1 <<<"$OUT")" || { red "docs/hardware/list.tsv is refused"; sed 's/^/        /' <<<"$OUT"; }

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
