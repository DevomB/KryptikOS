#!/usr/bin/env bash
# keyboard.sh against a stand-in variable, run file and loadkeys: which names
# the table takes, what a variable may hold, what a load records and what a
# store writes. The shipped table is checked for form. Against a stand-in sysfs
# and modprobe: which drivers load before eudev runs.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/build/service-scripts/keyboard.sh"
TABLE="$ROOT/build/config/keyboard-layouts"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for f in "$LIB" "$TABLE"; do [[ -f "$f" ]] || { echo "missing: $f"; exit 1; }; done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/vars"
# loadkeys records the keymap it was given, and fails when told to.
cat > "$T/bin/loadkeys" <<'EOF'
#!/bin/sh
[ ! -e "$KB_TEST/loadkeys-fails" ] || exit 1
for a in "$@"; do last="$a"; done
printf '%s\n' "$last" > "$KB_TEST/loaded"
EOF
chmod +x "$T/bin/loadkeys"
export KB_TEST="$T" KB_TABLE="$TABLE" KB_VAR="$T/vars/KryptikKeyboard" KB_RUN="$T/run-keyboard" KB_KEYMAPS=/keymaps
export PATH="$T/bin:$PATH"
# Each call in a fresh sh, as the callers source it; stdout, then the status.
kb() { sh -c '. "$1"; shift; "$@"' sh "$LIB" "$@"; }
var() { rm -f "$KB_VAR"; printf '\007\000\000\000%s' "$1" > "$KB_VAR"; }

echo "-- the shipped table"
names="$(kb kb_names)"
[[ "$(head -1 <<<"$names")" == us ]] && ok "us is the first layout" || bad "the first layout is '$(head -1 <<<"$names")'"
[[ "$(sort <<<"$names" | uniq -d | wc -l)" -eq 0 ]] && ok "no name is listed twice" || bad "a name is listed twice: $(sort <<<"$names" | uniq -d | tr '\n' ' ')"
odd="$(awk '!/^#/ && NF && (NF != 4 || $1 !~ /^[a-z0-9-]+$/ || length($1) > 32 || $2 !~ /^[A-Za-z0-9_.\/-]+\.map\.gz$/ || $2 ~ /\.\./ || $3 !~ /^[a-z0-9_]+$/ || $4 !~ /^(-|[a-z0-9_-]+)$/) { print $1 }' "$TABLE")"
[[ -z "$odd" ]] && ok "every row is a name, a keymap path, an xkb layout and a variant" || bad "malformed rows: ${odd}"

echo "-- names"
[[ "$(kb kb_row de)" == "de i386/qwertz/de-latin1.map.gz de -" ]] && ok "a name gives its row" || bad "de gave '$(kb kb_row de)'"
for n in '' DE 'de;reboot' '../de' 'de us' nosuchlayout "$(printf 'a%.0s' $(seq 33))"; do
    if kb kb_row "$n" > /dev/null 2>&1; then bad "'${n}' was taken as a layout"; else ok "'${n:0:20}' is not a layout"; fi
done

echo "-- what the variable may hold"
rm -f "$KB_VAR"
[[ -z "$(kb kb_stored)" ]] && ok "no variable is no name" || bad "no variable gave '$(kb kb_stored)'"
var de;            [[ "$(kb kb_stored)" == de ]] && ok "a name is read past the four bytes of attributes" || bad "de read as '$(kb kb_stored)'"
var 'de;reboot';   [[ -z "$(kb kb_stored)" ]] && ok "a value with other characters is no name" || bad "took '$(kb kb_stored)'"
var "$(printf 'a%.0s' $(seq 40))"; [[ -z "$(kb kb_stored)" ]] && ok "a value longer than a name is no name" || bad "took a 40-byte value"
printf '\007\000\000\000' > "$KB_VAR"; [[ -z "$(kb kb_stored)" ]] && ok "an empty value is no name" || bad "took an empty value"
printf 'de' > "$KB_VAR"; [[ -z "$(kb kb_stored)" ]] && ok "a file shorter than its attributes is no name" || bad "took a two-byte file"

echo "-- loading"
rm -f "$T/loaded" "$KB_RUN"
kb kb_load ch-fr; rc=$?
[[ "$rc" -eq 0 && "$(cat "$T/loaded")" == /keymaps/i386/qwertz/fr_CH.map.gz ]] && ok "the row's console keymap is what loadkeys is given" || bad "ch-fr: rc=${rc}, loadkeys got '$(cat "$T/loaded" 2>/dev/null)'"
[[ "$(cat "$KB_RUN")" == $'layout=ch-fr\nxkb_layout=ch\nxkb_variant=fr' ]] && ok "and the row is recorded for the session" || bad "recorded: $(tr '\n' '|' < "$KB_RUN")"
[[ "$(stat -c %a "$KB_RUN")" == 644 ]] && ok "where a session's user can read it" || bad "mode $(stat -c %a "$KB_RUN")"
[[ "$(kb kb_current)" == ch-fr ]] && ok "it is the layout in force" || bad "in force: $(kb kb_current)"
got="$(sh -c '. "$1"; kb_export_xkb; echo "$XKB_DEFAULT_LAYOUT/$XKB_DEFAULT_VARIANT"' sh "$LIB")"
[[ "$got" == ch/fr ]] && ok "the session exports its xkb layout and variant" || bad "exported '${got}'"
kb kb_load de; got="$(sh -c '. "$1"; kb_export_xkb; echo "$XKB_DEFAULT_LAYOUT/${XKB_DEFAULT_VARIANT:-}"' sh "$LIB")"
[[ "$got" == de/ ]] && ok "a layout without a variant exports none" || bad "exported '${got}'"
rm -f "$T/loaded"; kb kb_load nosuchlayout 2>/dev/null; rc=$?
[[ "$rc" -ne 0 && ! -e "$T/loaded" ]] && ok "a name the table lacks loads nothing" || bad "nosuchlayout: rc=${rc}"
touch "$T/loadkeys-fails"; kb kb_load fr 2>/dev/null; rc=$?; rm -f "$T/loadkeys-fails"
[[ "$rc" -ne 0 && "$(kb kb_current)" == de ]] && ok "a keymap that does not load leaves the record as it was" || bad "a failed load: rc=${rc}, in force $(kb kb_current)"
rm -f "$KB_RUN"; [[ "$(kb kb_current)" == us ]] && ok "with nothing loaded the layout in force is us" || bad "in force with no record: $(kb kb_current)"
printf 'xkb_layout=de;reboot\n' > "$KB_RUN"
got="$(sh -c '. "$1"; unset XKB_DEFAULT_LAYOUT; kb_export_xkb; echo "${XKB_DEFAULT_LAYOUT:-none}"' sh "$LIB")"
[[ "$got" == none ]] && ok "a record that is not a layout's exports nothing" || bad "exported '${got}'"

echo "-- storing"
rm -f "$KB_VAR"
kb kb_store us; rc=$?
[[ "$rc" -eq 0 && ! -e "$KB_VAR" ]] && ok "us with no variable writes nothing: none means us" || bad "us: rc=${rc}"
kb kb_store de; rc=$?
[[ "$rc" -eq 0 && "$(od -An -tx1 "$KB_VAR" | tr -d ' \n')" == 070000006465 ]] && ok "a name is written behind the attributes, and nothing after it" || bad "de: rc=${rc}, wrote $(od -An -tx1 "$KB_VAR" 2>/dev/null | tr -d ' \n')"
[[ "$(kb kb_stored)" == de ]] && ok "and reads back" || bad "read back '$(kb kb_stored)'"
kb kb_store us; [[ "$(kb kb_stored)" == us ]] && ok "us replaces another name" || bad "after us: '$(kb kb_stored)'"
kb kb_store nosuchlayout 2>/dev/null; rc=$?
[[ "$rc" -ne 0 && "$(kb kb_stored)" == us ]] && ok "a name the table lacks is not written" || bad "nosuchlayout stored: rc=${rc}"
KB_VAR="$T/no-such-directory/KryptikKeyboard" kb kb_store de 2>/dev/null; rc=$?
[[ "$rc" -ne 0 ]] && ok "without firmware variables a store fails" || bad "a store with no efivars succeeded"

echo "-- the desktop's own layouts, from the user's list"
desk() {   # desk CONTENT: what kb_export_desktop exports for a list holding CONTENT
    printf '%s' "$1" > "$T/desktop"
    sh -c '. "$1"; kb_load us > /dev/null; kb_export_xkb; kb_export_desktop "$2"
           echo "${XKB_DEFAULT_LAYOUT}/${XKB_DEFAULT_VARIANT}/${XKB_DEFAULT_OPTIONS:-}/${KRYPTIK_LAYOUTS:-}"' sh "$LIB" "$T/desktop"
}
[[ "$(desk 'us de-nodeadkeys')" == "us,de/,nodeadkeys/grp:win_space_toggle/us de-nodeadkeys" ]] \
    && ok "two layouts, their variants in order, and Super+Space to switch" || bad "two layouts gave '$(desk 'us de-nodeadkeys')'"
[[ "$(desk $'fr\n')" == "fr///fr" ]] && ok "one layout: no switch" || bad "one layout gave '$(desk $'fr\n')'"
[[ "$(desk 'us de fr it')" == "us,de,fr,it/,,,/grp:win_space_toggle/us de fr it" ]] \
    && ok "four, as many as a keymap holds" || bad "four gave '$(desk 'us de fr it')'"
[[ "$(desk 'us de fr it es')" == "us///" ]] && ok "a fifth leaves the machine's layout alone" || bad "five gave '$(desk 'us de fr it es')'"
[[ "$(desk 'us klingon')" == "us///" ]] && ok "a name the table lacks leaves the machine's layout" || bad "an unknown name gave '$(desk 'us klingon')'"
[[ "$(desk 'de;us *')" == "de,us/,/grp:win_space_toggle/de us" ]] && ok "other characters only part names, and reach no shell as a pattern" || bad "'de;us *' gave '$(desk 'de;us *')'"
[[ "$(desk 'de us-x')" == "us///" ]] && ok "a name with more to it is not the name" || bad "'de us-x' gave '$(desk 'de us-x')'"
[[ "$(desk '')" == "us///" ]] && ok "an empty list is none" || bad "an empty list gave '$(desk '')'"
rm -f "$T/desktop"
[[ "$(sh -c '. "$1"; kb_export_desktop "$2"; echo "${KRYPTIK_LAYOUTS:-none}"' sh "$LIB" "$T/desktop")" == none ]] \
    && ok "no list, nothing changed" || bad "no list changed something"

echo "-- a keyboard's drivers, before eudev runs"
# A laptop whose keyboard is HID over I2C behind an Intel serial-IO controller, a USB keyboard
# whose vendor's driver is a module, a generic one, and a GPU, Wi-Fi, camera and PS/2 mouse.
S="$T/sys"; M="$T/modules"
mkdir -p "$M"
cat > "$M/modules.dep" <<'EOF'
kernel/drivers/mfd/intel-lpss-pci.ko.zst: kernel/drivers/mfd/intel-lpss.ko.zst
kernel/drivers/mfd/intel-lpss.ko.zst:
kernel/drivers/pinctrl/intel/pinctrl-tigerlake.ko.zst: kernel/drivers/pinctrl/intel/pinctrl-intel.ko.zst
kernel/drivers/pinctrl/intel/pinctrl-intel.ko.zst:
kernel/drivers/hid/i2c-hid/i2c-hid-acpi.ko.zst: kernel/drivers/hid/i2c-hid/i2c-hid.ko.zst
kernel/drivers/hid/i2c-hid/i2c-hid.ko.zst:
kernel/drivers/hid/hid-multitouch.ko.zst:
kernel/drivers/hid/hid-apple.ko.zst:
kernel/drivers/gpu/drm/i915/i915.ko.zst:
kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko.zst:
kernel/drivers/media/usb/uvc/uvcvideo.ko.zst:
kernel/drivers/input/mouse/psmouse.ko.zst:
EOF
# What modprobe -R gives for each alias; hid-generic is built in, so modules.dep lacks it.
cat > "$T/aliases" <<'EOF'
pci:v00008086d0000A0E8sv0000103Csd00008A3Dbc0Csc80i00 intel_lpss_pci
acpi:INT34C5: pinctrl_tigerlake
acpi:ELAN0001:PNP0C50: i2c_hid_acpi
hid:b0018g0004v000004F3p00003195 hid_multitouch
hid:b0003g0001v000005ACp0000024F hid_apple
hid:b0003g0001v0000046Dp0000C31C hid_generic
pci:v00008086d00009A49sv0000103Csd00008A3Dbc03sc00i00 i915
pci:v00008086d0000A0F0sv00008086sd00000074bc02sc80i00 iwlwifi
usb:v04F2pB7E0d0001dcEFdsc02dp01ic0Eisc01ip00in00 uvcvideo
serio:ty01pr00id00ex00 psmouse
EOF
# What a module's binding adds: the controller's I2C client, then i2c-hid's HID device.
cat > "$T/adds" <<'EOF'
intel_lpss_pci i2c i2c-ELAN0001:00 acpi:ELAN0001:PNP0C50:
i2c_hid_acpi hid 0018:04F3:3195.0001 hid:b0018g0004v000004F3p00003195
EOF
# modprobe -qaR prints names, -qab records one line per call and adds what binding adds;
# any other flags fail, so a load without the blacklist is no load.
cat > "$T/bin/modprobe" <<'EOF'
#!/bin/sh
mode=$1; shift
case "$mode" in
    -qaR) for a in "$@"; do awk -v a="$a" '$1 == a { print $2 }' "$KB_TEST/aliases"; done ;;
    -qab) echo "$*" >> "$KB_TEST/probed"
          for m in "$@"; do
              awk -v m="$m" '$1 == m { print $2, $3, $4 }' "$KB_TEST/adds" | while read -r bus name alias; do
                  mkdir -p "$KB_SYS/bus/$bus/devices/$name"
                  printf '%s\n' "$alias" > "$KB_SYS/bus/$bus/devices/$name/modalias"
              done
          done ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$T/bin/modprobe"
dev() { mkdir -p "$S/bus/$1/devices/$2"; printf '%s\n' "$3" > "$S/bus/$1/devices/$2/modalias"; }   # dev BUS NAME MODALIAS
dev pci 0000:00:15.0 pci:v00008086d0000A0E8sv0000103Csd00008A3Dbc0Csc80i00
dev platform INT34C5:00 acpi:INT34C5:
dev hid 0003:05AC:024F.0002 hid:b0003g0001v000005ACp0000024F
dev hid 0003:046D:C31C.0003 hid:b0003g0001v0000046Dp0000C31C
dev pci 0000:00:02.0 pci:v00008086d00009A49sv0000103Csd00008A3Dbc03sc00i00
dev pci 0000:00:14.3 pci:v00008086d0000A0F0sv00008086sd00000074bc02sc80i00
dev usb 3-6:1.0 usb:v04F2pB7E0d0001dcEFdsc02dp01ic0Eisc01ip00in00
dev serio serio1 serio:ty01pr00id00ex00
words() { tr -s ' ' '\n' <<<"$1" | sed '/^$/d' | sort | paste -sd' ' -; }   # words LIST: sorted, one space apart
drivers() { KB_SYS="$S" KB_MODULES="$1" sh -c '. "$1"; kb_drivers' sh "$LIB"; }   # drivers MODULES_DIR
rm -f "$T/probed"; out="$(drivers "$M")"; rc=$?
[[ "$rc" -eq 0 && "$(words "$out")" == "hid_apple hid_multitouch i2c_hid_acpi intel_lpss_pci pinctrl_tigerlake" ]] \
    && ok "the keyboard path's modules are loaded, and named" || bad "rc=${rc}, named '${out}'"
[[ "$(words "$(sed -n 1p "$T/probed")")" == "hid_apple intel_lpss_pci pinctrl_tigerlake" ]] \
    && ok "first the controller, its pin controller and the USB keyboard's vendor driver" || bad "first round: '$(sed -n 1p "$T/probed")'"
[[ "$(sed -n 2p "$T/probed")" == i2c_hid_acpi && "$(sed -n 3p "$T/probed")" == hid_multitouch && "$(wc -l < "$T/probed")" -eq 3 ]] \
    && ok "then i2c-hid for the client the controller added, then the HID device's driver, and no more" \
    || bad "later rounds: $(tail -n +2 "$T/probed" | tr '\n' '|')"
for m in i915 iwlwifi uvcvideo psmouse hid_generic; do
    if grep -qw "$m" "$T/probed"; then bad "${m} was loaded before eudev"; else ok "${m} is left to eudev"; fi
done
rm -f "$T/probed"; out="$(drivers "$T/no-modules")"; rc=$?
[[ "$rc" -eq 0 && -z "$out" && ! -e "$T/probed" ]] && ok "with no module tree nothing is asked" || bad "no tree: rc=${rc}, '${out}'"
SYSINIT="$ROOT/build/service-scripts/sysinit.sh"
d="$(grep -n '=$(kb_drivers)' "$SYSINIT" | head -1 | cut -d: -f1)"
k="$(grep -n '|| keyboard_at_boot$' "$SYSINIT" | head -1 | cut -d: -f1)"
u="$(grep -n 'unlock_state "$state_dev"' "$SYSINIT" | head -1 | cut -d: -f1)"
[[ -n "$d" && -n "$k" && -n "$u" && "$d" -lt "$k" && "$d" -lt "$u" ]] \
    && ok "sysinit loads them before the layout is named and the passphrase asked" \
    || bad "kb_drivers at line '${d}', the layout at '${k}', the passphrase at '${u}'"

echo "-- the installer asks under the layout it installs"
INST="$ROOT/tools/install/kryptik-install.sh"
at() { grep -nF -- "$1" "$INST" | head -1 | cut -d: -f1; }
l="$(at 'kb_load "$KEYBOARD"')"; e="$(at 'Type ERASE to continue')"; p="$(at 'a passphrase for the state partition')"
s="$(at 'kb_store "$LAYOUT"')"; w="$(at 'sfdisk --quiet')"
[[ -n "$l" && -n "$e" && -n "$p" && "$l" -lt "$e" && "$l" -lt "$p" ]] \
    && ok "--keyboard's layout is loaded before ERASE and the passphrase are asked" \
    || bad "the layout is loaded at line '${l}', ERASE asked at '${e}', the passphrase at '${p}'"
[[ -n "$s" && -n "$w" && "$s" -lt "$w" ]] && ok "and named in the firmware before the disk is partitioned" \
    || bad "the layout is stored at line '${s}', the disk partitioned at '${w}'"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
