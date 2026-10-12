#!/usr/bin/env bash
# Tests for the net zone's answer to a scan (tools/net/netzone-init.sh, scan_lines and
# scan_radios): iw's listing becomes a line per network with its signal, security and SSID as
# iw escapes it, a random address is asked for first, a joined radio only listens, and a busy
# radio's last results are read.
# Offline, under each POSIX shell here, with iw and ip stood in for.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/tools/net/netzone-init.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
same()  { if [[ "$2" == "$3" ]]; then green "$1"; else red "$1" "got '$(tr '\n\t' '|>' <<<"$2")', want '$(tr '\n\t' '|>' <<<"$3")'"; fi; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

{ sed -n '/^scan_lines() {/,/^}/p' "$SCRIPT"; sed -n '/^scan_radios() {/,/^}/p' "$SCRIPT"; } > "$T/functions.sh"
grep -q '^scan_lines() {' "$T/functions.sh" && grep -q '^scan_radios() {' "$T/functions.sh" \
    || { echo "could not find scan_lines or scan_radios in ${SCRIPT#"$ROOT"/} (did their first lines move?)"; exit 1; }
grep -q "^trap 'scan_wanted=1' USR1" "$SCRIPT" \
    && green "the zone takes zone 0's ask (SIGUSR1) from its first lines, so one sent at its start is not lost" \
    || red "netzone-init.sh sets no SIGUSR1 handler before its start"

printf '%s\n' \
    'BSS 02:00:00:00:01:00(on nic0) -- associated' \
    '	freq: 2412.0' \
    '	capability: ESS Privacy ShortSlotTime (0x0411)' \
    '	signal: -30.00 dBm' \
    '	SSID: Home net' \
    '	RSN:	 * Version: 1' \
    '		 * Group cipher: CCMP' \
    '		 * Authentication suites: PSK SAE' \
    'BSS 02:00:00:00:01:01(on nic0)' \
    '	capability: ESS ShortSlotTime (0x0401)' \
    '	signal: -55.00 dBm' \
    '	SSID: Caf\xc3\xa9' \
    'BSS 02:00:00:00:01:02(on nic0)' \
    '	capability: ESS Privacy (0x0011)' \
    '	signal: -61.00 dBm' \
    '	SSID: wpa3 only' \
    '	RSN:	 * Version: 1' \
    '		 * Authentication suites: SAE' \
    'BSS 02:00:00:00:01:03(on nic0)' \
    '	capability: ESS Privacy (0x0011)' \
    '	signal: -71.00 dBm' \
    '	SSID: corp' \
    '	RSN:	 * Version: 1' \
    '		 * Authentication suites: IEEE 802.1X' \
    '	WPA:	 * Version: 1' \
    '		 * Authentication suites: PSK' \
    'BSS 02:00:00:00:01:04(on nic0)' \
    '	capability: ESS Privacy (0x0011)' \
    '	signal: -75.00 dBm' \
    '	SSID: old' \
    '	WPA:	 * Version: 1' \
    '		 * Authentication suites: PSK' \
    'BSS 02:00:00:00:01:05(on nic0)' \
    '	capability: ESS Privacy (0x0011)' \
    '	signal: -80.00 dBm' \
    '	SSID: wep' \
    'BSS 02:00:00:00:01:06(on nic0)' \
    '	capability: ESS Privacy (0x0011)' \
    '	signal: -82.00 dBm' \
    '	SSID: enhanced' \
    '	RSN:	 * Version: 1' \
    '		 * Authentication suites: OWE' > "$T/iw.out"
want_lines="$(printf '%s\t%s\t%s\n' \
    -30 wpa2/wpa3 'Home net' \
    -55 open 'Caf\xc3\xa9' \
    -61 wpa3 'wpa3 only' \
    -71 enterprise corp \
    -75 wpa old \
    -80 wep wep \
    -82 owe enhanced)"

# iw and ip stood in for: iw answers as $IW_SAYS tells it, by the scan's own flags.
mkdir -p "$T/bin"
cat > "$T/bin/iw" <<EOF
#!/bin/sh
echo "\$*" >> "$T/iw.calls"
case "\$*" in
    *"scan randomise") [ "\${IW_SAYS:-}" = random ] || exit 1 ;;
    *"scan dump") [ "\${IW_SAYS:-}" = busy ] || exit 1 ;;
    *"scan passive") [ "\${IW_SAYS:-}" = joined ] || exit 1 ;;
esac
cat "$T/iw.out"
EOF
printf '#!/bin/sh\nexit 0\n' > "$T/bin/ip"
chmod +x "$T/bin/iw" "$T/bin/ip"
cat > "$T/harness.sh" <<EOF
. "$T/functions.sh"
PATH="$T/bin:\$PATH"
SCAN="$T/scan"; WIRELESS="\$1"
case "\$2" in
    lines) scan_lines < "$T/iw.out" ;;
    radios) rm -f "$T/iw.calls" "\$SCAN"; IW_SAYS="\$3" scan_radios; cat "\$SCAN"; echo "--"; cat "$T/iw.calls" 2>/dev/null ;;
esac
EOF

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    echo "-- ${sh}"
    same "each network becomes its signal, security and SSID as iw escaped it" "$("$sh" "$T/harness.sh" "" lines)" "$want_lines"
    same "a radio with no network joined scans from a random address" \
        "$("$sh" "$T/harness.sh" nic0 radios random)" "$(printf 'radios nic0\n%s\n--\ndev nic0 scan randomise' "$want_lines")"
    same "a joined radio, refused a random address, only listens" \
        "$("$sh" "$T/harness.sh" nic0 radios joined)" "$(printf 'radios nic0\n%s\n--\ndev nic0 scan randomise\ndev nic0 scan passive' "$want_lines")"
    same "a radio its supplicant is scanning with gives the kernel's last results" \
        "$("$sh" "$T/harness.sh" nic0 radios busy)" "$(printf 'radios nic0\n%s\n--\ndev nic0 scan randomise\ndev nic0 scan passive\ndev nic0 scan dump' "$want_lines")"
    same "no radio is said, and nothing is scanned" "$("$sh" "$T/harness.sh" "" radios random)" "$(printf 'radios none\n--')"
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
