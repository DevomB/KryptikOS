#!/bin/bash
# Boot a medium under OVMF in serve mode, wait for the medium's root shell
# on the serial console, run the given commands there, and print the
# transcript. A developer probe, not a test: nothing is asserted.
#
#   probe-medium.sh (--usb IMG | --iso ISO) 'cmd1' 'cmd2' ...
set -u
export KRYPTIK_WORK=/root/kryptik/work KRYPTIK_SOURCES=/root/kryptik/sources KRYPTIK_OUT=/root/kryptik/out NO_COLOR=1
WT=/root/kryptik/main
kind="$1"; medium="$2"; shift 2
out="$("$WT/tools/image/run-ovmf.sh" "$kind" "$medium" --vars clean --mode serve --name probe)"
SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"
[[ -S "$SER" ]] || { echo "no serial: $out"; exit 1; }
steps=("expect:KRYPTIK_SMOKE: END" "sleep:3" "send:" "expect:[#$] ?$")
i=0
for c in "$@"; do i=$((i+1)); steps+=("send:echo PROBE-$i-BEGIN; $c; echo PROBE-$i-END" "expect:PROBE-$i-END\r?\n"); done
python3 "$WT/tools/image/vm-drive.py" --serial "$SER" --timeout 240 "${steps[@]}" > /dev/null 2>&1
rc=$?
sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
echo "drive rc=$rc; transcript $LOG"
tr -d '\r' < "$LOG" | sed -n '/PROBE-1-BEGIN/,$p' | grep -v "^PROBE-[0-9]*-BEGIN$" | cut -c1-200
