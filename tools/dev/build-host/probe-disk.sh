#!/bin/bash
# Boot an installed test disk under OVMF (no medium, user networking), log in
# as the preseeded tester, run each given command as root through su, and
# print the transcript from the login on. A developer probe: nothing is
# asserted. Commands must not contain single quotes (su -c wraps them).
#
#   probe-disk.sh DISK 'cmd1' 'cmd2' ...
#   PROBE_OVMF_ARGS='--gpu --mem 3072' probe-disk.sh DISK ...   extra run-ovmf
#   arguments (a virtual GPU, for a disk whose desktop session is the question)
set -u
export KRYPTIK_WORK=/root/kryptik/work KRYPTIK_SOURCES=/root/kryptik/sources KRYPTIK_OUT=/root/kryptik/out NO_COLOR=1
WT=/root/kryptik/main
disk="$1"; shift
VARSF="$KRYPTIK_WORK/vm/probe-vars.fd"; cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARSF"
# shellcheck disable=SC2086  # PROBE_OVMF_ARGS is a word list by design
out="$("$WT/tools/image/run-ovmf.sh" --no-media --disk "$disk" --vars-file "$VARSF" --mode serve --allow-reboot --net user ${PROBE_OVMF_ARGS:-} --name probe-disk)"
SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"
[[ -S "$SER" ]] || { echo "no serial: $out"; exit 1; }
steps=("expect:KRYPTIK_SMOKE: END" "login:tester:tester-pw")
i=0
for c in "$@"; do i=$((i+1)); steps+=("su:root-pw:echo PROBE-$i-BEGIN; $c; echo PROBE-$i-END"); done
python3 "$WT/tools/image/vm-drive.py" --serial "$SER" --timeout 300 "${steps[@]}" > /dev/null 2>&1
rc=$?
sleep 1; [[ -f "$PIDF" ]] && kill "$(cat "$PIDF")" 2>/dev/null
echo "drive rc=$rc; transcript $LOG"
tr -d '\r' < "$LOG" | sed -n '/PROBE-1-BEGIN/,$p' | grep -av "^PROBE-[0-9]*-BEGIN$\|^KRC[0-9]*=" | cut -c1-220
