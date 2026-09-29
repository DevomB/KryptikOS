#!/usr/bin/env bash
# Test tools/image/suite-lib.sh's boot wrappers against a stand-in run-ovmf.sh,
# which, like another suite booting on the same host, points the shared
# ovmf-serial.latest.log link at a stranger's transcript after every boot.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
command -v openssl >/dev/null 2>&1 || { echo "openssl required (suite-lib.sh hashes its passwords)"; exit 77; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/self" "$T/work/logs"
export KRYPTIK_WORK="$T/work" STUB_ARGS="$T/args"
cat > "$T/self/run-ovmf.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_ARGS"
mode=""; name=""; log=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) mode="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --log)  log="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ "$mode" == serve ]]; then
    d="$KRYPTIK_WORK/vm"; mkdir -p "$d"; rm -f "$d/$name.serial"
    python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$d/$name.serial"
    printf 'serial=%s\nqmp=%s\npid=%s\nlog=%s\nvars=%s\n' \
        "$d/$name.serial" "$d/$name.qmp" "$d/$name.pid" "$KRYPTIK_WORK/logs/ovmf-serial.$name.log" "$d/vars.fd"
    exit 0
fi
[[ "$mode" == smoke ]] || exit 2
printf 'boot %s\r\n' "$name" > "$log"
[[ -n "${STUB_INSTALLED:-}" ]] && printf 'KRYPTIK_INSTALL: rc=%s\r\n' "$STUB_INSTALLED" >> "$log"
echo "a stranger's boot" > "$KRYPTIK_WORK/logs/stranger.log"
ln -sfn "$KRYPTIK_WORK/logs/stranger.log" "$KRYPTIK_WORK/logs/ovmf-serial.latest.log"
exit "${STUB_RC:-0}"
EOF
chmod +x "$T/self/run-ovmf.sh"
cat > "$T/self/test-disk-size.sh" <<'EOF'
#!/usr/bin/env bash
printf 'test-disk-size %s\n' "$*" >> "$STUB_ARGS"
echo 12345678
EOF
cat > "$T/self/mk-testctl.sh" <<'EOF'
#!/usr/bin/env bash
printf 'mk-testctl %s\n' "$*" >> "$STUB_ARGS"
: > "$2"
EOF
chmod +x "$T/self/test-disk-size.sh" "$T/self/mk-testctl.sh"

die() { echo "die: $*"; exit 1; }
SELF="$T/self"
# shellcheck source=tools/image/suite-lib.sh
source "$ROOT/tools/image/suite-lib.sh"
# The wrappers' own verdict helpers are not this test's.
PASS=0; FAIL=0

echo "-- a smoke boot reads its own transcript, not the latest link"
smoke t1 --usb /medium.img --timeout 5 > /dev/null
check "run-ovmf.sh's status comes back" "$?" "0"
first="$BOOTLOG"
check "the transcript is the boot's own" "$(boot_txt)" "boot t1"
check "while the latest link names another" "$(cat "$KRYPTIK_WORK/logs/ovmf-serial.latest.log")" "a stranger's boot"
case "$first" in
    "$KRYPTIK_WORK"/logs/ovmf-serial.t1.*.log) ok "named where acceptance collects ovmf-serial.*.log" ;;
    *) bad "named where acceptance collects ovmf-serial.*.log (got ${first})" ;;
esac
check "run-ovmf.sh got the boot's mode, name and log, then the suite's arguments" \
    "$(tail -1 "$STUB_ARGS")" "--mode smoke --name t1 --log ${first} --usb /medium.img --timeout 5"

echo "-- two boots of one name in the same second keep two transcripts"
smoke t1 --timeout 5 > /dev/null
[[ "$BOOTLOG" != "$first" ]] && ok "a new log for the second boot" || bad "the second boot reused ${first}"
check "and the first transcript is still whole" "$(tr -d '\r' < "$first")" "boot t1"

echo "-- a failed boot's status reaches the suite"
STUB_RC=124 smoke t2 > /dev/null
check "the timeout's 124" "$?" "124"

echo "-- a fresh install: the disk sized from the medium, the installer's verdict"
DISK="$T/disk.img"; VMDIR="$T/vm"; TIMEOUT=900; mkdir -p "$VMDIR"
fresh_disk /medium.img --extra-mib 2048
check "the sizing tool got the medium and the suite's arguments" "$(tail -1 "$STUB_ARGS")" "test-disk-size --medium /medium.img --extra-mib 2048"
check "the disk has the size it gave" "$(stat -c %s "$DISK")" "12345678"
STUB_INSTALLED=0 install_disk t-install /medium.img --vars clean
check "an installer that reports rc=0 passes" "$?" "0"
check "run-ovmf.sh got the medium, disk, control disk and the suite's arguments" "$(tail -1 "$STUB_ARGS")" \
    "--mode smoke --name t-install --log ${BOOTLOG} --usb /medium.img --disk ${DISK} --testctl ${VMDIR}/testctl-t-install.img --timeout 900 --vars clean"
check "the control disk arms the install with the preseeded accounts" "$(grep '^mk-testctl' "$STUB_ARGS" | tail -1)" \
    "mk-testctl --out ${VMDIR}/testctl-t-install.img --key ${TESTCTL_KEY} install_target=/dev/vda smoke_poweroff=1 install_wait=5 ${PRESEED[*]}"
STUB_INSTALLED=1 install_disk t-install /medium.img --vars clean
[[ $? -ne 0 ]] && ok "an installer that reports rc=1 fails" || bad "an installer that reports rc=1 fails"
install_disk t-install /medium.img --vars clean
[[ $? -ne 0 ]] && ok "an installer that reports nothing fails" || bad "an installer that reports nothing fails"

echo "-- start_vm gives each serve boot what its suite parsed by hand"
command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 77; }
DISK="$T/disk.img"; VARSF="$T/vars.fd"
sorted() { tr ' ' '\n' <<<"$1" | sort | tr '\n' ' '; }
# The name and extra arguments of every serve boot the suites made themselves.
for call in "gui-p2 --net user --gpu --mem 3072" "install-p2" "install-p3" \
            "integ-p1" "integ-p4b" "integ-p5" "integ-p5 --disk $T/payload.img"; do
    read -r -a a <<<"$call"
    out="$("$SELF/run-ovmf.sh" --no-media --disk "$DISK" --vars-file "$VARSF" --mode serve --allow-reboot --name "${a[0]}" "${a[@]:1}")"
    by_hand="$(tail -1 "$STUB_ARGS")"
    # What each suite wrote out for itself.
    SER0="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF0="$(sed -n 's/^pid=//p' <<<"$out")"
    LOG0="$(sed -n 's/^log=//p' <<<"$out")"; QMP0="$(sed -n 's/^qmp=//p' <<<"$out")"
    start_vm "${a[@]}"
    check "${call}: the same serial, pid, log and QMP" "$SER|$PIDF|$LOG|$QMP" "$SER0|$PIDF0|$LOG0|$QMP0"
    check "${call}: run-ovmf.sh got the same arguments" "$(sorted "$(tail -1 "$STUB_ARGS")")" "$(sorted "$by_hand")"
done

echo
echo "suite-lib boot wrappers: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
