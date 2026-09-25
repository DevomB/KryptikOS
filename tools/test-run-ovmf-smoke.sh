#!/usr/bin/env bash
#
# run-ovmf.sh's smoke mode, with a stand-in QEMU: the verdict is the
# driver's, not a look at the process table.
#
# Smoke mode starts QEMU with its console on a socket and asks vm-drive.py
# to wait for the guest to go away. What it then reports depends on how it
# tells "the guest powered off" from "the timeout struck". A `kill -0` of
# QEMU's pid told the two apart, and it could not: QEMU closes its console
# in its shutdown, a moment before the process is gone, so the driver saw
# the close, the check found QEMU still there, and every clean poweroff was
# the timeout. The stand-in here closes its console and lingers half a
# second, the shape of that moment, so the first case fails on that logic
# in a second and needs no QEMU.
#
# Exit 0 when every case passes.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/ovmf" "$T/work"
: > "$T/ovmf/OVMF_CODE_4M.secboot.fd"; : > "$T/ovmf/OVMF_VARS_4M.fd"; : > "$T/medium.img"
# The stand-in: finds the console socket and the log in its arguments,
# opens the socket, waits for the driver, says what a kernel says last,
# closes the console, and is a process for half a second more, as QEMU is
# while it tears down. With STAY=SECONDS it stays that long before any of
# that, a guest that does not power off.
cat > "$T/qemu" <<'EOF'
#!/usr/bin/env python3
import os, socket, sys, time
chardev = next(a for a in sys.argv if a.startswith("socket,"))
opts = dict(p.split("=", 1) for p in chardev.split(",") if "=" in p)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(opts["path"]); s.listen(1)
c, _ = s.accept()
if os.environ.get("STAY"):
    time.sleep(float(os.environ["STAY"]))
last = b"reboot: Power down\r\n"
with open(opts["logfile"], "ab") as log:
    log.write(last)
c.sendall(last); c.close(); s.close()
time.sleep(0.5)
EOF
chmod +x "$T/qemu"

run_smoke() {   # run_smoke TIMEOUT: sets RC and OUT
    OUT="$(cd "$ROOT" && KRYPTIK_QEMU="$T/qemu" KRYPTIK_OVMF_DIR="$T/ovmf" KRYPTIK_WORK="$T/work" NO_COLOR=1 \
        tools/image/run-ovmf.sh --usb "$T/medium.img" --mode smoke --timeout "$1" --name t 2>&1)"; RC=$?
}

echo "-- the guest powers off and QEMU is gone before anyone looks"
run_smoke 20
check "smoke mode exits 0" "$RC" "0"
check "and does not call it the timeout" "$(grep -c 'timeout' <<<"$OUT")" "0"
check "the console reached the log" "$(cat "$T"/work/logs/ovmf-serial.t.*.log 2>/dev/null | grep -c 'Power down')" "1"

echo "-- the guest never powers off"
STAY=30 run_smoke 2
check "smoke mode exits 124 at its timeout" "$RC" "124"
check "and says so" "$(grep -c 'hit the 2s timeout' <<<"$OUT")" "1"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
