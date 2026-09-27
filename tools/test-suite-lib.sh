#!/usr/bin/env bash
# Test tools/image/suite-lib.sh's boot wrappers against a stand-in run-ovmf.sh,
# which, like another suite booting on the same host, points the shared
# ovmf-serial.latest.log link at a stranger's transcript after every boot.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
[[ "$mode" == smoke ]] || exit 2
printf 'boot %s\r\n' "$name" > "$log"
echo "a stranger's boot" > "$KRYPTIK_WORK/logs/stranger.log"
ln -sfn "$KRYPTIK_WORK/logs/stranger.log" "$KRYPTIK_WORK/logs/ovmf-serial.latest.log"
exit "${STUB_RC:-0}"
EOF
chmod +x "$T/self/run-ovmf.sh"

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

echo
echo "suite-lib boot wrappers: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
