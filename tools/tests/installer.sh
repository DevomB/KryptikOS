#!/usr/bin/env bash
# Installer checks that need no VM, no root and no disk.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="${ROOT}/tools/install/kryptik-install.sh"
RUNNER="${ROOT}/build/service-scripts/installer-run.sh"

pass=0; fail=0
green() { printf '  PASS  %s\n' "$*"; pass=$((pass + 1)); }
red()   { printf '  FAIL  %s\n' "$*"; fail=$((fail + 1)); }
note()  { printf '        %s\n' "$*"; }

for f in "$INSTALLER" "$RUNNER"; do
    [[ -f "$f" ]] || { printf 'missing: %s\n' "$f"; exit 1; }
done

echo "-- the harness can tell a pass from a failure"
if true;  then green "a true condition is seen as passing"; else red "broken harness"; fi
if false; then red "a false condition was seen as passing"; else green "a false condition is seen as failing"; fi

echo
echo "-- partition device naming"
# part_dev, taken from the installer: a name ending in a digit takes a "p".
eval "$(sed -n '/^part_dev()/,/^}/p' "$INSTALLER")"
if ! declare -F part_dev >/dev/null; then
    red "could not extract part_dev from the installer"
else
    check_dev() {
        got="$(part_dev "$1" 2)"
        if [[ "$got" == "$2" ]]; then green "$1 -> $got"; else red "$1 -> $got, expected $2"; fi
    }
    check_dev /dev/vdb      /dev/vdb2         # virtio, what the test VM uses
    check_dev /dev/sda      /dev/sda2         # scsi/sata
    check_dev /dev/nvme0n1  /dev/nvme0n1p2    # nvme: name ends in a digit
    check_dev /dev/mmcblk0  /dev/mmcblk0p2    # sd/emmc: same rule
    check_dev /dev/loop0    /dev/loop0p2      # loop: same rule
fi

echo
echo "-- tools the guest does not have must not be called"
# The image has util-linux and e2fsprogs, and none of these. Comments are skipped.
for absent in sgdisk gdisk partprobe parted rsync; do
    hits="$(grep -nE "(^|[^a-z-])${absent}([^a-z-]|$)" "$INSTALLER" "$RUNNER" | grep -v '^\s*#' | grep -vE '#.*'"${absent}" || true)"
    if [[ -z "$hits" ]]; then
        green "${absent} is not invoked"
    else
        red "${absent} is invoked, and is not in the image"
        printf '%s\n' "$hits" | sed 's/^/        /'
    fi
done

echo
echo "-- the installer refuses before it writes, not during"
grep -q 'command -v "\$tool"' "$INSTALLER" \
    && green "every external tool is checked up front" \
    || red "no tool preflight: a missing binary would be found mid-partition"
grep -q '\[ -b "\$TARGET" \]' "$INSTALLER" \
    && green "the target must be a block device" \
    || red "no block-device check"
grep -q 'is the disk this system is running from' "$INSTALLER" \
    && green "installing over the running root is refused" \
    || red "no running-root guard"
grep -q 'the target has mounted filesystems' "$INSTALLER" \
    && green "a target with mounted filesystems is refused" \
    || red "no mounted-target guard"
grep -q 'is in use: held open by' "$INSTALLER" \
    && green "a target held open by device-mapper or md is refused" \
    || red "no held-open guard: an unlocked LUKS partition on the target would be overwritten"
grep -qF -- '--replace-kryptik: everything on it' "$INSTALLER" \
    && green "a disk that carries Kryptik is replaced only with --replace-kryptik" \
    || red "no --replace-kryptik guard for a disk that carries Kryptik"
# A read-only medium must be refused as the disk this system runs from.
if awk '/is the disk this system is running from/ && !r { r = NR }
        /is read-only/ && !o { o = NR }
        END { exit !(r && o && r < o) }' "$INSTALLER"; then
    green "the running-root refusal comes before the read-only one"
else
    red "the read-only refusal comes first and would stand in for the running-root one"
fi
grep -q 'testctl_get install_replace' "$RUNNER" \
    && green "the runner passes --replace-kryptik only when the control disk asks" \
    || red "the runner has no install_replace switch"

echo
echo "-- the runner reports the installer's exit status, not something else's"
# After `cmd | sed`, $? is sed's. Match a call at the start of a line, not the
# word: comments and kryptik-install.json are not calls.
piped="$(grep -nE '^[[:space:]]*(/usr/sbin/)?kryptik-install[^|#]*\|' "$RUNNER" || true)"
if [[ -n "$piped" ]]; then
    red "the installer is still piped; rc would be the pipeline's last element"
    printf '%s
' "$piped" | sed 's/^/        /'
else
    green "the installer is not piped, so \$? is its own"
fi
grep -q 'rc=\$?' "$RUNNER" \
    && green "the runner captures an exit status" \
    || red "the runner never captures an exit status"

# The missing-binary path must not report success.
if sed -n '/no \/usr\/sbin\/kryptik-install/,/^fi/p' "$RUNNER" | grep -q 'rc=127'; then
    green "a missing installer reports a failing rc"
else
    red "a missing installer would report success"
fi

echo
echo "-- root.json is checked for form, and against the signed command line"
# The helpers, taken from the installer; die exits the subshell each runs in.
eval "$(sed -n '/^decimal_field()/,/^}/p; /^hex_field()/,/^}/p; /^verity_of()/,/^}/p' "$INSTALLER")"
die() { printf 'die: %s\n' "$*"; exit 1; }
if ! declare -F decimal_field >/dev/null || ! declare -F verity_of >/dev/null; then
    red "could not extract the record checks from the installer"
else
    out="$( (decimal_field total_bytes '1$(reboot)') 2>&1 )"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"total_bytes is not a number"* ]] \
        && green "a command in total_bytes is refused before any arithmetic" \
        || red "a command in total_bytes: rc=${rc} ${out}"
    out="$( (decimal_field total_bytes '1234567890123456') 2>&1 )"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"too large"* ]] \
        && green "a number too long for arithmetic is refused" \
        || red "a 16-digit total_bytes: rc=${rc} ${out}"
    ( decimal_field total_bytes 1073741824 ) >/dev/null 2>&1 \
        && green "a plain decimal passes" || red "a plain decimal was refused"
    out="$( (hex_field sha256 'deadbeef' 64) 2>&1 )"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"not a hash"* ]] \
        && green "a short hash is refused" || red "a short hash: rc=${rc} ${out}"
    h="$(printf 'a%.0s' $(seq 64))"
    ( hex_field sha256 "$h" 64 ) >/dev/null 2>&1 \
        && green "a 64-digit hash passes" || red "a 64-digit hash was refused"
    tmp="$(mktemp)"
    printf 'ro rootwait dm-mod.create="kryptik-root,,,ro,0 2097152 verity 1 /dev/sda2 /dev/sda2 4096 4096 262144 262144 sha256 %s 0123abcd 1 panic_on_corruption" mitigations=auto,nosmt\n' "$h" > "$tmp"
    got="$(verity_of "$tmp")"
    [[ "$got" == "262144 262144 ${h} 0123abcd" ]] \
        && green "the verity table's blocks, hash start, root hash and salt are read from the command line" \
        || red "verity_of read: ${got}"
    printf 'ro dm-mod.create="x,,,ro,0 8 verity 1 /dev/sda2 /dev/sda2 4096 4096 1 1 sha256 nothex 00 1 panic_on_corruption"\n' > "$tmp"
    [[ -z "$(verity_of "$tmp")" ]] \
        && green "a table whose root hash is not 64 hex digits reads as none" \
        || red "a malformed table was accepted"
    rm -f "$tmp"
fi

echo
echo "-- --slot-size is a number of MiB, no less than a slot needs"
eval "$(sed -n '/^slot_size_ok()/,/^}/p' "$INSTALLER")"
if ! declare -F slot_size_ok >/dev/null; then
    red "could not extract slot_size_ok from the installer"
else
    slot() { out="$( (slot_size_ok "$1" 3072) 2>&1 )"; rc=$?; }
    slot 3072; [[ "$rc" -eq 0 ]] && green "the size a slot needs is taken" || red "3072 of 3072: rc=${rc} ${out}"
    slot 4096; [[ "$rc" -eq 0 ]] && green "a larger slot is taken" || red "4096 of 3072: rc=${rc} ${out}"
    slot 3071; [[ "$rc" -ne 0 && "$out" == *"is less than the 3072 MiB a slot needs"* ]] \
        && green "a smaller slot is refused, with the size a slot needs" || red "3071 of 3072: rc=${rc} ${out}"
    slot '4096$(reboot)'; [[ "$rc" -ne 0 && "$out" == *"takes a number of MiB"* ]] \
        && green "a command in the size is refused before any arithmetic" || red "a command in the size: rc=${rc} ${out}"
    slot 04096; [[ "$rc" -ne 0 && "$out" == *"takes a number of MiB"* ]] \
        && green "a leading zero, which arithmetic reads as octal, is refused" || red "04096: rc=${rc} ${out}"
    slot 1234567890; [[ "$rc" -ne 0 && "$out" == *"too large"* ]] \
        && green "a size too long for arithmetic is refused" || red "a 10-digit size: rc=${rc} ${out}"
fi
grep -q 'testctl_get install_slot_mib' "$RUNNER" \
    && green "the runner passes --slot-size only when the control disk asks" \
    || red "the runner has no install_slot_mib switch"
echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1
