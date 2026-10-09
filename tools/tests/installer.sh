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
# After `cmd | sed`, $? is sed's. A call starts its line, unlike comments or kryptik-install.json.
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
# The checks kryptik-install and kryptik-recover share; die exits the subshell
# each runs in.
MEDIUM_ROOT="${ROOT}/build/service-scripts/medium-root.sh"
# shellcheck source=/dev/null
. "$MEDIUM_ROOT"
die() { printf 'die: %s\n' "$*"; exit 1; }
grep -q '^\. /usr/libexec/kryptik/medium-root\.sh' "$INSTALLER" \
    && grep -q '^ *\. /usr/libexec/kryptik/medium-root\.sh' "${ROOT}/tools/update/kryptik-recover" \
    && green "the installer and kryptik-recover take the medium's root through the same checks" \
    || red "the installer or kryptik-recover does not source medium-root.sh"
if ! declare -F decimal_field >/dev/null || ! declare -F verity_of >/dev/null || ! declare -F medium_root >/dev/null; then
    red "could not read the record checks from ${MEDIUM_ROOT}"
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
    # A medium's command line naming root hash $h, and its record.
    printf 'ro dm-mod.create="kroot,,0,ro,0 2097152 verity 1 PARTLABEL=kryptik-media PARTLABEL=kryptik-media 4096 4096 262144 262144 sha256 %s 0123abcd 1 panic_on_corruption" kryptik.media=usb\n' "$h" > "$tmp"
    rec="$(mktemp)"
    record() {   # record ROOT_HASH DATA_BLOCKS: root.json as stage 06 writes it
        printf '{\n  "version": "1.0.0",\n  "root_hash": "%s",\n  "salt": "0123abcd",\n  "data_bytes": 1073741824,\n  "data_blocks": %s,\n  "data_sectors": 2097152,\n  "hash_start_block": 262144,\n  "total_bytes": 1094713344,\n  "sha256": "%s"\n}\n' "$1" "$2" "$h" > "$rec"
    }
    record "$h" 262144
    out="$( (medium_root "$rec" "$tmp" && echo "took $ROOT_BYTES $VERSION $V_BLOCKS $V_HASH_START $V_SALT") 2>&1 )"; rc=$?
    [[ "$rc" -eq 0 && "$out" == "took 1094713344 1.0.0 262144 262144 0123abcd" ]] \
        && green "a record that names the signed root is taken, with the table's numbers" \
        || red "a matching record: rc=${rc} ${out}"
    b="$(printf 'b%.0s' $(seq 64))"
    record "$b" 262144
    out="$( (medium_root "$rec" "$tmp") 2>&1 )"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"root.json names root hash ${b}; the signed kernel carries ${h}"* ]] \
        && green "a record that names another root is refused, both hashes named" \
        || red "another root hash: rc=${rc} ${out}"
    record "$(printf '\033]0;owned\007')${h}" 262144
    out="$( (medium_root "$rec" "$tmp") 2>&1 )"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"root_hash is not a hash"* && "$out" != *$'\033'* ]] \
        && green "a root hash carrying a terminal sequence is refused without printing it" \
        || red "a terminal sequence in root_hash: rc=${rc}"
    record "$h" 262143
    out="$( (medium_root "$rec" "$tmp") 2>&1 )"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"262143 data blocks; the signed kernel carries 262144"* ]] \
        && green "a record that names another size of root is refused" \
        || red "another data_blocks: rc=${rc} ${out}"
    record "$h" 262144
    printf 'ro root=/dev/sda2 kryptik.media=usb\n' > "$tmp"
    out="$( (medium_root "$rec" "$tmp") 2>&1 )"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"could not read the root's verity table"* ]] \
        && green "a command line with no verity table is refused" \
        || red "no verity table: rc=${rc} ${out}"
    # A slot's kernel: its command line, inside the binary, names the root.
    # shellcheck disable=SC2034  # read by the sourced kernel_names_root
    V_HASH="$h"
    printf 'MZ\0\0\377pe\0dm-mod.create="kroot,,0,ro,0 2097152 verity 1 PARTLABEL=kryptik-a PARTLABEL=kryptik-a 4096 4096 262144 262144 sha256 %s 0123abcd 1 panic_on_corruption"\0\001' "$h" > "$tmp"
    kernel_names_root "$tmp" && green "a kernel whose command line carries the root hash is taken" \
        || red "a kernel that carries the root hash was refused"
    printf 'MZ\0\0\377pe\0dm-mod.create="kroot,,0,ro,0 2097152 verity 1 PARTLABEL=kryptik-a PARTLABEL=kryptik-a 4096 4096 262144 262144 sha256 %s 0123abcd 1 panic_on_corruption"\0\001' "$b" > "$tmp"
    kernel_names_root "$tmp" && red "a kernel for another root was taken" \
        || green "a kernel whose command line names another root is refused"
    kernel_names_root "$tmp.absent" && red "a missing kernel was taken" || green "a missing kernel is refused"
    rm -f "$tmp" "$rec"
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
# The layout's name goes into the firmware after the last refusal that says
# nothing was written, and before the disk is: a refused install changed nothing.
store="$(grep -n '^kb_store ' "$INSTALLER" | cut -d: -f1)"
refused="$(grep -n 'no state passphrase given; nothing was written' "$INSTALLER" | cut -d: -f1)"
written="$(grep -n '^sfdisk --quiet' "$INSTALLER" | cut -d: -f1)"
[[ "$store" =~ ^[0-9]+$ && "$refused" =~ ^[0-9]+$ && "$written" =~ ^[0-9]+$ && "$store" -gt "$refused" && "$store" -lt "$written" ]] \
    && green "the keyboard layout is stored after the passphrase is taken and before the first write" \
    || red "the keyboard layout is stored at line ${store:-none}; the passphrase is taken by ${refused:-none} and the disk written from ${written:-none}"
grep -q 'testctl_get install_slot_mib' "$RUNNER" \
    && green "the runner passes --slot-size only when the control disk asks" \
    || red "the runner has no install_slot_mib switch"

echo
echo "-- a preseed first boot could not use is refused before anything is written"
eval "$(sed -n '/^preseed_ok()/,/^}/p' "$INSTALLER")"
if ! declare -F preseed_ok >/dev/null; then
    red "could not extract preseed_ok from the installer"
else
    P="$(mktemp -d)"
    printf 'user=ana\npassword_hash=$6$salt$hash\n' > "$P/whole"
    printf 'user=ana\n' > "$P/nohash"
    printf 'password_hash=$6$salt$hash\n' > "$P/nouser"
    printf 'user=Ana\npassword_hash=$6$salt$hash\n' > "$P/upper"
    printf 'user=ana\r\npassword_hash=$6$salt$hash\r\n' > "$P/crlf"
    printf 'user=ana\npassword_hash=letmein\n' > "$P/plain"
    printf 'user=ana\npassword_hash=$6$salt$hash\nroot_password_hash=letmein\n' > "$P/rootplain"
    printf 'user=ana\npassword_hash=$6$rounds=5000$salt$hash./\nroot_password_hash=$y$j9T$salt$hash\n' > "$P/rounds"
    pre() { out="$( (preseed_ok "$1") 2>&1 )"; rc=$?; }
    pre "$P/whole"; [[ "$rc" -eq 0 ]] && green "a preseed naming a user and a hash is taken" || red "a whole preseed: rc=${rc} ${out}"
    pre "$P/absent"; [[ "$rc" -ne 0 && "$out" == *"cannot read the preseed"* ]] \
        && green "a preseed that cannot be read is refused, not skipped" || red "an unreadable preseed: rc=${rc} ${out}"
    pre "$P/nohash"; [[ "$rc" -ne 0 && "$out" == *"names no crypt password_hash="* ]] \
        && green "a preseed with no password hash is refused" || red "no hash: rc=${rc} ${out}"
    pre "$P/nouser"; [[ "$rc" -ne 0 ]] && green "a preseed with no user is refused" || red "no user: rc=${rc} ${out}"
    pre "$P/upper"; [[ "$rc" -ne 0 && "$out" == *"names no user first boot would create"* ]] \
        && green "a user name first boot would refuse is refused here" || red "user=Ana: rc=${rc} ${out}"
    pre "$P/crlf"; [[ "$rc" -ne 0 ]] && green "a preseed with CRLF line ends is refused" || red "CRLF: rc=${rc} ${out}"
    pre "$P/plain"; [[ "$rc" -ne 0 && "$out" == *"names no crypt password_hash="* ]] \
        && green "a password that is not a crypt hash is refused" || red "a plain password: rc=${rc} ${out}"
    pre "$P/rootplain"; [[ "$rc" -ne 0 && "$out" == *"root_password_hash= that is not a crypt hash"* ]] \
        && green "a root hash that is not a crypt hash is refused" || red "a plain root password: rc=${rc} ${out}"
    pre "$P/rounds"; [[ "$rc" -eq 0 ]] && green "sha512crypt with rounds= and a yescrypt root hash are taken" || red "rounds/yescrypt: rc=${rc} ${out}"
    rm -rf "$P"
fi
checked="$(grep -n '^\[ -z "\$PRESEED" \] || preseed_ok' "$INSTALLER" | cut -d: -f1)"
[[ "$checked" =~ ^[0-9]+$ && "$written" =~ ^[0-9]+$ && "$checked" -lt "$written" ]] \
    && green "the preseed is checked before the first write" \
    || red "the preseed is checked at line ${checked:-none}; the disk is written from ${written:-none}"

echo
echo "-- a mounted target is found by whatever name it was mounted by"
eval "$(sed -n '/^mounted_on()/,/^}/p' "$INSTALLER")"
if ! declare -F mounted_on >/dev/null; then
    red "could not extract mounted_on from the installer"
else
    M="$(mktemp -d)"; M="$(cd "$M" && pwd -P)"   # canonical, as readlink -f will give it
    mkdir -p "$M/dev" "$M/by-id"
    : > "$M/dev/vdb"; : > "$M/dev/vdb1"; : > "$M/dev/vdbb1"; : > "$M/dev/vda1"
    ln -s ../dev/vdb1 "$M/by-id/disk-part1"
    devs="$M/dev/vdb\n$M/dev/vdb1"
    devs="$(printf '%b' "$devs")"
    on() { printf '%s %s ext4 rw 0 0\n' "$1" "$2" | mounted_on "$devs"; }
    [[ "$(on "$M/dev/vdb1" /mnt)" == "$M/dev/vdb1 on /mnt" ]] && green "a partition mounted by its own name is found" || red "canonical: $(on "$M/dev/vdb1" /mnt)"
    [[ "$(on "$M/by-id/disk-part1" /mnt)" == "$M/by-id/disk-part1 on /mnt" ]] \
        && green "a partition mounted through a link to it is found" || red "through a link: '$(on "$M/by-id/disk-part1" /mnt)'"
    [[ -z "$(on "$M/dev/vdbb1" /mnt)" ]] && green "a disk whose name only starts the same is not" || red "a prefix: $(on "$M/dev/vdbb1" /mnt)"
    [[ -z "$(on "$M/dev/vda1" /)" ]] && green "another disk's mount is not" || red "another disk: $(on "$M/dev/vda1" /)"
    [[ -z "$(on tmpfs /tmp)" ]] && green "a mount with no device behind it is not" || red "tmpfs: $(on tmpfs /tmp)"
    rm -rf "$M"
fi
echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1
