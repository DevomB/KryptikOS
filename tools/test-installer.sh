#!/usr/bin/env bash
#
# Installer checks that need no VM, no root, and no disk.
#
# The installer is the one tool here that partitions a disk, so the parts of it
# that can be checked cheaply should be, every time - not only when someone
# spends fifteen minutes booting a guest to find out that a device name was
# built wrong.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
# Pull part_dev out of the installer and exercise it directly. A disk whose name
# ends in a digit takes a "p" separator; one that does not takes the number.
# Getting this wrong is how the first install run went looking for /dev/vdbp2.
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
# The base system has util-linux and e2fsprogs. It does NOT have gptfdisk or
# parted. Calling one is not a style question - it is the exact failure that made the
# first install run do nothing while reporting success.
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

echo
echo "-- the runner reports the installer's exit status, not something else's"
# `cmd | sed ...` followed by `rc=$?` captures sed, which always succeeds. That
# is how a "command not found" became rc=0.
# Match the INVOCATION, not the word. The first version of this check searched
# for "kryptik-install.*|" and flagged two innocent lines: a comment describing
# the old bug, and the filename kryptik-install.json inside a $(... || ...).
# A check that fires on a comment about a bug is not checking for the bug.
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
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1
