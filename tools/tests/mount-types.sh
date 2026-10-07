#!/usr/bin/env bash
# Every mount of a device the on-system tools make names its filesystem. An
# ESP and a control disk are FAT, and FAT holds no links: on another
# filesystem carrying the partition's label, a link at a name root writes
# would send the write to a disk or a file of the machine. Offline.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

# A mount that opens with its options has left the filesystem to be guessed.
LOOSE='(^|[^a-zA-Z_./-])mount +-o '
grep -qE "$LOOSE" <<<'    mount -o ro "$dev" /mnt || exit 1' && ! grep -qE "$LOOSE" <<<'    mount -t vfat -o ro "$dev" /mnt; umount -o x /mnt' \
    && green "the check sees a mount that names no filesystem, and passes one that does" || red "the check cannot tell the two apart"

cd "$ROOT" || exit 1
for f in build/service-scripts/*.sh tools/install/*.sh tools/update/kryptik-update tools/update/kryptik-recover; do
    loose="$(grep -nE "$LOOSE" "$f" | cut -d: -f1 | tr '\n' ' ')"
    [[ -z "$loose" ]] && green "${f}: every mount names its filesystem" || red "${f}: line(s) ${loose% } leave the filesystem to be guessed"
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
