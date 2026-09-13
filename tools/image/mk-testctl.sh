#!/usr/bin/env bash
# Make a kryptik-testctl control disk: an 8 MiB GPT image with one FAT
# partition labelled kryptik-testctl holding kryptik-test.conf.
#
#   tools/image/mk-testctl.sh --out FILE KEY=VALUE...
#
# Honoured by an install medium only (build/service-scripts/testctl.sh):
#   install_target=/dev/vdb  smoke_poweroff=1  install_wait=SECONDS
#   preseed_user=NAME  preseed_password_hash=HASH
set -Eeuo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
OUT=""; KV=()
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --out) OUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *=*) KV+=("$1"); shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$OUT" ]] || die "--out is required"
[[ "${#KV[@]}" -gt 0 ]] || die "at least one KEY=VALUE is required"
case "$OUT" in /dev/*|/sys/*|/proc/*) die "refusing to write ${OUT}" ;; esac
[[ -e "$OUT" && ! -f "$OUT" ]] && die "refusing: ${OUT} exists and is not a regular file"
for t in sfdisk mkfs.vfat mcopy truncate dd; do have "$t" || die "required tool not found: $t"; done

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "${KV[@]}" > "$tmp/kryptik-test.conf"
# partition: sectors 2048.. (6 MiB)
PSECT=$(( 6 * 2048 ))
truncate -s $(( PSECT * 512 )) "$tmp/part.img"
mkfs.vfat -F 12 -n TESTCTL "$tmp/part.img" >/dev/null
mcopy -i "$tmp/part.img" "$tmp/kryptik-test.conf" ::/kryptik-test.conf
rm -f "$OUT"
truncate -s $(( 8 * 1024 * 1024 )) "$OUT"
sfdisk --quiet --wipe always "$OUT" <<EOF
label: gpt
unit: sectors
start=2048, size=${PSECT}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="kryptik-testctl"
EOF
dd if="$tmp/part.img" of="$OUT" bs=512 seek=2048 conv=notrunc status=none
ok "control disk ${OUT}:"
sed 's/^/  /' "$tmp/kryptik-test.conf"
