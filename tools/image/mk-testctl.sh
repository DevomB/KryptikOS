#!/usr/bin/env bash
# Make a kryptik-testctl control disk: an 8 MiB GPT image with one FAT
# partition labelled kryptik-testctl holding kryptik-test.conf and its
# signature by the kryptik-testctl key, which the medium checks against its
# anchor before it honours a key: a disk signed by any other key is ignored.
#
#   tools/image/mk-testctl.sh --out FILE --key KRYPTIK-TESTCTL KEY=VALUE...
#
# Read only by an install medium; keys include (build/service-scripts/testctl.sh):
#   install_target=/dev/vdb  smoke_poweroff=1  install_wait=SECONDS
#   preseed_user=NAME  preseed_password_hash=HASH
set -Eeuo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
OUT=""; KEY=""; KV=()
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --out) OUT="${2:?}"; shift 2 ;;
        --key) KEY="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *=*) KV+=("$1"); shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$OUT" ]] || die "--out is required"
[[ -n "$KEY" && -f "$KEY" ]] || die "--key is required: the kryptik-testctl key the medium's anchor lists"
[[ "${#KV[@]}" -gt 0 ]] || die "at least one KEY=VALUE is required"
case "$OUT" in /dev/*|/sys/*|/proc/*) die "refusing to write ${OUT}" ;; esac
[[ -e "$OUT" && ! -f "$OUT" ]] && die "refusing: ${OUT} exists and is not a regular file"
for t in sfdisk mkfs.vfat mcopy truncate dd ssh-keygen; do have "$t" || die "required tool not found: $t"; done

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "${KV[@]}" > "$tmp/kryptik-test.conf"
ssh-keygen -Y sign -f "$KEY" -n kryptik-testctl "$tmp/kryptik-test.conf" < /dev/null > /dev/null 2>&1 \
    && [[ -s "$tmp/kryptik-test.conf.sig" ]] || die "could not sign the control file with ${KEY}"
# partition: sectors 2048.. (6 MiB)
PSECT=$(( 6 * 2048 ))
truncate -s $(( PSECT * 512 )) "$tmp/part.img"
mkfs.vfat -F 12 -n TESTCTL "$tmp/part.img" >/dev/null
mcopy -i "$tmp/part.img" "$tmp/kryptik-test.conf" "$tmp/kryptik-test.conf.sig" ::/
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
