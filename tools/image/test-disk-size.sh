#!/usr/bin/env bash
# The size a suite's installed-system test disk has to be, from the medium.
#
#   tools/image/test-disk-size.sh --medium USB.img [--payloads N] [--extra-mib M]
#
# Prints one word for `truncate -s`, such as 17536M.
#
#   --medium FILE    the USB medium the suite installs from
#   --payloads N     how many update payloads the suite keeps on kryptik-state
#                    at the same moment (default 0)
#   --extra-mib M    more room on kryptik-state for the suite's own data
#
# Every suite used `truncate -s 12G`. That was the root image of the day plus
# a guess, and it stopped being enough the day the image grew by a quarter of
# a gigabyte: the installer gives each slot the image plus half again, the
# state partition gets what is left, and on a 12 GiB disk what was left no
# longer held the two payloads the update suite stages there. The copy failed
# with "No space left on device", a truncated manifest was armed, and the
# suite spent 56 minutes in a boot loop saying so.
#
# So the size follows the image. The medium is an upper bound on the root
# image it carries, which keeps this free of any knowledge of where a build
# puts its files. The arithmetic is the installer's
# (tools/install/kryptik-install.sh): a slot is the image plus half, at least
# 512 MiB of room, rounded up to 64 MiB. If the two ever disagree the
# installer refuses the disk, by name and by number, which is a failure that
# says what it is.
set -euo pipefail

MEDIUM=""; PAYLOADS=0; EXTRA=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --medium)    MEDIUM="${2:?--medium needs a file}"; shift 2 ;;
        --payloads)  PAYLOADS="${2:?--payloads needs a number}"; shift 2 ;;
        --extra-mib) EXTRA="${2:?--extra-mib needs a number}"; shift 2 ;;
        -h|--help)   sed -n '2,14p' "${BASH_SOURCE[0]}" | cut -c3-; exit 0 ;;
        *) echo "test-disk-size: unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -f "$MEDIUM" ]] || { echo "test-disk-size: no medium at '${MEDIUM}'" >&2; exit 2; }
[[ "$PAYLOADS" =~ ^[0-9]+$ && "$EXTRA" =~ ^[0-9]+$ ]] || { echo "test-disk-size: --payloads and --extra-mib want whole numbers" >&2; exit 2; }

MIB=$(( 1024 * 1024 ))
img_mib=$(( ($(stat -c %s "$MEDIUM") + MIB - 1) / MIB ))
room_mib=$(( img_mib / 2 )); [[ "$room_mib" -ge 512 ]] || room_mib=512
slot_mib=$(( (img_mib + room_mib + 63) / 64 * 64 ))
esp_mib=1024          # an allowance, not the ESP's size: it is a few hundred MiB
# The installer will not accept a disk whose state partition cannot hold one
# payload and a gigabyte of data (image + 128 + 1024 MiB). That is the floor;
# a suite that stages more than one payload at once gets the rest, and every
# suite gets a further gigabyte to work in.
more=$(( PAYLOADS > 1 ? PAYLOADS - 1 : 0 ))
state_mib=$(( img_mib + 128 + 1024 + more * img_mib + 1024 + EXTRA ))
total_mib=$(( (2 + esp_mib + 2 * slot_mib + state_mib + 63) / 64 * 64 ))
printf '%sM\n' "$total_mib"
