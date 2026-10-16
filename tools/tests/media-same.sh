#!/usr/bin/env bash
# Stage 06's media functions, run on small stand-ins twice and two seconds apart, write the same
# bytes: the ESP, the images' FAT, the USB image and the ISO (docs/design/reproducible-builds.md).
# Needs dosfstools, mtools, sfdisk and xorriso: 77 without them.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
S06="$ROOT/build/stages/06-iso.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for t in mkfs.vfat mmd mcopy mdir sfdisk xorriso cmp; do
    command -v "$t" > /dev/null || { echo "media-same: no ${t} here"; exit 77; }
done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed -n '/^uuid_of() {/,/^}/p; /^again() {/,/^}/p; /^make_esp() {/,/^}/p; /^make_images_fs() {/,/^}/p;
        /^make_gpt_image() {/,/^}/p; /^make_iso() {/,/^}/p' "$S06" > "$T/fns.sh"
grep -E '^(root_json|part2_start)\(\) \{' "$S06" >> "$T/fns.sh"
for fn in uuid_of again make_esp make_images_fs make_gpt_image make_iso root_json part2_start; do
    grep -q "^${fn}() " "$T/fns.sh" || { echo "media-same: could not extract ${fn} from $S06"; exit 1; }
done
sha256_of_stdin() { sha256sum | cut -d' ' -f1; }
# shellcheck source=/dev/null
. "$T/fns.sh"

if grep -qx 'export TZ=UTC' "$S06"; then ok "stage 06 runs in UTC, where mtools writes FAT times"; else bad "stage 06 does not set TZ=UTC"; fi
export TZ=UTC SOURCE_DATE_EPOCH=1760000000
IMG="$T/img"; KRYPTIK_VERSION=1.2.3; SB_CERT="$T/sb.crt"
# shellcheck disable=SC2034  # read by make_esp, sourced above
ESP_MIB=64
mkdir -p "$IMG/kernels" "$T/medium"
for k in media-usb slot-a slot-b; do head -c 200000 /dev/zero | tr '\0' "${k:0:1}" > "$IMG/kernels/${k}.signed.efi"; done
head -c 4194304 /dev/zero | tr '\0' r > "$IMG/kryptik-root.img"
printf '%s  kryptik-root.img\n' "$(sha256_of_stdin < "$IMG/kryptik-root.img")" > "$IMG/kryptik-root.img.sha256"
printf '{\n  "version": "1.2.3",\n  "root_hash": "%s",\n  "total_bytes": 4194304\n}\n' "$(printf h | sha256_of_stdin)" > "$IMG/root.json"
printf 'a certificate\n' > "$SB_CERT"
printf 'base: x\n' > "$T/medium/images.manifest"
printf 'sig\n' > "$T/medium/images.manifest.sig"
head -c 300000 /dev/zero | tr '\0' f > "$T/medium/browser.img"

# again's own failure: a maker that writes the clock must not pass.
clock() { date +%s%N > "$1"; }
clock "$T/clock"
if again "$T/clock" clock > "$T/again.out" 2>&1; then bad "again passed a maker that writes the clock"; else ok "again fails a maker that writes the clock"; fi

echo "-- the ESP"
make_esp "$IMG/esp.img" media-usb > /dev/null 2>&1 || bad "make_esp failed"
if again "$IMG/esp.img" make_esp media-usb > "$T/esp.out" 2>&1; then ok "make_esp writes the same ESP two seconds later"; else bad "$(cat "$T/esp.out")"; fi
id="$(printf 'kryptik-esp %s %s %s' "$KRYPTIK_VERSION" "$(root_json root_hash)" media-usb | sha256_of_stdin)"
vol="$(od -An -tx4 -j67 -N4 "$IMG/esp.img" | tr -d ' ')"
if [[ "$vol" == "${id:0:8}" ]]; then ok "the ESP's volume ID is the hashed one (${vol})"; else bad "the ESP's volume ID is ${vol}, not ${id:0:8}"; fi

echo "-- the images' FAT"
make_images_fs "$T/medium" "$T/fs1.img" > /dev/null 2>&1 || bad "make_images_fs failed"
sleep 2
make_images_fs "$T/medium" "$T/fs2.img" > /dev/null 2>&1 || bad "make_images_fs failed a second time"
if cmp -s "$T/fs1.img" "$T/fs2.img"; then ok "make_images_fs writes the same FAT two seconds later"; else bad "make_images_fs wrote two different FATs"; fi

echo "-- the USB image"
make_gpt_image "$T/usb.img" "$IMG/esp.img" "$IMG/kryptik-root.img" kryptik-media "$T/fs1.img" > /dev/null 2>&1 || bad "make_gpt_image failed"
if again "$T/usb.img" make_gpt_image "$IMG/esp.img" "$IMG/kryptik-root.img" kryptik-media "$T/fs1.img" > "$T/usb.out" 2>&1; then
    ok "make_gpt_image writes the same USB image two seconds later"
else
    bad "$(tail -1 "$T/usb.out")"
fi
want="$(uuid_of "kryptik-gpt ${KRYPTIK_VERSION} $(root_json root_hash) kryptik-media")"
got="$(sfdisk -d "$T/usb.img" 2>/dev/null | sed -n 's/^label-id: //p')"
if [[ "${got,,}" == "$want" ]]; then ok "the USB image's disk GUID is the hashed one"; else bad "the USB image's disk GUID is ${got:-none}, not ${want}"; fi
n="$(sfdisk -d "$T/usb.img" 2>/dev/null | grep -c 'uuid=')"
if [[ "$n" -eq 3 ]]; then ok "the USB image's three partitions each have a GUID"; else bad "${n} of the USB image's partitions have a GUID"; fi

echo "-- the ISO"
make_iso "$T/a.iso" "$IMG/esp.img" "$T/medium" > /dev/null 2>&1 || bad "make_iso failed"
if again "$T/a.iso" make_iso "$IMG/esp.img" "$T/medium" > "$T/iso.out" 2>&1; then ok "make_iso writes the same ISO two seconds later"; else bad "$(tail -1 "$T/iso.out")"; fi
start="$(part2_start "$T/a.iso")"
if [[ -n "$start" ]] && cmp -s "$IMG/kryptik-root.img" <(dd if="$T/a.iso" bs=512 skip="$start" count=8192 status=none); then
    ok "the ISO's appended partition is the root image"
else
    bad "the ISO's appended partition (at ${start:-no sector}) is not the root image"
fi

echo
echo "media-same: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
