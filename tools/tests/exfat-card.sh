#!/usr/bin/env bash
# kryptik-stick against a card mkfs.exfat made, as a camera's comes: exfat-add.py puts a photo in
# a directory of its own, a note, and a name with accents on it; fsck.exfat finds the card sound;
# the reader names it, lists it through the card's own up-case table, copies each file off whole
# and writes nothing. Needs exfatprogs and cargo: 77 without them.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for t in mkfs.exfat fsck.exfat cargo python3; do
    command -v "$t" > /dev/null || { echo "exfat-card: no ${t} here"; exit 77; }
done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cargo build --quiet --locked --manifest-path "$ROOT/tools/stick/Cargo.toml" --target-dir "$T/target" \
    || { echo "exfat-card: kryptik-stick did not build"; exit 1; }
STICK="$T/target/debug/kryptik-stick"
CARD="$T/card.img"
truncate -s 64M "$CARD"
mkfs.exfat -L KCARD "$CARD" > "$T/mkfs.out" 2>&1 || { echo "exfat-card: mkfs.exfat: $(tr '\n' ' ' < "$T/mkfs.out")"; exit 1; }
head -c 300000 /dev/urandom > "$T/photo"
printf 'a note' > "$T/note"
printf 'deja vu' > "$T/accents"
python3 "$ROOT/tools/image/exfat-add.py" "$CARD" "$T/photo:DCIM/100CANON/IMG_0001.JPG" "$T/note:notes.txt" \
    "$T/accents:Été.txt" || { echo "exfat-card: exfat-add.py failed"; exit 1; }

echo "-- the card, as exfatprogs judges it"
if fsck.exfat -n "$CARD" > "$T/fsck.out" 2>&1; then ok "fsck.exfat finds the card sound"; else bad "fsck.exfat: $(tr '\n' ' ' < "$T/fsck.out")"; fi

echo "-- the reader"
before="$(sha256sum "$CARD" | cut -d' ' -f1)"
info="$("$STICK" --device "$CARD" 2>&1)"
[[ "$info" == *"exFAT, read-only"* && "$info" == *'label "KCARD"'* ]] && ok "the card is named, exFAT and read-only" || bad "said: ${info}"
listed="$("$STICK" --device "$CARD" list /dcim/100canon 2>&1)"
grep -qE ' IMG_0001\.JPG$' <<<"$listed" && ok "a directory is found without regard to case, and listed" || bad "listed: ${listed}"
mkdir -p "$T/out"
(cd "$T/out" && "$STICK" --device "$CARD" get /DCIM/100CANON/img_0001.jpg . > /dev/null 2>&1)
cmp -s "$T/photo" "$T/out/img_0001.jpg" && ok "the photo comes off whole along its FAT chain" || bad "the photo copied off differs"
(cd "$T/out" && "$STICK" --device "$CARD" get "/ÉTÉ.TXT" accents > /dev/null 2>&1)
cmp -s "$T/accents" "$T/out/accents" && ok "a name with accents is found through the card's up-case table" || bad "Été.txt did not come off as ÉTÉ.TXT"
"$STICK" --device "$CARD" get / "$T/out/all" > /dev/null 2>&1
if cmp -s "$T/photo" "$T/out/all/DCIM/100CANON/IMG_0001.JPG" && cmp -s "$T/note" "$T/out/all/notes.txt" \
   && cmp -s "$T/accents" "$T/out/all/Été.txt"; then ok "the whole card comes off as it was put"; else bad "the card's tree differs: $(cd "$T/out/all" 2>/dev/null && find . | tr '\n' ' ')"; fi
if "$STICK" --device "$CARD" put "$T/note" / > "$T/put.out" 2>&1; then
    bad "a write onto exFAT was taken"
elif grep -q 'exFAT is read here, not written' "$T/put.out"; then
    ok "a write is refused, as exFAT is read here alone"
else
    bad "put said: $(tr '\n' ' ' < "$T/put.out")"
fi
[[ "$(sha256sum "$CARD" | cut -d' ' -f1)" == "$before" ]] && ok "nothing on the card changed" || bad "the card changed under the reader"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
