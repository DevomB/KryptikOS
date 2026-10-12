#!/usr/bin/env bash
# Tests for tools/check-firmware-requested.sh on a fixture root.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/tools/check-firmware-requested.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
command -v gcc > /dev/null && command -v zstd > /dev/null || { echo "gcc and zstd make the fixture modules"; exit 77; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/root"; A="$T/accepted.txt"; K="$R/usr/lib/modules/6.18.0/kernel"
mkdir -p "$K" "$R/usr/lib/firmware/dir" "$R/usr/share/licenses/linux-firmware"
n=0
# A module whose .modinfo names firmware, as MODULE_FIRMWARE writes it.
module() {   # module NAME FIRMWARE...
    local f
    : > "$T/$1.c"
    for f in "${@:2}"; do
        n=$((n + 1))
        printf 'static const char fw%d[] __attribute__((section(".modinfo"), used)) = "firmware=%s";\n' "$n" "$f" >> "$T/$1.c"
    done
    gcc -c -o "$K/$1.ko" "$T/$1.c"
}
printf 'File: a.bin\nFile: b.bin\nRawFile: dir/x.bin\nFile: dir/y.bin\nLink: l.bin -> a.bin\n' \
    > "$R/usr/share/licenses/linux-firmware/WHENCE"
touch "$R/usr/lib/firmware/a.bin.zst" "$R/usr/lib/firmware/dir/x.bin.zst"
ln -s a.bin.zst "$R/usr/lib/firmware/l.bin.zst"
module wifi a.bin 'dir/*' c99.ucode l.bin
zstd -q --rm "$K/wifi.ko"
module eth b.bin
check() { NO_COLOR=1 bash "$CHECK" "$R" --accepted "$A" 2>&1; }

printf 'b.bin       # optional\ndir/y.bin   # an older version\n' > "$A"
out="$(check)"; rc=$?
[[ "$rc" -eq 0 && "$out" == *"2 modules name 5 files linux-firmware has: 3 shipped, 2 accepted"* ]] \
    && ok "shipped, accepted, globbed and compressed modules pass; a name linux-firmware lacks is not counted" \
    || bad "passing root: rc=$rc: $out"

printf 'dir/y.bin   # an older version\n' > "$A"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"NOT SHIPPED  b.bin  (eth)"* ]] \
    && ok "a named file linux-firmware has and the image lacks fails, with its module" || bad "missing file: rc=$rc: $out"

printf 'b.bin       # optional\ndir/*       # older versions\n' > "$A"
out="$(check)"; rc=$?
[[ "$rc" -eq 0 ]] && ok "an accepted glob covers what it matches" || bad "accepted glob: rc=$rc: $out"

printf 'b.bin       # optional\ndir/y.bin   # an older version\nz.bin       # gone\n' > "$A"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"ACCEPTS NOTHING  line 3: z.bin"* ]] \
    && ok "an accepted entry matching nothing fails, with its line" || bad "stale entry: rc=$rc: $out"

printf 'b.bin\ndir/y.bin   # an older version\n' > "$A"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"no reason after #"* ]] && ok "an entry without a reason is refused" || bad "no reason: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
