#!/usr/bin/env bash
# Tests for tools/delta-count.py: two small payloads whose blocks are known, the second also
# zstd'd as stage 06 may ship it, and payloads whose image is not what root.json says.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="${ROOT}/tools/delta-count.py"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# payload DIR VERSION TREE_BLOCKS CHAR...: one 4 KiB data block of each CHAR (0 for zeros), then the tree.
payload() {
    local d="$1" v="$2" tree="$3" c n=0; shift 3
    mkdir -p "$d"; : > "$d/kryptik-root.img"
    for c in "$@"; do
        if [[ "$c" == 0 ]]; then head -c 4096 /dev/zero; else head -c 4096 /dev/zero | tr '\0' "$c"; fi >> "$d/kryptik-root.img"
        n=$((n + 1))
    done
    head -c $((tree * 4096)) /dev/zero | tr '\0' t >> "$d/kryptik-root.img"
    printf '{\n  "version": "%s",\n  "data_blocks": %d,\n  "hash_start_block": %d,\n  "total_bytes": %d\n}\n' \
        "$v" "$n" "$n" "$(stat -c %s "$d/kryptik-root.img")" > "$d/root.json"
}
run() { python3 "$TOOL" "$@" > "$T/out" 2>&1; echo $?; }

payload "$T/a" 1.0.0 1 x y z 0
payload "$T/b" 1.0.1 2 y w 0 x v
rc="$(run "$T/a" "$T/b")"
if [[ "$rc" == 0 ]] && grep -qx "delta-count: of B's data blocks 3 are in A and 2 are not" "$T/out"; then
    green "y, x and the zeros are found in A wherever they lie, and w and v are not"
else
    red "the count of B's blocks" "rc ${rc}: $(tr '\n' '|' < "$T/out")"
fi
grep -q '^delta: .* MiB image from A' "$T/out" && grep -qF 'and a hash tree of 8192 bytes' "$T/out" \
    && green "the last line is the report's, and the tree is counted whole" \
    || red "the delta line or the tree" "$(tr '\n' '|' < "$T/out")"

if command -v zstd >/dev/null 2>&1; then
    zstd -q -19 "$T/b/kryptik-root.img" -o "$T/b/kryptik-root.img.zst" && rm "$T/b/kryptik-root.img"
    rc="$(run "$T/a" "$T/b")"
    if [[ "$rc" == 0 ]] && grep -qx "delta-count: of B's data blocks 3 are in A and 2 are not" "$T/out" \
        && grep -q 'its kryptik-root.img.zst is [0-9]* MiB$' "$T/out"; then
        green "a payload that ships the image zstd'd is read through zstd, and its size is named"
    else
        red "the zstd'd payload" "rc ${rc}: $(tr '\n' '|' < "$T/out")"
    fi
    printf 'not zstd' > "$T/b/kryptik-root.img.zst"
    rc="$(run "$T/a" "$T/b")"
    [[ "$rc" == 1 ]] && grep -q "^delta-count: " "$T/out" && green "a .zst zstd cannot unpack is refused" \
        || red "a damaged .zst" "rc ${rc}: $(tr '\n' '|' < "$T/out")"
else
    echo "  SKIP  no zstd: the zstd'd payload"
fi

# Images that are not what their root.json says.
payload "$T/short" 1.0.2 0 x y
sed -i -e 's/"data_blocks": 2/"data_blocks": 3/' -e 's/"total_bytes": 8192/"total_bytes": 12288/' "$T/short/root.json"
rc="$(run "$T/a" "$T/short")"
[[ "$rc" == 1 ]] && grep -qF "the image ends before root.json's 3 data blocks" "$T/out" \
    && green "an image shorter than its data blocks is refused" || red "a short image" "rc ${rc}: $(tr '\n' '|' < "$T/out")"
payload "$T/long" 1.0.3 1 x y
printf 'extra' >> "$T/long/kryptik-root.img"
rc="$(run "$T/long" "$T/b")"
[[ "$rc" == 1 ]] && grep -qF "and root.json says" "$T/out" \
    && green "an image longer than root.json's total is refused, A as well as B" || red "a long image" "rc ${rc}: $(tr '\n' '|' < "$T/out")"
mkdir -p "$T/none"; cp "$T/a/root.json" "$T/none/"
rc="$(run "$T/a" "$T/none")"
[[ "$rc" == 1 ]] && grep -qF "holds no kryptik-root.img" "$T/out" && green "a payload with no image is refused" \
    || red "no image" "rc ${rc}: $(tr '\n' '|' < "$T/out")"
rc="$(run "$T/a")"
[[ "$rc" == 2 ]] && green "one payload is a usage error" || red "usage" "rc ${rc}"

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
