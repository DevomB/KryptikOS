#!/usr/bin/env bash
# Test what the chrome's watcher reads each second without a fork (dm_suspended, waiting_zones,
# power_now and camera_now in tools/desktop/kryptik-chrome) against stand-in files: a suspended
# mapping by its name and not another's, the zones waiting on their volume's key, a field of the
# power service's state, and the zone the camera's grant names, each empty when its file is not
# there. Under each POSIX shell here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHROME="$ROOT/tools/desktop/kryptik-chrome"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1: got '$(tr '\n' '|' <<<"$2")', want '$(tr '\n' '|' <<<"$3")'"; fi; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -n '/^dm_suspended() {/,/^}/p; /^waiting_zones() {/,/^}/p; /^power_now() {/,/^}/p; /^camera_now() {/,/^}/p' "$CHROME" > "$T/fn.sh"
for fn in dm_suspended waiting_zones power_now camera_now; do
    grep -q "^${fn}() {" "$T/fn.sh" || { echo "could not extract ${fn} from $CHROME"; exit 1; }
done

mapping() {   # mapping N NAME SUSPENDED: a device-mapper device in the stand-in block directory
    mkdir -p "$T/block/dm-$1/dm"
    printf '%s\n' "$2" > "$T/block/dm-$1/dm/name"
    printf '%s\n' "$3" > "$T/block/dm-$1/dm/suspended"
}
mapping 0 kryptik-root-a 0
mapping 1 kryptik-state 1
mapping 2 kryptik-zone-work 1
mapping 3 kryptik-zone-personal 0
printf 'source=battery\ncharge=42\nwarning=10\n' > "$T/power"
printf 'zone untrusted\nname vivid\n' > "$T/grant"

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    echo "-- ${sh}"
    run() {   # run SCRIPT: SCRIPT with the functions, the stand-ins named as the chrome names them
        "$sh" -c '. "$1"; SYS_BLOCK="$2" POWER="$3" CAMERA="$4"; eval "$5"' sh "$T/fn.sh" "$T/block" "$T/power" "$T/grant" "$1" 2>&1
    }
    same "a suspended mapping, by its name" "$(run 'dm_suspended kryptik-state && echo yes || echo no')" "yes"
    same "not one that runs" "$(run 'dm_suspended kryptik-root-a && echo yes || echo no')" "no"
    same "nor one that is not there" "$(run 'dm_suspended kryptik-none && echo yes || echo no')" "no"
    same "the zones waiting on their volume's key" "$(run 'waiting_zones')" "work"
    same "a field of the power service's state" "$(run 'power_now warning; echo "[$pf]"; power_now charge; echo "[$pf]"')" "[10]
[42]"
    same "and none for a field it does not hold" "$(run 'power_now nothing; echo "[$pf]"')" "[]"
    same "the zone the camera's grant names" "$(run 'camera_now; echo "[$cz]"')" "[untrusted]"
    same "with no files there, nothing and no error" \
        "$("$sh" -c '. "$1"; SYS_BLOCK="$2/none" POWER="$2/none" CAMERA="$2/none"
              dm_suspended kryptik-state || echo no; waiting_zones; power_now warning; camera_now; echo "[$pf][$cz]"' sh "$T/fn.sh" "$T" 2>&1)" "no
[][]"
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
