#!/usr/bin/env bash
# kryptik-update and the ESP: a subcommand unmounts only a mount it made, and
# status leaves the ESP alone while an apply holds the lock. Every subcommand
# exits through one trap, and the checks the broker runs for each piece of an
# update unmounted the ESP from under an apply writing to it.
#
# The functions come from the tool itself, pointed at a scratch mountpoint,
# with mount stand-ins that keep a record. flock is the real one.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/update/kryptik-update"
command -v flock >/dev/null 2>&1 || { echo "flock not found; cannot run"; exit 77; }
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/esp/kryptik" "$T/boot"
echo b > "$T/esp/kryptik/committed-slot"
{
    echo 'set -eu'
    echo 'die() { echo "FAILED: $*" >&2; exit 1; }'
    echo 'esp_dev() { echo /dev/fake-esp; }'
    echo "mountpoint() { [ -e '$T/mounted' ]; }"
    echo "mount() { : > '$T/mounted'; echo mount >> '$T/calls'; }"
    echo "umount() { rm -f '$T/mounted'; echo umount >> '$T/calls'; }"
    echo 'sync() { :; }'
    echo 'running_slot() { echo a; }; running_version() { echo 1.0; }; kryptik-efiboot() { :; }'
    echo "ESP_MNT='$T/esp'; LOCK='$T/lock'; B='$T/boot'"
    sed -n '/^mount_esp() {/,/^}/p; /^umount_esp() {/,/^}/p; /^ESP_MINE=/p; /^trap .*umount_esp/p; /^cmd_status() {/,/^}/p' "$TOOL"
} > "$T/esp.sh"
for f in mount_esp umount_esp cmd_status; do
    grep -q "^$f() {" "$T/esp.sh" || { echo "could not extract $f from $TOOL"; exit 1; }
done
calls() { [[ ! -e "$T/calls" ]] || tr '\n' ' ' < "$T/calls"; }
fresh() { rm -f "$T/calls" "$T/mounted"; [[ "${1:-}" != mounted ]] || : > "$T/mounted"; }

fresh mounted; bash -c "source '$T/esp.sh'; true"
[[ -e "$T/mounted" && -z "$(calls)" ]] && ok "a subcommand that mounted nothing leaves another's mount alone" || bad "another's mount was taken: $(calls)"
fresh mounted; bash -c "source '$T/esp.sh'; mount_esp; umount_esp"
[[ -e "$T/mounted" && -z "$(calls)" ]] && ok "one that found the ESP mounted and used it leaves it mounted" || bad "found mounted, then unmounted: $(calls)"
fresh; bash -c "source '$T/esp.sh'; mount_esp; exit 3"
[[ ! -e "$T/mounted" && "$(calls)" == "mount umount " ]] && ok "its own mount is undone at exit, once" || bad "its own mount: $(calls)"

fresh; out="$(bash -c "source '$T/esp.sh'; cmd_status" 2>&1)"
[[ "$out" == *"committed slot:   b"* && "$(calls)" == "mount umount " ]] && ok "status reads the ESP when no update holds the lock" || bad "status alone: $(calls) / $out"
fresh; flock -x "$T/lock" sleep 3 & holder=$!
sleep 0.5
out="$(bash -c "source '$T/esp.sh'; cmd_status" 2>&1)"
wait "$holder"
[[ "$out" == *"being applied"* && -z "$(calls)" ]] && ok "status leaves the ESP alone while an apply holds the lock" || bad "status under an apply: $(calls) / $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
