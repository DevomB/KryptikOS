#!/usr/bin/env bash
# kryptik-update and the ESP: a subcommand unmounts only a mount it made,
# status leaves the ESP alone while an apply holds the lock, and a slot being
# written is named by nothing there, so rollback refuses it. The functions
# come from the tool itself, pointed at a scratch mountpoint, with mount
# stand-ins that keep a record; flock is the real one.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
    echo "ESP_MNT='$T/esp'; LOCK='$T/lock'; B='$T/boot'; DEGRADED='$T/degraded'"
    sed -n '/^mount_esp() {/,/^}/p; /^umount_esp() {/,/^}/p; /^ESP_MINE=/p; /^trap .*umount_esp/p; /^cmd_status() {/,/^}/p;
            /^other_slot() /p; /^unlist_slot() {/,/^}/p; /^cmd_rollback() {/,/^}/p' "$TOOL"
} > "$T/esp.sh"
for f in mount_esp umount_esp cmd_status other_slot unlist_slot cmd_rollback; do
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

echo "-- an apply cut short while it writes a slot"
mkdir -p "$T/esp/EFI/kryptik"
for s in a b; do printf 'kernel-%s' "$s" > "$T/esp/EFI/kryptik/kryptik-$s.efi"; echo "1.$s" > "$T/esp/kryptik/version-$s"; done
fresh; bash -c "source '$T/esp.sh'; unlist_slot b"
[[ ! -e "$T/esp/EFI/kryptik/kryptik-b.efi" && ! -e "$T/esp/kryptik/version-b" && "$(calls)" == "mount umount " ]] \
    && ok "the slot about to be written loses its kernel and version on the ESP, which is unmounted after" \
    || bad "unlisting slot b: $(calls) / $(ls "$T/esp/EFI/kryptik" "$T/esp/kryptik")"
[[ -e "$T/esp/EFI/kryptik/kryptik-a.efi" && "$(cat "$T/esp/kryptik/version-a")" == 1.a ]] \
    && ok "the running slot's are left alone" || bad "the running slot's kernel or version went"
fresh; out="$(bash -c "source '$T/esp.sh'; cmd_rollback" 2>&1)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"slot b has no kernel on the ESP"* ]] \
    && ok "rollback refuses a slot whose write never finished" || bad "rollback: rc=$rc / $out"
body="$(sed -n '/^cmd_apply() {/,/^}/p' "$TOOL")"
u="$(grep -n 'unlist_slot "$target"' <<< "$body" | head -1 | cut -d: -f1)"
w="$(grep -n 'dd if=/proc/self/fd/3 of=' <<< "$body" | head -1 | cut -d: -f1)"
[[ -n "$u" && -n "$w" && "$u" -lt "$w" ]] \
    && ok "apply takes the slot off the ESP before it writes a byte of it" \
    || bad "apply: the slot is taken off the ESP at line '${u}', written at line '${w}'"
# The manifest kept for the clock's floor goes with the slot, and comes back
# only once the slot has verified, before the trial is armed.
f="$(grep -n 'rm -rf "$B/release-$target"' <<< "$body" | head -1 | cut -d: -f1)"
v="$(grep -n 'say "slot $target verifies after write"' <<< "$body" | head -1 | cut -d: -f1)"
k="$(grep -n 'cp "$m" "$sig" "$B/release-$target/"' <<< "$body" | head -1 | cut -d: -f1)"
a="$(grep -n 'arm_trial "$target"' <<< "$body" | head -1 | cut -d: -f1)"
[[ -n "$f" && -n "$v" && -n "$k" && -n "$a" && "$f" -lt "$w" && "$v" -lt "$k" && "$k" -lt "$a" ]] \
    && ok "apply forgets the slot's kept manifest before writing it, and keeps the new one after it verifies" \
    || bad "apply: kept manifest removed at line '${f}', slot written at '${w}', verified at '${v}', kept at '${k}', armed at '${a}'"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
