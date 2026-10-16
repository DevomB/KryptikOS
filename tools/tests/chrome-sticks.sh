#!/usr/bin/env bash
# Test the chrome's USB stick window and the watcher's choice to open it (sticks_new, stick_zones
# and run_sticks in tools/desktop/kryptik-chrome) with a stand-in launcher: a stick is offered
# once while it stays in and again only after it was pulled out; the zones offered are neither
# the net zone nor one whose file refuses sticks; a letter and a number give that stick to that
# zone, to read unless w follows, e<N> takes it back, a stick no longer listed is no choice, and
# what the daemon names a stick is shown, never run. Under each POSIX shell here.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHROME="$ROOT/tools/desktop/kryptik-chrome"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1: got '$(tr '\n' '|' <<<"$2")', want '$(tr '\n' '|' <<<"$3")'"; fi; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
{
    sed -n '/^zone_field() {/,/^}/p' "$CHROME"
    sed -n '/^zone_is_nic() {/p' "$CHROME"
    sed -n '/^sticks_new() {/,/^}/p; /^stick_zones() {/,/^}/p; /^run_sticks() {/,/^}/p' "$CHROME"
} > "$T/fn.sh"
for fn in zone_field zone_is_nic sticks_new stick_zones run_sticks; do
    grep -q "^${fn}() {" "$T/fn.sh" || { echo "could not extract ${fn} from $CHROME"; exit 1; }
done

mkdir -p "$T/zones" "$T/block"
printf '[network]\nmode = "nic"\n' > "$T/zones/net.toml"
printf '[zone]\nlabel = "Untrusted"\nglyph = "U"\n' > "$T/zones/untrusted.toml"
printf '[zone]\nlabel = "Vault"\n[storage]\nmode = "encrypted"\nremovable = false\n' > "$T/zones/vault.toml"
printf '[zone]\nlabel = "Work"\nglyph = "W"\n' > "$T/zones/work.toml"
# The stand-in launcher writes every call down. --sticks prints the file sticks, which
# sticks.next replaces after it is printed once; untrusted holds a stick.
cat > "$T/launch" <<'EOF'
#!/bin/sh
d="$(dirname "$0")"
echo "$*" >> "$d/calls"
case "$1" in
    --sticks) cat "$d/sticks"; [ -f "$d/sticks.next" ] && mv "$d/sticks.next" "$d/sticks" ;;
    --info) if [ "$2" = untrusted ]; then echo 'stick ro QEMU HARDDISK, 0.1 GB, partition 1 (DATA)'; else echo 'stick none'; fi ;;
    --stick-grant) echo "$4 a stick" ;;
esac
exit 0
EOF
chmod +x "$T/launch"
DATA='sdb1 QEMU HARDDISK, 0.1 GB, partition 1 (DATA)'

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    echo "-- ${sh}"
    # One block device change: whether the watcher opens the window, and what it has seen after.
    offer() {
        "$sh" -c '. "$1"; LAUNCH="$2"; SYS_BLOCK="$3"; seen="$4"
                  if sticks_new; then echo "new|$seen"; else echo "old|$seen"; fi' sh "$T/fn.sh" "$T/launch" "$T/block" "$1"
    }
    rm -f "$T/block"/* "$T/sticks.next"; : > "$T/block/sda"; : > "$T/block/sda1"; : > "$T/sticks"
    same "no stick listed: no window" "$(offer "")" "old|"
    : > "$T/block/sdb"; : > "$T/block/sdb1"; echo "$DATA" > "$T/sticks"
    same "a stick plugged in opens the window" "$(offer "")" "new| sdb1"
    same "and not again while it stays in" "$(offer " sdb1")" "old| sdb1"
    : > "$T/sticks"
    same "given to a zone, it is held and listed no more, but still seen" "$(offer " sdb1")" "old| sdb1"
    echo "$DATA" > "$T/sticks"
    same "taken back, it opens no window" "$(offer " sdb1")" "old| sdb1"
    rm -f "$T/block/sdb" "$T/block/sdb1"; : > "$T/sticks"
    same "pulled out, it is forgotten" "$(offer " sdb1")" "old|"
    : > "$T/block/sdb"; : > "$T/block/sdb1"; echo "$DATA" > "$T/sticks"
    same "plugged back in, it opens the window again" "$(offer "")" "new| sdb1"

    # The window, with its pauses and screen clearing stood in for.
    window() {
        : > "$T/calls"
        printf '%b' "$1" | "$sh" -c '. "$1"; LAUNCH="$2"; ZONES="$3"; sleep() { :; }; clear() { :; }; run_sticks' \
            sh "$T/fn.sh" "$T/launch" "$T/zones" 2>&1
    }
    printf '%s\n%s\n' 'sdb1 QEMU HARDDISK, 0.1 GB, partition 1 (DATA $x `id`)' 'sdc SD32G, 31.3 GB' > "$T/sticks"
    out="$(window 'a2w\nb1\ne2\nz9\nc1\n\n')"
    same "a2w gives sdb1 to work to write, b1 sdc to untrusted to read, e2 takes work's back" \
        "$(grep -E '^--stick-(grant|eject)' "$T/calls")" "$(printf '%s\n' '--stick-grant work sdb1 rw' '--stick-grant untrusted sdc ro' '--stick-eject work')"
    same "the zones offered are untrusted and work alone" "$(grep -E '^  [0-9]\) ' <<<"$out" | head -2 | awk '{ print $1, $2 }')" "$(printf '1) untrusted\n2) work')"
    same "the zone holding a stick says which, and how to take it back" \
        "$(grep -c 'holds QEMU HARDDISK, 0.1 GB, partition 1 (DATA), to read (e1)' <<<"$out")" 6
    same "a stick's name is shown as the daemon said it, never run" \
        "$(grep -cF '  a) QEMU HARDDISK, 0.1 GB, partition 1 (DATA $x `id`)' <<<"$out")" 6
    same "an unknown choice and a stick not listed are refused" \
        "$(grep -o '?$\|no such stick or zone$' <<<"$out" | tr '\n' ' ')" "? no such stick or zone "
    # The list shrinks between two looks: a letter that was there is no choice after.
    printf '%s\n%s\n' "$DATA" 'sdc SD32G, 31.3 GB' > "$T/sticks"; echo "$DATA" > "$T/sticks.next"
    out="$(window 'x\nb1\n\n')"
    same "a stick gone from the list cannot be given" "$(grep -c '^--stick-grant' "$T/calls")" 0
    rm -f "$T/sticks.next"
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
