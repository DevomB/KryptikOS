#!/usr/bin/env bash
# Test the chrome's camera gestures (run_menu, menu_camera, camera_zone and run_camera in
# tools/desktop/kryptik-chrome) with a stand-in launcher: k and a zone's number grant that zone
# the camera, k alone takes it back, the menu's Camera line names the zone holding it, or says
# no zone does and whether the driver stayed loaded, and the camera's window lasts as long as
# the grant. Under each POSIX shell here.
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
    sed -n '/^zone_is_nic() {/p; /^power_field() {/p' "$CHROME"
    for fn in zone_field camera_zone menu_zones menu_network menu_power menu_update menu_sound menu_camera run_camera run_menu; do
        sed -n "/^${fn}() {/,/^}/p" "$CHROME"
    done
} > "$T/fn.sh"
for fn in camera_zone menu_camera run_camera run_menu; do
    grep -q "^${fn}() {" "$T/fn.sh" || { echo "could not extract ${fn} from $CHROME"; exit 1; }
done

mkdir -p "$T/zones"
printf '[network]\nmode = "nic"\n' > "$T/zones/net.toml"
printf '[zone]\nlabel = "Personal"\nglyph = "P"\n' > "$T/zones/personal.toml"
printf '[zone]\nlabel = "Work"\nglyph = "W"\n' > "$T/zones/work.toml"
# The stand-in launcher writes every call down and answers the camera's as kryptikd would.
cat > "$T/launch" <<'EOF'
#!/bin/sh
echo "$*" >> "$(dirname "$0")/calls"
case "$1" in
    --info) printf 'encrypted no\nrunning no\n' ;;
    --camera-grant) echo "Integrated Camera" ;;
    --camera-revoke) echo "none" ;;
esac
exit 0
EOF
chmod +x "$T/launch"

for sh in sh bash dash; do
    command -v "$sh" >/dev/null 2>&1 || continue
    echo "-- ${sh}"
    # One run of the chrome's code with what it reads stood in for; sleep and clear do nothing.
    chrome() {
        : > "$T/calls"
        printf '%b' "$1" | "$sh" -c '. "$1"; LAUNCH="$2"; ZONES="$3"; CAMERA="$4/grant"; CAMERA_STAYED="$4/stayed"
                                    SOUND=false; POWER=/nonexistent; sleep() { :; }; clear() { :; }; '"$2" \
            sh "$T/fn.sh" "$T/launch" "$T/zones" "$T" 2>&1
    }
    rm -f "$T/grant" "$T/stayed"
    out="$(chrome 'k2\nk\nk9\nq\n' run_menu)"
    same "k2 grants the second zone the camera, k alone takes it back" \
        "$(grep '^--camera' "$T/calls")" "$(printf '%s\n' '--camera-grant work' '--camera-revoke')"
    same "k with a number no zone has is refused" "$(grep -c 'no zone 9$' <<<"$out")" 1
    same "with no grant the menu says no zone has the camera" "$(grep -m1 '^Camera: ' <<<"$out")" "Camera: no zone"
    printf 'zone work\nnode video0\nname Integrated Camera\n' > "$T/grant"
    same "the menu names the zone that holds it, and the camera" "$(chrome 'q\n' run_menu | grep '^Camera: ' | head -1)" \
        "Camera: zone work holds it (Integrated Camera)"
    same "camera_zone reads the zone from kryptikd's record" "$(chrome '' camera_zone)" "work"
    rm -f "$T/grant"; : > "$T/stayed"
    same "a driver that stayed loaded is said" "$(chrome 'q\n' run_menu | grep '^Camera: ' | head -1)" \
        "Camera: no zone; its driver stays loaded, still held by a program, until the next grant"
    rm -f "$T/stayed"
    # The window ends with the grant: the record goes after the window's first look.
    printf 'zone work\nnode video0\nname Integrated Camera\n' > "$T/grant"
    out="$(printf '' | "$sh" -c '. "$1"; ZONES="$2"; CAMERA="$3/grant"; CAMERA_STAYED="$3/stayed"
                                 n=0; sleep() { n=$((n + 1)); [ "$n" -lt 2 ] || rm -f "$CAMERA"; }; clear() { :; }
                                 run_camera work' sh "$T/fn.sh" "$T/zones" "$T" 2>&1)"
    same "the window names the zone and the camera" "$(grep -c '^Zone work W Work holds the camera, Integrated Camera,$' <<<"$out")" 1
    same "and closes once the grant ends" "$(tail -1 <<<"$out")" "The camera is no longer zone work's."
done

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
