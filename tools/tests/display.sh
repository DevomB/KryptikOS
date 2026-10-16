#!/usr/bin/env bash
# `kryptik display` against a stand-in kryptik-display: what the user's file keeps after each
# choice, what it refuses, and that the choice is then made (kryptik-display apply).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLI="$ROOT/tools/kryptik"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
[[ -f "$CLI" ]] || { echo "missing: $CLI"; exit 1; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/config"
cat > "$T/bin/kryptik-display" <<'EOF'
#!/bin/sh
printf '%s\n' "${1:-list}" >> "$DISPLAY_TEST/called"
EOF
chmod +x "$T/bin/kryptik-display"
export DISPLAY_TEST="$T" XDG_CONFIG_HOME="$T/config" WAYLAND_DISPLAY=wayland-0 KRYPTIK_CONF=/nonexistent
export PATH="$T/bin:$PATH"
FILE="$T/config/kryptik/display"
run() { rm -f "$T/called"; bash "$CLI" display "$@" > "$T/out" 2>&1; }
called() { cat "$T/called" 2>/dev/null; }
lines() { cat "$FILE" 2>/dev/null; }

echo "-- listing"
if run && [[ "$(called)" == list ]]; then ok "display alone lists the monitors"; else bad "display alone: $(called) $(cat "$T/out")"; fi

echo "-- choices kept"
run eDP-1 1.5
[[ "$(lines)" == "eDP-1 1.5" && "$(called)" == apply ]] && ok "a scale is kept and made" || bad "eDP-1 1.5 left '$(lines)', called '$(called)'"
run HDMI-A-1 1 2560 0
[[ "$(lines)" == $'eDP-1 1.5\nHDMI-A-1 1 2560 0' ]] && ok "a second monitor's scale and place join it" || bad "HDMI-A-1 left '$(lines)'"
run eDP-1 2
[[ "$(lines)" == $'HDMI-A-1 1 2560 0\neDP-1 2' ]] && ok "a monitor chosen again keeps one line" || bad "eDP-1 2 left '$(lines)'"
printf '# mine\nDP-3 1.25\n' >> "$FILE"
run '*' 1
[[ "$(lines)" == $'HDMI-A-1 1 2560 0\neDP-1 2\n# mine\nDP-3 1.25\n* 1' ]] && ok "lines the user wrote stay, and * is a name" || bad "* 1 left '$(lines)'"
run eDP-1 auto
[[ "$(lines)" == $'HDMI-A-1 1 2560 0\n# mine\nDP-3 1.25\n* 1' && "$(called)" == apply ]] && ok "auto drops the monitor's line and makes the default" || bad "eDP-1 auto left '$(lines)', called '$(called)'"

echo "-- refusals"
before="$(lines)"
# Split into words without globbing: * is a monitor's name here.
set -f
for args in "eDP-1 0.4" "eDP-1 5" "eDP-1 4.5" "eDP-1 abc" "eDP-1 1.2345" "eDP-1 -1" \
            "a/b 1" "../x 1" "-x 1" "eDP-1" "eDP-1 1 10" "eDP-1 1 a b" "eDP-1 1 1.5 0" \
            "* 1 0 0" "eDP-1 auto 0 0"; do
    # shellcheck disable=SC2086
    if run $args; then bad "'${args}' was taken"; elif [[ -n "$(called)" || "$(lines)" != "$before" ]]; then bad "'${args}' changed the file or made a choice"; else ok "'${args}' is refused"; fi
done
set +f
if run 'eDP 1' 1; then bad "a name with a space was taken"; else ok "a name with a space is refused"; fi
if WAYLAND_DISPLAY='' bash "$CLI" display eDP-1 2 > "$T/out" 2>&1; then bad "a choice outside the session was taken"; else ok "outside the session it says to run it there"; fi
[[ "$(lines)" == "$before" ]] && ok "no refusal touched the file" || bad "the file is now '$(lines)'"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
