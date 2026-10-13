#!/usr/bin/env bash
# Test the chrome's update window (run_update in tools/desktop/kryptik-chrome): each choice
# reaches the launch daemon by the verb `kryptik update` uses, installing only after a y,
# and Enter or the end of input goes back.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHROME="$ROOT/tools/desktop/kryptik-chrome"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); [[ $# -gt 1 ]] && printf '        %s\n' "$2"; }
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -n '/^run_update() {/,/^}/p' "$CHROME" > "$T/fn.sh"
grep -q '^run_update() {' "$T/fn.sh" || { echo "could not extract run_update from $CHROME"; exit 1; }
# A launch daemon that records each request, and refuses to apply when REFUSE is set.
cat > "$T/launch" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
if [ "$*" = "--update apply" ] && [ -n "${REFUSE:-}" ]; then
    echo "error: no release has been asked for" >&2
    exit 1
fi
EOF
chmod +x "$T/launch"
# drive INPUT: run_update under sh, as the chrome runs, with INPUT as what is typed; prints
# the requests other than the status each pass shows.
drive() {
    : > "$T/calls"
    printf '%b' "$1" | CALLS="$T/calls" LAUNCH="$T/launch" \
        sh -c 'sleep() { :; }; clear() { :; }; . "$1"; run_update' sh "$T/fn.sh" > "$T/out" 2>&1
    grep -vx -- '--update status' "$T/calls" | tr '\n' '|'
}

same "f fetches, then Enter goes back" "$(drive 'f\n\n')" "--update fetch|"
same "each pass shows the status first" "$(grep -cx -- '--update status' "$T/calls")" "2"
same "x forgets the release asked for" "$(drive 'x\n\n')" "--update forget|"
same "a and m turn automatic fetching on and off" "$(drive 'a\nm\n\n')" "--update auto on|--update auto off|"
same "i installs after a y" "$(drive 'i\ny\n\n\n')" "--update apply|"
grep -q 'To try it, reboot' "$T/out" && ok "and says how to try it" || bad "no reboot hint after an install" "$(tr '\n' '|' < "$T/out")"
same "i with anything but y installs nothing" "$(drive 'i\n\n\ni\nyes\n\n')" ""
same "the end of input goes back, installing nothing" "$(drive 'i\n')" ""
same "a refused install is asked for once" "$(REFUSE=1 drive 'i\ny\n\n\n')" "--update apply|"
grep -q 'no release has been asked for' "$T/out" && ! grep -q 'To try it' "$T/out" \
    && ok "and its refusal is shown, with no reboot hint" || bad "a refused install" "$(tr '\n' '|' < "$T/out")"
same "anything else asks nothing of the daemon" "$(drive 'z\n\n')" ""

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
