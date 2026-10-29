#!/usr/bin/env bash
# A console= port the machine lacks, as a laptop's legacy ttyS0, fails every termios call and
# every write. The early console's wrapper must then sleep rather than start agetty there, and
# rc.shutdown, under -e, must move its output to tty0 and still bring everything down. Both
# scripts are taken out of their recipes and run with their paths under a scratch directory,
# stand-ins for stty, agetty and sleep, and /dev/full as the console that takes no write. Offline.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

[[ -w /dev/full ]] || { echo "SKIPPED, not a pass: no /dev/full to stand in for a console that takes no write"; exit 77; }

# A heredoc's body: the lines after the one holding OPEN, up to the next line that is EOF alone.
body() { awk -v open="$2" 'f && $0 == "EOF" { exit } f { print } index($0, open) { f = 1 }' "$1"; }
body "$ROOT/build/recipes/console.sh" "cat > /usr/libexec/kryptik-console <<'EOF'" > "$T/console.orig"
body "$ROOT/build/recipes/init.sh" "cat > \"\$skel/rc.shutdown\" <<'EOF'" > "$T/shutdown.orig"
[[ -s "$T/console.orig" ]] && green "the console wrapper is in console.sh" || red "no console wrapper in console.sh"
[[ -s "$T/shutdown.orig" ]] && green "rc.shutdown is in init.sh" || red "no rc.shutdown in init.sh"

mkdir -p "$T/bin" "$T/run" "$T/dev"
for held in sysinit firstboot; do echo "done" > "$T/run/kryptik-$held"; done
: > "$T/dev/ttyS0"; : > "$T/dev/tty0"; : > "$T/dev/console"
echo 'ro rootwait kryptik.slot=a' > "$T/cmdline"
cat > "$T/bin/stty" <<'S'
#!/bin/sh
exit "${STTY_RC:-0}"
S
cat > "$T/bin/sleep" <<'S'
#!/bin/sh
[ "$1" = infinity ] && echo "sleep infinity" >> "$RAN"
exit 0
S
cat > "$T/bin/agetty" <<'S'
#!/bin/sh
echo "agetty $*" >> "$RAN"
S
chmod +x "$T"/bin/*

echo "-- the early console's wrapper"
sed -e "s|/run/kryptik-|$T/run/kryptik-|g" \
    -e "s|/sys/class/tty/console/active|$T/active|g" \
    -e "s|\"/dev/\$dev\"|\"$T/dev/\$dev\"|g" \
    -e "s|/usr/sbin/agetty|$T/bin/agetty|g" \
    -e "s|/proc/cmdline|$T/cmdline|g" \
    -e "s|/usr/libexec/kryptik/medium-banner.sh|$T/bin/banner|g" \
    "$T/console.orig" > "$T/console"
started() {   # started ACTIVE STTY_RC: what the wrapper went on to run
    echo "$1" > "$T/active"; : > "$T/ran"
    RAN="$T/ran" STTY_RC="$2" PATH="$T/bin:$PATH" sh "$T/console" < /dev/null > /dev/null 2>&1
    cat "$T/ran"
}
got="$(started 'tty0 ttyS0' 1)"
[[ "$got" == "sleep infinity" ]] && green "a console port that answers no termios call gets no getty" \
    || red "a dead console port: ${got:-nothing ran}"
got="$(started 'tty0 ttyS0' 0)"
[[ "$got" == agetty*" ttyS0 vt220" ]] && green "a console port that answers gets its getty" \
    || red "a live console port: ${got:-nothing ran}"
got="$(started 'tty0' 0)"
[[ "$got" == "sleep infinity" ]] && green "a virtual terminal is left to getty-tty1" \
    || red "a virtual terminal: ${got:-nothing ran}"
grep -q 's6-pause' "$T/console.orig" && red "the wrapper runs s6-pause, which the image does not carry" \
    || green "the wrapper runs no s6-pause"

echo "-- rc.shutdown"
run_shutdown() {   # run_shutdown CONSOLE STTY_RC: rc.shutdown under -e, its console CONSOLE; its status
    sed -e "s|/dev/console|$1|g" -e "s|/dev/tty0|$T/tty0|g" "$T/shutdown.orig" > "$T/shutdown"
    : > "$T/tty0"
    STTY_RC="$2" PATH="$T/bin:$PATH" sh -e "$T/shutdown" < /dev/null > /dev/null 2>&1
}
run_shutdown /dev/full 1; rc=$?
if [[ "$rc" -eq 0 ]] && grep -q 'handing back to shutdownd' "$T/tty0"; then
    green "a console that takes no write: the output goes to tty0 and the script runs to its end"
else
    red "a console that takes no write: exit ${rc}, tty0 got: $(tr '\n' '|' < "$T/tty0")"
fi
: > "$T/live"
run_shutdown "$T/live" 0; rc=$?
if [[ "$rc" -eq 0 ]] && grep -q 'handing back to shutdownd' "$T/live" && [[ ! -s "$T/tty0" ]]; then
    green "a console that answers keeps the output"
else
    red "a console that answers: exit ${rc}, console got $(wc -l < "$T/live") lines, tty0 $(wc -l < "$T/tty0")"
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
