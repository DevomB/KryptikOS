#!/usr/bin/env bash
# Test firstboot.sh's done-check (from the account database, so an interrupted
# setup finishes at the next boot) on staged passwd and shadow files, and its
# time-limited console questions.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/build/service-scripts/firstboot.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed -n '/^regular_user() /p; /^has_password() /p; /^complete() /p' "$SRC" \
    | sed "s|/etc/passwd|$T/passwd|; s|/etc/shadow|$T/shadow|" > "$T/fns.sh"
[[ "$(grep -c '' "$T/fns.sh")" -eq 3 ]] || { echo "could not extract the three predicates from $SRC"; exit 1; }
# shellcheck source=/dev/null
. "$T/fns.sh"

state() {   # state "PASSWD LINES" "SHADOW LINES"
    printf '%s\n' "root:x:0:0::/root:/bin/bash" "nobody:x:65534:65534::/:/bin/false" $1 > "$T/passwd"
    printf '%s\n' $2 > "$T/shadow"
}
HASH='$6$salt$abcdefghijklmnopqrstuvwxyz'
is()  { if complete; then ok "$1"; else bad "$1"; fi; }
not() { if complete; then bad "$1"; else ok "$1"; fi; }

state "" "root:!:1::::::"
not "a fresh install is not done"
state "ana:x:1000:1000::/home/ana:/bin/bash" "root:!:1:::::: ana:!:1::::::"
not "a user made a moment before the power went (no password yet) is not done"
[[ "$(regular_user)" == ana ]] && ok "and the next boot finds that user instead of asking for a name" || bad "regular_user: '$(regular_user)'"
state "ana:x:1000:1000::/home/ana:/bin/bash" "root:!:1:::::: ana:${HASH}:1::::::"
not "a user who can log in, with root still locked, is not done: nobody could administer it"
state "ana:x:1000:1000::/home/ana:/bin/bash" "root:${HASH}:1:::::: ana:!${HASH}:1::::::"
not "a locked hash is not a password"
state "ana:x:1000:1000::/home/ana:/bin/bash" "root:${HASH}:1:::::: ana:${HASH}:1::::::"
is "a user and root who can both authenticate: done"
state "svc:x:999:999::/:/bin/false" "root:${HASH}:1:::::: svc:${HASH}:1::::::"
not "a system account is not the desktop user"

# Every console question has a time limit: the service holds up the login
# prompt and boot-success, so an unanswered one would hang a headless boot.
unbounded="$(grep -nE '<[[:space:]]*"\$tty"' "$SRC" | grep -vE 'read -r (-s )?-t "\$PROMPT_SECS"')"
[[ -z "$unbounded" ]] && ok "every question on the console has a time limit" || bad "a question on the console waits forever: ${unbounded}"

# set_password, with a FIFO for tty1 (each question opens it again, as the
# script does the terminal) and chpasswd recording what it was given.
sed -n '/^set_password() /,/^}/p' "$SRC" | sed "s|> \"\$tty\"|>> \"$T/screen\"|" > "$T/setpw.sh"
# shellcheck source=/dev/null
. "$T/setpw.sh"
declare -F set_password >/dev/null || { echo "no set_password in $SRC"; exit 1; }
chpasswd() { cat > "$T/chpasswd.in"; }
# shellcheck disable=SC2034  # read by set_password
PROMPT_SECS=1; tty="$T/tty"; mkfifo "$tty"; exec 7<>"$tty"
answer() { rm -f "$T/chpasswd.in"; printf '%b' "$1" >&7; set_password ana; RC=$?; GOT="$(cat "$T/chpasswd.in" 2>/dev/null)"; }
answer 'pw one\npw one\n'
[[ "$RC|$GOT" == "0|ana:pw one" ]] && ok "two matching answers set the password through chpasswd" || bad "matching answers: rc=$RC chpasswd got '$GOT'"
answer 'a\nb\nc\nc\n'
[[ "$RC|$GOT" == "0|ana:c" ]] && ok "answers that differ are asked for again" || bad "differing answers: rc=$RC chpasswd got '$GOT'"
answer '\n\n\n\n\n\n'
[[ "$RC|$GOT" == "1|" ]] && ok "three empty answers set nothing" || bad "empty answers: rc=$RC chpasswd got '$GOT'"
start=$SECONDS; answer ''
[[ "$RC|$GOT" == "1|" && $((SECONDS - start)) -le 3 ]] && ok "no answer: the question gives up at its time limit" || bad "no answer: rc=$RC after $((SECONDS - start)) s"
exec 7<&-

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
