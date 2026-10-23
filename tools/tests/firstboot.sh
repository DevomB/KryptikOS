#!/usr/bin/env bash
# Test firstboot.sh's done-check (from the account database, so an interrupted
# setup finishes at the next boot) on staged passwd and shadow files, and its
# time-limited console questions.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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

# A preseeded password the screen lock could not check would leave the user a lock that
# never opens: only SHA-512 and SHA-256 crypt are set.
sed -n '/^lockable_hash() /p' "$SRC" > "$T/lockable.sh"
# shellcheck source=/dev/null
. "$T/lockable.sh"
declare -F lockable_hash >/dev/null || { echo "no lockable_hash in $SRC"; exit 1; }
for h in "$HASH" '$5$salt$abcdefghijklmnopqrstuvwxyz'; do
    lockable_hash "$h" && ok "a preseeded ${h:0:3} hash is set" || bad "a preseeded ${h:0:3} hash is refused"
done
for h in '$y$j9T$salt$hash' '$2b$10$abcdefghijklmnopqrstuv' '$1$salt$hash' 'abJnggxhB/yWI' ''; do
    lockable_hash "$h" && bad "a preseeded '${h:0:3}' hash is set, which the lock cannot check" || ok "a preseeded '${h:0:3}' hash is refused"
done
grep -q 'if lockable_hash "$hash"; then' "$SRC" && ok "the preseed's user hash goes through it" || bad "the preseed sets the user's hash without lockable_hash"

# Every question has a time limit: the service holds up the login prompt and
# boot-success, so an unanswered one would hang a headless boot.
unbounded="$(grep -nE '\$\(ask ' "$SRC" | grep -vE '\$\(ask (-s )?"\$PROMPT_SECS" ')"
[[ -z "$unbounded" ]] && ok "every question has a time limit" || bad "a question waits forever: ${unbounded}"
grep -qx 'PROMPT_SECS=600' "$SRC" && ok "which is ten minutes, as the user guide says" || bad "the time limit is not 600 s: $(grep '^PROMPT_SECS=' "$SRC")"

# set_password, with chpasswd recording what it was given, and ask and tell
# (ask.sh, which test-ask.py covers) reduced to a FIFO of answers and a file
# for the screen.
sed -n '/^set_password() /,/^}/p' "$SRC" > "$T/setpw.sh"
# shellcheck source=/dev/null
. "$T/setpw.sh"
declare -F set_password >/dev/null || { echo "no set_password in $SRC"; exit 1; }
chpasswd() { cat > "$T/chpasswd.in"; }
tell() { printf '%s\n' "$@" >> "$T/screen"; }
ask() {
    [[ "$1" == -s ]] && shift
    local line
    printf '%s' "$2" >> "$T/screen"
    IFS= read -r -t "$1" line <&7 || return 1
    printf '%s' "$line"
}
# shellcheck disable=SC2034  # read by set_password
PROMPT_SECS=1; mkfifo "$T/answers"; exec 7<>"$T/answers"
answer() { rm -f "$T/chpasswd.in"; printf '%b' "$1" >&7; set_password ana; RC=$?; GOT="$(cat "$T/chpasswd.in" 2>/dev/null)"; }
answer 'pw one\npw one\n'
[[ "$RC|$GOT" == "0|ana:pw one" ]] && ok "two matching answers set the password through chpasswd" || bad "matching answers: rc=$RC chpasswd got '$GOT'"
answer 'a\nb\nc\nc\n'
[[ "$RC|$GOT" == "0|ana:c" ]] && ok "answers that differ are asked for again" || bad "differing answers: rc=$RC chpasswd got '$GOT'"
answer '\n\n\n\n\n\n'
[[ "$RC|$GOT" == "1|" ]] && ok "three empty answers set nothing" || bad "empty answers: rc=$RC chpasswd got '$GOT'"
start=$SECONDS; answer ''
[[ "$RC|$GOT" == "1|" && $((SECONDS - start)) -le 3 ]] && ok "no answer: the question gives up at its time limit" || bad "no answer: rc=$RC after $((SECONDS - start)) s"

# new_user, with useradd recording the name it was given.
sed -n '/^create_user() /,/^}/p; /^new_user() /,/^}/p' "$SRC" > "$T/newuser.sh"
# shellcheck source=/dev/null
. "$T/newuser.sh"
declare -F create_user >/dev/null || { echo "no create_user in $SRC"; exit 1; }
declare -F new_user >/dev/null || { echo "no new_user in $SRC"; exit 1; }
say() { echo "kryptik-firstboot: $*"; }
getent() { return 0; }
useradd() { printf '%s' "${@: -1}" > "$T/useradd.in"; printf '%s\n' "$@" > "$T/useradd.args"; }
names() { rm -f "$T/useradd.in"; : > "$T/screen"; name=""; printf '%b' "$1" >&7; new_user; RC=$?; GOT="$(cat "$T/useradd.in" 2>/dev/null)"; }
names 'ana\n'
[[ "$RC|$GOT|$name" == "0|ana|ana" ]] && ok "a name of lower-case letters makes the user" || bad "a plain name: rc=$RC useradd got '$GOT', name '$name'"
grep -qx 'kryptik,wheel' "$T/useradd.args" && ok "the user is in kryptik and wheel, not seat, which is dwl's" \
    || bad "useradd's arguments: $(tr '\n' ' ' < "$T/useradd.args")"
names 'Ana\nana\n'
[[ "$RC|$GOT" == "0|ana" ]] && grep -qF "refusing user name 'Ana': lower-case" "$T/screen" \
    && ok "a refused name is told why and asked for again" || bad "a refused name: rc=$RC useradd got '$GOT', screen: $(tr '\n' '|' < "$T/screen")"
names 'A\n-b\n\n'
[[ "$RC|$GOT" == "1|" ]] && ok "three refused names make no user" || bad "three refused names: rc=$RC useradd got '$GOT'"
start=$SECONDS; names ''
[[ "$RC|$GOT" == "1|" && $((SECONDS - start)) -le 3 ]] && ok "no name: the question gives up at its time limit" || bad "no name: rc=$RC after $((SECONDS - start)) s"
exec 7<&-

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
