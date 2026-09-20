#!/usr/bin/env bash
# First-boot setup knows when it is done from the account database, so a setup
# cut short anywhere is finished by the next boot. The three predicates are
# taken from build/service-scripts/firstboot.sh itself and pointed at staged
# passwd and shadow files. No root.
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

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
