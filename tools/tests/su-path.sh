#!/usr/bin/env bash
# What su gives root for PATH. s_shadow edits the PATH lines of shadow 4.16.0's login.defs, then
# s_etc's etc_login_defs sets its own lines: both run here on shadow's file as the build runs
# them, and ENV_SUPATH is read back as su reads it (su.c sets it with or without "-"). Offline.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=build/recipes/etc.sh
source "$ROOT/build/recipes/etc.sh"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf 'ENV_SUPATH\tPATH=/sbin:/bin:/usr/sbin:/usr/bin\nENV_PATH\tPATH=/bin:/usr/bin\n' > "$T/login.defs"

# s_shadow's own edit, as the recipe writes it.
edit="$(grep -o "/PATH=/{[^']*}" "$ROOT/build/recipes/shadow.sh")"
if [[ -n "$edit" ]] && sed -i -e "$edit" "$T/login.defs"; then
    green "s_shadow's PATH edit applies"
else
    red "no PATH edit found in build/recipes/shadow.sh"
fi

etc_login_defs "$T/login.defs"
etc_login_defs "$T/login.defs"
su_path="$(sed -n 's/^ENV_SUPATH[[:space:]]\{1,\}//p' "$T/login.defs")"
[[ "$su_path" == PATH=* && ":${su_path#PATH=}:" == *:/usr/sbin:* && ":${su_path#PATH=}:" == *:/usr/bin:* ]] \
    && green "su gives root ${su_path}" || red "su gives root ${su_path:-no PATH}, without /usr/sbin or /usr/bin"
[[ "$(grep -c '^ENV_SUPATH[[:space:]]' "$T/login.defs")" -eq 1 ]] \
    && green "one ENV_SUPATH line, run twice" || red "ENV_SUPATH lines: $(grep -c '^ENV_SUPATH' "$T/login.defs")"
grep -qx 'CONSOLE /etc/securetty' "$T/login.defs" && grep -qx 'SU_WHEEL_ONLY yes' "$T/login.defs" \
    && green "root stays off the terminals, and su is wheel's" || red "CONSOLE or SU_WHEEL_ONLY is not set"
grep -q "$(printf '^ENV_PATH\tPATH=/bin:/usr/bin$')" "$T/login.defs" \
    && green "other users' su PATH is shadow's" || red "ENV_PATH changed: $(grep '^ENV_PATH' "$T/login.defs")"

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
