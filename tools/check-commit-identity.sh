#!/usr/bin/env bash
# Check that commits are authored and committed by the one permitted identity.
# This is the only place it is written; both hooks and CI run this script.
#
#   tools/check-commit-identity.sh --pending      what the next commit would record
#   tools/check-commit-identity.sh <rev-range>    every commit in the range
#   tools/check-commit-identity.sh                every commit on every ref
#
# No $(...) in the per-commit loop: a fork per commit is slow on Windows.

set -uo pipefail

ALLOWED_NAME="DevomB"
ALLOWED_EMAIL="Devom.hb@yahoo.com"

# Registered to another GitHub account, which GitHub would show as the author;
# tooling offers it as "the user's email".
BANNED_EMAIL="devom.b@yahoo.com"

allowed_lc="${ALLOWED_EMAIL,,}"
banned_lc="${BANNED_EMAIL,,}"

bad=0
saw_banned=0

# judge NAME EMAIL WHAT  ->  0 when permitted, 1 (with a line) otherwise.
judge() {
    local name="$1" email="$2" what="$3"
    local email_lc="${email,,}"
    if [[ "$name" == "$ALLOWED_NAME" && "$email_lc" == "$allowed_lc" ]]; then
        return 0
    fi
    echo "check-commit-identity: REFUSED ${what}: ${name} <${email}>" >&2
    [[ "$email_lc" == "$banned_lc" ]] && saw_banned=1
    return 1
}

explain() {
    echo >&2
    if [[ "$saw_banned" -ne 0 ]]; then
        echo "    ${BANNED_EMAIL} is registered to the GitHub account DBs-Server-Service." >&2
        echo "    It is not this repository's identity and never was." >&2
    fi
    echo "    the only permitted identity is:  ${ALLOWED_NAME} <${ALLOWED_EMAIL}>" >&2
    echo "    fix:  git config user.name ${ALLOWED_NAME}; git config user.email ${ALLOWED_EMAIL}" >&2
    echo "    and never pass -c user.email, or set GIT_*_EMAIL, to anything else." >&2
}

if [[ "${1:-}" == "--pending" ]]; then
    # git var sees what the commit would: config, -c overrides and GIT_* env.
    for who in AUTHOR COMMITTER; do
        ident="$(git var "GIT_${who}_IDENT")"
        name="${ident%% <*}"
        email="${ident#*<}"
        email="${email%%>*}"
        judge "$name" "$email" "${who,,} of the pending commit" || bad=1
    done
    if [[ "$bad" -eq 0 ]]; then
        echo "check-commit-identity: pending commit is ${ALLOWED_NAME} <${ALLOWED_EMAIL}>"
    fi
else
    if [[ $# -eq 0 ]]; then
        set -- --all
    fi
    sep=$'\x1f'
    checked=0
    while IFS="$sep" read -r sha an ae cn ce; do
        [[ -z "$sha" ]] && continue
        checked=$((checked + 1))
        judge "$an" "$ae" "author of ${sha:0:12}" || bad=1
        judge "$cn" "$ce" "committer of ${sha:0:12}" || bad=1
    done < <(git log --format="%H${sep}%an${sep}%ae${sep}%cn${sep}%ce" "$@" --)
    if [[ "$bad" -eq 0 ]]; then
        echo "check-commit-identity: ${checked} commit(s), every one ${ALLOWED_NAME} <${ALLOWED_EMAIL}>"
    fi
fi

[[ "$bad" -eq 0 ]] || explain
exit "$bad"
