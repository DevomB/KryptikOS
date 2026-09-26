#!/usr/bin/env bash
# Tests for the git hooks, check-commit-identity.sh and install-git-hooks.sh.
# Each case commits into a throwaway repository whose core.hooksPath is the
# real hooks, so git itself runs them. Offline.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="${ROOT}/tools/git-hooks/pre-commit"
PUSH_HOOK="${ROOT}/tools/git-hooks/pre-push"
CHECKER="${ROOT}/tools/check-commit-identity.sh"
INSTALLER="${ROOT}/tools/install-git-hooks.sh"

# Read from the checker, so the tests cannot disagree with it.
ALLOWED_NAME="$(sed -n 's/^ALLOWED_NAME="\(.*\)"$/\1/p' "$CHECKER")"
ALLOWED_EMAIL="$(sed -n 's/^ALLOWED_EMAIL="\(.*\)"$/\1/p' "$CHECKER")"
BANNED_EMAIL="$(sed -n 's/^BANNED_EMAIL="\(.*\)"$/\1/p' "$CHECKER")"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$OUT"; }

[[ -f "$HOOK" ]] || { echo "no hook at ${HOOK}"; exit 1; }
[[ -f "$PUSH_HOOK" ]] || { echo "no hook at ${PUSH_HOOK}"; exit 1; }
[[ -f "$CHECKER" ]] || { echo "no checker at ${CHECKER}"; exit 1; }
[[ -n "$ALLOWED_NAME" && -n "$ALLOWED_EMAIL" && -n "$BANNED_EMAIL" ]] || { echo "could not read the identity constants from ${CHECKER}"; exit 1; }

# --- a throwaway repository with the real hook wired in ---------------------

FIX=""
newrepo() {
    FIX="${W}/repo$RANDOM$RANDOM"
    mkdir -p "${FIX}/tools/git-hooks" "${FIX}/build/lib" "${FIX}/build/stages"
    git -C "$FIX" init -q
    # The permitted identity, so other cases are not refused for it.
    git -C "$FIX" config user.name "$ALLOWED_NAME"
    git -C "$FIX" config user.email "$ALLOWED_EMAIL"
    git -C "$FIX" config advice.ignoredHook false
    # The CRLF case must stage its CR bytes; Git for Windows defaults
    # core.autocrlf to true, which strips them.
    git -C "$FIX" config core.autocrlf false
    cp "$HOOK" "${FIX}/tools/git-hooks/pre-commit"
    cp "$PUSH_HOOK" "${FIX}/tools/git-hooks/pre-push"
    cp "$CHECKER" "${FIX}/tools/check-commit-identity.sh"
    chmod +x "${FIX}/tools/git-hooks/pre-commit" "${FIX}/tools/git-hooks/pre-push" \
             "${FIX}/tools/check-commit-identity.sh"
    git -C "$FIX" config core.hooksPath tools/git-hooks
}

commit_in() {  # commit_in MESSAGE
    RC=0
    git -C "$FIX" commit -q -m "$1" > "$OUT" 2>&1 || RC=$?
}

mode_of() {  # mode_of PATH  (in HEAD)
    git -C "$FIX" ls-tree HEAD -- "$1" | awk '{print $1}'
}

has() { grep -qE -- "$1" "$OUT"; }

# Positive controls first: a hook that refused everything would pass every
# refusal case below.
echo "=== positive controls: the hook must let good commits through ==="

newrepo
printf '#!/usr/bin/env bash\necho fine\n' > "${FIX}/tools/good.sh"
chmod +x "${FIX}/tools/good.sh"
git -C "$FIX" add tools/good.sh
commit_in "a clean script"
if [[ "$RC" -eq 0 ]]; then green "a clean LF executable script commits"; else red "a clean LF executable script commits"; show; fi
if [[ "$(mode_of tools/good.sh)" == "100755" ]]; then
    green "and keeps its 100755 mode"
else
    red "and keeps its 100755 mode (got $(mode_of tools/good.sh))"
fi

printf 'just prose\n' > "${FIX}/README.md"
git -C "$FIX" add README.md
commit_in "a document"
if [[ "$RC" -eq 0 ]]; then green "a non-script file commits untouched"; else red "a non-script file commits untouched"; show; fi
if [[ "$(mode_of README.md)" == "100644" ]]; then
    green "and is NOT made executable"
else
    red "and is NOT made executable (got $(mode_of README.md))"
fi

echo
echo "=== the exec bit is fixed in the index, not refused ==="

newrepo
printf '#!/usr/bin/env bash\necho hi\n' > "${FIX}/tools/plain.sh"
chmod 644 "${FIX}/tools/plain.sh"
git -C "$FIX" add tools/plain.sh
if [[ "$(git -C "$FIX" ls-files -s -- tools/plain.sh | awk '{print $1}')" == "100644" ]]; then
    green "a script staged from a filesystem with no exec bit records 100644"
else
    red "a script staged from a filesystem with no exec bit records 100644"
fi
commit_in "a script with no exec bit"
if [[ "$RC" -eq 0 ]]; then green "the commit is allowed, not refused"; else red "the commit is allowed, not refused"; show; fi
if [[ "$(mode_of tools/plain.sh)" == "100755" ]]; then
    green "and the committed mode is 100755"
else
    red "and the committed mode is 100755 (got $(mode_of tools/plain.sh))"
fi
if has 'setting exec bit on tools/plain.sh'; then green "and it says what it changed"; else red "and it says what it changed"; show; fi

newrepo
printf '#!/usr/bin/env bash\necho stage\n' > "${FIX}/build/stages/99-thing.sh"
chmod 644 "${FIX}/build/stages/99-thing.sh"
git -C "$FIX" add build/stages/99-thing.sh
commit_in "a build stage"
if [[ "$(mode_of build/stages/99-thing.sh)" == "100755" ]]; then
    green "build/stages scripts are swept too"
else
    red "build/stages scripts are swept too (got $(mode_of build/stages/99-thing.sh))"
fi

# tools/test-*.py suites run like the shell ones, so they are swept too.
newrepo
printf '#!/usr/bin/env python3\nprint("hi")\n' > "${FIX}/tools/test-thing.py"
chmod 644 "${FIX}/tools/test-thing.py"
git -C "$FIX" add tools/test-thing.py
commit_in "a test suite in python"
if [[ "$(mode_of tools/test-thing.py)" == "100755" ]]; then
    green "a tools/test-*.py suite is swept too"
else
    red "a tools/test-*.py suite is swept too (got $(mode_of tools/test-thing.py))"
fi

newrepo
printf '# sourced, never executed\n' > "${FIX}/build/lib/common.sh"
chmod 644 "${FIX}/build/lib/common.sh"
git -C "$FIX" add build/lib/common.sh
commit_in "a sourced library"
if [[ "$(mode_of build/lib/common.sh)" == "100644" ]]; then
    green "build/lib/common.sh is left at 100644 deliberately"
else
    red "build/lib/common.sh is left at 100644 deliberately (got $(mode_of build/lib/common.sh))"
fi

echo
echo "=== the defect this suite exists for: hook files have no .sh suffix ==="

newrepo
printf '#!/usr/bin/env bash\nexit 0\n' > "${FIX}/tools/git-hooks/pre-push"
chmod 644 "${FIX}/tools/git-hooks/pre-push"
git -C "$FIX" add tools/git-hooks/pre-push
commit_in "a new hook, staged 644"
if [[ "$(mode_of tools/git-hooks/pre-push)" == "100755" ]]; then
    green "a hook file staged 100644 has its exec bit fixed"
else
    red "a hook file staged 100644 has its exec bit fixed (got $(mode_of tools/git-hooks/pre-push))"
    show
fi

# A hook committed 100644 is a hook git will not run.
newrepo
git -C "$FIX" add tools/git-hooks/pre-commit
commit_in "the hook itself"
if [[ "$(mode_of tools/git-hooks/pre-commit)" == "100755" ]]; then
    green "the pre-commit hook commits itself as 100755"
else
    red "the pre-commit hook commits itself as 100755 (got $(mode_of tools/git-hooks/pre-commit))"
fi

echo
echo "=== and the real repository, which is where it was actually wrong ==="

# safe.directory: acceptance runs this as root over a checkout root does not
# own; git trusts this checkout alone.
top="$(cd "$ROOT" && pwd -P)"
real_mode="$(git -c safe.directory="$top" -C "$top" ls-files -s -- tools/git-hooks/pre-commit | awk '{print $1}')"
if [[ "$real_mode" == "100755" ]]; then
    green "tools/git-hooks/pre-commit is 100755 in this repository's index"
else
    red "tools/git-hooks/pre-commit is ${real_mode} in this repository's index; git will ignore it in a fresh clone"
fi

echo
echo "=== refusals, each of which must actually refuse ==="

newrepo
printf '#!/usr/bin/env bash\r\necho windows\r\n' > "${FIX}/tools/crlf.sh"
git -C "$FIX" add tools/crlf.sh
# The staged blob must carry CR, or the refusal below proves nothing.
if git -C "$FIX" show :tools/crlf.sh | grep -qU $'\r'; then
    green "the CRLF fixture really is staged with CR bytes"
else
    red "the CRLF fixture really is staged with CR bytes"
fi
commit_in "a CRLF script"
if [[ "$RC" -ne 0 ]] && has 'contains CRLF'; then
    green "a staged CRLF script is refused"
else
    red "a staged CRLF script is refused (exit ${RC})"; show
fi
if has 'refusing the commit'; then green "with an explicit refusal"; else red "with an explicit refusal"; show; fi
if has 'no-verify'; then green "and the escape hatch is named"; else red "and the escape hatch is named"; show; fi

newrepo
printf '#!/usr/bin/env bash\nif [ then\n' > "${FIX}/tools/broken.sh"
chmod +x "${FIX}/tools/broken.sh"
git -C "$FIX" add tools/broken.sh
commit_in "a syntax error"
if [[ "$RC" -ne 0 ]] && has 'shell syntax error'; then
    green "a shell syntax error is refused"
else
    red "a shell syntax error is refused (exit ${RC})"; show
fi

newrepo
printf '#!/usr/bin/env bash\nif [ then\n' > "${FIX}/tools/broken.sh"
chmod +x "${FIX}/tools/broken.sh"
git -C "$FIX" add tools/broken.sh
RC=0
git -C "$FIX" commit -q --no-verify -m "bypass" > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -eq 0 ]]; then green "--no-verify still bypasses, as documented"; else red "--no-verify still bypasses, as documented"; show; fi

echo
echo "=== identity: one permitted, one banned by name, everything else refused ==="

# GitHub shows a commit under the account that registered its email, and the
# banned address belongs to another account.

newrepo
printf 'prose\n' > "${FIX}/note.md"
git -C "$FIX" add note.md
commit_in "under the permitted identity"
if [[ "$RC" -eq 0 ]]; then green "the permitted identity commits"; else red "the permitted identity commits"; show; fi
if has 'pending commit is'; then green "and the hook says which identity it confirmed"; else red "and the hook says which identity it confirmed"; show; fi

newrepo
printf 'prose\n' > "${FIX}/note.md"
git -C "$FIX" add note.md
RC=0
git -C "$FIX" -c user.email="$BANNED_EMAIL" commit -q -m "banned address" > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -ne 0 ]] && has 'REFUSED'; then
    green "the banned address is refused, even via -c user.email"
else
    red "the banned address is refused, even via -c user.email (exit ${RC})"; show
fi
if has 'DBs-Server-Service'; then green "and the refusal names the account it belongs to"; else red "and the refusal names the account it belongs to"; show; fi
if has 'never pass -c user.email'; then green "and says what not to do"; else red "and says what not to do"; show; fi
if [[ -z "$(git -C "$FIX" rev-parse --verify -q HEAD)" ]]; then green "and no commit was created"; else red "and no commit was created"; fi

newrepo
printf 'prose\n' > "${FIX}/note.md"
git -C "$FIX" add note.md
RC=0
GIT_AUTHOR_EMAIL="$BANNED_EMAIL" git -C "$FIX" commit -q -m "banned author via env" > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -ne 0 ]] && has 'REFUSED author'; then
    green "GIT_AUTHOR_EMAIL set to the banned address is refused"
else
    red "GIT_AUTHOR_EMAIL set to the banned address is refused (exit ${RC})"; show
fi

newrepo
printf 'prose\n' > "${FIX}/note.md"
git -C "$FIX" add note.md
RC=0
GIT_COMMITTER_EMAIL="$BANNED_EMAIL" git -C "$FIX" commit -q -m "banned committer via env" > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -ne 0 ]] && has 'REFUSED committer'; then
    green "GIT_COMMITTER_EMAIL set to the banned address is refused"
else
    red "GIT_COMMITTER_EMAIL set to the banned address is refused (exit ${RC})"; show
fi

newrepo
printf 'prose\n' > "${FIX}/note.md"
git -C "$FIX" add note.md
RC=0
git -C "$FIX" -c user.name=somebody-else commit -q -m "another name" > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -ne 0 ]] && has 'REFUSED'; then
    green "a different name with the right address is refused too"
else
    red "a different name with the right address is refused too (exit ${RC})"; show
fi
if ! has 'DBs-Server-Service'; then
    green "and the account note appears only for the banned address"
else
    red "and the account note appears only for the banned address"; show
fi

newrepo
printf 'prose\n' > "${FIX}/note.md"
git -C "$FIX" add note.md
RC=0
upper="$(printf '%s' "$ALLOWED_EMAIL" | tr '[:lower:]' '[:upper:]')"
git -C "$FIX" -c user.email="$upper" commit -q -m "same address, other case" > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -eq 0 ]]; then
    green "the permitted address is matched without regard to case, as GitHub matches it"
else
    red "the permitted address is matched without regard to case, as GitHub matches it"; show
fi

newrepo
rm -f "${FIX}/tools/check-commit-identity.sh"
printf 'prose\n' > "${FIX}/note.md"
git -C "$FIX" add note.md
commit_in "with the checker missing"
if [[ "$RC" -ne 0 ]] && has 'no identity checker'; then
    green "a hook that cannot find the checker refuses rather than passing"
else
    red "a hook that cannot find the checker refuses rather than passing (exit ${RC})"; show
fi

echo
echo "=== pre-push: nothing leaves under the wrong identity ==="

# A bad commit made with --no-verify must still be stopped at the push.
newrepo
REMOTE="${W}/remote$RANDOM.git"
git init -q --bare "$REMOTE"
git -C "$FIX" remote add origin "$REMOTE"
printf 'prose\n' > "${FIX}/a.md"
git -C "$FIX" add a.md
commit_in "good first commit"
RC=0
git -C "$FIX" push -q origin HEAD:refs/heads/main > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -eq 0 ]]; then green "a clean history pushes to a new ref"; else red "a clean history pushes to a new ref"; show; fi
if has 'every one'; then green "and the hook reports how many commits it checked"; else red "and the hook reports how many commits it checked"; show; fi

printf 'more\n' > "${FIX}/b.md"
git -C "$FIX" add b.md
git -C "$FIX" -c user.email="$BANNED_EMAIL" commit -q --no-verify -m "slipped past pre-commit" > /dev/null 2>&1
RC=0
git -C "$FIX" push -q origin HEAD:refs/heads/main > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -ne 0 ]] && has 'REFUSED'; then
    green "a banned-address commit made with --no-verify is refused at the push"
else
    red "a banned-address commit made with --no-verify is refused at the push (exit ${RC})"; show
fi
if has 'refusing the push'; then green "with an explicit refusal"; else red "with an explicit refusal"; show; fi
if has 'reset-author'; then green "and the repair is named"; else red "and the repair is named"; show; fi
if [[ "$(git -C "$REMOTE" rev-list --count main)" == "1" ]]; then
    green "and the remote still has only the clean commit"
else
    red "and the remote still has only the clean commit (has $(git -C "$REMOTE" rev-list --count main))"
fi

# The documented repair, then the push goes through.
git -C "$FIX" commit -q --amend --no-edit --reset-author > /dev/null 2>&1
RC=0
git -C "$FIX" push -q origin HEAD:refs/heads/main > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -eq 0 ]]; then green "after --reset-author under the permitted identity, the push succeeds"; else red "after --reset-author under the permitted identity, the push succeeds"; show; fi

echo
echo "=== install-git-hooks.sh verifies rather than asserting ==="

run_installer() {
    RC=0
    ( cd "$FIX" && NO_COLOR=1 KRYPTIK_ROOT="$FIX" bash "$INSTALLER" ) > "$OUT" 2>&1 || RC=$?
}

newrepo
git -C "$FIX" add tools/git-hooks/pre-commit
git -C "$FIX" -c core.hooksPath= commit -q --no-verify -m "hook at whatever mode it landed" 2>/dev/null
# Force the index mode back to 100644.
git -C "$FIX" update-index --chmod=-x -- tools/git-hooks/pre-commit
run_installer
if [[ "$RC" -eq 0 ]]; then green "the installer succeeds on a usable hook"; else red "the installer succeeds on a usable hook"; show; fi
if has 'recorded 100644 in the index'; then
    green "it notices the index mode a fresh clone would inherit"
else
    red "it notices the index mode a fresh clone would inherit"; show
fi
if [[ "$(git -C "$FIX" ls-files -s -- tools/git-hooks/pre-commit | awk '{print $1}')" == "100755" ]]; then
    green "and corrects it to 100755"
else
    red "and corrects it to 100755"; show
fi
if has 'COMMIT THAT CHANGE'; then green "and says the correction must be committed"; else red "and says the correction must be committed"; show; fi
if has 'confirmed runnable'; then green "success is phrased as confirmed, not assumed"; else red "success is phrased as confirmed, not assumed"; show; fi
if has 'core.hooksPath = tools/git-hooks'; then green "and reports the path it actually configured"; else red "and reports the path it actually configured"; show; fi

newrepo
chmod 644 "${FIX}/tools/git-hooks/pre-commit"
run_installer
# The installer chmods +x first, so this normally recovers; it must never
# claim success while the hook is not executable.
if [[ "$RC" -eq 0 ]] && [[ -x "${FIX}/tools/git-hooks/pre-commit" ]]; then
    green "a non-executable hook is made executable before success is claimed"
elif [[ "$RC" -ne 0 ]] && has 'git will IGNORE it'; then
    green "or the installer refuses and says git would ignore the hook"
else
    red "a non-executable hook is either fixed or refused"; show
fi

newrepo
printf 'not a hook\n' > "${FIX}/tools/git-hooks/untracked-thing"
chmod +x "${FIX}/tools/git-hooks/untracked-thing"
run_installer
if has 'not tracked by git'; then
    green "an untracked hook is flagged as not surviving a clone"
else
    red "an untracked hook is flagged as not surviving a clone"; show
fi

newrepo
rm -f "${FIX}/tools/git-hooks/"*
run_installer
if [[ "$RC" -ne 0 ]] && has 'no hook files'; then
    green "an empty hooks directory is refused, not reported as installed"
else
    red "an empty hooks directory is refused, not reported as installed (exit ${RC})"; show
fi

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
