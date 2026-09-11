#!/usr/bin/env bash
# Focused tests for tools/git-hooks/pre-commit and tools/install-git-hooks.sh.
#
#   ./tools/test-git-hooks.sh
#
# Deterministic and offline. Each case builds a throwaway git repository, points
# core.hooksPath at the real hook, and commits into it, so the hook is exercised
# by git rather than called directly.
#
# The case worth reading first is "a hook file staged 100644 has its exec bit
# fixed". tools/git-hooks/pre-commit was itself recorded 100644 from the day it
# was added. Git silently ignores a hook that is not executable -- it prints an
# advice line at commit time and carries on -- so in any checkout where nobody
# had run install-git-hooks.sh locally, every check in this file was inert while
# install-git-hooks.sh reported "hooks installed". The exec-bit sweep could not
# have caught it either: it only looked at *.sh, and hook files have no suffix.
#
# Positive controls come first. A hook that refused every commit would satisfy
# all the refusal cases below.

set -uo pipefail

unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="${ROOT}/tools/git-hooks/pre-commit"
INSTALLER="${ROOT}/tools/install-git-hooks.sh"

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

# --- a throwaway repository with the real hook wired in ---------------------

FIX=""
newrepo() {
    FIX="${W}/repo$RANDOM$RANDOM"
    mkdir -p "${FIX}/tools/git-hooks" "${FIX}/build/lib" "${FIX}/build/stages"
    git -C "$FIX" init -q
    git -C "$FIX" config user.name provenance-test
    git -C "$FIX" config user.email test@kryptik.invalid
    git -C "$FIX" config advice.ignoredHook false
    cp "$HOOK" "${FIX}/tools/git-hooks/pre-commit"
    chmod +x "${FIX}/tools/git-hooks/pre-commit"
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

# The whole point: a hook committed 100644 is a hook git will not run.
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

real_mode="$(git -C "$ROOT" ls-files -s -- tools/git-hooks/pre-commit | awk '{print $1}')"
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
# Prove the fixture is what it claims: the STAGED blob must carry CR, or this
# case would pass for the wrong reason. (An earlier draft used
# `git add --renormalize`, which succeeds while staging nothing for an untracked
# path, so the hook was refusing an empty commit rather than a CRLF file.)
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
echo "=== install-git-hooks.sh verifies rather than asserting ==="

run_installer() {
    RC=0
    ( cd "$FIX" && NO_COLOR=1 KRYPTIK_ROOT="$FIX" bash "$INSTALLER" ) > "$OUT" 2>&1 || RC=$?
}

newrepo
git -C "$FIX" add tools/git-hooks/pre-commit
git -C "$FIX" -c core.hooksPath= commit -q --no-verify -m "hook at whatever mode it landed" 2>/dev/null
# Force the index back to 100644: the state a fresh clone of the old repo saw.
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
# The installer chmods +x first, so on a normal filesystem this recovers; what
# must never happen is a success claim while the file is not executable.
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
