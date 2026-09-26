#!/usr/bin/env bash
# Install the git hooks: point core.hooksPath at tools/git-hooks, so they stay
# under review, and check that git will run each one.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

HOOKS_DIR="tools/git-hooks"
cd "$KRYPTIK_ROOT" || die "cannot enter ${KRYPTIK_ROOT}"

[[ -d "$HOOKS_DIR" ]] || die "no ${HOOKS_DIR} directory"

git config core.hooksPath "$HOOKS_DIR"
chmod +x "${HOOKS_DIR}"/* 2>/dev/null || true

# Git silently ignores a non-executable hook. The chmod above fixes only the
# working tree; a new checkout takes the index mode, so check that too.
problems=0
hooks=0
for h in "${HOOKS_DIR}"/*; do
    [[ -f "$h" ]] || continue
    hooks=$((hooks + 1))

    if [[ ! -x "$h" ]]; then
        err "${h} is not executable, so git will IGNORE it"
        err "  the filesystem may be unable to express the executable bit"
        err "  (NTFS cannot); a hook that cannot be marked executable cannot run"
        problems=$((problems + 1))
        continue
    fi

    mode="$(git ls-files -s -- "$h" 2>/dev/null | awk '{print $1}')"
    if [[ -z "$mode" ]]; then
        warn "${h} is not tracked by git, so it will not survive a fresh clone"
    elif [[ "$mode" == "100644" ]]; then
        warn "${h} is recorded ${mode} in the index"
        warn "  a fresh clone would get a hook git ignores, exactly as this"
        warn "  repository did. Correcting the index mode now."
        git update-index --chmod=+x -- "$h"
        ok "  ${h} is now 100755 in the index - COMMIT THAT CHANGE"
    fi

    # Ask git itself. A hook that runs and fails is fine: nothing is staged.
    name="$(basename "$h")"
    # stdin from /dev/null, or pre-push waits for a ref list.
    if git hook run "$name" 2>&1 < /dev/null | grep -q 'cannot find a hook'; then
        err "git cannot find a hook named ${name} even after the above"
        problems=$((problems + 1))
    fi
done

[[ "$hooks" -gt 0 ]] || die "no hook files in ${HOOKS_DIR}"
[[ "$problems" -eq 0 ]] || die "${problems} hook(s) git will not run.
Nothing here is installed in any useful sense until that is fixed, and a
pre-commit check that does not run is worse than none: it is a check that
everybody believes is happening."

ok "${hooks} hook(s) installed and confirmed runnable (core.hooksPath = $(git config core.hooksPath))"
echo
dim "The pre-commit hook fixes executable bits automatically and refuses"
dim "commits containing CRLF or shell syntax errors. Both of those have"
dim "broken a clone of this repository already."
