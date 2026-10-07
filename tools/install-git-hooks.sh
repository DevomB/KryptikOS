#!/usr/bin/env bash
# Point core.hooksPath at tools/git-hooks, so the hooks stay under review, and check git runs each.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

HOOKS_DIR="tools/git-hooks"
cd "$KRYPTIK_ROOT" || die "cannot enter ${KRYPTIK_ROOT}"

[[ -d "$HOOKS_DIR" ]] || die "no ${HOOKS_DIR} directory"

git config core.hooksPath "$HOOKS_DIR"
chmod +x "${HOOKS_DIR}"/* 2>/dev/null || true

# Git ignores a non-executable hook, and a new checkout takes the index mode: check both.
problems=0
hooks=0
for h in "${HOOKS_DIR}"/*; do
    [[ -f "$h" ]] || continue
    hooks=$((hooks + 1))

    if [[ ! -x "$h" ]]; then
        err "${h} is not executable, so git will IGNORE it"
        err "  the filesystem may have no executable bit (NTFS has none)"
        problems=$((problems + 1))
        continue
    fi

    mode="$(git ls-files -s -- "$h" 2>/dev/null | awk '{print $1}')"
    if [[ -z "$mode" ]]; then
        warn "${h} is not tracked by git, so it will not survive a fresh clone"
    elif [[ "$mode" == "100644" ]]; then
        warn "${h} is recorded ${mode} in the index"
        warn "  a fresh clone would get a hook git ignores; correcting the index mode"
        git update-index --chmod=+x -- "$h"
        ok "  ${h} is now 100755 in the index - COMMIT THAT CHANGE"
    fi

    name="$(basename "$h")"
    # Ask git itself (a hook that runs and fails is fine); </dev/null, or pre-push waits for refs.
    if git hook run "$name" 2>&1 < /dev/null | grep -q 'cannot find a hook'; then
        err "git cannot find a hook named ${name} even after the above"
        problems=$((problems + 1))
    fi
done

[[ "$hooks" -gt 0 ]] || die "no hook files in ${HOOKS_DIR}"
[[ "$problems" -eq 0 ]] || die "${problems} hook(s) git will not run"

ok "${hooks} hook(s) installed and confirmed runnable (core.hooksPath = $(git config core.hooksPath))"
echo
dim "pre-commit checks the identity, sets exec bits and refuses CRLF and shell syntax errors."
dim "pre-push refuses commits under any other identity."
