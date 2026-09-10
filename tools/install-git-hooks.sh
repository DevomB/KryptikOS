#!/usr/bin/env bash
# Install Kryptik's git hooks.
#
#   ./tools/install-git-hooks.sh
#
# Uses core.hooksPath so the hooks live in the repository and stay under
# review, rather than being copied into .git/hooks where nobody sees them
# change.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

HOOKS_DIR="tools/git-hooks"
cd "$KRYPTIK_ROOT" || die "cannot enter ${KRYPTIK_ROOT}"

[[ -d "$HOOKS_DIR" ]] || die "no ${HOOKS_DIR} directory"

git config core.hooksPath "$HOOKS_DIR"
chmod +x "${HOOKS_DIR}"/* 2>/dev/null || true

ok "hooks installed (core.hooksPath = ${HOOKS_DIR})"
echo
dim "The pre-commit hook fixes executable bits automatically and refuses"
dim "commits containing CRLF or shell syntax errors. Both of those have"
dim "broken a clone of this repository already."
