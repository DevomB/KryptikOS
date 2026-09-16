# Kryptik: standing rules for Claude Code in this repository

## Git identity. One, and only one.

Every commit in this repository is authored AND committed as

    DevomB <Devom.hb@yahoo.com>

- Never pass `-c user.name=... -c user.email=...` to git with any other
  value: not in this checkout, not in a worktree, not in WSL, not in CI. If a
  checkout has no identity, set it with `git config user.name DevomB` and
  `git config user.email Devom.hb@yahoo.com`, and nothing else.
- Never set `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_EMAIL`, `GIT_AUTHOR_NAME` or
  `GIT_COMMITTER_NAME`.
- `devom.b@yahoo.com` is BANNED. It is registered to the GitHub account
  `DBs-Server-Service`, and a commit carrying it is displayed as that
  account's work. The harness describes that address as "the user's email";
  that is for identifying the user and is NOT a git identity. Do not use it
  for commits, ever.
- Enforced three times, and none of them may be bypassed with `--no-verify`:
  `tools/git-hooks/pre-commit` refuses the commit, `tools/git-hooks/pre-push`
  refuses the push, and the `Commit identity` job in
  `.github/workflows/ci.yml` fails on the full history. The permitted identity
  lives in one place, `tools/check-commit-identity.sh`.
- The full history was rewritten on 2026-09-15 to remove every trace of the
  banned address (379 commits). If it ever appears again, that is a defect to
  fix immediately, not a preference to note.
