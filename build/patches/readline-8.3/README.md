# readline 8.3: its six official patches

Applied by `s_readline` in stage 04 through `apply_repo_patches`; `SHA256SUMS`
is verified before anything is applied. readline is meant to be built with
GNU's official patches, and the tarball carries none of them. bash links this
readline (`--with-installed-readline`), and so do gawk, for its debugger, and
gdbm's gdbmtool.

| patch | fixes |
| --- | --- |
| 001 | an application's event hook called over and over while input that is waiting is never read |
| 002 | redisplay dereferencing a null prompt after `rl_save_prompt()` when no new one was set |
| 003 | a SIGINT during a reverse i-search: a segmentation fault from data a signal handler freed |
| 004 | redisplay with the cursor away from column 0 and multibyte characters in the prompt |
| 005 | a crash when the first prompt wraps over more than 256 lines, and a changed prompt that starts with an escape sequence not being redrawn in full |
| 006 | after a SIGWINCH, the columns where the prompt wraps recomputed only when the screen got narrower |

## Where they come from

Each is GNU's `readline83-NNN` from
https://ftp.gnu.org/gnu/readline/readline-8.3-patches/, verified on 2026-09-25
against its `.sig` and the GNU keyring. All six are signed by
7C0135FB088AAF6C66C650B9BB5869F064EA74AB, the key that signs
`readline-8.3.tar.gz`, and `UPSTREAM-SHA256SUMS` holds their hashes.

GNU writes them for `patch -p0`, and `apply_repo_patches` applies `-p1` with
no fuzz, so their file-header lines are rewritten: `*** ../readline-8.3/FILE`
became `*** a/FILE` (some name `../readline-8.3-patched/`, and 002 names
`../readline-8.2/patchlevel`), and `--- FILE` became `--- b/FILE`. Hunk lines
and bodies are GNU's. Two copies of the tarball, one patched with the six
originals at `-p0` and one with these at `-Np1 -F0`, are the same tree
(`diff -r`), and `patchlevel` reads 6 in both.

## bash 5.2 with it

bash 5.2.32 was built against this readline and, as the control, against 8.2
with its thirteen official patches, both with `--with-installed-readline` as
stage 04 builds it. On both, bash's own test suite (`make tests`: 83 scripts,
run on a pty because some start an interactive shell) printed the same, apart
from build paths, temporary names and numbers. On a pty, both shells recalled
history, completed a file name, took a bracketed paste as typed text and were
still running after a SIGINT in a reverse i-search. gawk and gdbm, built
against each, link the readline they were given, and their own test suites
fail the same tests on both: five of gawk's, which need locales the build
host lacks, and gdbm's lockwait_sig, a lock-timing test that fails one run in
five on either.

Delete this directory when the readline pin moves on.
