# glibc 2.40: upstream loader fixes the release tarball shipped without

Applied by `s_glibc` in stages 01 and 04 through `apply_repo_patches
"glibc-${V_GLIBC}"` (build/lib/common.sh), after the LFS FHS patch. The
whole directory is an input to those steps' fingerprints; `SHA256SUMS` is
verified before anything is applied.

## Why

`build/BLOCKER.md` records the defect: on Kryptik, `pthread_exit()`,
`pthread_cancel()` and `backtrace()` abort with no message, because
`_dl_find_object` attributes every object loaded after startup to
`ld-linux-x86-64.so.2` itself. The cause is upstream glibc bug 31943: ld.so
is linked with `-z separate-code`, so its LOAD segments are not contiguous;
the kernel maps it with real gaps between them; later `mmap`s - including
every `dlopen` - land in those gaps; and `_dl_find_object` records ld.so as
one range `[l_map_start, l_map_end)` that covers them. libgcc's unwinder then
reads ld.so's `.eh_frame`, finds no FDE, and calls `abort()`.

## What is here

| file | upstream commit (release/2.40/master) | changes to the upstream output |
|---|---|---|
| `0001-...-BZ-32245.patch` | `626c048f32a979f77662bdcb1cca477c11d3f9c1` | NEWS hunk dropped |
| `0002-...-libc.so.patch` | `e8ac8a9844ba6ef92d49354c103c1320fcfc0087` | none |
| `0003-...-bug-31943.patch` | `2193f42655a9687ce66362905add03a4cfbc580e` | NEWS hunk dropped; one comment-only `elf/rtld.c` hunk dropped |

0003 is the fix. 0001 and 0002 precede it on the branch and touch the same
file; taking them keeps 0003 byte-identical in its code hunks. 0002 also
removes a duplicate copy of `_dl_find_object` from `libc.so` (an upstream
correctness fix in its own right).

The NEWS hunks cannot apply because the release-branch NEWS has a 2.40.1
section the 2.40 tarball does not; they change no code. The dropped rtld.c
hunk rewrote the comment above the loader's phdr setup ("callbacks." ->
"callbacks, and it is used by _dl_find_object."); the 2.40 tarball's comment
reads differently, so it cannot apply, and it changes no code either.
Every code hunk applies with `patch -p1 -F0` (no fuzz); 0003's hunks land
at line offsets because the branch carries other backports above them.

## How they were authenticated

Each commit was fetched on 2026-09-13 from both
`https://sourceware.org/git/?p=glibc.git;a=patch;h=<commit>` and
`https://github.com/bminor/glibc/commit/<commit>.patch`; the diff bodies
(everything from the first `diff --git`, minus the `index` lines the two
hosts abbreviate differently) were byte-identical. `UPSTREAM-SHA256SUMS`
records the sha256 of sourceware's output for each commit as fetched.
`SHA256SUMS` records the files as shipped here.

To re-derive: fetch the sourceware output, delete the `diff --git a/NEWS`
section (and, for 0003, the `@@ -1286,7 +1286,7 @@` rtld.c hunk), and
compare with `diff`. The `[Kryptik: ...]` line in each mail header records
the same thing in the file itself.

## The evidence that it is the fix

`make test-libc-unwind` (tools/test-libc-unwind.sh, run against the TARGET
glibc inside the chroot) probes all three entry points and asks
`_dl_find_object` directly which object it blames; upstream's own
`elf/tst-link-map-contiguous-ldso` test, added by 0003, is built by the
glibc test suite. See docs/OVERNIGHT_STATUS.md for the run that closed
build/BLOCKER.md.
