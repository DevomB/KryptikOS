# glibc 2.40: upstream loader fixes the release tarball shipped without

Applied by `s_glibc` in stages 01 and 04 through `apply_repo_patches
"glibc-${V_GLIBC}"` (build/lib/common.sh), after the LFS FHS patch. The
whole directory is an input to those steps' fingerprints; `SHA256SUMS` is
verified before anything is applied.

## Why

`build/BLOCKER.md` records the defect: on Kryptik, `pthread_exit()`,
`pthread_cancel()` and `backtrace()` abort with no message, because
`_dl_find_object` attributes every object loaded after startup to
`ld-linux-x86-64.so.2` itself, so libgcc's unwinder reads ld.so's
`.eh_frame`, finds no FDE, and calls `abort()`. Two upstream loader bugs
produce that symptom; this set carries the fixes for both, and the
second is the one Kryptik's loader actually had.

**Bug 31943** (0003, with 0001 and 0002 as its prerequisites): an ld.so
whose LOAD segments the kernel maps with gaps is recorded by
`_dl_find_object` as one range covering the gaps, and later `mmap`s -
every `dlopen` - land in them. The fix is on release/2.40/master. It is
correct and it is kept, but it is not what was wrong here: the ld.so
Kryptik links has four LOAD segments that abut page for page, the kernel
maps it without gaps, and applying 0001-0003 alone left
`make test-libc-unwind` failing exactly as before.

**Bug 33088** (0004): the loader stores its own map bounds -
`l_map_start = &__ehdr_start`, `l_map_end = _end` - in `_dl_start`, before
it has relocated itself, and that code must therefore take those two
addresses PC-relatively. GCC 14 at `-O2` vectorises the two adjacent
stores and materialises `&__ehdr_start` as a `.quad` in
`.data.rel.ro.local`, a word that needs a run-time relocation, then hoists
the load of it to the top of `_dl_start`, above `ELF_DYNAMIC_RELOCATE`.
The word holds the link-time value, 0, at that moment, so ld.so records
itself as `[0, _end)`. `_dl_find_object` then answers "ld.so" for every
address below libc that belongs to nothing it knows - which is where every
later `dlopen` is mapped. On Kryptik, `ldd` printed
`/lib64/ld-linux-x86-64.so.2 (0x0000000000000000)` and
`_dl_find_object((void *) 0x1000)` returned ld.so. Recompiling `rtld.c`
with `-fno-tree-slp-vectorize` or `-O1` removed the relocated constant;
none of the hardening flags mattered. Upstream fixed it in 2.42 with two
`asm` barriers (GCC bug 120653 records the compiler side). glibc 2.40
predates the fix and it was never backported to its branch.

## What is here

| file | upstream commit | changes to the upstream output |
|---|---|---|
| `0001-...-BZ-32245.patch` | release/2.40/master `626c048f32a979f77662bdcb1cca477c11d3f9c1` | NEWS hunk dropped |
| `0002-...-libc.so.patch` | release/2.40/master `e8ac8a9844ba6ef92d49354c103c1320fcfc0087` | none |
| `0003-...-bug-31943.patch` | release/2.40/master `2193f42655a9687ce66362905add03a4cfbc580e` | NEWS hunk dropped; one comment-only `elf/rtld.c` hunk dropped |
| `0004-...-__ehdr_start-and-_end.patch` | master `81467d4b6168c7ce40d951d6b32e387109c0e5ae` | `elf/rtld.c` hunk re-expressed for 2.40; `sysdeps/x86_64/Makefile` hunk unmodified |

0001 and 0002 precede 0003 on the branch and touch the same file; taking
them keeps 0003 byte-identical in its code hunks. 0002 also removes a
duplicate copy of `_dl_find_object` from `libc.so` (an upstream
correctness fix in its own right).

The NEWS hunks cannot apply because the release-branch NEWS has a 2.40.1
section the 2.40 tarball does not; they change no code. The dropped rtld.c
hunk in 0003 rewrote the comment above the loader's phdr setup
("callbacks." -> "callbacks, and it is used by _dl_find_object."); the
2.40 tarball's comment reads differently, so it cannot apply, and it
changes no code either.

0004's `elf/rtld.c` hunk is the upstream one with the loader's link map
spelled the way 2.40 spells it: `GL(dl_rtld_map)` where 2.42 has
`_dl_rtld_map`. The two added statements are otherwise upstream's:

    asm ("" : "+g" (GL(dl_rtld_map).l_map_start));
    asm ("" : "+g" (GL(dl_rtld_map).l_map_end));

Its `sysdeps/x86_64/Makefile` hunk adds a `make check` rule; this build
does not run glibc's test suite, so `s_glibc` in stages 01 and 04 runs the
same check itself (`readelf -rW elf/rtld.os` must show no `R_X86_64_64`
against `__ehdr_start` or `_end`) and stage 04 adds the runtime form (the
map start `LD_TRACE_LOADED_OBJECTS` prints for ld.so must not be 0).
Every code hunk applies with `patch -p1 -F0` (no fuzz); hunks land at line
offsets because the branch carries other backports above them.

## How they were authenticated

Each commit was fetched on 2026-09-13 from both
`https://sourceware.org/git/?p=glibc.git;a=patch;h=<commit>` and
`https://github.com/bminor/glibc/commit/<commit>.patch`; the diff bodies
(everything from the first `diff --git`, minus the `index` lines the two
hosts abbreviate differently, and minus the trailing format-patch
signature only sourceware appends) were byte-identical.
`UPSTREAM-SHA256SUMS` records the sha256 of sourceware's output for each
commit as fetched. `SHA256SUMS` records the files as shipped here.

To re-derive 0001-0003: fetch the sourceware output, delete the
`diff --git a/NEWS` section (and, for 0003, the `@@ -1286,7 +1286,7 @@`
rtld.c hunk), and compare with `diff`. To re-derive 0004: in the rtld.c
hunk replace `_dl_rtld_map` with `GL(dl_rtld_map)` and regenerate it
against 2.40's `elf/rtld.c` (the assignments are at line 478); the
Makefile hunk is sourceware's verbatim. The `[Kryptik: ...]` line in each
mail header records the same thing in the file itself.

## The evidence that it is the fix

`make test-libc-unwind` (tools/test-libc-unwind.sh, run against the TARGET
glibc inside the chroot) probes all three entry points, asks
`_dl_find_object` directly which object it blames for a dlopen()ed
address, and reads the loader's own map start back through
`LD_TRACE_LOADED_OBJECTS`. With 0001-0003 alone it failed (2 passed, 4
failed; the loader blamed itself). See docs/status.md for the
run with 0004 that closed build/BLOCKER.md.
