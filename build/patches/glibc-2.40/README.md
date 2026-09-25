# glibc 2.40: upstream's maintained release branch, and one loader fix it lacks

Applied by `s_glibc` in stages 01 and 04 through `apply_repo_patches
"glibc-${V_GLIBC}"` (build/lib/common.sh), after the LFS FHS patch. The
whole directory is an input to those steps' fingerprints; `SHA256SUMS` is
verified before anything is applied.

## What is here

| file | what it is |
|---|---|
| `0001-release-2.40-master-cdaa5d6db08e.patch` | everything upstream has committed to `release/2.40/master` since the 2.40 tag, up to commit `cdaa5d6db08ee6d7cdcb008ae83b6fe7856291c4` (2026-09-10, 230 commits), as one diff; `NEWS` and `advisories/` left out |
| `0004-elf-Add-optimization-barrier-for-__ehdr_start-and-_end.patch` | master `81467d4b6168c7ce40d951d6b32e387109c0e5ae`, the fix for bug 33088, which was never backported to the branch; its `elf/rtld.c` hunk re-expressed for 2.40, its `sysdeps/x86_64/Makefile` hunk unmodified |

The signed tarball stays the base. `glibc-2.40.tar.xz` is verified against
the GNU keyring like every other GNU source, and its contents are
byte-identical to the tree of the `glibc-2.40` tag (`git archive glibc-2.40`
against the unpacked tarball: no differing entry), so a diff between two
commit ids is exactly a diff against the tarball.

## Why the whole branch

The 2.40 tarball is the release of July 2024. The branch has since fixed,
among much else:

| | |
|---|---|
| CVE-2025-0395 | `assert`: under-allocated buffer for the failure message |
| CVE-2025-8058 (bug 33185) | `regcomp`: double free after an allocation failure |
| CVE-2025-15281 (bug 33814) | `wordexp`: fields not reset with `WRDE_REUSE` |
| CVE-2026-0861 | `memalign`: the alignment overflow check, reinstated |
| CVE-2026-0915 | `getnetbyaddr`: the NSS DNS backend |
| CVE-2026-4046 | iconv: pending character state in IBM1390 and IBM1399 |
| CVE-2026-4437, CVE-2026-4438 | the resolver: record counting, hostname validity |

(CVE-2025-4802 appears on the branch only as a test; its fix predates 2.40.
CVE-2025-5702 and CVE-2025-5745 are ppc64le string functions.)

Picking fixes one by one would mean guessing which of the 230 commits each
depends on. The branch is what upstream maintains and tests as 2.40.

`NEWS` is left out because the branch's has a 2.40.1 section the tarball's
lacks, so its hunks cannot apply; it changes no code. `advisories/` is
upstream's own record of its security advisories, text only, which the
branch reorganises; nothing builds from it.

## 0004: the loader's own map bounds (bug 33088)

Without it, `pthread_exit()`, `pthread_cancel()` and `backtrace()` abort
with no message: `_dl_find_object` attributes every object loaded after
startup to `ld-linux-x86-64.so.2` itself, so libgcc's unwinder reads ld.so's
`.eh_frame`, finds no FDE and calls `abort()`. Bug 31943 (an ld.so mapped
with gaps between its LOAD segments) gives the same symptom; its fix is on
the branch, in 0001, but it was not the cause here.

**Bug 33088**: the loader stores its own map bounds -
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
`asm` barriers (GCC bug 120653 records the compiler side). It was never
backported to `release/2.40/master`, and is not on it at `cdaa5d6d`.

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

Both patches apply with `patch -p1 -F0` (no fuzz), 0004 on top of 0001; 0004
lands at a line offset because the branch changed `elf/rtld.c` above it.

## How they were authenticated

**0001.** A git commit id is a hash of the tree it names and of its whole
history, so two hosts that answer with the same id for a branch are serving
the same content. On 2026-09-19:

    git ls-remote https://sourceware.org/git/glibc.git refs/heads/release/2.40/master
    git ls-remote https://gitlab.com/gnutools/glibc   refs/heads/release/2.40/master

both answered `cdaa5d6db08ee6d7cdcb008ae83b6fe7856291c4`. GitHub's
`bminor/glibc` answered `9fe8576664d43b87ca19401fb6a975e217e47623`, which is
an ancestor of it, twelve commits behind (2026-01-20): a lagging mirror, not
a disagreement. The patch is then a function of two commit ids and nothing
else:

    git -c core.abbrev=40 diff --full-index --no-renames --no-ext-diff --no-color \
        glibc-2.40..cdaa5d6db08ee6d7cdcb008ae83b6fe7856291c4 \
        -- . ':!NEWS' ':!advisories' > 0001-release-2.40-master-cdaa5d6db08e.patch

`--full-index` and `core.abbrev=40` keep the `index` lines from depending on
how many objects the clone happens to hold, and `--no-renames` keeps patch(1)
from having to understand git's rename headers, so anyone with a clone gets
these bytes. The range contains no binary change and no mode-only change
(`git diff --numstat` and `--summary` over the same range), which patch(1)
could not have carried. `UPSTREAM-SHA256SUMS` records the sha256 of that
command's output; it equals the file's entry in `SHA256SUMS`, because nothing
was edited afterwards.

The check that the patch is the branch and nothing else: unpack the tarball,
apply the LFS FHS patch, 0001 and 0004, and `diff -r` the result against
`git archive cdaa5d6d`. The only files that differ are the five the FHS
patch touches (`Makeconfig`, `nscd/nscd.h`, `nss/db-Makefile`, the two
`paths.h`) and the two 0004 touches (`elf/rtld.c`,
`sysdeps/x86_64/Makefile`), plus `NEWS` and `advisories/`.

**0004.** Fetched on 2026-09-13 from both
`https://sourceware.org/git/?p=glibc.git;a=patch;h=<commit>` and
`https://github.com/bminor/glibc/commit/<commit>.patch`; the diff bodies
(everything from the first `diff --git`, minus the `index` lines the two
hosts abbreviate differently, and minus the trailing format-patch signature
only sourceware appends) were byte-identical. `UPSTREAM-SHA256SUMS` records
the sha256 of sourceware's output as fetched. To re-derive it: in the
`rtld.c` hunk replace `_dl_rtld_map` with `GL(dl_rtld_map)` and regenerate
it against 2.40's `elf/rtld.c`; the Makefile hunk is sourceware's verbatim.
The `[Kryptik: ...]` line in its mail header records the same thing in the
file itself.

## Moving the pin along the branch

Re-run the two `ls-remote` commands; take the newest commit two hosts agree
on; regenerate 0001 with the command above; rename the file for the new
commit; regenerate `SHA256SUMS` and the 0001 line of `UPSTREAM-SHA256SUMS`;
confirm `patch -p1 -F0` still applies 0001 and then 0004 to the unpacked
tarball after the FHS patch; repeat the `diff -r` check. The toolchain
rebuilds from stage 01, because its glibc is this glibc.

## Tests

`make test-libc-unwind` (tools/test-libc-unwind.sh, against the target glibc
inside the chroot) probes the three unwinding entry points, asks
`_dl_find_object` which object it blames for a dlopened address, and reads
the loader's map start back through `LD_TRACE_LOADED_OBJECTS`. Without 0004
it fails, with the loader blaming itself.
