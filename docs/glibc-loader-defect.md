# The glibc loader defect: no unwinding after dlopen

> **Resolved 2026-09-13**; see "Resolution" at the end. The mechanism
> described below was the first hypothesis. The loader was contiguous after
> all, and the defect was glibc bug 33088 (a compiler-side hazard in the
> loader's own startup), fixed by `build/patches/glibc-2.40/0004-*.patch`.

Written 2026-09-11, while the kernel build was blocked on it. The kernel's
earlier blocker, its need for `bc`, which Kryptik pinned none of, had just
been resolved: signature-verified GNU bc 1.07.1 was pinned, fetched and
built, and stage 05 got past `timeconst.h`.

## The defect

A six-line program aborts on Kryptik:

```c
#include <pthread.h>
static void *w(void *a) { pthread_exit(NULL); }
int main(void) { pthread_t t; pthread_create(&t,0,w,0); pthread_join(t,0); }
```

```
Aborted (core dumped)     # rc=134, no message, 0 of 5 runs succeed
```

So does `pthread_cancel()`. So does `backtrace()`. The same programs run
correctly on the build host's glibc 2.39.

## Why

glibc implements `pthread_exit`, `pthread_cancel` and `backtrace` by
`dlopen`ing `libgcc_s.so.1` at the moment it needs them and forcing a stack
unwind through it. libgcc's unwinder asks the loader which object owns an
address, and where that object's `.eh_frame` is. Ours answers wrongly:

| `_dl_find_object(addr inside a **dlopened** libgcc_s)` | answer |
|---|---|
| Kryptik, glibc 2.40 | `/lib64/ld-linux-x86-64.so.2` ← the loader |
| Build host, glibc 2.39 | `/lib/x86_64-linux-gnu/libgcc_s.so.1` |

The unwinder believes that answer, reads the dynamic loader's `.eh_frame`,
finds no FDE for an address that is not in the loader at all, and libgcc calls
a bare `abort()` — no message, which is why this was invisible.

Only objects loaded **after** startup are affected. The same probe resolves
correctly when `libgcc_s.so.1` is present from the start, which is why C++
exceptions work (they link it via `DT_NEEDED`) while `pthread_exit` does not.

### What it is not

- Not a missing or broken `libgcc_s.so.1`. It is installed, `ldconfig` finds
  it, `dlopen` + `dlsym` resolve every `_Unwind_*` symbol, and
  `_Unwind_Backtrace` called directly walks both the main and thread stacks
  exactly like the host.
- Not the static-TLS surplus — `glibc.rtld.optional_static_tls` at 512, 4096
  and 16384 all abort, and the host's libgcc has the identical `PT_TLS`
  segment.
- **Not glibc BZ #32245.** That bug ("addition overflow in
  `_dl_find_object_update_1`") looked like an exact match by title and is
  fixed on the 2.40 stable branch, but commit `626c048f32` only adds
  `__builtin_unreachable` to silence a `-Wstringop-overflow` warning on hppa.
  It changes no behaviour on x86-64. Reading the patch rather than the summary
  is what ruled it out.

### It is every object, not just libgcc_s

Probing four libraries through the sysroot's own loader — no chroot needed:

```
$SYSROOT/lib/ld-linux-x86-64.so.2 --library-path $SYSROOT/usr/lib:$SYSROOT/lib ./dlfo2     libgcc_s.so.1 libz.so.1 libncursesw.so.6 libcrypto.so.3

  startup: main program      -> <main>                        correct
  startup: libc (printf)     -> .../usr/lib/libc.so.6         correct
  dlopened libgcc_s.so.1     -> .../lib/ld-linux-x86-64.so.2   WRONG
  dlopened libz.so.1         -> .../lib/ld-linux-x86-64.so.2   WRONG
  dlopened libncursesw.so.6  -> .../lib/ld-linux-x86-64.so.2   WRONG
  dlopened libcrypto.so.3    -> .../lib/ld-linux-x86-64.so.2   WRONG
```

The same binary against the host's glibc 2.39 names every library correctly.

So this is not about libgcc_s. Objects present at startup resolve correctly and
*every* object loaded afterwards resolves to the dynamic loader. That points at
the dlopen-time update of the mapping table `_dl_find_object` consults
(`_dl_find_object_update`) rather than at any per-library condition: the array
appears never to gain the new entry, and the lookup instead lands on an entry
whose recorded range wrongly covers the new mapping.

It also means the blast radius is wider than unwinding. Anything that asks the
loader which object an address belongs to gets the wrong answer for anything
dlopened — plugins, `dladdr`-based diagnostics, profilers, crash handlers.

### What is not yet known

The cause **inside** glibc. Established: the behaviour, that it is
deterministic, and that stock 2.39 does not do it. Our glibc is 2.40 with only
the FHS patch, configured `--enable-stack-protector=strong --enable-cet`,
built with `-O2 -fstack-protector-strong -fcf-protection=full`.

The first thing to check next is the `--enable-cet` / `__CET__` mismatch that
`s_glibc`'s own comment describes: our GCC is not `--enable-cet-default`, so
glibc's configure decides CET support is absent, while `-fcf-protection=full`
in CFLAGS defines `__CET__` per translation unit. `CET_ENABLED` is derived
from `__CET__` in `sysdeps/x86_64/sysdep.h`, so translation units can disagree
about it. x86-64's `link_map_machine` has no CET-conditional field — that much
has been checked and is why this is a lead rather than a conclusion — but
other loader structures have not been.

## Why it matters beyond the kernel build

This is a property of the **shipped** system, not of the build. Any Kryptik
program that calls `pthread_exit`, `pthread_cancel` or `backtrace` without
already linking `libgcc_s.so.1` dies on `SIGABRT` with no message. That is a
large class of ordinary software.

## What has been done about it

Not a fix — a workaround, plus a test that refuses to let it stay invisible:

- `build/stages/05-kernel.sh` exports
  `HOSTLDFLAGS="-Wl,--no-as-needed -lgcc_s"`, so the kernel's build-time host
  tools link libgcc_s at startup and resolve correctly. This unblocks the
  kernel link and nothing else. It is commented as a workaround at the point
  of use.
- `tools/test-libc-unwind.sh` (`make test-libc-unwind`) probes all three
  entry points, then asks `_dl_find_object` directly and prints which object
  it blamed. It carries positive controls in both directions — a program
  returning 0 must be seen passing, a deliberate `abort()` must be seen
  failing — so a harness that has stopped detecting anything says so. It
  scores 6/6 on the host's glibc 2.39 and is expected to fail on Kryptik until
  glibc is fixed.

## Open questions at the time

- Whether a glibc newer than 2.40, or a specific upstream commit, addresses
  `_dl_find_object` for objects loaded after startup. The answer has to come
  from reading the patch, not the bug title; that is what BZ #32245 cost.
- Whether Kryptik could ship with this defect present. The answer was no.

A glibc change invalidates only the `glibc` step's fingerprint, not the steps
after it (those hash prior step *names*, not their outputs), so a corrected
glibc can be rebuilt and reinstalled without rebuilding the whole base system.

## Resolution (2026-09-13)

Two upstream loader bugs produce the symptom above. The first hypothesis -
glibc bug 31943, an ld.so mapped with gaps between its LOAD segments - was
backported (`build/patches/glibc-2.40/0001..0003`) and made no difference:
`make test-libc-unwind` still failed 4 of 6, and `/proc/PID/maps` showed the
loader mapped in five abutting ranges with no gap for anything to land in.
The read that closed it, all inside the chroot against the stage 04 loader:

```
_dl_find_object((void *) 0x1000)     -> 0  map=[(nil),0x779f1bb562d8) name=/lib64/ld-linux-x86-64.so.2
_dl_find_object((void *) 0x10000000) -> 0  map=[(nil),0x779f1bb562d8) name=/lib64/ld-linux-x86-64.so.2
LD_TRACE_LOADED_OBJECTS=1 ./probe    ->    /lib64/ld-linux-x86-64.so.2 (0x0000000000000000)
```

The loader records its own map as `[0, l_addr + _end)`. Its map end is
right; its map start, `&__ehdr_start`, is 0. In `elf/rtld.os`:

```
d64:  movq   .data.rel.ro.local+0x14(%rip),%xmm2    # the top of _dl_start
d92:  lea    __ehdr_start-0x4(%rip),%rdx            # PC-relative: correct
RELOCATION RECORDS FOR [.data.rel.ro.local]:  0x18  R_X86_64_64  __ehdr_start
```

GCC 14 at `-O2` SLP-vectorised the two adjacent stores of the loader's map
bounds (`l_map_start = &__ehdr_start; l_map_end = _end;` in the always-inlined
`_dl_start_final`), took `&__ehdr_start` from a `.quad` in
`.data.rel.ro.local` - a word that needs a run-time relocation - and hoisted
that load to the entry of `_dl_start`, above `ELF_DYNAMIC_RELOCATE`. Before
the loader relocates itself the word holds the link-time value, 0. Every
address below libc that belongs to no initially loaded object then falls
inside `[0, _end)` and is attributed to ld.so; every later `dlopen` is mapped
exactly there. Recompiling `rtld.c` with `-fno-tree-slp-vectorize` or `-O1`
removed the relocated constant; removing each hardening flag in turn did not.

This is glibc bug 33088 (GCC bug 120653 on the compiler side), fixed upstream
for 2.42 by H.J. Lu with two `asm` barriers, never backported to 2.40.
`build/patches/glibc-2.40/0004-elf-Add-optimization-barrier-for-__ehdr_start-and-_end.patch`
carries it, re-expressed for 2.40's `GL(dl_rtld_map)` spelling. With it,
`rtld.os` takes both addresses with `lea` and has no `R_X86_64_64` against
either symbol.

What holds it closed: `s_glibc` in stages 01 and 04 runs upstream's
`make check` rule itself (`readelf -rW elf/rtld.os` must show no
`R_X86_64_64` against `__ehdr_start` or `_end`), stage 04 reads the
installed loader's own map start back through `LD_TRACE_LOADED_OBJECTS` and
fails if it is 0, and `tools/test-libc-unwind.sh` does the same on the
finished system before probing `pthread_exit`, `pthread_cancel`, `backtrace`
and `_dl_find_object`. The kernel stage's `HOSTLDFLAGS` workaround is gone:
`scripts/sorttable` ending its threads with `pthread_exit()` is now part of
the proof.

One correction to the text above: the note that a glibc change invalidates
only the `glibc` step was written before stamps chained their predecessors'
fingerprints (`deps=` in `stamp_fingerprint`). It now invalidates every step
after it, in stage 01 and everything built on it, and that rebuild is what
proved the fix.
