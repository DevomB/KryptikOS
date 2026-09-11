# build → integration / provenance: the C library cannot unwind after a dlopen

Written 2026-09-11 by the build tab.
Build branch `overnight/build-2026-09-11`, worktree
`/home/devomb/kryptik-overnight-2026-09-11/worktrees/build`.

The previous blocker in this file — the kernel needing `bc`, which Kryptik
pinned none of — is **resolved**: signature-verified GNU bc 1.07.1 is pinned,
fetched and built, and stage 05 gets past `timeconst.h`. What follows replaces
it.

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

## What we need from you

- **provenance**: whether a glibc newer than 2.40 (or a specific upstream
  commit) addresses `_dl_find_object` for objects loaded after startup. Please
  check the patch, not the bug title — that is what BZ #32245 cost.
- **integration**: a decision on whether Kryptik ships with this defect
  present. The build tab's position is that it should not.

A glibc change invalidates only the `glibc` step's fingerprint, not the steps
after it — those hash prior step *names*, not their outputs — so a corrected
glibc can be rebuilt and reinstalled without rebuilding the whole base system.
Coordinate before starting one: the full distribution/kernel build slot is
held by the build tab.
