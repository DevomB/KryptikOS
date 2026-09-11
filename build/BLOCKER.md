# build → integration / provenance: one blocker, and it is small

Written 2026-09-11 ~07:10 local by the build tab.
Build branch `overnight/build-2026-09-11`, worktree
`/home/devomb/kryptik-overnight-2026-09-11/worktrees/build`.

## The blocker: the kernel needs `bc`, and Kryptik pins none

Stage 05 completed `unpack`, `patch`, `config` and `compiler-check`, then
stopped:

```
/bin/sh: line 1: bc: command not found
make[2]: *** [Kbuild:24: include/generated/timeconst.h] Error 127
```

`linux-6.18.50/Kbuild:21` is:

```make
filechk_gentimeconst = echo $(CONFIG_HZ) | bc -q $<
```

and `arch/x86/kernel/asm-offsets.s` depends on that header, so every kernel
build needs it. Verified:

| | |
|---|---|
| `bc` in the sysroot | absent |
| `V_BC` in `versions.env` | absent |
| `bc-*` tarball in `sources/` | absent |
| `bc` in `sources.lock` | absent |

## Why the build tab did not just fix it

Adding it needs three files this tab does not own:

* `build/config/versions.env` — a `V_BC` pin
* `tools/fetch-sources.sh` — a manifest entry (a source-verification tool)
* `sources.lock` — an audited checksum line, which `docs/supply-chain.md`
  requires a human to audit against upstream signatures

The stage 04 recipe is one line and **is** this tab's to write; it is given
below, ready to paste, so the change is a pin plus a lock line plus a paste.

## What was deliberately not done instead

* **Building the kernel on the host.** The host has `bc`. It also has a
  different compiler, and stage 05 exists to build the kernel with the *target*
  toolchain — its `compiler-check` step asserts `gcc -dumpmachine` is
  `x86_64-kryptik-linux-gnu` before anything compiles. Using the host would
  defeat the stage.
* **Copying the host's `bc` into the chroot.** The chroot's PATH excludes the
  host deliberately, so that a build reaching a host binary fails loudly. The
  host `bc` is also dynamically linked against the host glibc.
* **Writing a shim.** `timeconst.bc` is a real program computing real
  constants from `CONFIG_HZ`. A stand-in would be fabricated build output.

## The change, in full

`build/config/versions.env`:

```sh
# Required by the kernel build: linux-6.18.50/Kbuild generates
# include/generated/timeconst.h with `bc -q`, and asm-offsets depends on it.
V_BC=1.07.1
```

`tools/fetch-sources.sh` — a GNU mirror entry alongside the other GNU
packages (`bc-1.07.1.tar.gz`, `${MIRROR_GNU}/bc/bc-1.07.1.tar.gz`), then
`make lock` and audit the new line.

`build/stages/04-base-system.sh` — in the `PACKAGES` array, **before** `kmod`
and anywhere after `flex`/`bison` (bc needs both, and both are already
earlier):

```sh
    # Build-time requirement of the kernel, not a shipped convenience:
    # linux/Kbuild generates include/generated/timeconst.h with `bc -q`, and
    # arch/x86 asm-offsets depends on that header. Without it stage 05 dies at
    # "bc: command not found" after the config step has already succeeded.
    "bc"          "native_build bc-${V_BC}.tar.gz bc-${V_BC} --with-readline"
```

`flex` and `bison` are at positions 16 and 3, so bc has what it needs
wherever it lands after those. Drop `--with-readline` if readline's position
is inconvenient; the kernel only ever calls `bc -q` non-interactively.

## Everything else is done and waiting

Stage 04 is **complete** (63/64; `man-db` is unwired and reported as such,
because it needs `gdbm`, which Kryptik also does not pin — same class of
problem, separately recorded).

The sysroot is finished, bootable-shaped, and manifested. `build/HANDOFF.md`
§7 has the paths, the digest and the exact commands. You can boot it on your
existing kernel today:

```sh
make vm-boot KERNEL=<your stock bzImage> \
             SYSROOT=/home/devomb/kryptik-overnight-2026-09-11/work/sysroot
```

That turns `boot-smoke.sh`'s `PASSED (HARNESS ONLY)` into a real Kryptik
userspace on a stock kernel — `/etc/os-release` carries
`BUILD_ID=2501ecf214b108f1f193ff44ec768df5716146de`, so the image says which
commit produced it rather than needing a marker file. It does not yet get you
the *kernel* half of the claim, which is what `bc` blocks.
