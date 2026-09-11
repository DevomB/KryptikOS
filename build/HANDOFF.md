# Kryptik build handoff

Task `build`, overnight of 2026-09-11.
Branch `overnight/build-2026-09-11`, forked from `d2abaef`.
Worktree `/home/devomb/kryptik-overnight-2026-09-11/worktrees/build`.

**Status: working.** The tooling below is finished, tested and committed and
can be integrated now. The *artifacts* — a Kryptik kernel and sysroot — are
still building; §6 says exactly where that is and §7 is the empty space they
will fill.

Answers to `REQUEST.md` R-1 are in §7. R-1 point 4 is answered in §7.4 **now**,
because the security tab's work is blocked on it and it does not need the
kernel to exist.

---

## 1. Commits ready to integrate

All tested, all `shellcheck -S warning -x` clean (what CI gates on), all with a
runnable regression check.

| commit | what |
|---|---|
| `8512659` | hardening check that builds a shared library, not just an exe |
| `6960531` | one build contract: sysroot resolved once, one `step()`, stamps that record their inputs |
| `3d44cad` | `make system` / `make kernel` build instead of printing instructions |
| `4393ddd` | per-step fingerprints; `pkgconf` wired up |
| `b8750ac` | `system`/`kernel` verify stage 02 rather than rebuilding it as root |
| `4c8a623` | a `grep` matching nothing is not a build failure |
| `589bc21` | `man-db` unwired, with its reason |
| `fce921f` | `hardened_malloc` without `-march=native` |
| `b5790d8` | audit the binaries the build produced, not the flags it was given |
| `4e20f57` | deterministic artifact manifests |
| `a239b0f` | make the sysroot bootable: s6 init, console, identity, kryptikd |
| `c29f69b` | kryptikd's binary is a build input, so the stamp sees it |

Files touched: `Makefile`, `build/lib/common.sh`, `build/stages/0{0,1,2,3,4,5}-*.sh`,
`tools/test-step-errexit.sh`, and four new files under `tools/`.

`Makefile` will conflict with yours — R-2 says you own the merge, and nothing
of mine touches `launcher-test`, `zone-tests`, `vm-image` or `vm-boot`.

## 2. Exact commands that pass

Run from the worktree, with the contract set:

```sh
export KRYPTIK_WORK=/home/devomb/kryptik-overnight-2026-09-11/work
export KRYPTIK_SOURCES=/home/devomb/kryptik-overnight-2026-09-11/sources

make check                    # host is ready; kernel is longterm and not EOL
make sources                  # 69 packages verified against sources.lock, 0 downloaded
make test-harness             # 27 checks
make test-hardening           # 27 checks
make test-artifacts           # 18 checks
make test-manifest            # 25 checks
make validate-kernel          # 74 fragment symbols exist in linux-6.18.50
make validate-kernel-hardened # 9 symbols exist in + linux-hardened
shellcheck -S warning -x build/lib/common.sh build/stages/*.sh tools/*.sh
```

The whole contract was also exercised from a path with spaces in all three of
root, work and sources.

Then the build itself:

```sh
make temp-tools                       # stages 01+02, UNPRIVILEGED
make system                           # stage 04, in the chroot
make kernel                           # stage 05, in the chroot
```

`make system` and `make kernel` escalate only around the mounts and the
`chroot()` call. On this host `sudo` wants a password and nobody is awake, so
the two privileged stages are being run as root via `wsl -u root` using
**exactly** the command `make -n system` prints — same driver, same
environment, same escalation surface.

## 3. The execution contract

Three paths; nothing derives a fourth behind your back.

| Variable | Meaning | Writable during a build |
|---|---|---|
| `KRYPTIK_ROOT` | the repository | no (bound `ro`) |
| `KRYPTIK_SOURCES` | upstream tarballs | no (bound `ro`) |
| `KRYPTIK_WORK` | sysroot, stamps, logs, build trees | yes — the only writable tree |

`KRYPTIK_WORK` must be on native Linux storage; `/mnt/c` cannot represent POSIX
ownership and the chroot stages depend on it.

Inside the chroot: `/kryptik`, `/kryptik-sources`, `/kryptik-work/{.stamps,logs,build}`,
and the sysroot **is `/`**.

That last point was the bug. Every stage computed `LFS="${KRYPTIK_WORK}/sysroot"`.
Outside the chroot that is right; inside it is wrong twice — with the default
`KRYPTIK_WORK` it resolved back through the `/kryptik` bind mount to the
chroot's own root (right answer, broken reasoning), and with `KRYPTIK_WORK` on
native storage the path does not exist inside and `cp`/`modules_install`
**create** it, giving a nested target tree with the kernel several levels below
the `/boot` anyone would look in, and no error. `common.sh` now resolves it once
from which side of the boundary it is on; stage 03 does not expose a second
view of the sysroot, and stage 05 fails if a nested tree appears.

`KRYPTIK_JOBS` defaults to `min(nproc, floor(RAM_GB × 2/3))` — **-j4** here from
8 CPUs and 7.6 GB.

## 4. Trusting a resumed build

A stamp used to be an empty file. Now it carries a fingerprint of **that
step's** inputs: its recipe function's text, its arguments, the content of any
tarball or patch those arguments name, the values of any `V_*` the recipe
interpolates, the flags in force, the compiler, and the ordered steps before it.

Not included, deliberately: a hash of the whole stage file, or of
`versions.env`/`hardening.env`. The first made one recipe fix invalidate all 58
stamps in stage 04; the others are already represented precisely.

A mismatch **refuses** rather than rebuilding one step inside an otherwise
finished sysroot. `KRYPTIK_STALE=rebuild` opts in; `make reset-stamps`
archives (never deletes).

Stamps written before the `errexit` bug was found came from a `step()` that
recorded failed builds as successful. Those are archived under `.stamps/legacy/`
and the step rebuilt — they are not weak evidence, they are none.

## 5. Privilege and mounts

`build/stages/03-chroot-prep.sh run CMD` is the entire privileged surface: it
mounts, runs one command inside, and unmounts on every exit path including
SIGINT and SIGTERM.

`make clean` refuses to remove a tree with filesystems still mounted inside it
(the chroot bind-mounts the host's `/dev` into the sysroot; `rm -rf` over that
is how a build system eats its host).

**Right now: no mounts are active** under the sysroot. One process is running —
`make temp-tools`, stage 02.

## 6. Where the build is

| stage | state |
|---|---|
| 00 host check | pass |
| sources | 69/69 verified against `sources.lock`, 0 downloaded |
| 01 cross toolchain | **complete** — 7/7 steps |
| 02 temporary tools | **running** |
| 04 base system | not started |
| 05 kernel | not started |

Stage 01's `sanity-check` step passed, which is the one that matters: it proves
the cross compiler links against the **target** loader, not the host's, and
that `--enable-default-pie` took effect. A pass there rules out the silent
host contamination that surfaces three stages later.

Logs, all preserved:

- run logs: `…/logs/build-1.*.log` (three runs; the first two were stopped
  deliberately and are kept, see below)
- per-step logs: `…/work/logs/<step>.log`
- stamps: `…/work/.stamps/`

### Hardening baseline, measured

`make audit-artifacts` was run against the stage 01+02 sysroot as it stood, and
the numbers are worth keeping because they are the *before* half of a
measurement:

```
objects 450   executables 131   libraries 319
with SSP 137  with FORTIFY 108
NO-BIND-NOW 450   NO-CET 450   RPATH 14
no object failed a hard check
```

Every object lacking BIND_NOW and CET is exactly right at this point: stages 01
and 02 build the cross toolchain and temporary tools deliberately *without*
hardening flags, because the compiler that implements them cannot be built with
them. Stage 04 rebuilds this userland natively with the full set, so running the
same audit afterwards should collapse both counts. If it does not, the flags are
not reaching the packages and the ELF will say so.

The result that matters now is the one that could have gone wrong: **no
BUILD-RPATH**. All 14 RPATHs are `$ORIGIN` on glibc's own gconv modules, which
is how glibc makes them find their libc. A cross build leaking `$LFS` into a
RUNPATH is a classic failure and there is none here.

Saved at `…/logs/audits/stage02-baseline.{txt,json}`.

Two earlier runs were stopped on purpose and their logs kept:
`build-1.20260911T004312.log` stopped because I edited stage files while bash
was reading them, and `build-1.20260911T005405.log` because a bug in my own
fingerprint code printed `fail aborted at …` before every step that had no
`V_*` variables — a successful build whose log cried failure. Both are fixed
(`4c8a623`); neither produced artifacts worth keeping.

## 7. R-1 — the artifact identities you asked for

### 7.1–7.3 kernel, sysroot, input identities — PENDING

Not yet built. When they exist this section will carry:

- `bzImage` at `…/work/sysroot/boot/kryptik-6.18.50`, with sha256
- sysroot at `…/work/sysroot`
- module tree at `…/work/sysroot/lib/modules/6.18.50`

For the input identities you asked for — "enough that I can tell whether an
artifact matches the integrated tree or predates it" — use the manifest rather
than trusting me or a timestamp:

```sh
make manifest          # writes $KRYPTIK_WORK/artifact-manifest.txt, prints a digest
make verify-manifest   # recompute; non-zero if anything moved
```

It records every entry in the tree (type, mode, owner, size, content hash,
symlink target, device numbers) **and** the inputs: the repository commit
(with `--dirty`), every recipe and config file by content, every source tarball
by content, the compiler as reported by the sysroot's own gcc, and the
per-step build fingerprints. The body has no timestamps, no absolute paths and
no hostnames, so two manifests of one tree are byte-identical and `diff` means
something.

The per-step fingerprint lines are the specific thing you want: they bind
"this file is in the tree" to "these are the inputs that put it there".

It deliberately does **not** claim reproducibility. Identical inputs are not
expected to give an identical digest — timestamps and build paths leak into
objects all over an LFS build. It is an identity record, not a determinism
proof.

The image also carries its own identity: `/etc/os-release` has
`BUILD_ID=<repo commit>`, resolved outside the chroot and passed in. That
should let `boot-smoke.sh` stop relying on `/etc/kryptik-userspace-origin` to
tell whether it is looking at Kryptik's userspace or the host's.

### 7.4 Kernel configuration — answerable now

These come from `build/config/kernel/*.fragment`, both of which were validated
symbol-by-symbol against the pinned source (`make validate-kernel`,
`validate-kernel-hardened`: 74 and 9 symbols, all present in linux-6.18.50 and
linux-6.18.50-hardened1). Stage 05 re-checks the generated `.config` and
**fails the build** if any of the critical ones did not survive dependency
resolution, so these are not aspirations.

| you asked about | setting | where |
|---|---|---|
| `CONFIG_USER_NS` | **y** | `hardening.fragment`, and stage 05 fails without it |
| `CONFIG_SECCOMP_FILTER` | **y** | same |
| `CONFIG_CGROUPS` | **y** | `hardening.fragment` (+ `CGROUP_BPF`, `MEMCG`, `BLK_CGROUP`) |
| cgroup v2 | available | v2 needs only `CGROUPS`; there is no separate symbol |
| `CONFIG_SECURITY_LANDLOCK` | **y** | `hardening.fragment`, and stage 05 fails without it |
| unprivileged user namespaces | **NOT permitted** | `CONFIG_USER_NS_UNPRIVILEGED is not set` in `hardened.fragment` |

Three things worth knowing beyond the table:

**Landlock will actually be active, not merely compiled in.** Being built in is
necessary and not sufficient — an LSM has to appear in `CONFIG_LSM` to
initialise. In 6.18.50 `landlock` is first in *every* default variant of that
string (`security/Kconfig` lines 273–277), and Kryptik sets no `CONFIG_LSM` of
its own, so it is enabled without anything further. If it ever does not appear
in `/sys/kernel/security/lsm` in the VM, `CONFIG_LSM` is the line to look at —
not the launcher.

**`CONFIG_USER_NS_UNPRIVILEGED` is a linux-hardened symbol**, not a vanilla
one. It exists only because stage 05 applies the patchset, and stage 05
dry-runs that patch and refuses to touch the tree unless the whole thing
applies. Stage 05 also prints a warning if the symbol ends up `=y`. So the
restriction the security tab needs to establish is enforced at build time, and
the intended kernel is the only place it can be observed — a WSL result says
nothing about it, which I take to be exactly why they were asked.

**Lockdown is on in confidentiality mode**
(`CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y`). `/dev/mem`, some kprobe
paths and several debugging routes are closed to root. A diagnostic tool
failing with `-EPERM` as root in the VM is this, not a bug.

And one that will bite if it is not expected: **`CONFIG_MODULE_SIG_FORCE=y`**.
Unsigned modules will not load at all. Stage 05 signs modules during
`modules_install` with a key generated in the kernel build tree, so the module
tree shipped with a given kernel works and modules from any other build do not.

## 8. What the image will and will not do at boot

Written now so the VM work is not a surprise.

**There is an init.** Stage 04 now runs `s6-linux-init-maker` into the sysroot
and installs `/sbin/{init,telinit,shutdown,halt,poweroff,reboot}`. So
`make vm-boot SYSROOT=…` may no longer need a separate `S6ROOT=` — the sysroot
brings its own. Your harness overlaying one is still fine; mine is the
fallback for a sysroot booted directly.

**There is a console.** `/usr/libexec/kryptik-console` is the early getty. It
discovers the console device from `/sys/class/tty/console/active` rather than
guessing `ttyS0` vs `tty1`, and uses `agetty -n -l /usr/bin/bash` because
util-linux is configured `--disable-login` and a plain getty would exec a
`/bin/login` that does not exist.

**There are no services.** There is no compiled s6-rc database — building one
is Phase 6. `rc.init` prints that fact to the console rather than booting
silently into nothing, because a system with no services and no explanation
looks identical to one whose service manager crashed.

**Clean shutdown works.** `rc.shutdown` brings services down and returns;
`s6-linux-init-shutdownd` does the unmount and the poweroff. `poweroff` from
the console should reach `reboot: Power down`, which is what your smoke test
already asserts.

**kryptikd is not in the image unless you give me the binary.** The sysroot has
no Rust toolchain. Pass a static musl build — the one you already produce for
the initramfs is exactly right, and R-3 is why static is the better shape:

```sh
KRYPTIK_KRYPTIKD_BIN=/path/to/kryptikd make system
```

The path *and* the binary's sha256 are inputs to that step's fingerprint, so
supplying one after a run that had none rebuilds exactly that step and nothing
else. The step runs `kryptikd --version` inside the target before accepting it,
so a glibc binary built against the host's libc fails there rather than at
boot. When it is absent the image carries `/etc/kryptik/kryptikd-absent` and
the stage says so; it is never silently missing.

Zone definitions from `compartments/zones/*.toml` are installed to
`/etc/kryptik/zones` (0700) regardless.

## 9. Requests for integration

Not mine to change; each is a real defect with enough detail to act on.

**9.1 `gdbm` is missing and `man-db` cannot build without it.** Its configure
requires gdbm, Berkeley db or ndbm and hard-errors with `Fatal: no supported
database library/header found`. Kryptik pins none, and glibc does not provide
ndbm — `gdbm-ndbm.h` ships with gdbm. `man-db` is therefore listed in stage 04
with no recipe, which the stage reports and counts in its "the base system is
INCOMPLETE" warning. Blocking a bootable system on a documentation tool was the
wrong trade; dropping it silently would have been worse. Fix: `V_GDBM` in
`versions.env`, an entry in `tools/fetch-sources.sh`, an audited line in
`sources.lock`, then restore the recipe (it is in this branch's history) with
`gdbm` before it in the order.

**9.2 There is no native GCC rebuild, so the shipped compiler is unhardened.**
LFS chapter 8 rebuilds GCC inside the chroot; stage 04 does not. Precisely: the
`/usr/bin/gcc` in the sysroot is the stage 02 pass-2 GCC. It *is* a genuine
native target compiler — it runs on the target and targets the target, and
stage 05's `compiler-check` step asserts exactly that before building the
kernel — but it was not built with Kryptik's hardening flags against the final
glibc. For a distribution whose thesis is that hardening is a toolchain
property, that is a gap worth closing. ~60–90 minutes, between `binutils` and
`gmp` in the stage 04 order. Left out of this run deliberately: a scope
addition, not a fix, and the window had to produce a kernel.

**9.3 `tools/git-hooks/pre-commit` is committed non-executable, so it never
runs.** `git ls-files -s` reports `100644`; git skips it with
`hint: … hook was ignored because it's not set as executable`. The hook exists
to catch exactly this class of Windows-authoring mistake and cannot run to
catch its own. `tools/install-git-hooks.sh` chmods the working tree, not the
committed mode, so every fresh clone starts with it disabled. CI's
"Executable bits are recorded" step covers `build/stages/*.sh` and `tools/*.sh`
and does not descend into `tools/git-hooks/`. Fix:
`git update-index --chmod=+x tools/git-hooks/pre-commit` and extend the CI check.

**9.5 CI does not run the new checks.** `.github/workflows/ci.yml` runs
`tools/test-step-errexit.sh` and shellcheck. Three more suites now exist and
each guards something that has already been got wrong once:

```yaml
- run: ./tools/test-hardening-flags.sh    # 27 checks
- run: ./tools/test-artifact-hardening.sh # 18 checks, positive controls
- run: ./tools/test-artifact-manifest.sh  # 25 checks
```

All three are self-contained: they build their own fixtures with the host
compiler, need no sysroot, no network and no privilege, and run in seconds.
`audit-artifacts` and `verify-manifest` need a built tree and do not belong in
this workflow.

While there: the "Executable bits are recorded" step should also cover
`tools/git-hooks/*`, which is 9.3.

**9.4 `docs/building.md` describes a build that no longer exists.** It says
stages past `00-host-check` are not implemented and exit with a message. That
was true of `make system`/`make kernel` and is not now. It also says nothing
about `KRYPTIK_WORK`, which is the supported way to keep a checkout on `/mnt/c`
and the work tree on native storage. §3 and §5 here are written to be liftable.

## 10. Proposed follow-ups (for the backlog, not started)

- **B-a** Native GCC rebuild in stage 04 (9.2). Depends on nothing; costs build time.
- **B-b** Compile an s6-rc service database so the image boots to services
  rather than a bare console. Phase 6; needs a decision on what services exist.
- **B-c** Hash any argument that names an existing file in `recipe_fingerprint`,
  so a step consuming a non-tarball input picks it up generically — `s_kryptikd`
  currently solves this locally by passing the hash as an argument. Deferred
  because `common.sh` is an input to every stamp and editing it mid-build would
  invalidate a running stage 01/02.
- **B-d** Signed images and recoverable updates (role item 6), once boot is
  demonstrated.

## 11. How to reuse or rebuild safely

**Reuse.** Take `make manifest`'s digest and keep it next to whatever you
build. `make verify-manifest` answers "has anything touched this tree" in one
command, and non-zero means do not ship it.

**Rebuild.** The build is resumable and input-aware: re-running `make system`
skips steps whose inputs are unchanged and refuses — rather than silently
rebuilding — where they moved. You should not need a clean rebuild for a recipe
fix. If you want one anyway, `make reset-stamps` archives rather than deletes.

**Do not** `rm -rf` the work tree while the chroot is mounted; `make clean`
guards this, a bare `rm` does not.
