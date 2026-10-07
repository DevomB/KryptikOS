# A kernel built with Clang for kernel CFI

The [roadmap](../roadmap.md) asks for a kernel built with Clang for kernel
control-flow integrity, with userspace staying on GCC. `hardening.fragment`
records why there is none today: kernel CFI needs a compiler with
`-fsanitize=kcfi`, and the toolchain is GCC. This document covers the
toolchain stage Clang adds, what changes in stage 05, the checker's accepted
list and the size budget, linux-hardened under Clang, and the other road to
the same option, GCC's own kCFI. The proposed decision is ADR-019 in
[decisions](../decisions.md).

## What kernel CFI buys

kCFI puts a hash of each function's type before every function that can be
called indirectly, and a check before every indirect call. A call through a
corrupted function pointer to anything but a function of the expected type
traps. Overwriting a function pointer is among the commonest steps in kernel
exploits, and under ADR-002 a kernel privilege escalation breaks every zone
at once. On CPUs with IBT, kCFI can be patched at boot into FineIBT, which
uses the hardware's landing pads and is faster (`cfi=auto`).

## Where things stand

- **One compiler.** Stage 05 refuses any compiler but the native target GCC
  that built userspace (`s_compiler_check` in `build/stages/05-kernel.sh`),
  and `s_verify_install` fails a kernel whose banner does not name GCC.
- **GCC plugins.** `hardening.fragment` sets `GCC_PLUGIN_LATENT_ENTROPY`,
  `KSTACK_ERASE` and `RANDSTRUCT_FULL`, the last two through GCC's plugins
  today, which is why stage 05 checks that the plugin headers exist.
- **The accepted list** (`build/config/kernel/checker-accepted.txt`) carries
  `CONFIG_CFI_CLANG`, `CONFIG_CFI_PERMISSIVE`, `CONFIG_CFI_AUTO_DEFAULT` and
  the `cfi` command-line parameter, all because no CFI is built.
- **The size budget** (`build/config/kernel/size-budget`) is the measured
  21,988,352-byte bzImage plus 5 %, 23,087,770 bytes. About 18 MB of it is
  microcode, which does not compress.
- **Linux 6.18 made the option compiler-neutral.** `CONFIG_CFI` replaced
  `CONFIG_CFI_CLANG`, which is now a transitional symbol, and it depends on
  `$(cc-option,-fsanitize=kcfi)`, not on Clang (`arch/Kconfig`). On x86,
  `FINEIBT` follows from `X86_KERNEL_IBT`, `CFI` and retpolines, and
  `CFI_AUTO_DEFAULT` (default on) means `cfi=auto`; off means `cfi=kcfi`.

## Constraints

- **ADR-009.** linux-hardened, rebased on each longterm release. Arch, its
  main user, builds it with GCC, so a Clang build of it is less exercised.
- **ADR-013.** The size budget, and the rule that a larger kernel is a
  decision, not a drift.
- **ADR-001 and the supply chain.** A compiler is a source like any other:
  pinned, its signature verified, its pin reviewed.
- **Userspace stays on GCC**, as the roadmap says. Nothing Clang builds may
  reach the root image except the kernel and its modules.
- **The checker's rule.** Each finding is fixed or accepted with its reason,
  and an entry that starts passing must go.

## The two roads

### Clang for the kernel

**The toolchain stage.** LLVM and Clang are built in the chroot by stage
04's GCC, with the cmake binary the chroot already runs for json-c, the
sysroot's ninja and Python, for the x86 target alone, and installed under
`/opt/llvm`, which stage 06 leaves out of the image as it leaves out cmake.
lld is not needed: `make CC=clang` uses Clang's integrated assembler and
GNU ld, and kCFI no longer needs link-time optimisation. The version is 21
or later, since `KSTACK_ERASE` needs Clang 21's stack-depth callback
(`CC_HAS_SANCOV_STACK_DEPTH_CALLBACK`). LLVM's release tarballs are signed
by its release managers, so the source gets a manifest row, a key with a
published route to its fingerprint, and a pin review like any other.

**Build time.** LLVM and Clang are a large C++ build: hours on the Distro
workflow's four-core runners. They need a job and a cache of their own,
keyed on their version and recipe, and that cache counts against the
repository's 10 GB with the others. The same build serves Firefox's bindgen
and wasm sandbox and Mesa's AMD driver (the browser and graphics design,
`docs/design/browser-and-graphics.md`, proposed beside this one), so it is
paid once.

**Stage 05.** `s_compiler_check` accepts Clang at the pinned version and
checks that it accepts `-fsanitize=kcfi` and targets the same triple.
`s_verify_install` takes a banner naming Clang. Modules are built by the
same Clang, as kbuild requires. The fragments change:

- `CONFIG_CFI=y`; `CFI_PERMISSIVE` not set; `CFI_AUTO_DEFAULT` not set, and
  `cfi=kcfi` on the command line, which is what the checker asks for.
  FineIBT is faster on CPUs with IBT; the checker prefers kCFI's checks, and
  Kryptik follows the checker unless a measurement says the cost is
  material.
- `GCC_PLUGIN_LATENT_ENTROPY` cannot be built by Clang. It leaves the
  fragment, since stage 05 refuses a fragment line that does not survive,
  and enters the accepted list with that reason.
- `RANDSTRUCT_FULL` is native to Clang, `KSTACK_ERASE` uses the stack-depth
  callback, and `INIT_STACK_ALL_ZERO`, `ZERO_CALL_USED_REGS`, `UBSAN_BOUNDS`
  with traps, `FORTIFY_SOURCE` and the speculation mitigations
  (`MITIGATION_SLS`, `MITIGATION_RETHUNK`, retpolines) are all available.
  Every line that resolves differently shows up in `kconfig_fragment_check`,
  which is the point of that check.

**The accepted list.** `CONFIG_CFI_CLANG`, `CONFIG_CFI_PERMISSIVE`,
`CONFIG_CFI_AUTO_DEFAULT` and `cmdline cfi` start passing and are removed,
as `tools/check-kernel-hardening.sh` demands. Whether the pinned checker
reads `CONFIG_CFI` or still looks for the old name decides what it reports;
a checker that does not know the rename keeps reporting `CFI_CLANG`, and the
entry's reason then says that. `CONFIG_GCC_PLUGIN_LATENT_ENTROPY` (and
`CONFIG_GCC_PLUGINS`, if the checker asks for it) is added.

**The size budget.** kCFI adds a hash before each address-taken function and
a check at each indirect call. Code grows by a few percent, but code is the
smaller part of the image: of 22 MB, about 18 MB is microcode. A 10 % growth
of the remaining 4 MB is 0.4 MB, inside the 1.1 MB of headroom. The first
Clang build is measured, and the budget is set again from it under the same
rule, the measurement plus 5 %.

**linux-hardened under Clang.** The patch set is C with no compiler
dependency beyond what mainline has, but it is mostly tested with GCC.
Each kernel update then carries a risk of a Clang-only build failure or
warning; stage 05 and CI's kernel job find it before anything ships, and a
fix goes upstream to linux-hardened rather than into a Kryptik patch.

**Proof that CFI is live.** LKDTM, the kernel's crash tester, depends on
debugfs, which is off. Instead, a small test module ships beside the
unsigned `mac80211_hwsim` control under `/usr/lib/kryptik/kernel/`. It is
signed with the kernel and calls a function through a pointer of the wrong
type when it loads. The integrity suite loads it as root and expects the
kernel's `CFI failure` report in its log and the loading process killed.

### GCC's own kCFI

Kees Cook's kCFI patches for GCC have been reviewed, and GCC's maintainers
plan to merge them for GCC 17
([LWN](https://lwn.net/Articles/1056601/)). Because 6.18 keys `CONFIG_CFI`
on `-fsanitize=kcfi`, a GCC that has it builds the same option with no
kernel change.

- **For:** one compiler family; the GCC plugins stay, latent entropy
  included; no LLVM stage for the kernel.
- **Against:** it is in no released GCC. In GCC 17 it would be new code in
  its first release, and using it means either moving the whole toolchain
  from GCC 14 to 17 (every package rebuilt, new warnings in old code) or
  building a second GCC for the kernel alone, the same shape of cost as
  Clang.

### No kernel CFI

What Kryptik has now. The accepted list keeps its CFI entries, and a
corrupted kernel function pointer stays the easiest way through.

## Recommendation

Clang for the kernel, at version 21 or later, in an LLVM stage of its own
that also serves the browser and Mesa. `CONFIG_CFI` on, `cfi=kcfi`, latent
entropy given up and recorded, and the budget measured again. Userspace
stays on GCC.

GCC's kCFI does not change this: it is not released, and since 6.18 the
option is the same whichever compiler provides it. When GCC 17 ships kCFI
and Kryptik's toolchain reaches it, the kernel can return to GCC with no
configuration change, and the LLVM stage stays only if something else still
needs it.

## The check that proves it done

- Stage 05 builds the kernel with the pinned Clang, refuses any other
  compiler, and its banner names it.
- The resolved configuration has `CONFIG_CFI=y`, `CFI_PERMISSIVE` and
  `CFI_AUTO_DEFAULT` off, and the command line carries `cfi=kcfi`.
- `make check-kernel-hardening` passes with the CFI entries gone from the
  accepted list and latent entropy accepted with its reason.
- The bzImage is within the re-measured budget.
- Every VM suite boots the Clang kernel, and the integrity suite's CFI probe
  module traps when loaded.
- Nothing under `/opt/llvm` is in the root image, and the artifact audit's
  view of userspace is unchanged.
