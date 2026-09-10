# Hardening Rationale

Kryptik's hardening is applied at the toolchain, so it covers every package by
construction. A package cannot opt out by forgetting to set a flag.

## Toolchain flags

Defined in [`build/config/hardening.env`](../build/config/hardening.env).

| Flag | Defends against | Cost |
|---|---|---|
| `-D_FORTIFY_SOURCE=3` | Buffer overflows in libc calls, with dynamic object sizes | Negligible; requires `-O2`+ |
| `-fstack-protector-strong` | Stack smashing | ~1% CPU |
| `-fstack-clash-protection` | Stack-clash / guard-page jumping | Negligible |
| `-fcf-protection=full` | ROP/JOP via Intel CET (shadow stack + IBT) | Negligible on supporting CPUs |
| `-fPIE -pie` | Defeats fixed-address exploitation; enables full ASLR | ~2% on x86-64 register pressure |
| `-Wl,-z,relro,-z,now` | GOT/PLT overwrite | Slower startup (eager binding) |
| `-Wl,-z,noexecstack` | Executable stack payloads | None |
| `-ftrivial-auto-var-init=zero` | Uninitialized-memory disclosure | ~0.5%, occasionally more |
| `-fno-delete-null-pointer-checks` | Compiler removing NULL checks it assumes are dead | None |

### Known-incompatible packages

Some packages genuinely break under `-pie` or `-D_FORTIFY_SOURCE=3` — notably
early toolchain bootstrap stages, the kernel itself (which manages its own
hardening), and anything performing custom relocation.

The escape hatch is `build/config/hardening-exceptions.txt`: one package per
line with a **required justification comment**. An exception without a stated
reason fails the build. Exceptions are reviewed, not accumulated.

## Allocator

Kryptik ships **hardened_malloc** as the system allocator rather than glibc's.
It provides slab quarantines, guard slabs, randomized allocation, and
canary-based detection of heap overflow.

Cost: measurably slower than glibc malloc on allocation-heavy workloads. This is
an accepted tradeoff. Benchmarks belong in `docs/benchmarks.md` once there is a
bootable system to benchmark — until then, no numbers are claimed.

## Kernel

Config fragment: [`build/config/kernel/hardening.fragment`](../build/config/kernel/hardening.fragment)

Kryptik follows the Kernel Self-Protection Project recommendations, plus the
options the zone model depends on (namespaces, cgroup v2, Landlock, seccomp,
dm-verity, dm-crypt).

Notable choices:

- `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` — zeroes heap allocations, killing a broad
  class of use-after-free info leaks. Costs a few percent. Worth it.
- `CONFIG_SLAB_FREELIST_HARDENED=y` and `_RANDOM=y` — frustrates heap grooming.
- `CONFIG_SECURITY_LOCKDOWN_LSM=y` in confidentiality mode — severs root's
  ability to read kernel memory via `/dev/mem`, kprobes, or unsigned modules.
  This is what makes "root in a zone" meaningfully weaker than "kernel access".
- `CONFIG_RANDOMIZE_BASE=y` / `CONFIG_RANDOMIZE_MEMORY=y` — KASLR.
- `CONFIG_MODULE_SIG_FORCE=y` — unsigned modules do not load.
- `CONFIG_DEVMEM=n`, `CONFIG_LEGACY_PTYS=n`, `CONFIG_BINFMT_MISC=n` — attack
  surface that Kryptik does not need.
- `CONFIG_SECURITY_LANDLOCK=y` — required by the zone model, not optional.

### Runtime sysctls

Set in `build/config/sysctl.d/`:

- `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1` — no kernel pointer leaks
- `kernel.unprivileged_bpf_disabled=1` and `net.core.bpf_jit_harden=2` — eBPF is
  a well-worn LPE path
- `kernel.yama.ptrace_scope=3` — no ptrace at all after boot
- `vm.mmap_rnd_bits=32` — maximum ASLR entropy on x86-64
- `net.ipv4.tcp_syncookies=1`, `rp_filter=1` — standard network hygiene

## setuid elimination

Kryptik ships no setuid binaries where a capability or a brokered service can do
the job. `ping` gets `CAP_NET_RAW`, not setuid root. Privilege transitions go
through `kryptikd`, which is auditable, rather than through a scattered set of
setuid binaries, which is not.

Enforced by `tools/audit-setuid.sh`, which fails the build on any setuid binary
not present in an explicit, justified allowlist.

## What hardening does not do

These mitigations raise exploitation cost. They do not make the system
unexploitable, and stacking more of them has diminishing returns against an
attacker with a good kernel bug. Hardening is the second line — the
compartmentalization model in [architecture.md](architecture.md) is the first,
and the threat model in [threat-model.md](threat-model.md) says where both end.
