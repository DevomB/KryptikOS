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
| *(PIE)* | Defeats fixed-address exploitation; enables full ASLR | ~2% on x86-64 register pressure |
| `-Wl,-z,relro,-z,now` | GOT/PLT overwrite | Slower startup (eager binding) |
| `-Wl,-z,noexecstack` | Executable stack payloads | None |
| `-ftrivial-auto-var-init=zero` | Uninitialized-memory disclosure | ~0.5%, occasionally more |
| `-fno-delete-null-pointer-checks` | Compiler removing NULL checks it assumes are dead | None |

### PIE comes from the compiler, not from flags

`-fPIE` and `-pie` are deliberately **absent** from `hardening.env`. Kryptik's
GCC is configured `--enable-default-pie`, so executables are position-independent
without them — confirmed by stage 01's sanity check and directly:

```
$ gcc <hardening flags, no -pie> -o exe exe.c
$ readelf -h exe   ->  Type: DYN (Position-Independent Executable file)
$ readelf -d exe   ->  FLAGS_1: NOW PIE
```

Carrying them anyway is not merely redundant, it is destructive. `-pie` makes
the linker pull in `Scrt1.o`, the executable startup object, which references
`main()`. A shared library has no `main`, so every `.so` fails to link:

```
ld: Scrt1.o: in function `_start`: undefined reference to `main`
```

This was found when Python — the first package in the build order that produces
a `.so` — failed on it. Every library after it would have failed identically.
The tempting fix, a per-package hardening exception, would have meant an
exception for nearly every package in the distribution; the flags were wrong,
not the packages.

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

## Zone syscall filtering

Every zoned process runs under a default-deny seccomp-bpf filter
(`compartments/kryptikd/src/seccomp.rs`). The allowlist names roughly 150
syscalls covering file and socket I/O, memory, process lifecycle, signals and
time; anything unnamed is `SECCOMP_RET_KILL_PROCESS`.

Verified blocked, by killing a real process rather than by inspection:

| Syscall | Why it is denied |
|---|---|
| `setns` | **enters another zone's namespaces** — defeats requirements 1–4 in one call |
| `ptrace`, `process_vm_readv/writev` | read or write another process's memory |
| `mount`, `umount2`, `pivot_root`, `chroot` | remount the filesystem out from under Landlock |
| `unshare` | nested namespaces; a known LPE surface |
| `bpf`, `perf_event_open` | long histories of privilege escalation |
| `userfaultfd` | reliable kernel heap-grooming primitive |
| `keyctl`, `add_key`, `request_key` | kernel keyring, repeated CVEs |
| `init_module`, `finit_module`, `kexec_load` | load kernel code |

Two details that decide whether such a filter works or merely looks like it
does. The x32 ABI reuses x86-64 syscall numbers with the high bit set, so a
filter written against x86-64 numbers is bypassable through x32 unless it is
explicitly rejected — it is. And every jump in the generated program has an
offset of 0 or 1, because the obvious "jump to the ALLOW at the end" encoding
silently breaks once the allowlist passes 255 entries.

`mprotect` is allowed, which means W^X can be defeated from inside a zone. Every
dynamic linker needs it, so denying it is not viable; the compensating control
is that Kryptik builds everything with RELRO and BIND_NOW, so the GOT is
read-only before `main()` runs.

## What hardening does not do

These mitigations raise exploitation cost. They do not make the system
unexploitable, and stacking more of them has diminishing returns against an
attacker with a good kernel bug. Hardening is the second line — the
compartmentalization model in [architecture.md](architecture.md) is the first,
and the threat model in [threat-model.md](threat-model.md) says where both end.
