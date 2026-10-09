# Hardening

Hardening is applied in the toolchain, so every package gets it without
opting in.

## Toolchain flags

Set in [`build/config/hardening.env`](../build/config/hardening.env) and
loaded from stage 04, which builds what ships; the cross toolchain and
temporary tools (stages 01 and 02) are built without them.

| Flag | Defends against | Cost |
| --- | --- | --- |
| `-D_FORTIFY_SOURCE=3` | overflows in libc calls, with dynamic object sizes | negligible; needs optimization |
| `-fstack-protector-strong` | stack smashing | ~1% CPU |
| `-fstack-clash-protection` | stack clash | negligible |
| `-fcf-protection=full` | ROP/JOP, through Intel CET (shadow stack and IBT) | negligible on supporting CPUs |
| PIE (compiler default) | fixed-address exploits; enables full ASLR | ~2% on x86-64 |
| `-Wl,-z,relro,-z,now` | GOT/PLT overwrite | slower startup |
| `-Wl,-z,noexecstack` | executable stack payloads | none |
| `-ftrivial-auto-var-init=zero` | uninitialized-memory disclosure | ~0.5% |
| `-fno-delete-null-pointer-checks` | NULL checks removed as dead code | none |

It also passes `-fno-strict-aliasing`, `-Wl,-z,separate-code` and
`-Wl,--as-needed`.

GCC is configured with `--enable-default-pie` and `--enable-default-ssp`, so a
package that ignores `CFLAGS` still gets both; stage 01 checks the PIE default
took. Do not add `-pie` to `hardening.env`: it links `Scrt1.o`, which
references `main()`, so every shared library fails to link.

### Exceptions

A package that cannot build with a flag goes in
`build/config/hardening-exceptions.txt` as `<package> <flag> # reason`;
`build/lib/common.sh` fails the build on an entry without a reason. The only
one is glibc's `-D_FORTIFY_SOURCE=3`, since glibc defines the fortify
machinery.

### What the audit finds

`make audit-artifacts` (`tools/check-artifact-hardening.sh`) reads the ELF
headers of every object. Stage 06 runs it strict on the root tree as it packs
it into the image, so a finding fails the build, and `make acceptance` runs it
strict again on the root image of the release it tests, mounted read-only, for
the record. A writable and executable segment, an executable stack, text
relocations or an RPATH into the build tree always fail it. In strict mode so
do a missing CET note, `BIND_NOW` or RELRO, a non-PIE executable and any other
RPATH, unless [`artifact-accepted.txt`](../build/config/artifact-accepted.txt)
lists the object with its reason: `kryptikd` and `kryptik-wlproxy`, which
stable rustc does not mark for CET, GMP's assembly, and the rpaths that
man-db, perl and glibc's converters need or that repeat the loader's own
directory. An entry that matches nothing fails too, so the list holds only
what the image has. A new finding is fixed in its package's recipe, not by
weakening the check. The stack protector and FORTIFY are counted, not required
of each object: a function without a local array gets no canary and a call
with no known size no `_chk` variant, so an object with neither shows nothing
about its flags. The record lists the objects without either.

Packages stage 04 builds before its glibc (the first built with
`--enable-cet`) link stage 01's crt files, which carry no CET note, so each is
built again right after glibc. Stage 04 also rebuilds GCC with the flags and
`--enable-cet`, and the step fails unless `libgcc_s` and `libstdc++` (which
glibc's unwinder and every C++ program load) carry IBT and SHSTK and `gcc`
itself is PIE with `BIND_NOW`. No program stage 02 built for the chroot is
left in the image.

## Allocator

ADR-005 makes hardened_malloc the system allocator. Stage 04 builds it without
`-march=native` and installs `/usr/lib/libhardened_malloc.so`. Stage 06 writes
`/etc/ld.so.preload` into the image's root, so every process of the running
system uses it, and kryptikd writes each zone its own preload naming only that
library (a zone never sees the host's). The build chroot never has the file.
hardened_malloc's guard pages are separate mappings, so `vm.max_map_count` is
1048576. The booted medium and the zones suite check that a process has the
library mapped. No benchmark numbers are claimed.

## Kernel

Three fragments in `build/config/kernel/`:
[`hardening.fragment`](../build/config/kernel/hardening.fragment) (KSPP's
recommendations and what zones need: namespaces, cgroup v2, Landlock, seccomp,
dm-verity, dm-crypt), `hardened.fragment` (options only linux-hardened has,
ADR-009) and `boot.fragment` (ADR-013).

- `INIT_ON_ALLOC` and `INIT_ON_FREE` by default: zeroed heap memory, against
  a broad class of info leaks, for a few percent.
- `SLAB_FREELIST_HARDENED`, `SLAB_FREELIST_RANDOM`: against heap grooming.
- Lockdown in confidentiality mode: root cannot read kernel memory through
  `/dev/mem`, kprobes or unsigned modules, which is what makes root in a zone
  weaker than kernel access.
- `RANDOMIZE_BASE`, `RANDOMIZE_MEMORY`: KASLR.
- `MODULE_SIG_FORCE`: only modules signed by the build load. The key is the
  kernel build's own (`certs/signing_key.pem`), made with the kernel tree, and
  never leaves the machine that used it: the Actions cache keeps the tree
  without it, so a run that restores the tree makes a new key, links the
  kernel with it and signs the modules again. Releases are no different: no
  module key is kept ([release keys](release-keys.md)).
- `KSTACK_ERASE`, `RANDSTRUCT_FULL`: stack erasing and structure layout
  randomization (the 6.18 names; the old `GCC_PLUGIN_*` symbols are derived
  and cannot be set).
- Also on: KFENCE, trapping UBSAN bounds checks, page table checking,
  `DEBUG_VIRTUAL`, a strict IOMMU by default, the EFI stub's early-DMA and
  reset-attack protections, the TPM as an entropy source, `/proc/pid/mem`
  write protection, userspace shadow stacks.
- Off: `bpf()`, SELinux (LSMs are `landlock,lockdown,yama`), `/dev/mem`,
  `/proc/kcore`, MSR and CPUID devices, legacy PTYs, `binfmt_misc`, kexec,
  hibernation, IA-32 emulation, debugfs, ftrace, kprobes, io_uring, sysrq,
  ACPI table overrides, core dumps, `/proc/pid/pagemap`.

Stage 05 refuses a `.config` that lost any fragment line
(`build/lib/kconfig-check.sh`, shared with `tools/resolve-kernel-config.sh`
in CI): kconfig silently drops a line for an unmet dependency, an overriding
`select` or an invisible prompt, leaving a mitigation the fragment claims and
the kernel lacks.

`kernel-hardening-checker`, KSPP's reference list, runs on the resolved
`.config` and the shipped command line in stage 05 and CI
(`tools/check-kernel-hardening.sh`). Each failure it reports is fixed or
listed with its reason in
[`checker-accepted.txt`](../build/config/kernel/checker-accepted.txt), and
entries that start passing are reported as stale so the list shrinks.

### Command line

Besides the root device, the command line stage 06 compiles into each signed
kernel carries `mitigations=auto,nosmt nosmt pti=on page_alloc.shuffle=1
hash_pointers=always`: every CPU mitigation with SMT off (ADR-011), page table
isolation even on CPUs the kernel believes unaffected (a few percent on
syscalls), randomized free page lists, and `%p` pointers hashed even where an
option would print them raw.

### Sysctls

[`build/config/sysctl.d/`](../build/config/sysctl.d/) sets, among others,
`kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`,
`kernel.yama.ptrace_scope=3` (no ptrace after boot),
`kernel.perf_event_paranoid=3`, `vm.mmap_rnd_bits=32` and the
`fs.protected_*` settings. Every key in the file exists on the shipped
kernel, and `make zones-test` reads each back: what the kernel does not
build has no sysctl, so there is none for BPF (no `bpf()`; seccomp's classic
filters do not need it), kexec, userfaultfd, 32-bit mappings or core dumps.

## setuid elimination

Privilege transitions go through kryptikd, where they can be audited, not
through setuid binaries or file capabilities. A setuid binary needs a
justified entry in `build/config/setuid-allowlist.txt`, which lists `su`, the
only way from a login to root, and `passwd`, which nothing brokers yet. A file
carrying capabilities (`security.capability`) needs one in
`build/config/capability-allowlist.txt`, which is empty. The recipes install
no other bit: shadow's eight other tools lose theirs after its install,
util-linux is built with `--disable-makeinstall-setuid` and
`--disable-makeinstall-chown` (wall's setgid tty is under that hook), and
inetutils without traceroute. Stage 06 runs `tools/audit-setuid.sh` over the
image's root and fails the build on any unlisted bit or capability; on a root
staged by hand, `--strip` takes them off instead. Either way the audit fails
when it cannot read a directory, on a list entry without a justification, and
on a strip that would take the bit or the capabilities off a listed file
through a hard link. `make zones-test` audits the installed root again: the
bits are on the listed binaries alone, no file carries capabilities, and
every sysctl reads back as `build/config/sysctl.d` says.

## Zone syscall filter

Every zoned process runs under a default-deny seccomp-bpf filter
(`compartments/kryptikd/src/seccomp.rs`) allowing about 200 syscalls. Anything
else is `SECCOMP_RET_KILL_PROCESS`, except that the `set*id` calls,
`setgroups` and `capset` fail with `EPERM` and `inotify_init` and
`inotify_init1` with `ENOSYS`, so programs that try them carry on. `unshare`
and `clone` with namespace flags fail with `EPERM` too: Firefox, Chromium and
bubblewrap probe for user namespaces at start and must hear no, as the kernel
tells an unprivileged caller. `clone3` fails with `ENOSYS` so libc falls back
to `clone`, the `TIOCSTI` and `TIOCLINUX` ioctls are killed, `SIOCETHTOOL`,
`SIOCSMIIREG` and the drivers' private range fail with `EPERM` (with the nic
zone's `CAP_NET_ADMIN` they would rewrite a NIC's EEPROM, flash or PHY, which
outlives a reinstall), and `socket` is limited to `AF_UNIX`, `AF_INET`,
`AF_INET6` and `NETLINK_ROUTE`. A zone policy
file can widen this in named ways but never re-allow a denied syscall
([zone policy files](design/zone-policy-files.md)).

| Denied | Why |
| --- | --- |
| `setns` | enters another zone's namespaces |
| `ptrace`, `process_vm_readv/writev` | another process's memory |
| `mount`, `umount2`, `pivot_root`, `chroot`, the new mount API | remount the filesystem out from under Landlock |
| `unshare` | nested namespaces, a known LPE surface |
| `bpf`, `perf_event_open` | long histories of privilege escalation |
| `userfaultfd` | kernel heap grooming |
| `keyctl`, `add_key`, `request_key` | kernel keyring, repeated CVEs |
| `init_module`, `finit_module`, `kexec_load` | load kernel code |
| `io_uring_*` | does I/O without syscalls, past the filter |

`compartments/tests/adversarial.sh` makes 12 of these calls under the filter
and expects SIGSYS; from `unshare` and a namespace `clone` it expects `EPERM`.

Other architectures are refused, and x32 calls (x86-64 numbers with bit 30
set) are killed before the allowlist. Each allowed syscall is a compare
followed by its own ALLOW, so no jump spans the list: BPF jump offsets are one
byte, and a single jump to a shared ALLOW breaks past 255 entries.

`mprotect` is allowed, since every dynamic linker needs it, so a zone can
defeat W^X. RELRO and BIND_NOW compensate: the GOT is read-only before
`main()` runs.

## Limits

These mitigations raise the cost of exploitation; they do not make the system
unexploitable. Compartmentalization ([architecture](architecture.md)) is the
first line and hardening the second; the [threat model](threat-model.md) says
where both end.
