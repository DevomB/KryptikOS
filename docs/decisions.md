# Architecture decision records

Each record gives the decision, the reasons and the cost. All are accepted.

## ADR-001: Build from Linux From Scratch

Kryptik's hardening is toolchain-wide and its init path is unusual. A base
distribution would bring its compiler defaults, package layout and setuid
binaries, and all three would have to be fought.

**Cost:** months before a bootable image, and permanent ownership of security
updates for every package shipped. This is the project's largest cost.

## ADR-002: Kernel isolation, not a hypervisor

Zones are namespaces, cgroup v2, Landlock and seccomp, not Xen. Qubes'
hypervisor boundary is stronger, but it needs VT-d, costs battery life and
makes GPU acceleration painful. Kryptik is for users who would run Qubes but
not pay that hardware cost.

**Cost:** a kernel privilege escalation compromises every zone
([threat model](threat-model.md#kernel-local-privilege-escalation)).

## ADR-003: Zone 0 runs no user applications

Once a browser runs in zone 0 "just this once", the system is a Linux box with
containers.

**Cost:** friction. Every "can I just run this on the host" is refused.

## ADR-004: Wayland only, no X11

X11 lets any client log every other client's keystrokes and capture the whole
screen, which ADR-003 cannot allow.

**Cost:** an X11-only application needs Xwayland in its own zone, where it can
leak only that zone.

## ADR-005: hardened_malloc as the system allocator

It adds slab quarantines, guard slabs, randomized allocation and
heap-overflow canaries. Built and installed, not yet preloaded
([hardening](hardening.md#allocator)).

**Cost:** slower on allocation-heavy workloads.

## ADR-006: s6-rc as init and service supervisor

PID 1 is s6-svscan; s6-rc manages service dependencies. systemd's sandboxing
is better, but zones already provide it and kryptikd owns zone lifecycle.
Socket activation and journald do not justify a large privileged PID 1 in a
system that assumes a local attacker looking for privileged code.

**Cost:** off the LFS path, so every service definition is written from
scratch; seatd instead of logind; the `net` zone runs its own DHCP client, and
no other zone touches a real interface; logging is s6-log per service, with no
aggregation.

**Revisit if** writing service definitions becomes the main cost of the base
system.

## ADR-007: Landlock and seccomp only, no SELinux or AppArmor

SELinux policy written from zero is plausibly a bigger project than the
distribution, and a policy too large to audit gives confidence, not security.
AppArmor is path-based, which composes badly with per-zone mount namespaces,
where one path means different things in different zones. Isolation rests on
Landlock for file access, seccomp-bpf for syscalls, cgroup v2 for resources,
and namespaces for network and IPC: a zone's network is an absent interface,
not a policy rule, so Landlock's late network support does not matter.

**Cost:** a Landlock bypass has no second MAC layer behind it.

**Revisit** once zone semantics are stable enough to write a policy against.

## ADR-008: glibc

musl is smaller and easier to audit, and fits Kryptik better. But much
software assumes glibc, and time on compatibility shims is time not spent on
the compartment layer, which is the new part of Kryptik.

**Cost:** more attack surface than musl, and switching later means rebuilding
from stage 01.

**Revisit** after the compartment layer, when a libc swap is a contained
experiment.

## ADR-009: An LTS kernel with linux-hardened

Kryptik pins linux 6.18.x (longterm) with the matching linux-hardened patch.
A kernel that is not longterm reaches end of life within months, so
`make check-kernel-eol` fails on a pinned kernel that is EOL or not longterm,
and `make kernel` runs it first.

A kconfig fragment can only turn on what mainline has. linux-hardened adds
what mainline has not merged: stronger ASLR entropy, more slab sanitization,
tighter usercopy checks, less of the surface mainline keeps for compatibility.

**Cost:** the kernel moves only when a matching linux-hardened release exists,
so a fix can land days after mainline stable, and Kryptik kernel patches are
rebased on linux-hardened. linux-hardened is a partial, community-maintained
descendant of grsecurity, which is commercial and unavailable: do not call
Kryptik grsecurity-hardened.

**Rejected:** mainline with kconfig only, which is not enough for what the
project claims; an own patchset, since any kernel hooks zones need go on top
of linux-hardened, not instead of it.

## ADR-010: kryptikd is written in Rust

kryptikd runs privileged in zone 0: it parses zone definitions, builds
namespaces, applies seccomp and Landlock, runs the broker and holds the keys
to zone volumes. A memory-safety bug there breaks what separates every zone.
Kryptik pays for `-D_FORTIFY_SOURCE=3`, hardened_malloc and `INIT_ON_ALLOC`
because memory-safety bugs are the most exploited class; C for this one
process would contradict that.

**Cost:**

- rustc is not built from source: that needs an existing rustc, or mrustc, a
  project of its own. The shipped kryptikd and kryptik-wlproxy are built by an
  upstream toolchain pinned in the Distro workflow, a trust anchor
  [supply-chain.md](supply-chain.md) otherwise avoids.
- kryptikd depends on `libc` only; every new crate is a supply-chain decision
  justified in review.
- A Rust toolchain is a lot to carry for one daemon.

**Rejected:** C (smallest bootstrap, but see above); Go, whose runtime and
scheduler fight `clone()`, `unshare()` and per-thread namespace state; shell,
unsuitable for holding privilege and parsing untrusted zone state.

Rust is for kryptikd and Kryptik's own tools, not a distribution-wide rule:
coreutils stays coreutils.

## ADR-011: SMT off, every CPU mitigation on

Every signed kernel's command line carries `mitigations=auto,nosmt`: every
mitigation the kernel knows for the CPU, and simultaneous multithreading off.

**Why:** the threat is a compromised zone reaching the kernel or another zone.
L1TF, MDS, TAA and their successors leak between the two hardware threads of a
core, so a zone on one thread can read another zone, or the kernel, on the
other. KSPP recommends the setting and kernel-hardening-checker fails without
it.

**Cost:** half the logical CPUs on an SMT machine, roughly 15 to 30 percent of
parallel throughput. Single-threaded performance is unchanged.

**Revisit when** SMT can stay on without two trust domains sharing a core.
Each zone already asks for its own core-scheduling cookie at launch
([privileged launch](design/privileged-launch.md#core-scheduling)); what is
missing is a measurement on real hardware of what `nosmt` costs and whether
the cookies hold under load. Until then `nosmt` stays; with no sibling threads
online the kernel refuses the cookie (`ENODEV`) and `kryptikd status` says
`no-smt`.

## ADR-012: Device firmware from linux-firmware, on the verified root

The image ships the firmware laptop graphics and Wi-Fi need, from the pinned
`linux-firmware` release, as selected by `build/config/firmware.list`,
zstd-compressed under `/lib/firmware` on the dm-verity root. The drivers that
load it are signed modules, so they probe after the root is mounted.

**Why:** Intel, AMD and Qualcomm Wi-Fi and AMD GPUs do not run without vendor
firmware, and Intel graphics runs degraded. Without it most laptops have no
Wi-Fi.

These are vendor binaries, not built from source as
[supply-chain.md](supply-chain.md) otherwise requires, and run by the device's
own processor under the kernel's control of the bus (IOMMU on and strict).
Kryptik establishes that the tarball is the one kernel.org signed, its hash is
pinned, each file's licence is the one `WHENCE` records, and the copy the
kernel loads is on the verified root, so replacing it means re-signing the
kernel.

**Left out:** NVIDIA (nouveau needs tens of megabytes of GSP firmware per
generation, and the firmware framebuffer gives those machines a display);
Bluetooth and sound, which no zone uses yet. What is not on the list is not
shipped.

**CPU microcode** is the same decision. The early loader runs before any
filesystem and there is no initramfs, so Intel and AMD microcode is built into
each signed kernel (`CONFIG_EXTRA_FIRMWARE`, stage 05), about 17 MB. Without
it a machine runs whatever microcode its firmware last shipped, which on older
machines means known, unfixed CPU vulnerabilities.

**Cost:** about 135 MB after zstd (385 MB of files; Intel Wi-Fi is 56 MB and
amdgpu 38 MB compressed) on a 2.7 GB root image, and an input nobody here can
read.

## ADR-013: A driver is built in only when boot needs it

With no initramfs, a driver is built into the signed kernel only if it finds,
verifies or mounts the root; gives a console and keyboard before the root is
mounted; or cannot work as a module (netfilter for the `net` zone, microcode,
the watchdog, a few platform drivers that misbehave when loaded late).
Everything else, including every network card, GPU and pointing device, is a
signed module that eudev loads at coldplug. What Kryptik never uses (sound,
network filesystems, CardBus, AGP, software RAID, conntrack helpers) is not
built. The rule heads `build/config/kernel/boot.fragment`, and stage 05 fails
a kernel larger than `build/config/kernel/size-budget`.

**Why:** a built-in driver is on every machine whether or not its device is. A
module loads only where it is used, through the path real Wi-Fi and graphics
need anyway. The VM gets no exception: with virtio-net and virtio-gpu as
modules, every acceptance run proves module autoload.

**Not shrunk:** about 17 MB of the kernel is microcode, which is encrypted and
does not compress. Pre-2011 CPUs, which cannot boot Kryptik, account for 0.4 MB,
not worth a rule. Four server-only Xeon families take 6.8 MB and stay while the
README lists server hardware: a server whose microcode is left out still boots
on old microcode, and nobody would notice.
