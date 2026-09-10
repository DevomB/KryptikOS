# Architecture Decision Records

Each record states the decision, the reasoning, and what it costs. Records
marked **OPEN** are unresolved and block the phase noted.

---

## ADR-001: Build from Linux From Scratch, not an existing base
**Status:** Accepted

Kryptik's hardening is toolchain-wide and its init path is unusual. Inheriting a
base distro means inheriting its compiler defaults, its package layout, and its
setuid binaries — then fighting all three.

**Cost:** Months before a bootable image, and permanent ownership of security
updates for every package shipped. This is the largest cost in the project and
it does not go away.

---

## ADR-002: Kernel-based isolation, not a hypervisor
**Status:** Accepted

Namespaces + cgroups v2 + Landlock + seccomp, rather than Xen.

Qubes' hypervisor boundary is stronger. It also demands VT-d, punishes battery
life, and makes GPU acceleration painful. Kryptik targets the user who would run
Qubes but won't tolerate the hardware tax.

**Cost:** A kernel LPE compromises every zone. Documented as L1 in the threat
model. Non-negotiable consequence of this ADR.

---

## ADR-003: Zone 0 runs no user applications
**Status:** Accepted

The load-bearing invariant. Once a browser runs in zone 0 "just this once", the
system is a Linux box with containers, not a compartmentalized OS.

**Cost:** Real friction. Every convenience request that starts with "can I just
run this on the host" gets refused.

---

## ADR-004: Wayland only, no X11
**Status:** Accepted

X11's design lets any client keylog every other client and screenshot the entire
display. That is directly incompatible with ADR-003.

**Cost:** X11-only applications need Xwayland inside their own zone, which is
acceptable — the isolation boundary is the zone, so a per-zone Xwayland leaks
only to itself.

---

## ADR-005: hardened_malloc as the system allocator
**Status:** Accepted

See [hardening.md](hardening.md).

**Cost:** Slower on allocation-heavy workloads.

---

## ADR-006: s6-rc as init and service supervisor
**Status:** Accepted (2026-09-10, resolved by maintainer delegation)

PID 1 is s6-svscan; service dependency management is s6-rc.

systemd has the better sandboxing primitives, but Kryptik does not need them:
zones already provide namespace, cgroup, seccomp and Landlock confinement, and
`kryptikd` owns zone lifecycle regardless. That reduces systemd's advantage to
socket activation and journald, neither of which justifies a very large,
privileged PID 1 in a system whose threat model (L1) already assumes a hostile
local attacker hunting for privileged surface.

**Cost — real and worth stating:**
- Off the documented LFS path. Both LFS editions ship sysvinit or systemd;
  s6-rc means writing service definitions from scratch.
- No `logind`. Wayland seat management needs **seatd** instead.
- No `networkd`. The `net` zone runs its own DHCP client; other zones never
  touch a real interface, so this is narrower than it sounds.
- No journald. Logging is s6-log per service, which is simpler but means
  building log aggregation if it is ever wanted.

**Revisit if:** service definition authoring becomes the dominant cost in
Phase 3.

---

## ADR-007: Landlock + seccomp only for v1; no SELinux or AppArmor
**Status:** Accepted (2026-09-10, resolved by maintainer delegation)

No traditional MAC layer ships in v1.

Writing SELinux policy from zero for a from-scratch distribution is plausibly a
larger project than the distribution itself, and a policy that is too large to
audit provides confidence rather than security. AppArmor is easier to author but
path-based, and path-based confinement composes badly with per-zone mount
namespaces where the same path means different things in different zones.

What actually carries the isolation:

| Concern | Mechanism |
|---|---|
| Filesystem access | Landlock ruleset, applied at zone entry, unprivileged and unbypassable |
| Syscall surface | seccomp-bpf, default-deny allowlist |
| Network | dedicated netns — not a policy rule, an absent interface |
| IPC | dedicated ipcns |
| Resources | cgroup v2 |

Landlock's coverage is narrower than SELinux's, and its network restrictions
arrived only in later ABI versions. Neither matters here: Kryptik isolates
networks with namespaces rather than policy, so the gap falls on ground already
covered.

**Cost:** Less defense-in-depth. A Landlock bypass is not backstopped by a
second MAC layer.

**Revisit at Phase 6**, once zone semantics are stable and a policy would be
written against a fixed target rather than a moving one.

---

## ADR-008: glibc
**Status:** Accepted (2026-09-10, resolved by maintainer delegation)

musl is smaller, cleaner, and easier to audit — genuinely the better fit for
Kryptik's stated values. It is still the wrong choice right now.

Phase 1's goal is "does it boot". Choosing musl means spending that phase
debugging glibc-assuming software instead, and every hour spent on a
compatibility shim is an hour not spent on the compartment layer in Phase 5 —
which is the part of Kryptik that is actually novel. The libc is not what makes
this project interesting.

**Cost:** Larger attack surface than musl, and a real migration cost if this is
revisited later — the toolchain is built around this choice, so changing it
means rebuilding from stage 01.

**Revisit after Phase 5**, when the interesting work is done and a libc swap is
a contained experiment rather than a bootstrap risk.

---

## ADR-009: Track an LTS kernel and carry the linux-hardened patchset
**Status:** Accepted (2026-09-10)

Kryptik pins **linux 6.18.x (longterm)** and applies the matching
**linux-hardened** patch before building.

### The defect this fixes

The original pin was 6.10.5. That kernel is **not longterm**, was released in
August 2024, and reached end-of-life within about two months of release. A
security distribution shipping a kernel with roughly two years of unpatched
CVEs is not a security distribution — it is the single worst defect the project
had, and it sat in `versions.env` looking like a normal version number.

Non-LTS kernels are disqualified on principle from here on. `make check-kernel-eol`
queries kernel.org and fails if the pinned version is EOL or not longterm, so
this cannot silently recur.

### Why linux-hardened

Until now Kryptik only applied a kconfig fragment. That flips switches Torvalds
already built — the same thing Fedora and Arch do — and does not justify calling
the result a hardened kernel. linux-hardened carries mitigations upstream has
rejected or not merged: stronger ASLR entropy, expanded slab sanitization,
tighter usercopy checks, and reduced attack surface in areas mainline keeps for
compatibility.

It also constrains the kernel choice in a useful way: linux-hardened only tracks
LTS branches, so adopting it makes the EOL mistake above structurally impossible
to repeat.

### Costs

- **Version coupling.** The kernel can only move when a matching
  `linux-hardened` release exists. A kernel CVE fix may therefore land days
  behind mainline stable.
- **Patch conflicts.** Any Kryptik-local kernel patch must be rebased against
  linux-hardened rather than mainline.
- **Not grsecurity.** linux-hardened is a partial, community-maintained
  descendant of the grsecurity patchset, not the real thing. grsecurity is
  commercially licensed and unavailable. Do not describe Kryptik as
  grsecurity-hardened.

### Rejected alternatives

- **Mainline stable + kconfig only** — what Kryptik was doing. Insufficient for
  the claim the project makes about itself.
- **Own patchset from scratch** — Phase 5 may still require kernel work if the
  zone model needs hooks Landlock cannot express (see ADR-002). That would be
  carried *on top of* linux-hardened, not instead of it.

---

## ADR-010: kryptikd is written in Rust
**Status:** Accepted (2026-09-10)

`kryptikd` runs privileged in zone 0. It parses zone definitions, creates
namespaces, applies seccomp and Landlock policy, brokers the only three
channels that cross a zone boundary, and holds the keys to per-zone volumes. It
is the single most security-critical piece of userspace in the system: a
memory-safety bug there does not compromise one zone, it compromises the
mechanism that separates all of them.

Writing that component in C, in a project whose entire premise is hardening,
would be difficult to defend. Kryptik spends real performance to get
`-D_FORTIFY_SOURCE=3`, hardened_malloc, and `INIT_ON_ALLOC` precisely because
memory-safety bugs are the dominant exploited class. Choosing C for the one
process that mediates every boundary would contradict that.

### Costs, which are not small

- **rustc must be bootstrapped into the build.** rustc is written in Rust, so
  building it from source requires an existing rustc. The honest options are a
  downloaded stage0 binary (a trust anchor Kryptik does not control, which cuts
  against docs/supply-chain.md) or mrustc, which is a project of its own.
  Unresolved; tracked as a Phase 5 blocker rather than pretended away.
- **Large dependency surface if unmanaged.** kryptikd uses `libc` and direct
  syscalls, not a broad crate tree. Every added dependency is a supply-chain
  decision and needs justifying in review.
- **Toolchain size.** A Rust toolchain in the base system is a lot of bytes for
  one daemon.

### Rejected

- **C** — smallest bootstrap, no new toolchain, but see above.
- **Go** — memory-safe, but the runtime and goroutine scheduler are awkward
  around `clone()`, `unshare()`, and per-thread namespace semantics, which is
  exactly the work kryptikd does.
- **Shell** — genuinely unsuitable for holding privilege and parsing untrusted
  zone state.

### Boundary

Rust is for `kryptikd` and Kryptik-authored tooling. It is not a general policy
for the distribution: coreutils stays coreutils.
