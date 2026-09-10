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

## ADR-006: Init system and service supervisor
**Status:** **OPEN** — blocks Phase 3

Zone lifecycle management needs a supervisor. Candidates:

- **systemd** — best-in-class sandboxing primitives, cgroup v2 integration, and
  socket activation, all of which the zone model wants. Very large trust base
  running as PID 1, which cuts against everything else here.
- **s6 / s6-rc** — small, auditable, excellent supervision semantics. Requires
  building zone lifecycle management ourselves.
- **runit** — simplest, but weakest cgroup story.

Leaning **s6-rc**: `kryptikd` has to own zone lifecycle regardless, so systemd's
main advantage is largely redundant, and a small PID 1 is easier to justify in
a threat model that already assumes a hostile local attacker.

**Needs:** a decision before stage 04 (base system) writes any service files.

---

## ADR-007: Mandatory access control layer
**Status:** **OPEN** — blocks Phase 4

Landlock and seccomp are already required by ADR-002. The question is whether a
traditional MAC layer sits alongside them.

- **SELinux** — strictest, best-understood, enormous policy authoring burden on
  a distro with no inherited policy.
- **AppArmor** — path-based, far easier to author, weaker guarantees.
- **Landlock only** — no policy language to maintain; unprivileged and
  composable, but coverage is narrower than either alternative.

Leaning **Landlock + seccomp only for v1**, revisited once zone semantics are
stable. Writing SELinux policy from zero for a from-scratch distro is plausibly
a larger project than the distro itself.

---

## ADR-008: libc
**Status:** **OPEN** — blocks Phase 1

- **glibc** — LFS default, maximum compatibility, large attack surface.
- **musl** — small, auditable, cleanly written. Breaks glibc-assuming software
  and complicates shipping proprietary binaries in zones.

Leaning **glibc** for v1. Choosing musl means fighting compatibility bugs during
the phase where the goal is simply "does it boot", and that fight can be taken
later if it is worth taking at all.

**Needs:** a decision before stage 01 — the toolchain is built around this.
