# Kryptik

A from-scratch Linux distribution built on two commitments:

1. **Nothing runs uncompartmentalized.** Every application lives inside a named
   security zone with its own namespaces, filesystem, network path, and policy.
   There is no "just run it on the host" escape hatch.
2. **Every binary is hardened before it ships.** Hardening is a property of the
   toolchain, not a package you install afterward. If it is in the image, it was
   compiled with the full mitigation set.

Kryptik is built from source via Linux From Scratch — no upstream distro base,
no inherited packaging decisions.

## Status

**Pre-alpha. Nothing bootable yet.** See [docs/roadmap.md](docs/roadmap.md) for
the phase breakdown and what "done" means at each step.

| Area | State |
|---|---|
| Host requirement check | Working, run against a real Ubuntu host |
| Source fetching, checksum locking | Working, 25 sources pinned |
| Upstream signature verification | Working, **24 of 25 verified** |
| Kernel currency + fragment validation | Working, enforced in CI |
| Stage 01 — cross toolchain | **Built and verified** — target loader + PIE confirmed |
| Stage 02 — temporary tools | **Built and verified** — 17 packages, chroot-ready sysroot |
| Stage 05 — hardened kernel | Implemented, not yet executed |
| Stage 04, 06 — base system, ISO | Stubs — next work |
| **Phase 5 — the compartment layer** | **Not started. This is the actual thesis.** |

Everything above the compartment layer is, so far, a well-audited Linux From
Scratch build. What makes Kryptik *Kryptik* is Phase 5, and none of it exists
yet. That is stated plainly here rather than buried.

## Why this exists

The security-distro space is crowded, so the differentiator has to be real:

| Distro | Model | Gap Kryptik targets |
|---|---|---|
| **Qubes OS** | Xen paravirtualization, per-app VMs | Requires VT-x/VT-d and heavy hardware; poor laptop battery life; GPU passthrough is painful |
| **Tails** | Amnesic live system, Tor-routed | Stateless by design — unusable as a daily driver |
| **Kali / Parrot / BlackArch** | Offensive tooling collections | Tooling bundles on a normal, unhardened base — a Kali host is not a hardened host |
| **Whonix** | Two-VM Tor gateway | Solves network anonymity only, not general compartmentalization |

Kryptik's bet: **Qubes-grade isolation using kernel primitives instead of a
hypervisor** — namespaces, cgroups v2, Landlock, seccomp, and per-zone
encrypted storage. Weaker isolation than a hypervisor on paper, but it runs on
ordinary hardware with ordinary battery life, which is what makes people
actually use it.

That tradeoff is stated plainly and deliberately in
[docs/threat-model.md](docs/threat-model.md). A shared kernel is a shared
attack surface. Kryptik does not pretend otherwise.

## Repository layout

```
build/
  stages/       Ordered LFS build stages (00-host-check → 06-iso)
  config/       Pinned versions, hardening flags, kernel config fragments
  lib/          Shared shell helpers
compartments/   Zone definitions and the compartment manager
  policy/       Per-zone seccomp / Landlock / AppArmor policy
packages/       Kryptik-specific package definitions
tools/          Source fetching, checksum locking, dev utilities
docs/           Architecture, threat model, hardening rationale, decisions
out/            Build artifacts (gitignored)
```

## Building

Kryptik must be built on Linux. On Windows, use WSL2 or a container.

```sh
make check      # verify host toolchain meets LFS requirements
make sources    # fetch and checksum-verify upstream tarballs
make toolchain  # stage 1-2: cross toolchain + temporary tools
make system     # stage 3-4: chroot and base system
make kernel     # stage 5: hardened kernel
make iso        # stage 6: bootable image
```

Run `make check` first — it names exactly what your host is missing.
Full host setup, including WSL2 specifics: [docs/building.md](docs/building.md).

## Design documents

- [docs/architecture.md](docs/architecture.md) — the compartmentalization model
- [docs/threat-model.md](docs/threat-model.md) — what Kryptik defends against, and what it does not
- [docs/hardening.md](docs/hardening.md) — toolchain and kernel hardening rationale
- [docs/decisions.md](docs/decisions.md) — architecture decision records, including open questions
- [docs/roadmap.md](docs/roadmap.md) — phased plan
- [docs/supply-chain.md](docs/supply-chain.md) — source integrity and its current gaps
- [docs/building.md](docs/building.md) — host setup

## License

GPL-2.0-or-later for Kryptik's own tooling. Built packages retain upstream
licenses. See [LICENSE](LICENSE).
