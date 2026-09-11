# Kryptik

A from-scratch Linux distribution built on two commitments:

1. **Nothing runs uncompartmentalized.** Every application lives inside a named
   security zone with its own namespaces, filesystem, network path, and policy.
   There is no "just run it on the host" escape hatch.
2. **Every binary is hardened before it ships.** Hardening is a property of the
   toolchain, not a package you install afterward. If it is in the image, it was
   compiled with the full mitigation set.

Kryptik is built from source via Linux From Scratch — no upstream distro base,
no inherited packaging decisions. Its binaries carry their own target triple:

```
$ sysroot/usr/bin/bash --version
GNU bash, version 5.2.32(1)-release (x86_64-kryptik-linux-gnu)
```

## Status

**Pre-alpha. Kryptik does not boot yet.** See [docs/roadmap.md](docs/roadmap.md)
for the phase breakdown.

## How this document describes status

Four words, used the same way everywhere in this repository:

| word | means |
|---|---|
| **planned** | designed and written down. No code. |
| **implemented** | the code exists and builds. |
| **tested** | an automated check exercises it and is capable of failing. |
| **release-validated** | tested on the Kryptik kernel and the Kryptik userspace, in a VM or on hardware. |

**Nothing in Kryptik is release-validated yet**, because stage 04 has not
produced a userspace and stage 05 has not produced a kernel. Everything below
that says "tested" was tested on a developer host and, where noted, in a VM
running a *stock* kernel. That is a real result and it is not the same result.

| Area | State |
|---|---|
| Host requirement check | **tested** — `build/stages/00-host-check.sh`, run against a stock Ubuntu host |
| Source fetching and checksum locking | **tested** — `tools/fetch-sources.sh` |
| Upstream signature verification | **tested** — `tools/verify-signatures.sh`; run it for the current count, see below |
| Provenance for unsigned sources | **tested** — `tools/verify-provenance.sh`, 30 offline fixture checks |
| Kernel currency and fragment validation | **tested** — 23 offline fixture checks, enforced in CI |
| Stage 01 — cross toolchain | **implemented**, last executed 2026-09-10 |
| Stage 02 — temporary tools | **implemented**, last executed 2026-09-10 |
| Stage 03/04 — chroot and base system | **implemented**, never executed end to end |
| Stage 05 — hardened kernel | **implemented**, never executed |
| Stage 06 — bootable image | **planned** — the script is a stub |
| Zone definitions and validation | **tested** — 65 unit checks |
| `kryptikd run` — the launch path | **tested** — 73 checks on a developer host, 78 as root in a VM |
| Developer VM (boot, s6, console) | **tested** — `tools/vm/`, 16 boot checks against a *stock* kernel |
| Per-zone cgroup limits, LUKS volumes, veth topology, brokers | **planned** — and refused at runtime rather than faked |

### No verification counts are quoted here, deliberately

Earlier revisions of this file and of `docs/supply-chain.md` carried four
different source counts — "24 of 25", "21 of 22", "54 of 69", "60 of 69" — and
the tool producing them was itself miscounting: it cached imported keys under
`build/work/keys`, so the same inputs reported 34 verified / 20 unaudited on a
first run and 54 / 0 on a second. A number in prose cannot be kept honest.
Run the tool:

```sh
make verify              # detached GPG signatures
make verify-provenance   # signed tags and publisher checksums for the rest
```

### What a zone actually does today

`kryptikd run` builds the zone itself; the test no longer simulates one with
`unshare`. A zone whose definition promises something this build does not
deliver is **refused**, not quietly downgraded:

```
$ kryptikd run untrusted -- /bin/sh -c 'echo hi'
kryptikd: could not start zone "untrusted": zone "untrusted" asks for guarantees this build does not provide:
  - storage.mode = "ephemeral": a PLAIN DIRECTORY, NOT yet wiped on stop
  - [policy]: per-zone seccomp/landlock files are NOT yet applied; the shared base policy would be used
  - [limits]: resource limits are NOT yet applied; no cgroup would be created
Refusing rather than implying a guarantee that does not hold.
Set KRYPTIK_EXPERIMENTAL=1 to run it anyway, without them.
```

With the override, the zone is real:

```
$ KRYPTIK_EXPERIMENTAL=1 kryptikd run untrusted -- /bin/sh -c \
    'echo pid=$$; echo host=$(hostname); echo procs=$(ls /proc | grep -c "^[0-9]*$")'
pid=1
host=untrusted
procs=4                 # 70 processes visible on the host at the time
```

`kryptikd explain <zone>` prints the whole boundary — namespaces, the Landlock
rule table, the synthesized `/etc`, the `/dev` node list, the environment
allowlist and the syscall count — without starting anything.

What remains in Phase 5 is persistent zone lifecycle (`run` is one-shot),
per-zone LUKS2 volumes, cgroup resource limits, the veth/bridge topology, and
the brokered file and clipboard channels. Each is refused at runtime today
rather than silently approximated.

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
  kryptikd/     The compartment manager itself (Rust)
  policy/       Per-zone seccomp / Landlock / AppArmor policy
  tests/        adversarial.sh (primitives) and launcher.sh (the real launch path)
packages/       Kryptik-specific package definitions
tools/          Source fetching, checksum locking, dev utilities
  vm/           The developer VM: build an initramfs, boot it, check the log
docs/           Architecture, threat model, hardening rationale, decisions
out/            Build artifacts (gitignored)
```

## Building

Kryptik must be built on Linux. On Windows, use WSL2 or a container.

```sh
make check      # verify host toolchain meets LFS requirements
make sources    # fetch and checksum-verify upstream tarballs
make toolchain  # stages 01-02: cross toolchain + temporary tools
make system     # stages 03-04: chroot and base system (needs root)
make kernel     # stage 05: hardened kernel
make iso        # stage 06: bootable image  [planned - the stage is a stub]
```

Run `make check` first — it names exactly what your host is missing.
Full host setup, including WSL2 specifics: [docs/building.md](docs/building.md).

Testing the compartment layer needs no build at all:

```sh
make zone-tests # both zone suites: the primitives and the real launch path
make vm-boot KERNEL=<any bzImage> S6ROOT=<dir with s6 + busybox>
```

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
