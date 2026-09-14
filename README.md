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

**Pre-alpha, and now a whole system.** The build produces a hardened kernel
with the linux-hardened patchset, install media (a USB image and an ISO)
that boot by UEFI firmware alone with no boot loader to configure, an
installer, an installed system that verifies its root with dm-verity on every
boot and keeps state on its own labelled partition, A/B updates with a judged
trial boot and an authenticated recovery path from the medium, a zoned Wayland
desktop, and one command, `make acceptance`, that runs every gate against
named images and refuses to call anything a pass that did not run.

What that command has proven on which images is recorded, per gate, in
[docs/OVERNIGHT_STATUS.md](docs/OVERNIGHT_STATUS.md) and in the acceptance
report exported beside the tested images. Read that before this file: the
table below says what exists and how it is tested, not that a particular
build passed.

## How this document describes status

Four words, used the same way everywhere in this repository:

| word | means |
| --- | --- |
| **planned** | designed and written down. No code. |
| **implemented** | the code exists and builds. |
| **tested** | an automated check exercises it and is capable of failing. |
| **release-validated** | tested on the Kryptik kernel and the Kryptik userspace, in a VM or on hardware, by `make acceptance` on the exact images that are shipped. |

| Area | State |
| --- | --- |
| Host requirement check | **tested** — `build/stages/00-host-check.sh` |
| Source fetching, checksum locking, signature and provenance verification | **tested** — `tools/fetch-sources.sh`, `tools/verify-signatures.sh`, `tools/verify-provenance.sh`; run them for the current counts (see below) |
| Kernel currency and fragment validation | **tested** — offline fixture checks; `make validate-kernel-boot` and `make validate-kernel-hardened` |
| Stages 01–02 — cross toolchain, temporary tools | **tested** — rebuilt from scratch 2026-09-13; the glibc loader carries two upstream fixes the 2.40 tarball lacks (`build/patches/glibc-2.40/`), and each glibc build proves with `readelf` that its loader takes its own map bounds without a run-time relocation |
| Stage 04 — base system | **tested** — every package builds with the hardening set; in the chroot, `make test-libc-unwind` proves the target libc unwinds through a dlopened library, `make smoke-userspace` runs the userland, `make audit-artifacts` reads the ELF headers of what shipped |
| Stage 05 — hardened kernel | **implemented** — EFI stub, compiled-in command line with `CMDLINE_OVERRIDE`, dm-init verity root, Landlock, cgroup v2, restricted unprivileged user namespaces; the kernel proves itself only by booting the media (below) |
| Stage 06 — install media and release payloads | **implemented** — USB image and ISO with the kernels signed by a build-generated developer Secure Boot key, a signed release manifest per payload |
| Firmware boot of the media (G3) | **tested** — `make media-smoke-usb` / `media-smoke-iso`: firmware discovery only, no `-kernel`, `-initrd`, `-append` or host filesystem; the acceptance run reads the recorded QEMU commands back to attest it |
| Installation and the installed system's state (G4) | **tested** — `make install-test` (install, boot alone with a fresh variable store, reboot, cold boot, refusals including an injected I/O error), `make state-test` (a cloned disk, ambiguous labels, a corrupt or missing state partition: the system boots degraded and says so) |
| Boot integrity (G5) | **tested** — `make media-smoke-secureboot`, `make media-refused-foreign-keys` (Microsoft keys must refuse the medium, proven by the firmware's own refusal message), `make integrity-test` (a foreign-signed boot file refused, a tampered root refused by dm-verity before any userspace, recovery from the medium with state intact) |
| Zones, network and encrypted storage on the installed kernel (G6, G7) | **tested** — `make zones-test`: the guest-side `zones-check.sh` and the compartment suites shipped in the image, run as root on the Kryptik kernel |
| The zoned desktop (G8) | **tested** — `make gui-test`: the session on a virtual GPU, what a zone's client is and is not offered through its proxy, zone borders and title prefixes photographed windowed and fullscreen, per-zone clipboards, the clipboard-move gesture, and file transfers answered by keystrokes on the trusted chrome |
| A/B updates and recovery (G9) | **tested** — `make update-test`: apply, trial boot, commit, rollback, refusals (wrong key, modified image, truncated kernel, unlisted file, downgrade, concurrent run, full disk), interruptions, and a deliberately broken trial that falls back |
| Zone definitions, `kryptikd run`, lifecycle, limits, ephemeral storage | **tested** — unit checks in kryptikd, `compartments/tests/` as root |
| Per-zone LUKS2 volumes | **tested** — lifecycle as root on a developer host; on the target kernel inside `zones-test` |
| The broker: file transfer with the person's consent, per-zone clipboards, the zone 0 clipboard gesture | **tested** — kryptikd unit tests, `compartments/tests/serve.sh`; on the target inside `gui-test` |
| The compositor layer: `kryptik-wlproxy`, `zoneid`, the dwl zone-border patch | **tested** — `make compositor-test` (including the live proxy against a real socket), `make identity-test` |
| `kryptik` — the command a person types | **tested** — `compartments/tests/cli.sh` |
| `make acceptance` | **implemented** — every gate G1–G10 in one run, PASS / FAIL / INCOMPLETE per item, with a report and an export that re-hashes what it copies |

**Release-validated** is the column that matters, and it is earned per build:
the acceptance report names the source revision, the image hashes, the
firmware and the kernel it ran against. Nothing here has run on physical
hardware; the developer signing key is generated by the build; the builds
are not reproducible bit for bit.

### No verification counts are quoted here, deliberately

Earlier revisions of this file carried four different source counts, and the
tool producing them was itself miscounting. A number in prose cannot be kept
honest. Run the tool:

```sh
make verify              # detached GPG signatures
make verify-provenance   # signed tags and publisher checksums for the rest
```

### What a zone actually does today

`kryptik` is the command; `kryptikd` is what it calls. The zone is real — its
own pid namespace, its own hostname, and four processes where the host has 142:

```
$ kryptik run untrusted -- /bin/sh -c \
    'echo pid=$$; echo host=$(hostname); echo procs=$(ls /proc | grep -c "^[0-9]*$")'
kryptikd: zone "untrusted": ephemeral storage is a tmpfs freed on exit; its pages can reach swap, so this is not secure erasure
pid=1
host=untrusted
procs=4
```

That warning is printed on **every** launch, not once at setup. Ephemeral
storage does what it says — the tmpfs is gone when the zone exits — and it is
not secure erasure, because those pages can reach swap, so the sentence stays.

A zone with `storage.mode = "encrypted"` lives on its own LUKS2 volume. It
asks for its passphrase when it starts — on the terminal, or in a trusted
window the chrome opens — and the passphrase travels to the daemon on a file
descriptor, never on a command line. On an installed system an ordinary user's
`kryptik shell`, `run` and `stop` go through the session's launch service
(`kryptikd serve`), which is the only thing that runs with privilege.

`kryptikd explain <zone>` prints the whole boundary — namespaces, the Landlock
rule table, the synthesized `/etc`, the `/dev` node list, the environment
allowlist and the syscall count — without starting anything.

Files cross zones only through the broker socket inside the sending zone, only
in a direction the zone's policy names, and only after the person answers the
question the trusted chrome shows. The clipboard is per zone; one payload moves
when zone 0 asks for it, through the chrome's menu. `kryptik` has no command
for either, on purpose.

## Why this exists

The security-distro space is crowded, so the differentiator has to be real:

| Distro | Model | Gap Kryptik targets |
| --- | --- | --- |
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
  patches/      In-repository patch sets with provenance (glibc-2.40/)
  services/     The s6-rc service tree; service-scripts/ what they run
  desktop/      dwl config and the zone colour table the compositor is built with
  guest-tests/  Checks that run inside the installed system
  lib/          Shared shell helpers
compartments/   Zone definitions and the compartment manager
  kryptikd/     The compartment manager itself (Rust): zones, volumes, broker, serve
  zones/        The shipped zones and their policy
  tests/        adversarial.sh (primitives), launcher.sh, cli.sh, serve.sh, update.sh
compositor/     kryptik-wlproxy (the per-zone Wayland proxy) and zoneid (colour identity)
tools/
  acceptance.sh The one entrypoint: every gate, one verdict
  image/        Stage 06 helpers, the OVMF runner, the VM drivers
  install/      kryptik-install; update/ kryptik-update and kryptik-recover
  desktop/      kryptik-session, kryptik-chrome, kryptik-launch, the dwl patch
  net/          The net zone's fail-closed setup
  vm/           The developer VM: an initramfs on any kernel, for the zone layer
docs/           Architecture, threat model, hardening rationale, decisions
out/            Build artifacts (gitignored)
```

## Building

Kryptik must be built on Linux. On Windows, use WSL2 or a container.

```sh
make check      # verify host toolchain meets LFS requirements
make sources    # fetch and checksum-verify upstream tarballs
make toolchain  # stage 01: cross toolchain            (unprivileged)
make temp-tools # stage 02: temporary tools            (unprivileged)
make system     # stage 04: the base system, in the chroot (needs root)
make kernel     # stage 05: hardened kernel
make media      # stage 06: install media and the signed release payload
```

Run `make check` first — it names exactly what your host is missing.
Full host setup, including WSL2 specifics: [docs/building.md](docs/building.md).

Testing needs no build for the host suites, and the built media for the rest:

```sh
make test                      # every host-side suite that needs no root
make acceptance EXPORT=DIR     # every gate on the newest media; needs root and KVM
```

Boot, install, update and recovery instructions for a built release:
[docs/BOOT_INSTALL_RECOVER.md](docs/BOOT_INSTALL_RECOVER.md).

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
