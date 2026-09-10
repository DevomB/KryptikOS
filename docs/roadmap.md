# Roadmap

Phases are ordered by dependency, not by interest. Each has an unambiguous exit
test — "it works" is not an exit test.

## Phase 0 — Scaffolding ✅ **COMPLETE**

- [x] Repository structure
- [x] Architecture, threat model, hardening rationale
- [x] Host requirement checker
- [x] Source fetching with checksum locking
- [x] Resolve ADR-008 (libc) — glibc
- [x] Generate and audit `sources.lock` — 24 of 25 verified against upstream signatures

**Exit test:** `make check && make sources` succeeds on a clean Debian/Arch host.

## Phase 1 — Cross toolchain ✅ **COMPLETE**

Binutils + GCC + glibc, two passes, built against a sysroot so the host
toolchain never contaminates the target. Implemented in
`build/stages/01-toolchain.sh`; resumable via per-step stamps.

Hardening flags are introduced *after* the bootstrap compiler exists. Pass-1
GCC cannot be built with the full flag set — it is the thing that implements
the flags.

**Exit test: PASSED** on 2026-09-10. The cross compiler produces binaries
requesting `/lib64/ld-linux-x86-64.so.2` — the target loader, not the host's —
and `readelf -h` confirms position-independent output, so `--enable-default-pie`
took effect.

Build times on an 8-core / 7GB host at `-j6`: binutils ~4min, GCC ~24min,
kernel headers 34s, glibc ~7min, libstdc++ ~2min.

**What actually went wrong:** not the hardening flags. The failure was that a
V_LINUX bump left stale kernel headers in the sysroot and glibc began compiling
against a mix of two kernel versions. Fixed by clearing the header tree first.

## Phase 2 — Temporary tools and chroot ✅ **COMPLETE**

Enough userland to enter a chroot and build the rest of the system from inside.
Implemented in `build/stages/02-temp-tools.sh` (17 packages, resumable).
**Written but not yet executed** — stage 01 must land first.

**Exit test: PASSED** on 2026-09-10. All 17 packages cross-compiled into the
sysroot; the nine binaries a chroot needs are present, and the built `bash`
requests the target loader rather than the host's.

Sysroot is 3.1GB. Slowest steps: gcc pass 2 ~29min, binutils pass 2 ~3min,
findutils ~2min; everything else under 100s.

The binaries identify as Kryptik's own target, not the host's:

```
$ sysroot/usr/bin/bash --version
GNU bash, version 5.2.32(1)-release (x86_64-kryptik-linux-gnu)

$ /usr/bin/bash --version                 # host, for comparison
GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)
```

## Phase 3 — Base system

Full package set, all built with the hardening flag set. hardened_malloc wired
in as the system allocator. Init system from ADR-006.

- [x] Resolve ADR-006 (init) — s6-rc (+ seatd for Wayland seat management)

**Exit test:** system boots to a shell under QEMU. `tools/audit-setuid.sh`
reports zero unjustified setuid binaries.

**Realistic effort:** the longest phase. Each package that breaks under
`-D_FORTIFY_SOURCE=3` or `-pie` is an individual investigation.

## Phase 4 — Hardened kernel

Linux LTS with the linux-hardened patchset applied (ADR-009), then built with
the KSPP fragment, module signing enforced, lockdown in confidentiality mode,
dm-verity and Landlock enabled.

- [x] Resolve ADR-007 (MAC layer) — Landlock + seccomp only for v1
- [x] Resolve ADR-009 (kernel) — LTS only, plus linux-hardened
- [ ] Apply the linux-hardened patch in stage 05

**Exit test:** boots; `lockdown` reports confidentiality; unsigned module load
fails; `kernel-hardening-checker` reports no missing KSPP options;
`make validate-kernel` reports every fragment symbol present in the pinned
source; `make check-kernel-eol` reports the kernel is longterm.

## Phase 5 — The compartment layer

Where Kryptik stops being "LFS with good flags" and becomes Kryptik.

- [ ] `kryptikd` zone lifecycle (create, start, stop, destroy)
- [ ] Per-zone netns + veth + bridge topology; `net` zone as sole NIC holder
- [ ] Per-zone LUKS2 volumes, unlocked on start, key-wiped on stop
- [ ] Per-zone seccomp and Landlock policy application
- [ ] Brokered file transfer and clipboard
- [ ] `vault` zone with no network namespace

**Exit test:** from `untrusted`, with root inside the zone, it is impossible to
(a) list processes in another zone, (b) read another zone's filesystem, (c)
reach the physical NIC, or (d) read `vault`. Each verified by a written test,
not by inspection.

## Phase 6 — Compositor and GUI isolation

Per-zone Wayland proxy, clipboard brokering, screen-capture blocking, per-zone
window border colors.

**Exit test:** an application in zone A cannot capture or keylog zone B's
surfaces. Every window is visually attributable to its zone.

## Phase 7 — Bootable signed image

Secure Boot chain, dm-verity signed root, initramfs embedded in the signed
kernel image, installer.

**Exit test:** installs on real hardware, boots with Secure Boot enabled, and a
tampered root filesystem fails to boot rather than booting silently.

## Explicitly deferred

- Reproducible builds — desirable, and a genuine differentiator, but it
  multiplies Phase 3's difficulty. Revisit after Phase 5.
- Package manager and binary repository — source-only until there is something
  worth distributing.
- Side-channel mitigation (L4) — needs core scheduling; not before Phase 7.
- Hardware certification list.

## A note on timeline

LFS to a bootable base is a well-documented path and mostly a matter of grinding
through it. Phases 5 through 7 are the actual project, and they are not
documented anywhere — that is original systems work. Anyone estimating this in
weeks is estimating Phase 1.
