# Roadmap

Phases are ordered by dependency, not by interest. Each has an unambiguous exit
test — "it works" is not an exit test.

## Phase 0 — Scaffolding *(current)*

- [x] Repository structure
- [x] Architecture, threat model, hardening rationale
- [x] Host requirement checker
- [x] Source fetching with checksum locking
- [x] Resolve ADR-008 (libc) — glibc
- [ ] Generate and audit `sources.lock`

**Exit test:** `make check && make sources` succeeds on a clean Debian/Arch host.

## Phase 1 — Cross toolchain *(in progress)*

Binutils + GCC + glibc, two passes, built against a sysroot so the host
toolchain never contaminates the target. Implemented in
`build/stages/01-toolchain.sh`; resumable via per-step stamps.

Hardening flags are introduced *after* the bootstrap compiler exists. Pass-1
GCC cannot be built with the full flag set — it is the thing that implements
the flags.

**Exit test:** target toolchain compiles a static hello-world that runs under
`qemu-user`; `readelf -d` confirms RELRO, BIND_NOW, and PIE on a dynamic build.

**Realistic effort:** the LFS toolchain chapters are well-trodden. Expect
failures to come from the hardening flags, not from LFS.

## Phase 2 — Temporary tools and chroot

Enough userland to enter a chroot and build the rest of the system from inside.

**Exit test:** `chroot` into the target with a working shell and coreutils, host
filesystem fully detached.

## Phase 3 — Base system

Full package set, all built with the hardening flag set. hardened_malloc wired
in as the system allocator. Init system from ADR-006.

- [x] Resolve ADR-006 (init) — s6-rc (+ seatd for Wayland seat management)

**Exit test:** system boots to a shell under QEMU. `tools/audit-setuid.sh`
reports zero unjustified setuid binaries.

**Realistic effort:** the longest phase. Each package that breaks under
`-D_FORTIFY_SOURCE=3` or `-pie` is an individual investigation.

## Phase 4 — Hardened kernel

Kernel built with the KSPP fragment, module signing enforced, lockdown in
confidentiality mode, dm-verity and Landlock enabled.

- [x] Resolve ADR-007 (MAC layer) — Landlock + seccomp only for v1

**Exit test:** boots; `lockdown` reports confidentiality; unsigned module load
fails; `kernel-hardening-checker` reports no missing KSPP options.

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
