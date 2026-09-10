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

## Phase 5 — The compartment layer *(in progress)*

Where Kryptik stops being "LFS with good flags" and becomes Kryptik.

**The four exit requirements now hold** (see below). What remains is lifecycle
and the brokered channels, not the isolation primitives.

- [x] Zone definition format, parser, and cross-zone invariants
- [x] Namespace set + `mount_proc` / `mount_sysfs` (isolate.rs)
- [x] Landlock filesystem confinement (landlock.rs) — ABI-aware
- [x] Adversarial exit test, passing 12/12
- [x] `kryptikd run` — creates a zone and executes inside it, applying
      namespaces, proc/sysfs remounts, Landlock and seccomp in that order
- [ ] `kryptikd stop` / persistent zone state (run is one-shot today)
- [ ] Per-zone veth + bridge topology; `net` zone as sole NIC holder
- [ ] Minimal per-zone `/dev` — a zone currently inherits the caller's `/dev`
      rather than getting a devtmpfs with null/zero/urandom/tty and nothing
      else. This grants more than it should and is a known gap, not a decision.
- [ ] Per-zone LUKS2 volumes, unlocked on start, key-wiped on stop
- [x] Per-zone seccomp filters — default-deny BPF allowlist, 13 dangerous syscalls verified killed
- [ ] Brokered file transfer and clipboard

**Exit test: PASSING** as of 2026-09-10 — `compartments/tests/adversarial.sh`,
12 checks, 0 failures, run as root *inside* the zone against a real 6.6 kernel.

```
Requirement 1 — cannot list processes in another zone     PASS
Requirement 2 — cannot read another zone's filesystem     PASS
Requirement 3 — cannot reach the physical NIC             PASS
Requirement 4 — cannot read the vault                     PASS
Requirement 5 — cannot reach dangerous kernel syscalls    PASS
```

Requirement 5 is not from `architecture.md`. The original four are about
reaching another *zone*; none of them says anything about reaching the
*kernel*, and `threat-model.md` concedes as L1 that a kernel LPE compromises
every zone at once. The syscall surface a zone can touch is part of the
boundary whether the original list said so or not.

**`kryptikd` now drives this itself.** The test above originally used
`unshare(1)`, which proved the primitives were sound but said nothing about
whether kryptikd applied them correctly. `kryptikd run NAME -- CMD` creates the
zone; verified independently:

```
uid inside          0            processes visible   3 (host: 41)
pid inside          1            vault interfaces    lo only
mount(2)            SIGSYS       read outside rootfs Permission denied
```

Three bugs surfaced only by running it: a missing parent/child handshake that
left the zone unmapped and running as nobody; a Landlock allowlist without
`/proc`, so a working pid namespace still gave "cannot open directory /proc";
and `cat` dying on `fadvise64`, which was absent from the seccomp allowlist.
That last one is why `kryptikd seccomp-trace` exists — a KILL tells you a zone
died, a TRAP tells you what it died on.

Two findings came out of writing it rather than out of reading the design:

- **sysfs is not namespaced by unshare.** The network namespace correctly denies
  a zone the *use* of host interfaces, but `/sys/class/net` still enumerated
  `docker0` and `eth0` — free reconnaissance for a compromised zone. Fixed by
  `isolate.rs::mount_sysfs`.
- **A mount namespace is not filesystem isolation.** It gives a zone its own
  mount *table*, not its own view of the files; requirements 2 and 4 failed
  outright until Landlock was implemented. The test keeps that as an explicit
  negative control so the reason is never lost.

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
