# Roadmap

Sections are ordered by dependency, not by interest. Each has an unambiguous exit
test — "it works" is not an exit test.

## Scaffolding

Complete.

- [x] Repository structure
- [x] Architecture, threat model, hardening rationale
- [x] Host requirement checker
- [x] Source fetching with checksum locking
- [x] Resolve ADR-008 (libc) — glibc
- [x] Generate and audit `sources.lock` — run `make verify` for the current
      count; it is deliberately not quoted here, because four different
      counts were in circulation and the tool producing them was miscounting

**Exit test:** `make check && make sources` succeeds on a clean Debian/Arch host.

## Cross toolchain

Complete; exit test passed 2026-09-10.

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

## Temporary tools and chroot

Complete; exit test passed 2026-09-10.

Enough userland to enter a chroot and build the rest of the system from inside.
Implemented in `build/stages/02-temp-tools.sh` (17 packages, resumable).
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

## Base system

Complete.

Full package set, all built with the hardening flag set. hardened_malloc wired
in as the system allocator. Init system from ADR-006.

- [x] Resolve ADR-006 (init) — s6-rc (+ seatd for Wayland seat management)
- [x] Every package of stage 04 builds and installs; `make audit-artifacts`
      reads the ELF headers of what shipped rather than trusting the flags
- [x] The target libc unwinds through a dlopened library
      (`make test-libc-unwind`): glibc 2.40's loader needed two upstream
      fixes the tarball lacks (`build/patches/glibc-2.40/`, bugs 31943 and
      33088); the second was found by reading the built loader, not the bug
      titles

**Exit test:** the system boots to a shell under QEMU — met by the media of
the bootable signed image, which boot this base system on the hardened kernel
(`make media-smoke-usb`). `tools/audit-setuid.sh` reports zero unjustified
setuid binaries.

## Hardened kernel

Linux LTS with the linux-hardened patchset applied (ADR-009), then built with
the KSPP fragment, module signing enforced, lockdown in confidentiality mode,
dm-verity and Landlock enabled.

- [x] Resolve ADR-007 (MAC layer) — Landlock + seccomp only for v1
- [x] Resolve ADR-009 (kernel) — LTS only, plus linux-hardened
- [x] Apply the linux-hardened patch in stage 05
- [x] EFI stub with the command line compiled in (`CMDLINE_OVERRIDE`), so the
      root slot, the verity root hash and its salt are part of the signed
      kernel; dm-init builds the verified root with no initramfs

**Exit test:** boots; `lockdown` reports confidentiality; unsigned module load
fails; `kernel-hardening-checker` reports nothing beyond the accepted list
(`make check-kernel-hardening`; stage 05 runs it on the config it builds and
CI on the same fragments resolved against the same source); every fragment
line survives resolution (`build/lib/kconfig-check.sh`, in both places);
`make validate-kernel` reports every fragment symbol present in the pinned
source; `make check-kernel-eol` reports the kernel is longterm. The boot is
measured by the bootable signed image's media tests; the module-signing and lockdown
assertions are not yet individual checks.

## The compartment layer

Where Kryptik stops being "LFS with good flags" and becomes Kryptik.

**The four exit requirements hold** (see below), and the lifecycle, the
network topology, the encrypted volumes and the brokered channels have landed
since. What remains on the target is the acceptance evidence
(`make zones-test`, `make gui-test`).

- [x] Zone definition format, parser, and cross-zone invariants
- [x] Namespace set + `mount_proc` / `mount_sysfs` (isolate.rs)
- [x] Landlock filesystem confinement (landlock.rs) — ABI-aware
- [x] Adversarial exit test (the isolation primitives), passing 14/14
- [x] `kryptikd run` — creates a zone and executes inside it, applying
      namespaces, proc/sysfs remounts, Landlock and seccomp in that order
- [x] `kryptikd stop` / persistent zone state; a registry, `status`, `gc`
- [x] Per-zone veth + bridge topology; the `net` zone as sole NIC holder,
      fail-closed (`tools/net/netzone-init.sh`), NAT and DNS through it
- [x] Minimal per-zone `/dev` — tmpfs with an explicit node list, plus a
      private `/dev/shm` and `/dev/pts`; nothing else exists for the zone
- [x] Per-zone LUKS2 volumes, unlocked on start with a passphrase that never
      touches a command line, closed on stop; header backup and restore
- [x] Per-zone seccomp filters — default-deny BPF allowlist, 13 dangerous syscalls verified killed
- [x] Brokered file transfer, answered by the person through the trusted
      chrome, and per-zone clipboards moved only by the zone 0 gesture
- [x] `kryptikd serve`: the launch daemon a session talks to, with socket
      identity, descriptor ownership, request deadlines and real readiness

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
*kernel*, and the threat model concedes that a kernel LPE compromises every
zone at once. The syscall surface a zone can touch is part of the
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

## Compositor and GUI isolation

Per-zone Wayland proxy, clipboard brokering, screen-capture blocking, per-zone
window border colors.

- [x] `kryptik-wlproxy`: one proxy per zone, hand-rolled wire format, an
      allowlist of globals (no screencopy, data device, layer shell, virtual
      input, dmabuf export, gamma, output management or session lock), the
      zone stamped into every app_id and title
- [x] `zoneid`: the colour identity invariant (CIEDE2000 under colour-vision
      deficiency models) and the palette the shipped zones must satisfy
- [x] dwl draws every window's border in its zone's colour, fullscreen
      included; the chrome (zone 0) records the focused zone, asks the
      transfer questions and reads passphrases in its own windows
- [x] `kryptik-session` from an authenticated tty1 login; the daemon owns
      the runtime directory

**Exit test:** an application in zone A cannot capture or keylog zone B's
surfaces; every window is visually attributable to its zone. Measured by
`make gui-test` on the installed system: what a zone's client is offered and
refused, the border colour photographed windowed and fullscreen, and the
clipboard and transfer flows driven by keystrokes.

## Bootable signed image

Secure Boot chain, dm-verity signed root with its hash compiled into the
signed kernel, installer.

- [x] Stage 06: the verity root image, both slot kernels and the media kernel
      signed with a developer key, a USB image and an ISO, a signed release
      payload per version (the
      [boot and update design](design/boot-and-updates.md))
- [x] `kryptik-install`: whole-disk install with read-back verification and
      refusals; unattended through a control disk for the tests
- [x] State partition found by identity on the root disk; degraded and honest
      when it is ambiguous, corrupt or missing
- [x] A/B updates: `kryptik-update` verifies the manifest, every file and the
      embedded root hash before its first write, arms one trial boot;
      `boot-success` judges the trial and commits; rollback; `--recovery`
- [x] `kryptik-recover` from the medium: commit or restore a slot, state
      untouched
- [ ] Physical hardware

**Exit test:** installs on real hardware, boots with Secure Boot enabled, and a
tampered root filesystem fails to boot rather than booting silently. The
second and third parts are measured under OVMF by `make integrity-test` and
`make media-refused-foreign-keys`; the first has not happened, and the signing
key is a build-generated test anchor, not a production one.

## Version 1.0

What 1.0 means: Kryptik installs and runs on real machines with Secure Boot
on, reaches a network over a wire or a radio, updates itself from releases
signed by a key that is not the build's own, ships nothing it knows to be
vulnerable, and every row of the README's status table reads *tested* or
*release-validated*. A person can install it, log in, work in zones from a
terminal and a text browser, and keep it up to date. It is not yet a desktop
to live in; that is version 2.

Each item names what finishes it. An item is done when its check exists and
passes, not when its code is written.

### It runs on real machines

- [ ] **Physical hardware.** Installed and booted with Secure Boot on at
      least three machines: a wired desktop, an Intel laptop on Wi-Fi alone,
      an AMD laptop. The exit test of the bootable signed image, above. What
      each machine lacked becomes a line in `boot.fragment` or
      `firmware.list`, and the machines become the first rows of a hardware
      list in the README.
- [ ] **CPU microcode.** Nothing loads it. With no initramfs it is built into
      the signed kernel from the pinned firmware release (AMD) and Intel's
      microcode release, and the boot smoke test reports the revision it
      found and the one it loaded.
- [ ] **A clock that is right.** The image has no time synchronisation, and
      certificate validation and update freshness both assume the time.
      Zone 0 has no network, so the net zone asks (NTS or NTP) and zone 0
      decides: the broker carries the answer, zone 0 refuses one that moves
      the clock backwards past the last release's date or forwards by more
      than a bound without consent.

### It can be trusted by someone who did not build it

- [ ] **Production keys.** The release key and the Secure Boot key are
      generated by each build, so no two builds trust each other and nobody
      outside can verify either. 1.0 has a release key and a Secure Boot key
      that live offline, a written ceremony for making, using, rotating and
      revoking them, a build that signs with a key it is handed and refuses to
      invent one for a release, and an installed system that accepts the next
      release and refuses a development build.
- [ ] **No known-vulnerable pins.** glibc 2.40 carries Kryptik's two loader
      fixes and not the release branch's security backports (CVE-2025-0395,
      CVE-2025-4802 and others): move to a maintained glibc or carry the
      backports, with the unwind test still passing. Then every pin checked
      against its upstream's security releases, and
      `tools/check-support-status.sh` extended so CI fails when a pin falls
      behind one.
- [ ] **An update channel.** `kryptik-update` applies a payload from a
      mounted disk and nothing fetches one. The net zone downloads a release
      by URL into a transfer area; zone 0 verifies the manifest signature,
      every file and the embedded root hash exactly as it does today, and
      refuses a downgrade. A release process that publishes the payload, its
      signature and the corresponding source.
- [ ] **The state partition is encrypted.** `/home`, `/var` and the `/etc`
      overlay sit on plain ext4, so a stolen laptop gives up zone 0's home,
      the Wi-Fi passphrases and the zone volumes' headers. LUKS2 on
      `kryptik-state`, unlocked at boot by a passphrase (and later a TPM, see
      version 2), created by the installer, with the state test's degraded
      paths still honest.
- [ ] **kryptikd is built from pinned source by a pinned compiler.** Today the
      runner's rustc compiles it and the result is copied in (ADR-010's
      unresolved cost). A pinned rustc in the build (its published binary,
      pinned and verified like cmake's, is an acceptable first step and says
      so) and a build that refuses any other.

### It fails safe and says what it is

- [ ] **A watchdog for a hung userspace.** `boot-success` judges a trial boot
      once; a system that hangs after that stays hung. The hardware watchdog
      (or softdog) fed by a supervised service, and a hang test in the state
      suite. Written: the kernel options, the `watchdog` service, and the
      test that stops the feeder and expects a second boot. Ticked when that
      test has passed in an acceptance run.
- [ ] **Every status row is tested.** Stage 05, stage 06 and `make
      acceptance` read *implemented* in the README: each gets the check that
      can fail, or the row says why it cannot.
- [ ] **The accepted lists are reviewed.** `checker-accepted.txt`,
      `hardening-exceptions.txt`, the setuid allowlist and the artifact
      audit's soft findings (no CET, no `BIND_NOW`, not PIE, `RPATH`): each
      entry closed or re-justified for the release, with the audit's counts in
      the release notes.
- [ ] **Core scheduling per zone, and the SMT decision.** Zones carry their
      own cookie; ADR-011 is revisited with a measurement, and the command
      line says `nosmt` or does not for a written reason.
- [ ] **The net zone's remaining hardening.** Bridge ports pinned to their
      assigned MAC and address (`docs/design/net-zone.md`, not built), and
      dhcpcd with privilege separation inside the zone or a recorded reason
      it cannot have it.
- [ ] **Someone else has attacked it.** The two hand-written trust boundaries,
      the broker's protocol and `kryptik-wlproxy`'s wire parser, fuzzed in CI
      with a corpus kept in the tree (written: seeded mutation in both unit
      suites, [how and its limit](design/broker.md#the-two-parsers-attacked);
      neither parser broke); and one review of kryptikd's launch path
      by a person who did not write it, with the findings and their fixes in
      `docs/`.
- [ ] **A release, as an object.** Version numbering, release notes generated
      from the acceptance report, the licences of everything shipped
      (firmware included, from `WHENCE`) in the image and beside the download,
      the corresponding source bundle, and install, update and recovery
      instructions that were followed by someone other than their author.

## Version 2

What 2.0 means: a desktop someone can live in, built the same way.

- **Applications.** A graphical browser and the toolkit stack under it (fonts,
  GTK or Qt, a media stack), per zone, with GPU rendering considered zone by
  zone rather than switched on; a mail client, a document viewer, a file
  manager that understands transfers between zones.
- **Software from somewhere.** A package manager and a signed binary
  repository, or zones that carry their own userland (an image per zone,
  updated like the root). The decision is an ADR before it is code.
- **The laptop.** Sound (per zone, brokered like the clipboard), Bluetooth,
  suspend and resume with the zone volumes' keys dropped across it, power
  management, display hotplug and multiple monitors, keyboard layouts and
  input methods.
- **Disk unlock by the TPM.** Measured boot and a state partition sealed to
  it, with a passphrase as the fallback; the reset-attack mitigation's clean
  shutdown path.
- **Reproducible builds.** Two builds of one commit produce one image, checked
  by CI; then a bootstrappable toolchain (something like `live-bootstrap`) so
  the first compiler is not the host's.
- **A kernel built with Clang,** for kernel control-flow integrity, with
  userspace staying on GCC; and NVIDIA graphics if nouveau's firmware ever
  fits the budget.
- **Installer choices.** Beside another operating system, on more than one
  disk, with a chosen slot size; an upgrade path for a machine whose slots
  have become too small.
- **Anonymity as a zone property.** A Tor or VPN uplink a zone can be routed
  through, enforced by the net zone rather than configured inside the zone.
- **A hardware certification list,** kept by people who ran the acceptance
  suite on the machine they are vouching for.
- **An independent audit** of the whole boundary (kernel configuration,
  kryptikd, the compositor path, the update chain), published.

## A note on timeline

LFS to a bootable base is a well-documented path and mostly a matter of grinding
through it. The compartment layer, the compositor and the bootable signed image are the
actual project, and they are not documented anywhere — that is original systems work. Anyone estimating this in
weeks is estimating the cross toolchain.
