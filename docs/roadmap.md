# Roadmap

Each item names the check that finishes it. An item is done when its check
exists and passes, not when its code is written. What is tested today is in
[status.md](status.md).

## Built

| Layer | Exit test |
| --- | --- |
| Scaffolding: host check, source fetching with a checksum lock | `make check && make sources` on a clean Debian or Arch host |
| Cross toolchain (stage 01): binutils, GCC and glibc against a sysroot | the cross compiler emits PIE binaries that request the target loader |
| Temporary tools (stage 02) | everything a chroot needs is present, and the built `bash` requests the target loader |
| Base system (stage 04), s6-rc init (ADR-006) | the system boots to a shell (`make media-smoke-usb`); `make test-libc-unwind`; `tools/audit-setuid.sh` reports no unjustified setuid binary |
| Hardened kernel (stage 05): LTS plus linux-hardened (ADR-009), Landlock and seccomp (ADR-007) | `make check-kernel-hardening`, `make validate-kernel`, `make check-kernel-eol`; the media boot it |
| Compartment layer: zones, `kryptikd run`, lifecycle, the net zone, per-zone LUKS2 volumes, seccomp, the broker, `kryptikd serve` | `compartments/tests/adversarial.sh` as root inside a zone: no other zone's processes, no other zone's files, no physical NIC, no vault, no dangerous syscalls; `make zones-test` on the installed system |
| Compositor and GUI isolation: `kryptik-wlproxy`, `zoneid`, zone borders, the trusted chrome | a zone cannot capture or keylog another zone's surfaces, and every window is attributable to its zone (`make gui-test`) |
| Bootable signed image: stage 06, `kryptik-install`, the state partition, A/B updates, `kryptik-recover` | Secure Boot on and a tampered root refused under OVMF (`make integrity-test`, `make media-refused-foreign-keys`) |

## Version 1.0

Kryptik installs and runs on real machines with Secure Boot on, reaches a
network over a wire or a radio, updates itself from releases signed by a key
that is not the build's own, ships nothing it knows to be vulnerable, and
every row of the status table reads *tested*. A user can install it, log in,
work in zones from a terminal and a text browser, and keep it up to date.

### Runs on real machines

- [ ] **Physical hardware.** Installed and booted with Secure Boot on at least
      three machines: a wired desktop, an Intel laptop on Wi-Fi alone, an AMD
      laptop. What each lacked becomes a line in `boot.fragment` or
      `firmware.list`, and the machines start a hardware list in the README.
- [x] **CPU microcode.** Built into the signed kernel from Intel's release and
      AMD's containers in linux-firmware; stage 05 refuses a kernel without
      the blobs. The load itself is proven only on a physical machine.
- [x] **A clock that is right.** The net zone measures the offset with SNTP;
      zone 0 never goes below the build date, applies corrections up to an
      hour, and asks the user beyond that ([time design](design/time.md)).
      Five guest checks prove it on the installed system.

### Trusted by someone who did not build it

- [ ] **Production keys.** A release key and a Secure Boot key kept offline,
      a written ceremony for making, using, rotating and revoking them, a
      build that signs with a key it is handed and refuses to invent one for
      a release, and an installed system that accepts the next release and
      refuses a development build.
- [ ] **No known-vulnerable pins.** Every pin behind its upstream has a review
      in `tools/pin-reviews.tsv`, and `tools/check-pin-reviews.sh` fails CI
      without one. Done when the rebuilt image passes acceptance and the held
      pins are moved or patched (a release runs the gate with `--no-held`).
      Still to write: a check that the glibc branch has moved past the pinned
      commit.
- [ ] **An update channel** ([design](design/update-channel.md)). The net zone
      fetches a release; zone 0 verifies it as it does a payload from disk.
      Done when the update suite fetches, stages, applies and commits a
      release over the test network, and the release tooling publishes a
      signed pointer.
- [ ] **An encrypted state partition** ([design](design/state-encryption.md)).
      Done when the install, state and integrity suites pass with it.
- [x] **kryptikd built by a pinned compiler.** The Distro workflow installs
      rustc 1.98.1 from Rust's release tarballs, held to the SHA-256 in
      `build/config/rust.lock` as sources.lock holds cmake's (each checked
      against the Rust release key when pinned), and refuses to build the
      shipped binaries with any other.

### Fails safe and says what it is

- [x] **A watchdog for a hung userspace.** The state suite stops the feeder
      and the machine resets and comes back with its data.
- [ ] **Every status row is tested.** Stage 05, stage 06 and `make
      acceptance` read *implemented*: each gets a check that can fail, or the
      row says why it cannot.
- [ ] **The accepted lists are reviewed.** `checker-accepted.txt`,
      `hardening-exceptions.txt`, the setuid allowlist and the artifact
      audit's soft findings: each entry closed or re-justified, with the
      audit's counts in the release notes.
- [ ] **Core scheduling per zone, and the SMT decision.** ADR-011 revisited
      with a measurement; the command line says `nosmt` or not, for a written
      reason.
- [x] **The net zone's remaining hardening.** Decided, with the reasons, in
      the [net zone design](design/net-zone.md).
- [ ] **Someone else has attacked it.** The broker protocol and
      `kryptik-wlproxy`'s wire parser are fuzzed in the unit suites with a
      corpus in the tree ([broker design](design/broker.md)); still needed is
      a review of kryptikd's launch path by someone who did not write it.
- [ ] **A release, as an object.** Version numbering, release notes from the
      acceptance report, the licences of everything shipped (firmware from
      `WHENCE`), the corresponding source, and install, update and recovery
      instructions followed by someone other than their author.

## Version 2

A desktop someone can live in, built the same way.

- **Applications.** A graphical browser and the toolkit stack under it, per
  zone, with GPU rendering decided zone by zone; a mail client, a document
  viewer, a file manager that understands transfers between zones.
- **Software from somewhere.** A package manager and a signed binary
  repository, or zones that carry their own userland. An ADR first.
- **The laptop.** Per-zone sound brokered like the clipboard, Bluetooth,
  suspend and resume with volume keys dropped across it, power management,
  hotplug and multiple monitors, keyboard layouts and input methods.
- **Disk unlock by the TPM.** Measured boot and a state partition sealed to
  it, with the passphrase as fallback.
- **Reproducible builds,** checked by CI, then a bootstrappable toolchain so
  the first compiler is not the host's.
- **A kernel built with Clang** for kernel CFI, userspace staying on GCC.
- **Installer choices.** Beside another OS, across disks, a chosen slot size,
  and an upgrade path when slots become too small.
- **Anonymity as a zone property.** A Tor or VPN uplink enforced by the net
  zone.
- **A hardware certification list** from people who ran acceptance on the
  machine they vouch for.
- **An independent audit** of the whole boundary, published.
