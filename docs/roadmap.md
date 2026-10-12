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
| Compartment layer: zones, `kryptikd run`, lifecycle, the net zone, per-zone LUKS2 volumes, seccomp, the broker, `kryptikd serve` | `compartments/tests/adversarial.sh`, each attempt under the part of a zone that refuses it (its namespaces, its Landlock rules or its seccomp filter): no other zone's processes, no other zone's files, no physical NIC, no vault, no dangerous syscalls; `make zones-test` on the installed system |
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
      Planned for October 2026.
- [x] **CPU microcode.** Built into the signed kernel from Intel's release and
      AMD's containers in linux-firmware; stage 05 refuses a kernel without
      the blobs. The load itself is proven only on a physical machine.
- [x] **A clock that is right.** The net zone measures the offset with SNTP;
      zone 0 never goes below the build date, applies corrections up to an
      hour, and asks the user beyond that ([time design](design/time.md)).
      Six guest checks prove it on the installed system: the floor's boot
      service ran, a clock set to 2000 came back to the build date, a
      release dated 2099 that the release key did not sign left the floor
      alone, a claim of two minutes was applied, one before the build date
      was refused, and a day's jump waited for the user.

### Trusted by someone who did not build it

- [ ] **Production keys.** A release key and a Secure Boot key held in the
      repository's protected release environment, which only a release tag's
      build can use, and only once the maintainer approves it; their public
      halves in the tree under `build/config/release/`; a written procedure
      for making, using, rotating and revoking them
      ([release keys](release-keys.md)); a build that signs with a key it is
      handed and refuses to invent one for a release; and an installed system
      that accepts the next release and refuses a development build.
      Acceptance's production part, with a throwaway key medium, proves a
      build signing with the medium it is handed and the installed system's
      half; `tools/tests/release-keys.sh` proves a production build refuses to
      make keys of its own. The statement key goes to the `github-pages`
      environment, which only main's workflows reach, and
      `tools/make-release-keys.sh` refuses to store it unless that
      environment deploys from main alone (`tools/tests/make-release-keys.sh`).
      The keys are still to be made.
- [x] **No known-vulnerable pins.** Every pin behind its upstream has a review
      in `tools/pin-reviews.tsv`, and `tools/check-pin-reviews.sh` fails CI
      without one. No pin is held, and a release runs the gate with
      `--no-held`. A CVE that no release fixes yet is recorded in its pin's
      review, with why it does not reach Kryptik.
      `tools/check-source-currency.sh` also says when glibc's release branch
      has moved past the commit its patch set was cut from.
- [x] **An update channel** ([design](design/update-channel.md)). The net zone
      fetches a release; zone 0 verifies it as it does a payload from disk,
      as nobody, on copies. `tools/release-channel.sh` publishes a release
      with its signed statement and re-signs the statement on a schedule.
      Stage 06 publishes each build with it, and the update suite fetches,
      stages, applies and commits the release from that channel over the
      test network. When no statement has come for 30 days, whether the
      newest went old or none came since the install, the login prompt, the
      launcher and `kryptik update status` say so: the update suite moves
      the clock to read the prompt for both and status for an old one, the
      desktop suite sets up both of the launcher's lines, and kryptikd's
      unit tests hold status for an install that heard none. A clock that
      reads more than a day before the newest statement would refuse every
      newer one, so the prompt and status say that too, and the update
      suite moves the clock 3 days back to read both.
- [x] **An encrypted state partition** ([design](design/state-encryption.md)).
      The install suite finds it is LUKS, asked for at boot and mounted on
      `/var`; the state suite boots degraded and says why when it is
      missing or unreadable; the integrity suite recovers a machine with
      its state intact.
- [x] **kryptikd built by a pinned compiler.** The Distro workflow installs
      rustc 1.98.1 from Rust's release tarballs, held to the SHA-256 in
      `build/config/rust.lock` as sources.lock holds cmake's (each checked
      against the Rust release key when pinned), and refuses to build the
      shipped binaries with any other.

### Fails safe and says what it is

- [x] **A watchdog for a hung userspace.** The state suite stops the feeder
      and the machine resets and comes back with its data.
- [x] **Every status row is tested.** Each row of the status table names
      the check that can fail it; stage 05, stage 06 and `make acceptance`
      were the last to read *implemented*.
- [x] **The accepted lists are reviewed.** `checker-accepted.txt`,
      `hardening-exceptions.txt`, the setuid allowlist and the artifact
      audit's soft findings: each entry closed or re-justified, with the
      audit's counts in the release notes. Acceptance fails on an artifact
      finding that `build/config/artifact-accepted.txt` gives no reason for.
- [x] **Core scheduling per zone, and the SMT decision.** ADR-011 decides:
      `nosmt` stays, since a zone's cookie cannot keep it off the thread
      beside the kernel, whose execution carries no cookie; each zone still
      takes a cookie, since root can turn SMT back on through
      `/sys/devices/system/cpu/smt/control`.
- [x] **The net zone's remaining hardening.** Decided, with the reasons, in
      the [net zone design](design/net-zone.md).
      [Net zone surface](design/net-zone-surface.md) weighs three ways to
      narrow what it still reaches in the kernel.
- [x] **Someone else has attacked it.** The broker protocol and
      `kryptik-wlproxy`'s wire parser are fuzzed in the unit suites with a
      corpus in the tree ([broker design](design/broker.md)). kryptikd's
      launch path, the update chain, the broker and the desktop boundary
      (`kryptik-wlproxy` and the compositor) have each been reviewed by
      someone who did not write them, and what they found is fixed. So has
      the net zone: what that read found is fixed, or stated in the
      [threat model](threat-model.md#compromised-net-zone) where it stays.
- [ ] **A release, as an object.** Version numbering, release notes from the
      acceptance report, the licences of everything shipped (firmware from
      `WHENCE`), the corresponding source, and install, update and recovery
      instructions followed by someone other than their author. The source is
      `make source-bundle`: every locked tarball with its signatures, the
      crates the Rust binaries link, and the repository at the build commit,
      with a manifest. Stage 04 installs each source's licence files under
      `/usr/share/licenses/`, firmware's `WHENCE` among them, and acceptance
      fails on a source without any; the build fails on a crate either
      `Cargo.lock` names without its texts in `build/licences`. A tag
      `v<version>` builds and tests that version and drafts it on the
      repository's Releases page with its source and its acceptance record
      ([releases](releases.md)). The suites follow the user guide's own
      steps: the medium's console suite types the install, the state
      header's backup to a second disk and `kryptik-recover`'s commands as
      the guide gives them; the state suite answers first-boot setup at the
      console; the update suite runs `kryptik update` and `kryptik-update`
      as the guide does; and every claim the guide's install, first-boot,
      update and recovery text makes has a check behind it. Still needed, by
      someone other than their author, as no virtual machine can: writing a
      stick from a downloaded release and checking it as the guide says,
      including from macOS or Windows; the same steps on a real machine
      (above); and reading the guide for what it leaves unclear.

### What the architecture promises and the tree does not yet keep

- [x] **Xwayland.** Not built, and ADR-004 says so: X11 programs are
      outside 1.0, and Version 2's applications decide whether one runs
      inside a zone.
- [x] **cpu and io limits.** `cpu_max` is a share of one CPU as a percentage,
      held by cgroup `cpu.max`; `io_max` is bytes per second each way on an
      encrypted zone's volume, held by `io.max` on the volume's devices
      ([design](design/resource-limits-and-ephemeral-zones.md)). The launcher
      suite measures both; `untrusted` ships with `cpu_max = "200%"` and
      `net` with `"100%"`, and the zones suite reads both back.
      Weights are not set: `io.weight` waits on a kernel choice, blk-iocost or BFQ.
- [x] **The setuid audit fails.** Stage 06 refuses an unlisted setuid bit and
      a list entry without its reason; shadow's and util-linux's spare bits are
      dropped in their recipes, and traceroute is not built. The zones suite
      audits the installed root again: setuid bits, file capabilities and the
      sysctls as applied.
- [x] **Signatures as a gate.** `tools/verify-signatures.sh --strict` runs
      on every push in CI's source-manifest job. Every key has a published
      route to its fingerprint (`tools/key-provenance.tsv`), except ten that
      have no usable key (elfutils, file, flex, libevdev, libmnl, lvm2,
      wpa_supplicant, xkeyboard-config, zlib, zstd), which
      `tools/source-notes.tsv` accepts with the routes that were tried; a
      note left after its key is held fails the gate.
- [x] **Zone 0 runs no user application, proven.** The desktop suite reads
      every process with a zone's terminal up: outside the zones' cgroups only
      zone 0's own programs run, and the zone's terminal is seen in its cgroup.
- [x] **The shipped-binary audit reads the image's root.** Stage 06 fails
      the build on a finding in the tree it packs. The stack protector and
      FORTIFY stay counts, since an object without either shows nothing about
      its flags ([hardening](hardening.md#what-the-audit-finds)); the record
      names such objects.
- [x] **A destroy verb.** `kryptikd volume destroy NAME` erases a stopped
      zone's key slots and deletes its container; it refuses an open volume
      ([design](design/encrypted-volumes.md)). The zone's definition stays.

## Version 2

A desktop someone can live in, built the same way.

- **Applications.** A graphical browser and the toolkit stack under it, per
  zone, with GPU rendering decided zone by zone; a mail client, a document
  viewer, a file manager that understands transfers between zones.
- **Software from somewhere.** A package manager and a signed binary
  repository, or zones that carry their own userland. An ADR first.
- **The laptop.** Per-zone sound brokered like the clipboard, Bluetooth,
  suspend and resume with volume keys dropped across it, power management,
  hotplug and multiple monitors, input methods and a second keyboard layout
  to switch to.
- **Disk unlock by the TPM.** Measured boot and a state partition sealed to
  it, with the passphrase as fallback.
- **Reproducible builds,** checked by CI, then a bootstrappable toolchain so
  the first compiler is not the host's.
- **A kernel built with Clang** for kernel CFI, userspace staying on GCC.
- **Installer choices.** Beside another OS, across disks, and an upgrade path
  when slots become too small.
- **Anonymity as a zone property.** A Tor or VPN uplink enforced by the net
  zone.
- **A hardware certification list** from people who ran acceptance on the
  machine they vouch for.

## Housekeeping

- [x] **File organization.** Every Rust module's tests sit beside it in
      `<module>/tests.rs`; stage 04's recipes are one file per step under
      `build/recipes/`, with the order and the runner kept in the stage and
      every step's fingerprint unchanged; the tools' suites live in
      `tools/tests/`, one per tool. Organization, not abstraction: no layer
      without a second caller. The launcher suite stays one file.
- **An independent audit** of the whole boundary, published.
