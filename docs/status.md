# Status

What exists, how it is tested, and what `make acceptance` last proved. The
suites are defined in `tools/acceptance.sh`; per-item logs and serial
transcripts are in each Distro run's artifacts.

## What is tested

**implemented**: the code exists and builds. **tested**: an automated check
exercises it and can fail. Acceptance runs everything on the exact images
that ship, under QEMU with OVMF firmware.

| Area | State |
| --- | --- |
| Host requirement check | **tested**: `build/stages/00-host-check.sh` |
| Source fetching, checksum locking, signature and provenance verification | **tested**: `make verify`, `make verify-provenance` |
| Kernel currency, fragment validation and hardening | **tested**: `make validate-kernel-boot` and `validate-kernel-hardened` check that every fragment symbol exists; `make check-kernel-hardening` resolves the config against the pinned source, refuses a dropped fragment line and holds kernel-hardening-checker to `build/config/kernel/checker-accepted.txt` |
| Stages 01–02: cross toolchain, temporary tools | **tested**: glibc carries two upstream loader fixes the 2.40 tarball lacks (`build/patches/glibc-2.40/`), and each glibc build proves with `readelf` that its loader takes its own map bounds without a run-time relocation |
| Stage 04: base system | **tested**: every package builds with the hardening set; `make test-libc-unwind` (the target libc unwinds through a dlopened library), `make smoke-userspace`, `make audit-artifacts` (the ELF headers of what shipped) |
| Stage 05: hardened kernel | **implemented**: EFI stub, compiled-in command line with `CMDLINE_OVERRIDE`, dm-init verity root, Landlock, cgroup v2; the stage refuses a config that drops a fragment line or that kernel-hardening-checker faults beyond the accepted list. The kernel proves itself by booting the media |
| Stage 06: install media and release payloads | **implemented**: USB image and ISO with kernels signed by a build-generated Secure Boot key, a signed release manifest per payload |
| Firmware boot of the media | **tested**: `make media-smoke-usb` / `media-smoke-iso`, firmware discovery only (no `-kernel`, `-initrd`, `-append` or host filesystem; acceptance reads the recorded QEMU commands back) |
| Installation and the state partition | **tested**: `make install-test` (install, boot alone, reboot, cold boot, refusals including an injected I/O error), `make state-test` (a cloned disk, ambiguous labels, a corrupt or missing state partition: the system boots degraded and says so) |
| Boot integrity | **tested**: `make media-smoke-secureboot`, `make media-refused-foreign-keys` (Microsoft keys refuse the medium), `make integrity-test` (a foreign-signed boot file refused, a tampered root refused by dm-verity, recovery from the medium with state intact) |
| Zones, network and encrypted storage on the installed kernel | **tested**: `make zones-test`, running `zones-check.sh` and the compartment suites as root on the Kryptik kernel |
| The zoned desktop | **tested**: `make gui-test`, covering what a zone's client is offered through its proxy, zone borders and title prefixes windowed and fullscreen, per-zone clipboards, the clipboard-move gesture and file transfers answered on the trusted chrome |
| A/B updates and recovery | **tested**: `make update-test`, covering apply, trial boot, commit, rollback, refusals (wrong key, modified image, truncated kernel, unlisted file, downgrade, concurrent run, full disk), interruptions and a broken trial that falls back |
| Zone definitions, `kryptikd run`, lifecycle, limits, ephemeral storage | **tested**: kryptikd unit tests, `compartments/tests/` |
| Per-zone LUKS2 volumes | **tested**: lifecycle as root on a developer host; on the target kernel in `zones-test` |
| The broker: consented file transfer, per-zone clipboards, the zone 0 clipboard gesture | **tested**: kryptikd unit tests, `compartments/tests/serve.sh`; on the target in `gui-test` |
| The compositor layer: `kryptik-wlproxy`, `zoneid`, the dwl zone-border patch | **tested**: `make test-compositor` (including the live proxy against a real socket), `make test-desktop-identity` |
| `kryptik`, the user-facing command | **tested**: `compartments/tests/cli.sh` |
| `make acceptance` | **implemented**: every suite in one run, PASS / FAIL / INCOMPLETE per item, with a report and an export that re-hashes what it copies |

## Last full pass

Revision `55e1652` on `main`, 2026-09-20, release `0.1.20260920.55e16523.1`.
Every suite passed, and no suite's own summary counted a failure:

| Suite | Result | What ran |
| --- | --- | --- |
| inputs | PASS | revision, compositor sources, `sources.lock`, media hashes |
| build | PASS | host suites 18/0, libc unwinding 7/0, userspace smoke, artifact hardening audit, kernel config validation, upstream support status |
| boot | PASS | USB image 38/0, ISO 38/0, firmware-only boot attested from the recorded QEMU commands |
| install | PASS | install-test 43/0, state-test 54/0 (with the watchdog reset) |
| integrity | PASS | Secure Boot 38/0, foreign keys refused 6/0, integrity-test 26/0 |
| zones | PASS | zones-test 42/0 (network, encrypted storage and the clock on the Kryptik kernel) |
| desktop | PASS | gui-test 30/0 |
| update | PASS | update-test 21/0 |
| release | PASS | export |

Not yet proven by a run: the kernel with drivers as modules and its size
budget, the update channel's fetch on the installed system, and the encrypted
state partition.

## Known gaps

- Nothing has run on physical hardware.
- Releases are signed by a developer key the build generates, and the
  kernel's modules by one each kernel build makes for itself.
- The watchdog catches a machine that has stopped, not one that is merely
  broken. A supervised service feeds every watchdog device, so a machine
  whose userspace stops being scheduled resets (the state suite proves it by
  stopping the feeder). A crashed service or a frozen desktop is not
  detected, because a false reboot is worse than the hang. A hung kernel is
  reset only by a hardware timer (Intel TCO, AMD SP5100) or the lockup
  detectors; no physical timer has been exercised.
- glibc is 2.40 with upstream's maintained release branch applied as of
  2026-09-10 (`build/patches/glibc-2.40/`). Nothing moves the pin along the
  branch automatically, and 2.40 is three releases old.
- The artifact audit still reports soft findings: binaries without CET or
  BIND_NOW, some non-PIE objects, some RPATHs. Each run's audit log has the
  counts.
- dhcpcd runs without its own privilege separation; the net zone is its
  sandbox.
- The builds are not reproducible bit for bit.
- A tree restored from the Actions cache is resumed by its step stamps, and a
  step whose inputs changed builds again over what its old version installed.
  Nothing records what a step installed, so a file the new version no longer
  installs stays in the image. Recording it safely means a list per step kept
  until the step succeeds, NUL-separated, with removals held to the end of the
  stage and never of a shared object something still links.
- The setuid audit does not look at file capabilities (`security.capability`),
  the other way a file is given privilege.
