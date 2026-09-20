# Kryptik status

What `make acceptance` has proven, and on which images. The suites are
defined in `tools/acceptance.sh`. Superseded results are replaced here, not
appended; raw logs stay in the run's artifacts, never in Git.

## Where builds run

The whole distribution is built and tested on GitHub's runners by the
`Distro` workflow (`.github/workflows/distro.yml`): stages 01–02, then stages
04–06 and the signed media, then `make acceptance` under KVM on the exact
images that came out. Each run uploads the acceptance report with per-item
logs and serial transcripts. A push to `main` that changes more than
documentation starts a run; a newer push cancels one in flight.

## Last full pass

Revision `9749cd8` on `main`, 2026-09-16, release `0.1.20260916.9749cd84`.
Every suite passed:

| Suite | Result | What ran |
| --- | --- | --- |
| inputs | PASS | revision, compositor sources, `sources.lock`, media hashes |
| build | PASS | host suites 16/0, libc unwinding 7/0, userspace smoke, artifact hardening audit, kernel config validation, upstream support status |
| boot | PASS | USB image 36/0, ISO 36/0, firmware-only boot attested from the recorded QEMU commands |
| install | PASS | install-test 43/0, state-test 47/0 |
| integrity | PASS | Secure Boot 36/0, foreign keys refused 6/0, integrity-test 23/0 |
| zones | PASS | zones-test 37/0 (network and encrypted storage on the Kryptik kernel) |
| desktop | PASS | gui-test 30/0 |
| update | PASS | update-test 21/0 |
| release | PASS | export |

All of this ran under QEMU with OVMF firmware. Nothing has run on physical
hardware yet.

## Since then

- `5c88a65` renamed the acceptance suites. Its Distro run failed one item,
  `build / kernel-config`: `5a3d77d` had added `CONFIG_TG3`, which is not a
  kernel symbol, so the Broadcom tg3 driver would silently have been left
  out. The fragment now says `CONFIG_TIGON3`. Unverified until the next run.

## Known gaps

Documented rather than closed:

- The watchdog catches a machine that has stopped, not one that is merely
  broken. A supervised service feeds every watchdog device; if userspace
  stops being scheduled the machine resets, and the state suite proves it
  by stopping the feeder. A crashed service or a frozen desktop on a
  machine that is otherwise running is not detected, on purpose: a false
  reboot is worse than the hang. A hung kernel is reset only where there
  is a hardware timer (Intel TCO, AMD SP5100) or the lockup detectors
  panic first; no physical timer has been exercised yet.
- Releases are signed by a developer key the build generates.
- Nothing has run on physical hardware.
- glibc is 2.40 with upstream's maintained release branch applied as of
  2026-09-10 (`build/patches/glibc-2.40/`), so it carries that branch's
  security fixes; nothing moves the pin along the branch automatically, and
  2.40 is three releases old.
- The artifact audit still reports soft findings: binaries without CET or
  BIND_NOW, some non-PIE objects, some RPATHs. The audit's log in each run
  has the current counts.
- dhcpcd runs without its own privilege separation inside the net zone; the
  zone is its sandbox.
- The builds are not reproducible bit for bit.

## Decisions that shaped the current system

- glibc stays at 2.40 with the upstream `_dl_find_object` fixes and the fix
  for bug 33088, the defect the loader actually had
  ([docs/glibc-loader-defect.md](glibc-loader-defect.md)). Both glibc builds
  (stages 01 and 04) apply the same patches, and each proves with `readelf`
  that the loader takes its own map bounds without a run-time relocation.
- The boot chain has one loader, the kernel's EFI stub. The command line
  (root slot by partition label, verity root hash, salt) is compiled in and
  `CMDLINE_OVERRIDE` ignores load options; dm-init builds the verity root
  with no initramfs; A/B slots switch by `BootNext` and are committed only
  after a boot that boot-success judged healthy. See
  [the boot and update design](design/boot-and-updates.md).
- Test media honour a `kryptik-testctl` control disk. Installed systems are
  driven over the serial console as an ordinary user, with `su` for
  privileged steps; root cannot log in at a terminal.
- Build stamps chain by fingerprint across stages, so a change to an early
  package rebuilds everything after it.
- Transfers between zones ask the person through the trusted chrome, and the
  clipboard moves between zones only by the zone 0 gesture.
