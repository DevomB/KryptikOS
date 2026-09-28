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
| Stage 05: hardened kernel | **tested**: the stage refuses a config that drops a fragment line or that kernel-hardening-checker faults beyond the accepted list; every VM suite boots the kernel (EFI stub, compiled-in command line with `CMDLINE_OVERRIDE`), `make integrity-test` its dm-init verity root, and `make zones-test` Landlock, seccomp and cgroup v2 on it |
| Stage 06: install media and release payloads | **tested**: the firmware, install, integrity and update suites boot its USB image and ISO, whose kernels carry a build-generated Secure Boot key's signature; the stage strips every setuid bit the allowlist does not justify (`tools/tests/audit-setuid.sh`) and checks that the image's trust anchor refuses a statement signed by the release key |
| Firmware boot of the media | **tested**: `make media-smoke-usb` / `media-smoke-iso`, firmware discovery only (no `-kernel`, `-initrd`, `-append` or host filesystem; acceptance reads the recorded QEMU commands back) |
| Installation and the state partition | **tested**: `make install-test` (install, boot alone, reboot, cold boot, refusals including an injected I/O error), `make state-test` (a cloned disk, ambiguous labels, a corrupt or missing state partition: the system boots degraded and says so) |
| Boot integrity | **tested**: `make media-smoke-secureboot`, `make media-refused-foreign-keys` (Microsoft keys refuse the medium), `make integrity-test` (a foreign-signed boot file refused, a tampered root refused by dm-verity, recovery from the medium with state intact) |
| Zones, network and encrypted storage on the installed kernel | **tested**: `make zones-test`, running `zones-check.sh` (the net zone associating over a `mac80211_hwsim` radio, the installed root's setuid bits and file capabilities against the allowlists, and every sysctl read back) and the compartment suites as root on the Kryptik kernel |
| The zoned desktop | **tested**: `make gui-test`, covering what a zone's client is offered through its proxy, zone borders and title prefixes windowed and fullscreen, per-zone clipboards, the clipboard-move gesture and file transfers answered on the trusted chrome |
| A/B updates and recovery | **tested**: `make update-test`, covering apply, trial boot, commit, rollback, refusals (wrong key, modified image, truncated kernel, unlisted file, downgrade, concurrent run, full disk), interruptions and a broken trial that falls back |
| Zone definitions, `kryptikd run`, lifecycle, limits, ephemeral storage | **tested**: kryptikd unit tests, `compartments/tests/` |
| Per-zone LUKS2 volumes | **tested**: lifecycle as root on a developer host; on the target kernel in `zones-test` |
| The broker: consented file transfer, per-zone clipboards, the zone 0 clipboard gesture | **tested**: kryptikd unit tests, `compartments/tests/serve.sh`; on the target in `gui-test` |
| The compositor layer: `kryptik-wlproxy`, `zoneid`, the dwl zone-border patch | **tested**: `make test-compositor` (including the live proxy against a real socket), `make test-desktop-identity` |
| `kryptik`, the user-facing command | **tested**: `compartments/tests/cli.sh` |
| `make acceptance` | **tested**: `tools/tests/acceptance-inputs.sh` covers the release it chooses, the verdict, the merge of a run split across machines and the export's list; every suite runs in one run or in parts, PASS / FAIL / INCOMPLETE per item, with a report and an export that re-hashes what it copies |

## The last full pass

The newest green Distro run on main is the last full pass: its verdict job
fails unless every suite passed. The run's `acceptance-report` artifact holds
the merged `REPORT.md`, one row per item, `results.tsv` and each item's log
under `work/acceptance/`, and each part's logs and serial transcripts under
`parts/`. A local `make acceptance EXPORT=DIR` writes the same report for the
media it tested.

## Known gaps

- Nothing has run on physical hardware.
- Every release so far is signed by a developer key the build generates. A
  production build signs only with keys it is handed, and none have been
  made. The kernel's modules are signed by a key each kernel build makes for
  itself.
- The watchdog catches a machine that has stopped, not one that is merely
  broken. A supervised service feeds every watchdog device, so a machine
  whose userspace stops being scheduled resets (the state suite proves it by
  stopping the feeder). A crashed service or a frozen desktop is not
  detected, because a false reboot is worse than the hang. A hung kernel is
  reset only by a hardware timer (Intel TCO, AMD SP5100) or the lockup
  detectors; no physical timer has been exercised.
- glibc is 2.40 with upstream's maintained release branch applied as of
  2026-09-10 (`build/patches/glibc-2.40/`). Nothing moves the pin along the
  branch automatically, though `tools/check-source-currency.sh` reports when
  the branch has moved on.
- The artifact audit still reports soft findings, objects without CET and
  RPATHs among them. Each has a reason in
  `build/config/artifact-accepted.txt`, and acceptance fails on any other.
  Each run's audit log has the counts.
- dhcpcd runs without its own privilege separation; the net zone is its
  sandbox.
- The builds are not reproducible bit for bit.
- A resumed tree builds a changed step again over what its old version
  installed, and nothing records what a step installed. In CI a new package
  version, or a package dropped from `sources.lock`, starts stage 04 again
  from the stage 02 tree, but a recipe change does not: a file its new
  version no longer installs stays in the image, as it does in a local work
  directory rebuilt with `KRYPTIK_STALE=rebuild`. Removing such files safely
  needs a record of what each rebuild wrote, not a before and after listing,
  with removals held to the end of the stage and never of a shared object
  something still links.
