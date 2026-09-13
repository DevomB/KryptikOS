# Kryptik overnight run status (2026-09-13)

Authoritative run record for the scope in `docs/OVERNIGHT_GOAL.md`. Superseded
facts are replaced, not appended. Raw logs live under the ignored build output
named below, never in Git.

## Acceptance gates

| Gate | State | Evidence |
| --- | --- | --- |
| G1 Baseline | ACTIVE | Branch `overnight-2026-09-13/impl` from integration tip 75f1cc3; cherry-picks ffff72f, 3fcf4bf, a67b1ba; compositor import b2c715d; harness/glibc commits 5b5ae9c, ed83946. Build inputs and paths below. |
| G2 Runtime/build | ACTIVE | glibc fix carried as `build/patches/glibc-2.40/` (upstream bug 31943 backport); harness chain proven by `tools/test-step-errexit.sh` (58 checks, 14 fail against the old harness). Target proof pending: `make test-libc-unwind` after stage 04. |
| G3 Firmware boot | OPEN | |
| G4 Installation | OPEN | |
| G5 Boot integrity | OPEN | |
| G6 Zones/network | OPEN | |
| G7 Storage | OPEN | |
| G8 Desktop | OPEN | |
| G9 OS updates | OPEN | |
| G10 Delivery | OPEN | |

## Environment and the one authoritative tree

- Linux build host: WSL2 distro `kryptik-build` (Ubuntu 24.04.4, root by
  default, `build` uid 1000 for the unprivileged stages, /dev/kvm present,
  8 CPUs, 7 GB RAM, kernel 6.6.87.2-microsoft-standard-WSL2).
  Installed 2026-09-13 with `wsl --install Ubuntu-24.04 --name kryptik-build
  --location C:\Users\devom\kryptik-wsl\kryptik-build --no-launch`.
- The original `Ubuntu` distro cannot start: its `ext4.vhdx` is attached to
  the Windows host as PhysicalDrive1 (read-only, RAW, via the Virtual Disk
  Service at 2026-09-11 23:54:01). `Dismount-DiskImage` from an elevated
  PowerShell releases it; a non-elevated call returns silently. The old
  worktrees and artifacts under `/home/devomb` are unreachable until then;
  nothing in them is needed, every source is re-fetched and re-verified.
- Worktree: `/root/kryptik/impl` (WSL) = `\\wsl.localhost\kryptik-build\root\kryptik\impl`.
- Contract: `KRYPTIK_WORK=/root/kryptik/work`, `KRYPTIK_SOURCES=/root/kryptik/sources`
  (71 tarballs/patches, 467 MB, all verified against `sources.lock`),
  `KRYPTIK_OUT=/root/kryptik/out`. Jobs: -j4 (RAM-bound).
- Windows checkout `C:\Coding-Projects\Linux Distro` stays on `main`
  (d2abaef) with its 16 mode-only changes and untracked `compositor/`
  untouched; final artifacts are exported to `out/overnight/` there.
- Tectonix 0.5.7 baseline on the implementation root: quality_signal 6841,
  bottleneck "equality" (cognitive complexity in `spawn.rs::run_in_zone`,
  `main.rs::cmd_check`); `.tectonix/session-baseline.json` written. Triage
  only.

## Active jobs

| Job | Command | Log |
| --- | --- | --- |
| build orchestrator | `/root/build-run.sh` (stages 01+02 as `build`, then waits for `/root/kryptik/GO-04`, `GO-05`) | `/root/kryptik/logs/build-run.out`, per-stage `temp-tools.log`, `system.log`, `kernel.log` |
| glibc reproduction | `/root/glibc-repro.sh` (host build of 2.40 unpatched vs patched with Kryptik flags) | `/root/kryptik/logs/glibc-repro.out` |

## Decisions taken in this run

- glibc: keep 2.40, apply upstream's own release/2.40/master backport of the
  bug 31943 fix (plus its two branch prerequisites) rather than bump versions
  mid-build; provenance in `build/patches/glibc-2.40/README.md`. The 2.40
  tarball still lacks the branch's later security backports (e.g.
  CVE-2025-0395, CVE-2025-4802); recorded as a known weakness for a
  version bump after this run, not hidden.
- Stamps chain by fingerprint and seed across stages (ed83946). Cost: a
  change to an early package rebuilds what follows; benefit: no stale
  downstream artifact can claim to be current.

## Next commands

```sh
# inside kryptik-build, as root
tail -f /root/kryptik/logs/build-run.out
touch /root/kryptik/GO-04     # after kryptikd is built and stage 04 edits are done
touch /root/kryptik/GO-05     # after the kernel fragment edits are done
```

## Unresolved blockers

- None external. The Ubuntu VHD lock is worked around, not cleared.
