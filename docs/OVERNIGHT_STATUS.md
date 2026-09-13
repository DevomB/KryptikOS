# Kryptik run status (2026-09-13)

Authoritative run record for the scope in `docs/OVERNIGHT_GOAL.md`. Superseded
facts are replaced, not appended. Raw logs live under the ignored build output
named below, never in Git. The work is ongoing development on `main`; the
"overnight" in the file names is historical.

## Acceptance gates

| Gate | State | Evidence |
| --- | --- | --- |
| G1 Baseline | PASS | `overnight-2026-09-13/impl` fast-forwarded into `main` (d2abaef -> 76599a1) in the Windows checkout that owns `main`; every later change is a small attributed commit on `main`. The original compositor sources and the 16 mode-only Windows diffs are preserved under `out/preserve-2026-09-13/` (untracked, by design). Inputs and paths below. |
| G2 Runtime/build | ACTIVE | The four reproduced failures are repaired with regressions: wlproxy pollfd crash (session loop bounded, accept last; `compositor/wlproxy/tests/live.rs`), UTF-8 title panic (char-boundary truncation), zoneid palette floor (coarse-to-fine refinement; shipped zones re-derived), Makefile `update-test` duplicate (`update-tree-test`). The libc defect: the bug 31943 backport was necessary but not what was wrong; the loader recorded its own map as starting at 0 (glibc bug 33088, GCC 14 SLP vectorisation of `_dl_start`), fixed by `build/patches/glibc-2.40/0004-*.patch` with build-time checks in stages 01/04 and a runtime probe in `test-libc-unwind` (eb72a56). The from-scratch rebuild that proves it started 14:26 (see Active jobs). Pending on it: `make test-libc-unwind`, `audit-artifacts`, `smoke-userspace`, then stage 05 without the `HOSTLDFLAGS` workaround (removed). |
| G3 Firmware boot | OPEN | Implemented, drivers written, untested on real media: stage 06, `run-ovmf.sh` (no -kernel/-initrd/-append/host sharing; the command line is now recorded per boot and `make acceptance` attests it), `media-smoke.sh` with the strict refusal check (`--expect-refused` needs the firmware's own "Access Denied"/"Security Violation" and a tried boot option). Runs after stage 06. |
| G4 Installation | OPEN | Implemented, untested: `kryptik-install.sh`, `install-test.sh` (install, boot alone with fresh vars, reboot, cold boot, refusals incl. blkdebug I/O error), `state-test.sh` (clone, ambiguous labels, corrupt, missing state -> degraded and honest). |
| G5 Boot integrity | OPEN | Implemented, untested: EFI stub + compiled-in cmdline + dm-init verity root, developer Secure Boot key, `ovmf-vars.sh`, `integrity-test.sh` (enforced SB, foreign boot file refused, root tamper refused, recovery from the medium, offline state tamper). |
| G6 Zones/network | OPEN | Implemented, untested on the installed kernel: fail-closed `netzone-init.sh`, `build/guest-tests/zones-check.sh` + `zones-test.sh` (kernel support, net zone readiness, zone 0 offline, routed egress/DNS, no global IPv6, bridge separation, stop/restart, limits, lifecycle) and the compartment suites shipped in the image. |
| G7 Storage | OPEN | LUKS2 volumes implemented and lifecycle-tested as root on the build host; the installed-system checks (init, wrong passphrase, persist, mapping gone after stop, ephemeral gone, concurrent refused, full volume, header backup/restore, vault offline, no passphrase on any command line) are in `zones-check.sh`, pending the build. |
| G8 Desktop | OPEN | Built into the image (stage 04 `desktop`, `dwl` with the zone-border patch, `kryptik-wlproxy`, `kryptik-launch`, `kryptik-session`, `kryptik-chrome` with consent windows and the clipboard-move gesture, `kryptikd serve` with readiness, socket identity and deadlines; `serve.sh` 37 checks). `build/guest-tests/gui-check.sh` + `gui-test.sh` (25+ guest verdicts, QMP screenshot checked against `zone-colours.h`, keystrokes for fullscreen and consent) written (ae2e9c3), pending the build. |
| G9 OS updates | OPEN | Implemented, untested: `kryptik-update` (manifest hashes drive slot read-back and ESP kernel hash; three-step trial arming; degraded refusal), `boot-success.sh` (health-judged commit, trial semantics), `kryptik-efiboot`, `update-test.sh` (A->B, refusals, recovery, interruptions, broken trial). Needs two releases (`make media KRYPTIK_VERSION=...` twice). |
| G10 Delivery | ACTIVE | `make acceptance` written (`tools/acceptance.sh`): every gate on named artifacts, PASS/FAIL/INCOMPLETE per item, minimum-checks positive control per VM driver, firmware-only attestation from the recorded QEMU commands, report with revision/hashes/firmware/kernel/commands/exit/logs, `EXPORT=DIR` copies and re-hashes. `docs/BOOT_INSTALL_RECOVER.md` is the instructions file it ships. Not yet run: no media until the rebuild ends. |

## Environment and the one authoritative tree

- `main` lives in the Windows checkout `C:\Coding-Projects\Linux Distro`
  (core.filemode=false; commits as DevomB). The Linux build host is the WSL2
  distro `kryptik-build` (Ubuntu 24.04, root; `build` uid 1000 for the
  unprivileged stages; /dev/kvm; 8 CPUs, 7 GB RAM). It builds from
  `/root/kryptik/main`, a detached snapshot worktree of `main` moved with
  `git checkout --detach main` at safe build boundaries only; nothing is
  committed there. The old `/root/kryptik/impl` worktree is retired.
- Contract: `KRYPTIK_WORK=/root/kryptik/work`, `KRYPTIK_SOURCES=/root/kryptik/sources`
  (102 tarballs/patches verified against `sources.lock`), `KRYPTIK_OUT=/root/kryptik/out`.
  Static binaries handed to stage 04: `/root/kryptik/kryptikd-musl`
  (sha256 0275b910...) and `/root/kryptik/kryptik-wlproxy-musl` (db341c97...),
  built from the snapshot with `cargo --target x86_64-unknown-linux-musl`.
- Final artifacts go to `C:\Coding-Projects\Linux Distro\out\overnight\`
  (`make acceptance EXPORT=...`).

## Active jobs

| Job | Command | Log |
| --- | --- | --- |
| from-scratch rebuild (driver pid 1444554 in the distro, started 14:26:48) | `build-system.sh FRESH=1`: stamps archived to `.stamps/legacy/reset-20260913T142648`, previous trees set aside as `work/sysroot.old-20260913T142648` and `work/build.old-20260913T142648` (kept, not deleted); stage 01 and 02 as `build`, stage 04 and `make test-libc-unwind` as root, from snapshot eb72a56 | `/root/kryptik/logs/build-system.out`, `toolchain.log`, `temp-tools.log`, `system.log`, `libc-unwind.log` |

Recorded durations of the previous run: stage 01 0.8 h, stage 02 1.1 h,
stage 04 1.5 h. Expect the sysroot around 18:00 and the kernel after it.

## Decisions taken in this run

- glibc: keep 2.40; carry upstream's release/2.40/master `_dl_find_object`
  fixes (bug 31943 and prerequisites) AND the master fix for bug 33088, which
  is the defect Kryptik's loader actually had. Both glibc builds (stage 01
  and 04) apply the same set; each proves with `readelf` that `rtld.os` takes
  `__ehdr_start`/`_end` without a run-time relocation, and stage 04 reads the
  installed loader's map start back. The tarball still lacks the branch's
  later security backports (CVE-2025-0395, CVE-2025-4802 and others): a known
  weakness for a version bump.
- The rebuild is from scratch rather than resumed: the patch set is an input
  to stage 01's glibc, everything after it was invalid by the stamp chain, and
  the sysroot held root-owned stage 04 files an unprivileged stage 01 could
  not replace. The old trees are set aside, not removed.
- Boot chain (Design 08): the kernel's EFI stub is the only loader; the
  command line (root slot by PARTLABEL, verity root hash, salt) is compiled
  in and CMDLINE_OVERRIDE ignores load options; dm-init builds the verity
  root with no initramfs; A/B via BootNext + BOOTX64.EFI commit after a
  boot that boot-success judged healthy. No GRUB, no systemd-boot, no
  unsigned file in the chain.
- Test arming: install media honour a kryptik-testctl control disk;
  installed systems are driven over the serial login as an ordinary user,
  `su` with root's password for privileged steps. Root cannot log in at a
  terminal.
- Stamps chain by fingerprint and seed across stages: a change to an early
  package rebuilds what follows; no stale downstream artifact can claim to be
  current.
- Transfers between zones ask the person through the trusted chrome
  (`/run/kryptik-consent`); the clipboard moves only by the zone 0 gesture.

## Next commands

```sh
# inside kryptik-build, as root, from /root/kryptik/main
tail -f /root/kryptik/logs/build-system.out
# when it prints SYSTEM AND LIBC PROOF DONE:
make SUDO= kernel && make SUDO= media && make SUDO= media KRYPTIK_VERSION=0.1.$(date +%Y%m%d).b
make SUDO= acceptance EXPORT="/mnt/c/Coding-Projects/Linux Distro/out/overnight"
```

## Unresolved blockers

- None external. The original Ubuntu distro's VHD lock (PhysicalDrive1) is
  worked around, not cleared; nothing in it is needed.
