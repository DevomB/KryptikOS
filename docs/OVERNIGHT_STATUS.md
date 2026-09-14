# Kryptik run status (2026-09-13 to 2026-09-14)

Authoritative run record for the scope in `docs/OVERNIGHT_GOAL.md`. Superseded
facts are replaced, not appended. Raw logs live under the ignored build output
named below, never in Git. The work is ongoing development on `main`; the
"overnight" in the file names is historical.

## Acceptance gates

| Gate | State | Evidence |
| --- | --- | --- |
| G1 Baseline | PASS | `overnight-2026-09-13/impl` fast-forwarded into `main` (d2abaef -> 76599a1) in the Windows checkout that owns `main`; every later change is a small attributed commit on `main`. The original compositor sources and the 16 mode-only Windows diffs are preserved under `out/preserve-2026-09-13/` (untracked, by design). Inputs and paths below. |
| G2 Runtime/build | PASS (host and chroot; the target-boot half is G3) | From-scratch rebuild of snapshot eb72a56 finished 20:18 (stage 01 14:27-17:52, throttled while the host was idle; stage 02 17:52-19:07; stage 04 19:08-20:18). `make test-libc-unwind` on the new sysroot: 7 passed, 0 failed - pthread_exit, pthread_cancel, backtrace, the loader's own map start recorded (0x0000707ced4c1000), `_dl_find_object` attributes a dlopened object correctly. The glibc step's own checks: no run-time relocation against `__ehdr_start`/`_end` in rtld.os, the loader carries IBT/SHSTK, ld.so's map start read back non-zero. The four reproduced failures are repaired with regressions: wlproxy pollfd crash (session loop bounded, accept last; `compositor/wlproxy/tests/live.rs`), UTF-8 title panic (char-boundary truncation), zoneid palette floor (coarse-to-fine refinement; shipped zones re-derived), Makefile `update-test` duplicate (`update-tree-test`). The libc defect: the bug 31943 backport was necessary but not what was wrong; the loader recorded its own map as starting at 0 (glibc bug 33088, GCC 14 SLP vectorisation of `_dl_start`), fixed by `build/patches/glibc-2.40/0004-*.patch` with build-time checks in stages 01/04 and a runtime probe in `test-libc-unwind` (eb72a56). The from-scratch rebuild that proves it started 14:26 (see Active jobs). Host side, on the current tree in isolation (18:40): kryptikd 149 unit tests; `run-tests.sh --strict` suites all pass on ext4 (launcher 145/0 with the 3 listed gaps, cli 17/0, serve 37/0, update-tree 20/0, compositor 104/0 + audit, harness 58, hardening 27, services 81, boot-success 28, s6-init 32, manifest 25); `validate-kernel-config --boot/--hardened` pass; the artifact audit of the previous sysroot has no hard failure (501 soft findings: 107 without BIND_NOW, 28 non-PIE, 324 without CET, 42 RPATH - recorded as a known weakness). On the new sysroot, inside the chroot, by `make acceptance`: `test-libc-unwind` 7/7, `userspace-smoke` 32 checks, the artifact audit with no hard failure, `validate-kernel-config`; stage 05 built without the `HOSTLDFLAGS` workaround. |
| G3 Firmware boot | PASS on media `0.1.20260913.812998c6` | `make acceptance` items media-smoke-usb and media-smoke-iso (each above the 25-check control) and firmware-only-boot (every recorded QEMU command line free of `-kernel`/`-initrd`/`-append` and host sharing). What the first real media taught: the USB root needed `dm-mod.waitfor=PARTLABEL=...` before `dm-mod.create` (the verity data device was not there yet), the ISO's appended partition needed a GUID type, and boot-smoke resolves `/dev/root` to the dm device. Re-run on the media of db1a32a pending. |
| G4 Installation | PASS on `812998c6` | install-test 43 passed, 0 failed (install, boot alone with fresh vars, reboot, cold boot, refusals including the blkdebug I/O error; firstboot created the preseeded user). state-test 47 passed, 0 failed (clone, ambiguous labels, corrupt, missing state: degraded and honest). |
| G5 Boot integrity | 3 of 4 items PASS on `812998c6`; integrity-test repaired, unverified | ovmf-vars PASS (developer key enrolled, certificate read back); media-smoke-secureboot 36/0; media-refused-foreign-keys 6/0 (the firmware's own refusal, a tried boot option). integrity-test failed 18/5: its data-block tamper sat in a block nothing reads at boot, the system came up normally, and the "named the corruption" match was the command line's own verity text. Fixed 5435a8d (the tamper hits the ext4 superblock; only the kernel's verity message counts) and db1a32a (its payload mount under `/run`, not the read-only `/mnt`). |
| G6 Zones/network | FAIL on `812998c6` (26 passed, 11 failed); repaired 05e9d7b, unverified | Root cause, probed on the kept VM disk: inside the nic zone `/run` was read-only and `/var` absent, so dhcpcd died on its pid file before asking for a lease, and `netzone-init.sh` itself was ended by the shell at `: > /run/uplink-resolv.conf` (a failed redirection on a special builtin exits a POSIX sh). No routed zone had a path; nine of the eleven failures follow from that. kryptikd now gives the nic zone, and only it, private tmpfs mounts at `/run` and `/var/lib` with matching Landlock rules; the script waits for the lease and reads the uplink's DNS from dhcpcd's own resolv.conf. The compartment suites on the target kernel: launcher exit 0 with the three accounted gaps (NETR, POL6, LC15/16), adversarial 0, cli 0; the boundary suite failed all 54 probes because as root its fixtures had no zone identity, which kryptikd refuses. Repaired the way the launcher suite does it; on the build host it now passes 54/0 as root and 50/0 unprivileged (4 designed skips), and the root run exposed a kryptikd defect fixed in the same commit: a privileged transfer into an ephemeral zone failed with EOVERFLOW because host root is not a uid the zone's user namespace maps. The broker delivers as the destination identity now. |
| G7 Storage | same run as G6 (the storage checks are in `zones-check.sh`); three check defects repaired 05e9d7b | On the target: volume init, wrong passphrase refused, data persists, mapping gone after stop, ephemeral gone, concurrent open refused, full volume survived, header restore all PASS. The three that failed were the checks, not the volumes: the damaged-header check zeroed only the primary LUKS2 header and cryptsetup opened the volume from the intact secondary (now both headers, and the zone must not run); the vault check compared a raw `0` line; the passphrase-leak grep matched its own command line. |
| G8 Desktop | FAIL on `812998c6` (5 of 25); repaired 05e9d7b, unverified | The first run of this gate on real media: the compositor never started. `kryptik-session` exported `WAYLAND_DISPLAY=wayland-0` before exec'ing dwl, and wlroots reads that as "nest inside that display", so dwl tried to connect to a socket that did not exist yet and died before opening the GPU ("Could not connect to remote display"). dwl names its own socket and exports it to the chrome itself; the session no longer sets it. Every other verdict followed from that one. What did pass: the GPU device, seatd, launch-daemon readiness, the hidden globals, consent cleanup. |
| G9 OS updates | FAIL on `812998c6` at phase 2; repaired db1a32a, unverified past phase 1 | Phase 1 passed (install A, boot, zone volume created, version reported). Phase 2's first guest command did `mkdir /mnt/p` on the read-only verity root and phases 2-7 never ran; the driver mounts payloads under `/run/upd` now. Phases 2-7 (apply, trial boot, commit, refusals, recovery, rollback, interruptions, broken trial) are unproven until the next run. |
| G10 Delivery | ACTIVE | `make acceptance` (`tools/acceptance.sh`) has run three times on `812998c6` (one full pass, two `ONLY=` repair passes): every gate on named artifacts, PASS/FAIL/INCOMPLETE per item, the minimum-checks control per VM driver, firmware-only attestation from the recorded QEMU commands, a report with revision/hashes/firmware/kernel/commands/exit/logs. `EXPORT=DIR` copies and re-hashes; `docs/BOOT_INSTALL_RECOVER.md` is the instructions file it ships. The export is made only by a run in which every gate is PASS, which is still ahead. |

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
  and `/root/kryptik/kryptik-wlproxy-musl` (hashes on the last lines of `logs/musl-build.log`),
  built from the snapshot with `cargo --target x86_64-unknown-linux-musl`.
- Final artifacts go to `C:\Coding-Projects\Linux Distro\out\overnight\`
  (`make acceptance EXPORT=...`).

## Active jobs

| Job | Command | Log |
| --- | --- | --- |
| post-build on snapshot db1a32a - RUNNING since 01:26 on 2026-09-14 | `post-build.sh` (nice 10, ionice idle, so the host stays usable): the snapshot moved to db1a32a at a safe boundary (no chroot driver, no VM), the musl `kryptikd` and `kryptik-wlproxy` rebuilt from it, incremental `make system` (the kryptikd, desktop, netzone and tests steps re-run because their fingerprinted inputs changed, and what follows them), `make kernel` (inputs unchanged), then `make media` for release A (`0.1.20260914.<sha8 of db1a32a>`) and release B (`<A>.1`, the update test's target). | `/root/kryptik/logs/post-build.out`, then `musl-build.log`, `system2.log`, `kernel.log`, `media-a.log`, `media-b.log` |

The previous media, `0.1.20260913.812998c6`, stay under `work/images/` until
the new ones exist; their acceptance runs are under `work/acceptance/`
(`20260914T001642` is the `ONLY=G4,G5,G6/G7,G8,G9` pass whose results the
table records; it was stopped during update-test's phase 4, after phase 2
had failed, because the later phases can only repeat that failure at a
timeout each).

The host driver scripts are in `tools/dev/build-host/` (copied to
`/root/kryptik/bin/` in the distro, from where they run detached with
`setsid`). `probe-disk.sh DISK 'cmd'...` boots an installed test disk and
runs commands as root over serial: how the net zone was diagnosed.

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

## Session checkpoint 2026-09-14 01:30

Since the 2026-09-13 checkpoint, on `main` in order: 9e24ceb (the drivers
reach root through a login shell), 6557abb (the serial driver's su step
keeps the command's output), 5435a8d (integrity tamper hits the
superblock), 05e9d7b (the net zone's state directories, the desktop's
compositor start, transfers into ephemeral zones as root, the boundary
suite as root, three zones-check defects), db1a32a (payload mounts under
`/run`). A second agent (Codex, also committing as DevomB) works in the same
checkout: c4f903a (stage 06 records the release instead of copying it,
acceptance removes VM disks after a pass) and 262f89a (zoneid import) are
theirs. Before every commit: `git status`, `git log`; never run two
acceptance passes against the same VM disks. The tree is clean.

Resume order, inside `kryptik-build` as root:

1. `cat /root/kryptik/logs/post-build.out` - wait for `POST-BUILD DONE`
   (it prints A's version; each stage's log is named on its END line).
   If a stage failed: fix on `main`, then `bash /root/kryptik/bin/post-build.sh`
   again (it moves the snapshot and resumes from the stamps).
2. `ONLY=G5,G6/G7,G8,G9 bash /root/kryptik/bin/run-acceptance.sh` - the
   gates repaired since `812998c6`, on the new media, without export.
   Read `/root/kryptik/logs/acceptance.out`; each item's log is under
   `work/acceptance/<time>/`, each VM's transcript under `work/logs/`
   (`ovmf-serial.<name>.<time>.log`, with `.cmd` beside it).
3. Repair, commit, `post-build.sh` again (image-side changes need new media;
   driver-only changes need only the snapshot moved: `git checkout --detach
   main` in `/root/kryptik/main` while nothing runs from it).
4. `bash /root/kryptik/bin/run-acceptance.sh` with no `ONLY`: every gate,
   about two hours, exporting to `C:\Coding-Projects\Linux Distro\out\overnight`.
   The task is complete only when that run's REPORT.md has every gate PASS.
5. Update this table, README.md's release-validated line and
   docs/roadmap.md to the evidence.

Known gaps that are documented rather than closed: no watchdog for a
userspace that hangs after boot-success judged the trial healthy; the
release is signed by a build-generated developer key; nothing has run on
physical hardware; glibc 2.40 lacks the branch's later CVE backports; the
artifact audit's soft findings (324 without CET, 107 without BIND_NOW, 28
non-PIE, 42 RPATH); dhcpcd runs without its own privilege separation
inside the net zone (no dhcpcd user in a zone's synthesized passwd; the
zone is the sandbox).

## Next commands

```sh
# inside kryptik-build, as root
tail -f /root/kryptik/logs/post-build.out                       # until POST-BUILD DONE
ONLY=G5,G6/G7,G8,G9 bash /root/kryptik/bin/run-acceptance.sh    # the repaired gates, no export
bash /root/kryptik/bin/run-acceptance.sh                         # every gate, exported
```

## Unresolved blockers

- None external. The original Ubuntu distro's VHD lock (PhysicalDrive1) is
  worked around, not cleared; nothing in it is needed. The build distro's
  VHD (113 GB) was attached to the host once while WSL was stopped (not by
  this session); compaction needs the user (see the memory note on VHD
  growth).
