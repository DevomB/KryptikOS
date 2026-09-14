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
| G3 Firmware boot | PASS on `8333d751` (USB 36/0, ISO 36/0, firmware-only-boot) | The padded root image (eb1166b) brought the ISO back. |
| G4 Installation | PASS on `8333d751` | install-test 43/0, state-test 47/0. |
| G5 Boot integrity | PASS on `8333d751` (all four items; integrity-test 23/0) | |
| G6 Zones/network | 35 passed, 2 failed on `8333d751`; both repaired on main, unverified | The net zone leases its uplink (`dhcpcd on eth0: uplink=10.0.2.15/24`, `READY ... nat=yes dns=yes`); routed zones reach the bridge and the world; the launcher suite passes 144/0 with only the four accounted gaps, the boundary suite 0 failures, adversarial and cli 0. Left: routed-ipv6-bridge (a fresh zone's fd19:: address is still under duplicate address detection when the check probes it; the ICMP helper now retries through its timeout, e9b03c5) and the driver's phase-4 mapping verdict, which matched phase 2's own words again and now reads only the tagged listing (c047d2a; the listing was `MAPPER:control`). |
| G7 Storage | PASS on `8333d751` within zones-test (all eleven volume checks) | |
| G8 Desktop | 22 of 32 on `8333d751`; the remaining causes repaired on main, unverified | The chrome's launcher window opens (zone 0, `ZONE 0 (trusted)`), zone windows are recorded with their zone and title prefix, fullscreen keeps the record, a second zone gets its window, the proxy offers and refuses what it should. Left, and read from the kept disk's state partition: the zone label came out `UNKNOWN ZONE untrusted` because `/usr/lib/kryptik/zones` was installed 0700 and the session's chrome could not read it (0755/0644 now, 7b43aab); every clipboard and transfer probe was refused before reaching a zone - a zone runs one supervised command at a time and the check handed second commands to zones whose windows were up, and the probes were multi-line `python3 -c` programs the launch protocol refuses ("argument 2 contains a newline"). The check now stops each window before asking its zone anything else and speaks to the broker through the one-line `broker-client.py`, keeping both zones resident across the clipboard gesture (8f959fa). |
| G9 OS updates | on `8333d751` the gate was ended by hand mid-run (the second session stopped the pass once the fixes above were on main); its driver fixes (f292343) are unverified; 15 of 21 on `bae1de53` | On the installed system: apply, trial boot, health-judged commit, authenticated recovery, rollback, and both interruptions hold. The six that failed on `bae1de53` were the driver's (refusal variants of the running release; a commit line boot-success no longer prints; phase 7 out of state-partition space) and are repaired. |
| G10 Delivery | ACTIVE | `make acceptance` has run five times on real media (two full passes, three `ONLY=` repair passes); the report and per-item logs are under `work/acceptance/<time>/`. The export is made only by a run in which every gate is PASS, which is still ahead. |

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
| the fifth release, from main at 8f959fa - STARTED 07:55 on 2026-09-14, killed at 07:56 by a `wsl --shutdown` for a compaction of the build VHD (`diskpart` held `ext4.vhdx` from 08:10; 108.8 GB on disk); RESTARTED the moment the distro starts again | `post-build.sh && run-acceptance.sh` (this session, the host idle and main clean): the kryptikd step (zone files 0644), the tests step (gui-check, broker-client.py, icmp-echo.py), media A and B; then every gate with the export to `out/overnight`. Nothing known is left unrepaired on main. Expect the build in about 20 minutes and the acceptance about two hours. | `/root/kryptik/logs/post-build.out`, then `run-acceptance.out`, `acceptance.out`, `work/acceptance/<time>/` |
| the fourth release, `0.1.20260914.8333d751` - its full run was ended by hand during the update gate at 07:5x (the second session stopped it once the repairs above were committed); results in the table | | `work/acceptance/20260914T065442/` |

Two sessions work in this checkout (both commit as DevomB). Rules that
kept them from colliding: `git status` and `git log` before every commit;
stage hunks, not files, when the other session has the file open; never
two chroot drivers or two acceptance passes at once (`post-build.sh` refuses
while the sysroot is mounted); check `pgrep -fa post-build` before
starting one; the kept VM disks under `work/vm/` belong to whoever's run
made them and may vanish.

The host driver scripts are in `tools/dev/build-host/` (copied to
`/root/kryptik/bin/` in the distro, from where they run detached with
`setsid`). `probe-disk.sh DISK 'cmd'...` boots an installed test disk and
runs commands as root over serial (`PROBE_OVMF_ARGS='--gpu --mem 3072'` for
a desktop question); cheaper for logs alone: `losetup -Pf --show disk.img`
and mount `p4` (kryptik-state) read-only, the guest logs are under
`log/kryptik/` (`gui-check/*.out`, `zone-*.log`, `session.log`).

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

## Session checkpoint 2026-09-14 06:40

On `main` since the 04:15 checkpoint, in order: ca91115 (launcher suite's
broker client reads a refusal past EPIPE), e909beb (the chrome starts
havoc without -e), d034fd9 (status), eb1166b (root image padded to whole
4096-byte blocks), 4dd8480 (NETLINK_GENERIC for the net zone), 96c59ab
(cgroup sweep retries a busy leaf), 542018d (consent watcher's lock is not
a question), 7d2c83e (VM disks removed only after a run that passed),
14f99f7 (M8/M9 count sweepable leaves), f292343 (update-test's refusal
variants, commit wording, phase 7 space), c047d2a (zones-test phase 4 reads
the tagged listing), e9b03c5 (icmp-echo.py retries), 7b43aab (zone files
0644), 8f959fa (gui-check: one command per zone, broker-client.py). The tree
is clean.

Resume order, inside `kryptik-build` as root:

1. `pgrep -fa post-build` - if nothing runs and no acceptance is running,
   `setsid -f nice -n 10 ionice -c 2 -n 7 bash /root/kryptik/bin/post-build.sh > /root/kryptik/logs/post-build.out 2>&1`
   and wait for `POST-BUILD DONE` (about an hour: the desktop, kryptikd,
   tests and stage 06 steps, and the kernel if its recipe or stage 04
   changed beneath it).
2. `bash /root/kryptik/bin/run-acceptance.sh` with no `ONLY`: every gate,
   exported to `C:\Coding-Projects\Linux Distro\out\overnight` (about two
   hours). The task is complete only when that run's REPORT.md has every
   gate PASS.
3. If a gate fails: `work/acceptance/<time>/<gate>.log`, the VM transcripts
   `work/logs/ovmf-serial.<name>.<time>.log`, and for the desktop the kept
   disk's `log/kryptik/session.log` (loop-mount p4). Repair, commit,
   post-build for image-side changes (driver-only: move the snapshot with
   `git checkout --detach main` in `/root/kryptik/main` while nothing runs
   from it), `ONLY=<gates> run-acceptance.sh`, then step 2 again.
4. Update this table, README.md's release-validated line and
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
pgrep -fa post-build; pgrep -fa run-acceptance                  # nothing may be running
setsid -f nice -n 10 ionice -c 2 -n 7 bash /root/kryptik/bin/post-build.sh > /root/kryptik/logs/post-build.out 2>&1
tail -f /root/kryptik/logs/post-build.out                       # until POST-BUILD DONE
bash /root/kryptik/bin/run-acceptance.sh                         # every gate, exported
```

## Unresolved blockers

- None external. The original Ubuntu distro's VHD lock (PhysicalDrive1) is
  worked around, not cleared; nothing in it is needed. The build distro's
  VHD (113 GB) was attached to the host once while WSL was stopped (not by
  this session); compaction needs the user (see the memory note on VHD
  growth).
