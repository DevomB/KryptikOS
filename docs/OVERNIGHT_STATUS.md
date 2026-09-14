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
| G3 Firmware boot | USB PASS (36/0) and firmware-only-boot PASS on `bae1de53`; ISO FAIL 4/32 there, repaired eb1166b, unverified | The ISO's root grew past a 2048-byte boundary with this release and the CD's linear map refused a length that was not whole 2048-byte blocks ("len=5373942 not aligned to h/w logical block size 2048 of sr0"); the root image is padded to whole 4096-byte blocks now. The USB medium, whose blocks are 512 bytes, never saw it. Earlier releases passed the ISO by the accident of their size. |
| G4 Installation | PASS on `bae1de53` | install-test 43/0, state-test 47/0, unchanged from `812998c6`. |
| G5 Boot integrity | PASS on `bae1de53` (all four items) | ovmf-vars; media-smoke-secureboot 36/0; media-refused-foreign-keys 6/0; integrity-test 23/0: Secure Boot enforced on the medium and the installed system, a foreign-signed kernel refused by the firmware, the superblock tamper caught by dm-verity at 3 s with a panic before any userspace, recovery from the medium with state intact, and offline tampering of the state partition reaching nothing privileged. |
| G6 Zones/network | 32 passed, 5 failed on `bae1de53`; every cause repaired on main, unverified | The bridge is reachable from routed zones now (the ICMP range and the datagram probe of 90a84de work), the boundary suite passes on the target (0 failures), adversarial and cli pass. Still without an uplink: dhcpcd got past chown and then died at its first socket, a NETLINK_GENERIC one it opens for nl80211 events ("if_opensockets: Address family not supported by protocol"); the net zone's policy allows the family (4dd8480), and on the installed system eth0 then leased 10.0.2.15 with its default route. The three guest failures (routed-egress, egress-after-restart, reattach-after-restart) are that uplink. The launcher suite's one failure, M9, was the suite counting the supervised net zone's own live leaf under `/sys/fs/cgroup/kryptik/` as abandoned; it counts only leaves a sweep may touch, and the sweep itself retries a busy leaf and names what it could not remove (96c59ab, 14f99f7). |
| G7 Storage | PASS on `bae1de53` within zones-test (all eleven volume checks, phase 4 included) | |
| G8 Desktop | 19 of 32 on `bae1de53`; the remaining cause repaired e909beb, unverified | The staged proxy socket works: a zone's client reaches its proxy, is offered the needed globals and none of the hidden ones, its bind is refused and logged, a zone window is recorded with its zone, label and title prefix, and fullscreen keeps that record. What still failed all traced to the chrome opening no window: havoc has no `-e`, and every chrome window (launcher menu, consent questions, the passphrase prompt) was started as `havoc -e ...`, which prints havoc's usage and exits; the program now follows the options directly. The consent watcher's own lock file was also being counted as a pending question (542018d). |
| G9 OS updates | 15 of 21 on `bae1de53`; the six were the driver's, repaired f292343, unverified | On the installed system: apply, trial boot, health-judged commit ("committed: BOOTX64.EFI is now slot b"), authenticated recovery to the older release, rollback, and both interruptions (during the slot write, and between arming and reboot) hold. The driver's faults: it made its refusal variants from the running release, which the updater refuses as "nothing to apply" before any defect is reached (they come from the older release with `--recovery` now); it looked for a commit line boot-success no longer prints; and phase 7 ran out of state-partition space beside the copies earlier phases had left. |
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
| the third release, `0.1.20260914.bae1de53` - its full acceptance ended 06:35 on 2026-09-14 with the gate results in the table (verdict FAIL: ISO, zones, desktop, updates) | `post-build.sh && run-acceptance.sh`, started by the second session at 04:02 | `/root/kryptik/logs/acceptance.out`, `work/acceptance/20260914T050800/` (its export to `out/overnight` is that failing release's and will be replaced) |
| the fourth release, from main at f292343 or later - NEXT | `post-build.sh` (the chrome, the net zone's NETLINK_GENERIC, the cgroup sweep, the suites and the padded root image are all image-side), then `run-acceptance.sh` with the export. Nothing known is left unrepaired on main when it starts. | `/root/kryptik/logs/post-build.out`, then `acceptance.out` |

Two sessions work in this checkout (both commit as DevomB). Rules that
kept them from colliding: `git status` and `git log` before every commit;
stage hunks, not files, when the other session has the file open; never
two chroot drivers or two acceptance passes at once (`post-build.sh` refuses
while the sysroot is mounted, which is what saved 04:02); check
`pgrep -fa post-build` before starting one; the kept VM disks under
`work/vm/` belong to whoever's run made them and may vanish.

The host driver scripts are in `tools/dev/build-host/` (copied to
`/root/kryptik/bin/` in the distro, from where they run detached with
`setsid`). `probe-disk.sh DISK 'cmd'...` boots an installed test disk and
runs commands as root over serial (`PROBE_OVMF_ARGS='--gpu --mem 3072'` for
a desktop question); cheaper for logs alone: `losetup -Pf --show disk.img`
and mount `p4` (kryptik-state) read-only, the guest logs are under
`log/kryptik/`.

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
variants, commit wording, phase 7 space). The tree is clean.

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
