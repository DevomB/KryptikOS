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
| G5 Boot integrity | 3 of 4 items PASS; integrity-test 22 of 23 on `d238dd44`, repaired 85b1c35, unverified | ovmf-vars, media-smoke-secureboot (36/0) and media-refused-foreign-keys (6/0) pass on both releases. On `d238dd44` the superblock tamper works as designed: dm-verity names the corruption at 3 s and the kernel panics before any userspace. The one failing check looked for the kernel's "Linux version" banner, which the command line's `loglevel=4` never lets reach the console (every "Linux version" the drivers see is boot-smoke's own line); the check now reads a panicking boot by its kernel console lines. The same assumption in update-test's phase 7 was fixed before it could fail (88657ea). |
| G6 Zones/network | 28 passed, 9 failed on `d238dd44`; every cause repaired on main, unverified | The net zone came up (36 of 43 guest checks) but dhcpcd was killed by SIGSYS on `chown(2)` of its own control socket (audit syscall=92): chown sat on kryptikd's denied list, which no zone policy may re-allow, for a reason from the one-uid days; with CAP_CHOWN dropped a chown can only be a no-op, so the four chown syscalls left the denied list (still outside the base allowlist) and the net policy allows it (90a84de). No routed zone could reach even the bridge for two more reasons: kryptikd wrote the ICMP group range as `0 65534` in host gids, which maps to nothing inside a zone with a real identity, and the guest checks pinged with inetutils `ping`, which wants a raw socket a zone rightly lacks; the range now names the zone's own host gid and the checks probe with an ICMP datagram socket (`icmp-echo.py`). The pid storm is python (bash's fork retries outlasted the timeout) and the zones VM gets 3 GB for its tmpfs bound (4a6bd2b). Suites on the target: adversarial 0, cli 0; the boundary suite 2 failures (D1 imported ctypes, absent from the shipped python - now `unshare -U`, and the image rebuilds python after libffi/openssl/expat (bae1de5); G12 waited out a 60 s consent deadline - now 3 s); the launcher suite 143/1 with M9: a cgroup a killed launcher left survived the sweep because kernfs gives a cgroup directory the time it was first looked at, so the sweep now goes by whether the launcher pid is alive (4a6bd2b); H1c is an accounted gap (zone 0 has no interface by design). |
| G7 Storage | PASS on `d238dd44` within zones-test (all eleven volume checks) | volume init, wrong passphrase refused, data persists, mapping gone after stop, ephemeral gone, concurrent open refused, full volume survived, both-headers-zeroed refused, header restore, vault offline, no passphrase leak. The driver's phase-4 "mapping left open" verdict was a false positive (it matched phase 2's own wording in the session transcript); it reads the tagged listing now (d068ab2). |
| G8 Desktop | 9 of 21 on `d238dd44`; two causes repaired, one open | The compositor now starts (session socket, dwl running, focus record written) and the hidden-globals and consent-cleanup verdicts hold. Every zone window failed at setup: the zone child, root only inside its own user namespace, could not walk the session's 0700 `/run/user/1000/kryptik/` to the proxy socket; a privileged launch now stages the verified socket in the zone's registry entry (f906943). Open: the chrome's own launcher window never appeared ("(no window)" in the focus record). havoc draws with a built-in fallback font, so the absent TrueType file was not it (DejaVu is shipped now regardless); the guest check now preserves the session log on the state partition (8da6e5b) so the next run says why. |
| G9 OS updates | 6 of 15 on `d238dd44`; phase 2's cause repaired, phases 2-7 unproven | Phase 1 passes. Phase 2 was refused at "unlisted file in the payload: lost+found": the payload is the root of an ext4 medium and carries the filesystem's own directory; the updater passes over an empty one and refuses a populated one (037e482, with a test variant). Phase 3's refusals that did run all held (wrong key, altered image, truncated kernel, extra file). Phases 4-7 only inherited phase 2's state. |
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
| post-build on snapshot bae1de5, then a full acceptance - RUNNING since 04:02 on 2026-09-14 (started by the second session). NOT in that release: the chrome fix (havoc takes no `-e`; every chrome window failed to open), the launcher-suite client fix and the session-log preservation, all committed after the snapshot moved - so its G8 will still fail, and one more `post-build.sh` and one more full run follow it. | `post-build.sh && run-acceptance.sh`: the musl binaries from bae1de5, incremental `make system` (python rebuilt after libffi/openssl/expat and everything after it, the DejaVu font step, the suites and guest checks, kryptikd with the chown and ICMP-range changes), the kernel (its recipe changed: 79d98c3), media A and B; then every gate with the export to `out/overnight`. Expect the build to take about two hours and the acceptance two more. | `/root/kryptik/logs/post-build.out`, `system2.log`, `kernel.log`, `media-a.log`, `media-b.log`; then `acceptance.out` and `work/acceptance/<time>/` |

Two sessions work in this checkout (both commit as DevomB). Rules that
kept them from colliding: `git status` and `git log` before every commit;
stage hunks, not files, when the other session has the file open; never
two chroot drivers or two acceptance passes at once (`post-build.sh` refuses
while the sysroot is mounted, which is what saved 04:02); the kept VM
disks under `work/vm/` belong to whoever's run made them and may vanish.

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

## Session checkpoint 2026-09-14 04:15

On `main` since the 01:30 checkpoint, in order: 79d98c3 (stage 05 archives
the stamps of a kernel tree that is gone), 4cedb0d and 85b1c35 (integrity
test reads a panicking boot by its console lines), 88657ea (update-test
phase 7 the same way), d068ab2 (zones-test reads the mapper listing it
asked for), f906943 (a privileged launch stages the zone's proxy socket in
its registry entry), 037e482 (the updater passes over an empty
lost+found), aae90bc (H1c accounted), 90a84de (chown leaves the denied
list and the net zone allows it; the ICMP range names the zone's host gid;
icmp-echo.py; DejaVu fonts; boundary D1/G12), 4a6bd2b (cgroup sweep by
launcher liveness, immediate refusal with nobody to ask, python pid storm,
3 GB for the zones VM), bae1de5 (python rebuilt with ctypes and ssl),
8da6e5b (session log preserved; probe-disk GPU). The tree is clean.

Resume order, inside `kryptik-build` as root:

1. `cat /root/kryptik/logs/post-build.out` until `POST-BUILD DONE` (A's
   version is on that line), then `/root/kryptik/logs/run-acceptance.out`
   and `acceptance.out` for the chained full run and its verdict. If a
   stage failed, its log is named on the END line; fix on `main`, then
   `bash /root/kryptik/bin/post-build.sh` again.
2. If gates fail: read `work/acceptance/<time>/<gate>.log`, the VM
   transcripts `work/logs/ovmf-serial.<name>.<time>.log`, and for the
   desktop the kept disk's `log/kryptik/session.log` (loop-mount p4).
   Repair, commit, `post-build.sh` for image-side changes (driver-only
   changes need only `git checkout --detach main` in `/root/kryptik/main`
   while nothing runs from it), then `ONLY=<gates> run-acceptance.sh`.
3. `bash /root/kryptik/bin/run-acceptance.sh` with no `ONLY`: every gate,
   exported to `C:\Coding-Projects\Linux Distro\out\overnight`. The task is
   complete only when that run's REPORT.md has every gate PASS.
4. Update this table, README.md's release-validated line and
   docs/roadmap.md to the evidence.

Known gaps that are documented rather than closed: no watchdog for a
userspace that hangs after boot-success judged the trial healthy; the
release is signed by a build-generated developer key; nothing has run on
physical hardware; glibc 2.40 lacks the branch's later CVE backports; the
artifact audit's soft findings (324 without CET, 107 without BIND_NOW, 28
non-PIE, 42 RPATH); dhcpcd runs without its own privilege separation
inside the net zone (no dhcpcd user in a zone's synthesized passwd; the
zone is the sandbox); the launcher suite's BRK4 answered a foreign peer
with a broken pipe once on the target (seen in one instrumented run, not
in the gate) and is worth watching.

## Next commands

```sh
# inside kryptik-build, as root
tail -f /root/kryptik/logs/post-build.out                       # until POST-BUILD DONE
tail -f /root/kryptik/logs/acceptance.out                       # the chained full run
bash /root/kryptik/bin/run-acceptance.sh                         # again, if repairs were needed
```

## Unresolved blockers

- None external. The original Ubuntu distro's VHD lock (PhysicalDrive1) is
  worked around, not cleared; nothing in it is needed. The build distro's
  VHD (113 GB) was attached to the host once while WSL was stopped (not by
  this session); compaction needs the user (see the memory note on VHD
  growth).
