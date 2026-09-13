# Kryptik overnight run status (2026-09-13)

Authoritative run record for the scope in `docs/OVERNIGHT_GOAL.md`. Superseded
facts are replaced, not appended. Raw logs live under the ignored build output
named below, never in Git.

## Acceptance gates

| Gate | State | Evidence |
| --- | --- | --- |
| G1 Baseline | PASS | Branch `overnight-2026-09-13/impl` from integration tip 75f1cc3; cherry-picks ffff72f, 3fcf4bf, a67b1ba as b2a7640, e107095, 7c34f4f; compositor import b2c715d; every later change is a small attributed commit. Inputs/paths below. |
| G2 Runtime/build | ACTIVE | glibc fix: `build/patches/glibc-2.40/` (upstream bug 31943 backport, provenance in its README) applied by stages 01 and 04. Harness: stamps chain by fingerprint and seed across stages (ed83946); `tools/test-step-errexit.sh` 58 checks, 14 of them fail against the old harness (control). Target proof pending: `make test-libc-unwind` after stage 04, then `make audit-artifacts`, `smoke-userspace`. Open question: the previous build's ld.so gaps are unexplained (this toolchain links 4K-aligned, contiguous segments); the target artifact decides. |
| G3 Firmware boot | OPEN | Implemented, untested: stage 06 (`build/stages/06-iso.sh`), `tools/image/run-ovmf.sh` (no -kernel/-initrd/-append), `media-smoke.sh`. Runs after stage 06. |
| G4 Installation | OPEN | Implemented, untested: `tools/install/kryptik-install.sh` (Design 08 layout, read-back verification, refusals), `tools/image/install-test.sh` (install, boot alone with fresh vars, reboot, cold boot, refusal cases incl. blkdebug I/O error). |
| G5 Boot integrity | OPEN | Implemented, untested: kernel EFI stub + CMDLINE_OVERRIDE + dm-init verity root (`build/config/kernel/boot.fragment`), developer Secure Boot key + sbsign in stage 06, `ovmf-vars.sh` (clean/enrolled/ms stores), `media-smoke.sh --vars enrolled` and `--expect-refused`. Tamper/recovery tests still to write. |
| G6 Zones/network | OPEN | Landlock layer and probes integrated (e107095). NAT/resolver/DHCP packages pinned and recipes written; `netzone-init.sh` and the VM topology run still to do. |
| G7 Storage | ACTIVE | LUKS2 volumes implemented in kryptikd (13123c7): real lifecycle test passed as root on the build host (init, double-format refused, wrong passphrase refused with no mapping, write/close/reopen). VM checks V1-V11 on the target kernel pending the build. |
| G8 Desktop | ACTIVE | Wayland stack, wlroots/dwl, havoc, lynx, nano pinned and in stage 04. kryptik-wlproxy complete (ff7e21c, 35 tests). kryptikd launch daemon `serve`, `--wayland-socket`, `--passphrase-fd` (c42b2ec, 143 tests). Drafted, not yet built into the image: `build/desktop/{zone-colours.h,dwl-config.h}`, `tools/desktop/dwl-zone-borders.py` (applies cleanly to pinned dwl 0.8), `tools/desktop/kryptik-launch.c` (compiles). Still to write: kryptik-chrome (bar/prompt/menu), kryptik-session, `kryptikd-serve` s6 service, `info`/`runtime` requests in serve.rs, stage 04 `desktop` step, GUI/broker VM tests. |
| G9 OS updates | OPEN | Implemented, untested: `tools/update/kryptik-update`, `boot-success.sh`, `kryptik-efiboot` (C), release trust anchor (stage 04 `release-trust`), signed payloads (stage 06 `payload`). Update test with A/B builds still to write. |
| G10 Delivery | OPEN | `make acceptance` and the export to `out/overnight/` not written. |

## Environment and the one authoritative tree

- Linux build host: WSL2 distro `kryptik-build` (Ubuntu 24.04.4, root by
  default, `build` uid 1000 for the unprivileged stages, /dev/kvm present,
  8 CPUs, 7 GB RAM, kernel 6.6.87.2-microsoft-standard-WSL2). Installed
  2026-09-13 with `wsl --install Ubuntu-24.04 --name kryptik-build
  --location C:\Users\devom\kryptik-wsl\kryptik-build --no-launch`. dm-crypt
  and loop devices work in it (the LUKS2 lifecycle test ran there).
- The original `Ubuntu` distro cannot start: its `ext4.vhdx` is attached to
  the Windows host as PhysicalDrive1 (read-only, RAW, via the Virtual Disk
  Service at 2026-09-11 23:54:01). `Dismount-DiskImage` from an elevated
  PowerShell releases it; a non-elevated call returns silently. Nothing in
  it is needed: every source was re-fetched and re-verified.
- Worktree: `/root/kryptik/impl` (= `\\wsl.localhost\kryptik-build\root\kryptik\impl`),
  branch `overnight-2026-09-13/impl`.
- Contract: `KRYPTIK_WORK=/root/kryptik/work`, `KRYPTIK_SOURCES=/root/kryptik/sources`
  (102 tarballs/patches, all verified against `sources.lock`),
  `KRYPTIK_OUT=/root/kryptik/out`. Jobs: -j4 (RAM-bound).
- Windows checkout `C:\Coding-Projects\Linux Distro` stays on `main`
  (d2abaef) with its 16 mode-only changes and untracked `compositor/`
  untouched; final artifacts go to `out/overnight/` there.
- Tectonix 0.5.7 baseline on the implementation root: quality_signal 6841,
  bottleneck "equality" (cognitive complexity in `spawn.rs::run_in_zone`,
  `main.rs::cmd_check`); session baseline written. Triage only.

## Active jobs

| Job | Command | Log |
| --- | --- | --- |
| build orchestrator (pid 416 in the distro) | `/root/build-run.sh`: stages 01+02 done (02 complete 11:09), stage 04 running since 11:09 with `KRYPTIK_KRYPTIKD_BIN=/root/kryptik/kryptikd-musl` (sha256 76273631, includes serve/volume support), then waits for `/root/kryptik/GO-05` | `/root/kryptik/logs/build-run.out`, `temp-tools.log`, `system.log`, `kernel.log` |

## Source provenance of the 31 new pins

`tools/verify-signatures.sh --fetch-unknown-keys`: LVM2, cryptsetup, openssh,
libmnl, libnftnl, nftables, dnsmasq, dhcpcd, meson, wayland, wayland-protocols,
xkeyboard-config, libdrm, libevdev, libdisplay-info, wlroots carry valid
OpenPGP signatures by keys not yet audited (recorded in `keys.manifest`);
lynx and nano verify against held keys; cmake and pixman publish signed
checksums (not yet wired into verify-provenance); json-c, popt, libaio, ninja,
libxkbcommon, mtdev, libinput, seatd, hwdata, dwl, havoc are lock-only.
Nothing lock-only is called verified.

## Decisions taken in this run

- glibc: keep 2.40, apply upstream's own release/2.40/master backport of the
  bug 31943 fix plus its two prerequisites; the tarball still lacks the
  branch's later security backports (CVE-2025-0395, CVE-2025-4802 and
  others): a known weakness for a version bump after this run.
- Boot chain (Design 08): the kernel's EFI stub is the only loader; the
  command line (root slot by PARTLABEL, verity root hash, salt) is compiled
  in and CMDLINE_OVERRIDE ignores load options; dm-init builds the verity
  root with no initramfs; A/B via BootNext + BOOTX64.EFI commit after a
  successful boot. No GRUB, no systemd-boot, no unsigned file in the chain.
- Test arming: the command line can no longer carm tests, so install media
  honour a kryptik-testctl control disk; installed systems are driven over
  the serial login (`vm-drive.py`) as an ordinary user, `su` with root's
  password (set at first boot) for privileged steps. Root cannot log in at a
  terminal (`/etc/securetty` is empty).
- Stamps chain by fingerprint and seed across stages: a change to an early
  package rebuilds what follows; no stale downstream artifact can claim to be
  current.

## Session checkpoint 2026-09-13 11:15 (session paused by the user)

Committed on `overnight-2026-09-13/impl` since the last checkpoint: e892b42 net
zone, a5ecf2e recover + integrity/update test drivers, ff7e21c wlproxy,
c42b2ec kryptikd serve, d51e515 + 7dd445d desktop drafts. Stage 04 is
building unattended in the `kryptik-build` distro; do NOT edit
`build/stages/04-base-system.sh` while it runs (bash reads it incrementally)
- write a temp file and rename, or wait for `system.log` to end.

Resume order: (1) finish the desktop pieces listed under G8 and add the
`desktop` step to stage 04 (after `nano`, before `etc`; wlproxy binary via
`KRYPTIK_WLPROXY_BIN`, built with `cargo build --release --target
x86_64-unknown-linux-musl -p kryptik-wlproxy` in `compositor/`); (2) when
stage 04 ends, `make SUDO= test-libc-unwind` (G2 proof), then re-run `make
SUDO= system` with both binaries so the new step runs; (3) `touch GO-05`;
(4) media, boot, install, integrity and update tests as below.

## Next commands

```sh
# inside kryptik-build, as root
tail -f /root/kryptik/logs/build-run.out
# after stage 04:
cd /root/kryptik/impl && export KRYPTIK_WORK=/root/kryptik/work KRYPTIK_SOURCES=/root/kryptik/sources
make SUDO= test-libc-unwind      # the target loader: the G2 proof
touch /root/kryptik/GO-05        # then the kernel
make SUDO= media && make media-smoke-usb media-smoke-iso media-smoke-secureboot media-refused-foreign-keys && make install-test
```

## Unresolved blockers

- None external. The Ubuntu VHD lock is worked around, not cleared.
