# Design 08 — Firmware boot, verified root slots, persistent state and updates

Status: decided 2026-09-13 for the overnight scope; implemented by stage 06,
`tools/install/kryptik-install.sh`, `tools/image/*`, `build/service-scripts/`
and the `kryptik-update` / `kryptik-efiboot` tools. Read with Design 04
(zone volumes) and `docs/hardening.md`.

## The chain, in one paragraph

The firmware is the only loader. Each bootable Kryptik kernel is a UEFI
application (the kernel's own EFI stub) whose command line is compiled in
(`CONFIG_CMDLINE_BOOL` + `CONFIG_CMDLINE_OVERRIDE`: load options from the
firmware or an edited boot entry are ignored) and which is signed with the
developer Secure Boot key. That command line names the root slot by GPT
partition label and carries the dm-verity root hash and salt; the kernel's
own `dm-mod.create=` (`CONFIG_DM_INIT`) builds the verity device before it
mounts root, so there is no initramfs, no bootloader, no unsigned file and
no editable text between the firmware's signature check and the read-only
verified root. Mutable state lives on a separate partition. Two root slots
and a firmware `BootNext` trial give A/B updates with a bounded fallback.

## Partition layout (one layout for media, installer, updater)

Every partition is found by its GPT partition label; nothing depends on
`/dev/vdX` vs `/dev/sdX` vs `/dev/nvme0n1pX`.

| # | label | type | content |
|---|---|---|---|
| 1 | `kryptik-esp` | EFI System, FAT32, 512 MiB | `EFI/BOOT/BOOTX64.EFI` (the committed slot's kernel), `EFI/kryptik/kryptik-a.efi`, `EFI/kryptik/kryptik-b.efi`, `kryptik/version-a`, `kryptik/version-b` |
| 2 | `kryptik-a` | Linux root (x86-64) | verity root image, slot A: ext4 (no journal, read-only) followed by its hash tree |
| 3 | `kryptik-b` | Linux root (x86-64) | the same for slot B (empty on a fresh install) |
| 4 | `kryptik-state` | Linux filesystem, ext4, rest of disk | `/var`, the `/etc` overlay, zone volumes (LUKS2 files under `/var/lib/kryptik/zones/`), update staging |

Install media:

| medium | partitions | root device on the kernel command line |
|---|---|---|
| USB image (`kryptik-<ver>-usb.img`) | `kryptik-esp` + `kryptik-media` (a verity root image) | `PARTLABEL=kryptik-media` |
| ISO (`kryptik-<ver>.iso`) | ISO9660 with an El Torito EFI image (the ESP) and the verity root image appended at a known sector offset | a `linear` dm target over `/dev/sr0` at that offset, then verity on top |

The root image bytes are identical on the USB medium, in slot A after an
install, and in a later update payload; only the kernel command line
(`kryptik.slot=`, `kryptik.media=`, the device) differs, so the media
carries all the signed kernel variants it needs to install
(`EFI/kryptik/kryptik-a.efi`, `kryptik-b.efi`) and the installer copies
bytes; it never re-signs and holds no key.

## The kernel command line, and why it is inside the signature

```
dm-mod.create="kroot,,0,ro,0 <data_sectors> verity 1 PARTLABEL=kryptik-a PARTLABEL=kryptik-a 4096 4096 <data_blocks> <hash_start_block> sha256 <root_hash> <salt> 1 panic_on_corruption"
root=/dev/dm-0 ro rootwait console=tty0 console=ttyS0,115200 panic=10 kryptik.slot=a
```

- The root hash is the identity of the root filesystem. Putting it in the
  signed PE binds the userland to the kernel that boots it: replacing either
  alone fails at the firmware (kernel) or at the first read of a modified
  block (root). `panic_on_corruption` turns a modified block into a kernel
  panic and, with `panic=10`, a reboot, which is what the A/B fallback below
  relies on; a serial log shows exactly which layer refused.
- `CONFIG_CMDLINE_OVERRIDE` is what makes this real. Without it, a boot
  entry's optional data (writable by anyone who can write EFI variables, i.e.
  root) or a hostile bootloader could append `init=/bin/sh` or a different
  `dm-mod.create=`. The EFI stub honours the same option: load options are
  neither parsed nor appended.
- `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` stays on but is not the mechanism:
  the hash is authenticated by the kernel signature, not by a separate
  signature in a keyring.

Stage 05 builds the kernel once (`kryptik-6.18.50`, unbound: its command
line names no root and it is not shipped as a boot file). Stage 06 builds
the verity image, learns the hash, and relinks the kernel once per variant
(`media-usb`, `media-iso`, `slot-a`, `slot-b`) with only `CONFIG_CMDLINE`
changed; modules are untouched and their signatures stay valid. Each
variant is then signed with `sbsign`.

## Secure Boot, developer tier

- A developer key pair (RSA-3072, self-signed X.509) is generated on first
  use under `${KRYPTIK_WORK}/keys/sb/` (0600, never in Git, never in an
  image); `kryptik-sb.crt` is exported with the images.
- OVMF test variable stores are built from the clean `OVMF_VARS_4M.fd` with
  the developer certificate enrolled as PK, KEK and db (`tools/image/
  ovmf-vars.sh`). Nothing is enrolled in any physical firmware. A test
  that needs "no keys" uses the clean store; a test that needs "Microsoft
  keys only" uses `OVMF_VARS_4M.ms.fd`, in which our kernels must be refused.
- This proves that the chain enforces *a* key and that our artifacts are
  bound to it. It is not production certification, and the documentation
  says so.

## Mutable state

`sysinit` mounts `PARTLABEL=kryptik-state` at `/var` (ext4, `nosuid,nodev`),
falling back to a tmpfs with a loud message on media without one; then an
overlay for `/etc` (`lower=/etc` from the verified root, `upper=/var/lib/
kryptik/etc/upper`; only the account database, the machine's identity and
clock may live in that upper layer - anything else found there, a preload
library or a udev rule say, is moved to `lib/kryptik/etc/quarantine` before
the overlay is mounted, since the state partition is not authenticated),
`/home` from `/var/home`, tmpfs on `/run`, `/tmp`.
The verified root stays read-only; a write to it is an error, not a
persistence bug. There is no swap: zone confidentiality is argued for the
LUKS2 volumes (Design 04), and an unencrypted swap would undercut it.
Creating encrypted swap is a later, explicit change.

## Installer

`kryptik-install --target /dev/X --yes` runs from the booted medium:

1. Preflight every tool, the target's identity (block device, whole disk,
   not the medium, not the running root's underlying disk through any dm or
   loop stack, nothing mounted from it, no active swap on it, larger than
   ESP + 2 × root image + 512 MiB), and the sizes of what it will copy.
2. Partition with `sfdisk` (GPT, the four labelled partitions), re-read.
3. `dd` the ESP image and the root image from the medium's own partitions
   (or, on the ISO, from the appended offsets) into partitions 1 and 2;
   verify each copy by `sha256sum` against the values recorded in
   `/etc/kryptik-image.json`; `mkfs.ext4` partition 4.
4. On the target ESP, make `EFI/BOOT/BOOTX64.EFI` the slot A kernel and
   write `kryptik/version-a`. Write `/etc/kryptik-install.json` into the
   state partition. `sync`, `fsync` the device.
5. Report; every failure exits non-zero and says which step; the runner
   records the installer's own status, not sed's.

The installed disk boots with no firmware variables at all through the
removable-media path (`BOOTX64.EFI`). `kryptik-efiboot` additionally
creates a `Kryptik` Boot#### entry when the firmware allows it; it is a
convenience, not a dependency.

## Updates (A/B, bounded fallback, authenticated recovery)

A payload is `{kryptik-root.img, kryptik-a.efi, kryptik-b.efi, manifest,
manifest.sig}`. The manifest lists every file's sha256, the version, the
minimum version it may be applied over, the root hash, and is signed with
the release key (Ed25519, `tools/release-manifest.sh`); the public key
ships in the image at `/etc/kryptik/trust/release.pub`. The updater
(`kryptik-update`) runs in zone 0 with no network; fetching is the net
zone's job and the payload arrives as files in `/var/lib/kryptik/updates/`.

1. **Verify before touching anything**: signature over the manifest with
   the shipped key; every file's hash; the version is newer than the
   running one unless `--recovery` is given explicitly (which still
   requires a valid signature: recovery is authorised downgrade, not
   unsigned boot); the payload's `kryptik-<inactive>.efi` embeds the
   manifest's root hash (checked by `strings`-free byte search).
2. Write the root image to the inactive slot with `dd conv=fsync`, read it
   back and hash it.
3. Copy the inactive slot's kernel to `EFI/kryptik/kryptik-<inactive>.efi.new`,
   `fsync`, rename into place, write `kryptik/version-<inactive>`.
4. Arm the trial: `kryptik-efiboot next <inactive>` sets a Boot#### entry
   for that file and `BootNext`. Record `trial=<inactive>` in
   `/var/lib/kryptik/boot/state`. Reboot.
5. On boot, `boot-success` (an s6 oneshot that depends on the whole default
   bundle) reads `kryptik.slot=`. If it is the trial slot: commit — copy
   its kernel over `EFI/BOOT/BOOTX64.EFI.new`, `fsync`, rename; clear the
   trial record. If the trial slot did not come up (panic, verity failure,
   hang without success), the firmware consumed `BootNext` and the next
   boot falls back to `BOOTX64.EFI`, still the old slot; `boot-success`
   sees `trial=<other>` with `kryptik.slot=` the old one and records the
   failure, so the updater refuses to re-arm the same payload without
   `--retry`.
6. Rollback: `kryptik-update rollback` arms the other slot the same way
   (its kernel and version file are still on the ESP); the slot's root
   image is untouched by the update.

Zone data is on `kryptik-state` and is never written by any of the above.

Limits, stated: the ESP is FAT, so the two renames are the only
non-atomic points; each is preceded by a complete, fsynced copy and
followed by a state that boots either way (`BootNext` is consumed exactly
once; `BOOTX64.EFI` is replaced only after a successful boot of the new
slot). Power-loss tests in a VM are QEMU process kills at those points with
`cache=writeback` and explicit fsyncs; they show the recovery logic, not
storage-controller behaviour.
