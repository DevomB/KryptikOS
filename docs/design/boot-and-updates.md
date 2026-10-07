# Boot and updates

The firmware is the only loader. Each bootable kernel is a UEFI application
(the EFI stub) signed with the developer Secure Boot key, with its command
line compiled in. The command line names the root slot and carries its
dm-verity root hash, and the kernel's `dm-mod.create=` (`CONFIG_DM_INIT`)
builds the verity device before mounting root: no initramfs, bootloader or
editable file lies between the firmware's signature check and the read-only
verified root. Mutable state is on a separate
[encrypted partition](state-encryption.md). Two root slots and a firmware
`BootNext` trial give A/B updates with a bounded fallback.

## Layout

Partitions are found by GPT label, never by device name.

| # | label | content |
| --- | --- | --- |
| 1 | `kryptik-esp` | FAT32, 512 MiB: `EFI/BOOT/BOOTX64.EFI` (the committed slot's kernel), `EFI/kryptik/kryptik-{a,b}.efi`, `kryptik/version-{a,b}`, `kryptik/committed-slot` |
| 2 | `kryptik-a` | slot A: read-only ext4 without a journal, then its verity hash tree |
| 3 | `kryptik-b` | slot B, empty after install |
| 4 | `kryptik-state` | LUKS2 with ext4 inside, rest of disk: `/var`, the `/etc` upper layer, `/home`, zone volumes, update staging |

The USB image holds `kryptik-esp` and `kryptik-media`; the ISO holds the ESP
as its El Torito image and the root image at a sector offset (a `linear` dm
target over `/dev/sr0`, verity on top). The root image is byte-identical on
the medium, in slot A and in a payload, so the installer copies bytes and
signs nothing.

## The command line

```text
dm-mod.waitfor=PARTLABEL=kryptik-a dm-mod.create="kroot,,0,ro,0 <data_sectors> verity 1 PARTLABEL=kryptik-a PARTLABEL=kryptik-a 4096 4096 <data_blocks> <hash_start_block> sha256 <root_hash> <salt> 1 panic_on_corruption"
root=/dev/dm-0 ro rootwait console=tty0 console=ttyS0,115200 panic=10 loglevel=4 mitigations=auto,nosmt pti=on page_alloc.shuffle=1 hash_pointers=always nosmt kryptik.slot=a
```

- The root hash in the signed kernel binds userland to kernel: replacing
  either fails at the firmware or at the first read of a modified block,
  which `panic_on_corruption` and `panic=10` turn into the reboot the A/B
  fallback relies on.
- `CONFIG_CMDLINE_OVERRIDE` stops a boot entry's load options (writable by
  root through EFI variables) from appending `init=/bin/sh` or another
  `dm-mod.create=`.
- `dm-mod.waitfor=` makes dm-init, which does not retry, wait for a slowly
  probed disk or USB stick.
- `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` is on but not the mechanism; the
  kernel's signature authenticates the hash.
- `tools/check-kernel-hardening.sh` checks the parameters after `loglevel`.

Stage 06 relinks stage 05's unbound kernel per variant (`media-usb`,
`media-iso`, `slot-a`, `slot-b`; `06-kernel-bind.sh`), changing only
`CONFIG_CMDLINE` so module signatures stay valid, and signs each with
`sbsign`. The developer key (RSA-3072) is made on first use under
`${KRYPTIK_WORK}/keys/sb/`, never enters Git or an image, and is enrolled
only in disposable OVMF variable stores (`tools/image/ovmf-vars.sh`). That
shows the chain enforces a key; it is not production certification. A
production image (`KRYPTIK_ROLE=production`) is signed with the key on the key
medium that `KRYPTIK_KEYS` names, and no key is made (`build/lib/release-keys.sh`,
[building](../building.md)). Stage 06 runs on the host: no key is ever
inside the chroot, where the upstream build scripts run, and a release's keys
reach only the job that signs, never the one that ran the chroot
([release keys](../release-keys.md#where-they-are-used)).

## Mutable state

`sysinit` unlocks `kryptik-state` on the disk the root came from (a label
alone is not an identity) and mounts it at `/var`. An install medium uses a
tmpfs. An installed system without a usable state partition boots degraded:
`/var` is a tmpfs, and first boot, the desktop, the update commit and the
updater refuse to run.

`/etc` overlays `/var/lib/kryptik/etc/upper` on the verified `/etc`. The
state partition is not authenticated, so the upper layer may hold only the
account database, the machine's identity and clock, and `resolv.conf`;
anything else is quarantined before mounting. Nothing that decides privilege
(init, services, sysctls, zone definitions, the release trust anchor) is read
from `/etc`. There is no swap.

## Installer

`kryptik-install --target DISK [--yes] [--dry-run] [--replace-kryptik]`
checks everything first: a whole, writable disk that is not the running
root's (through any dm or loop layer, so from a medium never the medium),
with nothing mounted, swapped on or held open by device-mapper or md, and
enough room. A disk that carries any `kryptik-` partition (an old
installation, a medium, a test-control disk) is refused unless
`--replace-kryptik` asks for it; nothing overrides the other refusals. Then it
asks for the state passphrase, partitions,
copies the ESP and root image from the medium, reads slot A back against the
medium's `root.json`, creates the LUKS2 state partition and makes
`BOOTX64.EFI` the slot A kernel. Every failure names its step.

`root.json` is the medium's own record and is not signed, so the installer
and `kryptik-recover --restore-slot` take it through the same checks
(`build/service-scripts/medium-root.sh`): every field has its form before it
is used, the record must name the root hash and size in the medium's signed
command line, each slot kernel copied from the medium must carry that hash,
and the slot written must verify against it (`veritysetup verify`) before
anything names it. A kernel's signature is the firmware's to check, at boot.

The installed disk boots `BOOTX64.EFI` through the removable-media path with
no firmware variables. `kryptik-efiboot` adds a `Kryptik slot <x>` Boot####
entry for a trial. When the trial ends, committed or not, `forget` removes
Kryptik's entries and `BootNext`, and the committed slot gets its own entry
back. Firmware re-adds its own disk entry at the end of `BootOrder`, so an
entry left in front of it must boot what `BOOTX64.EFI` boots; this one does,
and is a second way to the committed slot should `BOOTX64.EFI` be lost. An
entry is Kryptik's when its description and its file say so, never by its
number: slot a's is `Boot00A0` and slot b's `Boot00B0` unless another system
already uses that number, and then the next free one, the other system's
entry left alone.

## Updates

A payload directory holds exactly `kryptik-root.img`, `kryptik-a.efi`,
`kryptik-b.efi`, `root.json`, `manifest` and `manifest.sig`. The manifest
lists each file's sha256 and size, the version and the role, and is signed by
the release key (Ed25519, `ssh-keygen -Y`, namespace `kryptik-release`).
Versions are ordered as `sort -V` orders them. A production release is
numbered MAJOR.MINOR.PATCH, which that order reads as a person does
([release keys](../release-keys.md)). The trust anchor and required role are on the verified root in
`/usr/share/kryptik/trust/`, never in `/etc`, which the state partition can
shadow; stage 06 writes them from the build's role and keys. An image without
the role file accepts no release: a missing file is never read as
`development`. `kryptik-update apply DIR` runs in zone 0 without network;
payloads come from [the update channel](update-channel.md) or by hand.

1. Verify everything before writing, from a root-only copy of the manifest
   and signature: the signature; the role; a newer version unless
   `--recovery` (still signed: an authorised downgrade); every file's hash and
   size, with nothing unlisted; and `root.json`'s root hash embedded in both
   kernels (`grep -a -F`). Refuse while the state is degraded, another update
   runs or a trial is armed.
2. Take the inactive slot's kernel and version file off the ESP, so an apply
   cut short leaves nothing that `rollback` or `kryptik-recover --commit-slot`
   would take. Write the slot (`dd conv=fsync`) and read it back.
3. Put its kernel on the ESP as `.efi.new`, fsync, check it, rename; write
   its version file. Keep the verified manifest and signature in
   `/var/lib/kryptik/boot/release-<slot>/` for the [clock's floor](time.md).
4. Record the trial (`armed=0`), run `kryptik-efiboot set-next <inactive>`,
   record `armed=1`, reboot.
5. `boot-success` judges the trial slot: state persistent; eudev, seatd, the
   launch daemon, the net zone and the login getty up; kryptikd finding kernel
   support and the zones; an unambiguous ESP. Healthy: it copies the kernel
   over `BOOTX64.EFI` (`.new`, fsync, rename), updates `committed-slot`,
   clears the trial and forgets the entries, and the slot's kept manifest
   raises the clock's floor if it is the newest. Unhealthy: it records that,
   forgets the entries and reboots into the committed slot, `BootNext` being
   spent. On a degraded state the trial record is out of reach, so
   `committed-slot` says whether the boot is a trial. A trial that never comes
   up also lands on the committed slot; the fallback records `trial.failed`
   and forgets the entries, and the updater will not re-arm that payload
   without `--retry`, which root gives (`su` from the administration login
   on tty2; the refusal prints the command). Only a trial reboots; an
   unhealthy committed slot is reported and left running, and so is a trial
   on a degraded state whose ESP cannot be read, since nothing then says it
   is one.

   The net zone is in the check on purpose: a release whose net zone cannot
   come up could never fetch the release that fixes it. Whoever can crash
   that net zone at will can hold a machine on its old release this way, but
   can already do as much by dropping its traffic.
6. `kryptik-update rollback` arms the other slot the same way.
7. The earlier release stays bootable, since rollback needs it, and its
   kernel is signed like any other. A firmware entry or `BootNext` that
   something outside Kryptik sets (firmware setup, another system) boots it.
   boot-success reads the committed slot off the ESP at every boot: a slot
   that runs with no trial on record and is not the committed one is
   recorded as `uncommitted`, never as `ok`; its entries are forgotten and
   the machine reboots, once, to the committed slot. If it comes up there
   again it is left running, to be put right from it
   (`kryptik-update status` shows the result). This does not stop someone
   who rewrites the ESP itself: the committed slot's name there is not
   signed.

Zone data is never written. On the FAT ESP the two renames are the only
non-atomic steps; each follows a complete, fsynced copy and leaves a system
that boots either way. From the medium, `kryptik-recover` commits or rewrites
a slot and restores the state header ([user guide](../user-guide.md)).

## Tests

`make acceptance` runs the OVMF suites in `tools/image/`: `media-smoke.sh`
(firmware boot, Secure Boot enforced, Microsoft-only keys refused),
`install-test.sh`, `integrity-test.sh` (a foreign-signed boot file refused, a
flipped root block stopping the boot, recovery), `update-test.sh` (apply,
refusals, recovery, rollback, a broken trial, interruptions, the network
path) and `state-test.sh` (cloned, ambiguous, corrupt and missing state).
Host-side: `tools/tests/boot-success.sh`, `efiboot.sh`,
`update-esp.sh`, `installer.sh`, `sysinit-etc-upper.sh`,
`release-manifest.sh`, `release-channel.sh`.

## Files

`build/stages/06-iso.sh`, `06-kernel-bind.sh`,
`tools/install/kryptik-install.sh`, `build/service-scripts/sysinit.sh`,
`medium-root.sh`,
`boot-success.sh`, `tools/update/kryptik-update`, `kryptik-recover`,
`tools/efi/kryptik-efiboot.c`, `tools/release-manifest.sh`.
