# Installer choices

The [roadmap](../roadmap.md) asks for installer choices: beside another OS,
across disks, a chosen slot size, and an upgrade path when slots become too
small. Today the installer takes a whole disk and the installed system boots
through the removable-media path. Under [releases](../releases.md), a change
that needs a reinstall is a major version, so the upgrade path decides how
often a major version happens. The proposed decision is ADR-023 in
[decisions](../decisions.md).

## Where things stand

- **A whole disk.** `kryptik-install --target DISK` refuses a partition, the
  disk it runs from, anything mounted, swapped on or held open, and a disk
  with any `kryptik-` partition unless `--replace-kryptik` asks for it. It
  writes four GPT partitions: `kryptik-esp` (512 MiB, from the medium),
  `kryptik-a`, `kryptik-b`, and `kryptik-state` with the rest
  (`tools/install/kryptik-install.sh`, [boot and updates](boot-and-updates.md#installer)).
- **Slot size.** Each slot is the image plus half again, at least 512 MiB
  more, rounded up to 64 MiB. Today's root image is about 1,560 MiB, so a
  slot is 2,368 MiB, and a machine installed now takes releases about
  800 MiB larger before `kryptik-update apply` refuses one ("slot b is N
  bytes; the root image needs M").
- **Boot path.** The installed disk boots `\EFI\BOOT\BOOTX64.EFI`, a copy of
  the committed slot's kernel, through the removable-media path with no
  firmware variables. `kryptik-efiboot` writes `Boot####` entries around a
  trial; when it ends the committed slot keeps one, and a fresh install has
  none until its first trial.
- **Identity.** The kernel finds its slot by `PARTLABEL` on whatever disk
  has it, and dm-verity refuses a slot that is not the one its root hash
  names. `sysinit` takes the state partition only from the disk the root
  came from (`devices.sh`): a label alone is not an identity.
- **Secure Boot.** The user enrols Kryptik's certificate in the firmware's db.
  The acceptance run proves that a firmware with Microsoft's keys alone
  refuses the medium.

## Constraints

- **ADR-014.** The firmware is the only loader. Choosing between operating
  systems is the firmware's boot menu, never a boot loader of Kryptik's.
- **The threat model.** Boot integrity rests on Secure Boot enforcing
  Kryptik's certificate, and the firmware is trusted
  ([threat model](../threat-model.md)).
- **The state partition holds everything** and is never converted in place
  ([state encryption](state-encryption.md#decisions)). Any tool that touches
  it must leave either the old layout or the new one after a crash.
- **The installer's habits stay:** every check before the first write, every
  failure naming its step, and a dry run that writes nothing.

## A chosen slot size

`--slot-size` covers the user who knows. The default is the question.
Image plus half again was right for a root that grew slowly. Version 2 puts
more in the root: firmware, Mesa if the compositor moves to the GPU, and the
browser stack itself unless applications ship as images (ADR-015, proposed
in `docs/design/software-delivery.md`). The browser design works out that the
software-rendered browser in the root alone leaves about 400 MiB of today's
slot.

Recommendation: a default of twice the image or 4 GiB, whichever is larger,
rounded to 64 MiB. That costs about 3.4 GiB of disk over today's layout,
raising the smallest disk from about 8 GB to about 12 GB. In exchange, the
root can roughly double before any machine needs the path below. The plan
the installer prints says how large a release the slots will take.

## When slots become too small

### Tell the user before the download

`kryptik-update apply` refuses an image larger than the inactive slot only
after the whole release has been fetched. The manifest already lists the
root image's size. `check-manifest`, which zone 0 runs on the manifest
before it takes any other file from the channel
([update channel](update-channel.md#bytes-in-an-order-that-bounds-them)),
can compare that size with the inactive slot and refuse at once, naming the
fix.

### Ways to get bigger slots

- **Reinstall.** Back up, install from a newer medium, restore. Nothing
  backs up a state partition's contents today except by hand. A lost
  passphrase, a missed zone volume or a cut cable loses data. This is the
  reinstall that [releases](../releases.md) prices as a major version.
- **Move the state partition's start.** Shrink it, move every block of it
  towards the end of the disk, and grow the slots into the gap. A cut in the
  middle of the move loses the partition that holds everything. Rejected.
- **Extend a slot with a second partition.** The kernel's `dm-mod.create`
  could join a slot and an extension with a linear table. But the command
  line is compiled into kernels every machine shares, so every machine would
  need the same extension partitions. Rejected.
- **New slots at the end of the disk.** Shrink the state partition from its
  end, which moves no data, and create two larger slot partitions in the
  space freed. Then rename the labels: the old slots become
  `kryptik-old-a` and `kryptik-old-b`, and the new ones take `kryptik-a`
  and `kryptik-b`. The signed kernels name slots by label, so they boot the
  new slots with no change.

### Recommendation: new slots at the end, from the medium

`kryptik-recover --grow-slots MIB --disk DISK`, run from the install medium
of the release that needs it, with nothing mounted:

1. Check everything first: the disk is this installation's, the state
   partition opens with the passphrase given, its filesystem is clean and has
   room to lose twice the new slot size, and the new layout fits.
2. Shrink the state partition at its end: `resize2fs`, then
   `cryptsetup resize`, then the partition table. Each step leaves a
   partition that opens and mounts.
3. Create two partitions in the freed space, labelled `kryptik-new-a` and
   `kryptik-new-b`. Write the medium's root into the one that will be
   committed and read it back, as the installer and `--restore-slot` do.
4. Rename all four labels in one GPT write. Before it the old slots boot;
   after it the new ones do.
5. Commit the new slot (`BOOTX64.EFI` and `committed-slot` on the ESP, as
   `--commit-slot` does).

The old slots' space, about 4.6 GiB on today's layout, stays unused: giving
it to the state partition would mean moving its start. A release whose image
no longer fits the slots of machines installed from older media is a major
version. Its migration is a medium step, not a reinstall, but the user must
boot a medium all the same. `--grow-slots` ships on the medium of the last
minor release before it, so users can move at their own time.

## Beside another OS

### Its own ESP

- **Sharing the other OS's ESP** is rejected. Windows makes a 100 MiB ESP
  (260 MiB on 4K-sector disks) and keeps its own fallback loader at
  `\EFI\Boot\bootx64.efi`. Kryptik's kernels are about 22 MB each, and an
  update holds `BOOTX64.EFI`, both slots and a `.new`, about 90 MB: more
  than such an ESP has free. Kryptik's renames would also run on a FAT that
  another system writes too.
- **A second ESP of Kryptik's own**, labelled `kryptik-esp` as now, in the
  free space. The firmware boots by device path from `Boot####` entries, so
  two ESPs coexist, and all of Kryptik's ESP logic, found by label on the
  root's disk, stays as it is.

### Its own boot entry

The removable-media path belongs to the firmware's fallback for a disk, and
with two ESPs on one disk, which one the firmware takes is the firmware's
choice. Beside another OS, Kryptik boots by a `Boot####` entry of its own,
named `Kryptik`, that points at the committed slot's kernel.
A fresh install has no entry until its first trial, so the installer makes
it (`kryptik-efiboot ensure`). The installer puts it first in `BootOrder` and nothing reorders it
afterwards: if the other OS moves itself first, as Windows updates do, the
user picks Kryptik from the firmware's boot menu. ADR-014 stands, with no
boot loader.

### Secure Boot's database

Windows needs Microsoft's keys in db, and Kryptik's certificate goes in
beside them. Anything Microsoft's keys sign can then run before Kryptik's
kernel: Windows Boot Manager; shim, and every distribution's loader behind
it; and older signed boot managers with known bypasses until dbx revokes
them, as the BlackLotus bootkit used one (CVE-2022-21894). Code that runs
before Kryptik's kernel can change it in memory after the firmware checks
its signature. On a machine whose db holds only Kryptik's certificate,
nothing else runs. With the TPM unlock design (ADR-017, proposed), PCR 4 and
PCR 7 would differ after such a chain and the TPM would not unseal. But the
passphrase prompt that follows cannot tell the user why.

Enrolling Kryptik's certificate also changes db, which BitLocker binds
through PCR 7. The next Windows boot asks for BitLocker's recovery key, and
the guide must say to have it at hand before enrolling.

### The installer

`kryptik-install --beside DISK` uses the largest free region of a GPT disk
and nothing else:

- it refuses an MBR disk, since Kryptik boots by UEFI only;
- it never resizes or writes another system's partition: the user shrinks
  Windows from Windows first;
- the other partitions' bytes are the same before and after;
- `--dry-run` prints the region and the layout.

### What it changes in the threat model

Proposed addition to "Offline physical access", to apply with the change
that builds this:

> On a machine that also boots another operating system, Secure Boot's
> database keeps that system's keys, so anything they sign can run before
> Kryptik's kernel. Boot integrity there also rests on that system's boot
> chain and on the firmware's revocation list being current.

## Across disks

A small fast disk for the slots and a large one for the state, or a machine
whose large disk is not the one it boots from.

- **The state partition's identity.** `sysinit` takes the state partition
  from the root's own disk. Across disks, the installer writes the state
  partition's PARTUUID and LUKS UUID to the ESP (`kryptik/state-identity`).
  `sysinit` then takes the partition labelled `kryptik-state` that matches
  both, waits a bounded time for its disk to appear, and otherwise boots
  degraded with the reason. The ESP is not authenticated. Rewriting the file
  points `sysinit` at a partition the user's passphrase does not open, which
  is the degraded state, or at a clone, which the state suite already
  covers.
- **Two Kryptik disks in one machine** stay a known limit. The kernel takes
  the first `kryptik-a` it finds, and dm-verity refuses the wrong one, so
  the boot fails safe but fails. The installer keeps refusing a disk that
  carries `kryptik-` labels unless asked by name.
- **Slots on two disks** are rejected: two disks to fail and nothing gained.

## Recommendation

1. A default slot of twice the image or 4 GiB, whichever is larger, with
   `--slot-size` for more.
2. `check-manifest` refuses a release too large for the inactive slot before
   the image is fetched, and names the fix.
3. `kryptik-recover --grow-slots` from the medium: shrink the state
   partition at its end, add two larger slots there, swap the labels in one
   GPT write. A release that needs it is a major version, and the tool
   ships a minor release earlier.
4. Beside another OS: Kryptik's own ESP in free space, its own `Boot####`
   entry, its certificate beside Microsoft's in db, and the threat-model
   text above. BitLocker's recovery key is warned about before enrolment.
5. Across disks: the state partition's identity on the ESP, and a bounded
   wait for its disk.

## The check that proves it done

The install suite, extended:

- a default install makes slots of the new size, and `--slot-size` larger
  ones;
- on a disk laid out as Windows lays one out (a 100 MiB ESP with
  `\EFI\Microsoft`, a Microsoft reserved partition, a data partition, then
  free space), `--beside` installs into the free space alone. The other
  partitions hash the same before and after, and the system boots by its
  own `Boot####` entry;
- with the state partition on a second disk, the system boots and finds it.
  A clone with the same label but another PARTUUID gives the degraded state
  and says why;
- after an install from a small image, a larger release is refused by
  `check-manifest` before its image is fetched. `--grow-slots` from the new
  medium keeps a marker written under `/home`, the release then applies and
  commits, and a power cut at each step of `--grow-slots` leaves a disk that
  boots the old slots or the new.
