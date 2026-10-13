# Removable storage

Someone hands the user a USB stick with a PDF on it, or the user wants a
document out of `work` and onto a stick. Nothing in Kryptik does either
today. This design keeps the rules the architecture already set: zone 0
runs no user applications ([ADR-003](../decisions.md)), a zone reaches
zone 0 only through its proxy and its [broker](broker.md), and every zone
shares one kernel, so whatever the kernel parses for one zone it parses
for all of them. [ADR-025](../decisions.md) decides it: no mount.

## Where things stand

When a stick is plugged in:

- **The kernel** binds `usb-storage` or `uas`, adds a SCSI disk, and reads
  its partition table, as it does for any disk. That stays in every option
  below.
- **eudev**, as root in zone 0, creates the device nodes (`root:disk`,
  0660). Its blkid builtin then reads each partition's superblock to name
  the `/dev/disk/by-label` and `by-uuid` links
  (`60-persistent-storage.rules`). Kryptik's own tools find their
  partitions by GPT label with `blkid`, which probes every disk, sticks
  included, and each keeps to one disk: the root's (`devices.sh`) or the
  one it was named (the installer, `kryptik-recover`). A stick with
  Kryptik's labels stands in for nothing.
- **Nothing mounts it.** The only way to the files is root mounting the
  stick by hand in zone 0. There the kernel's FAT driver, built in for the
  ESP (`boot.fragment`), parses whatever the stick holds, and a zone then
  gets the files by a [transfer](broker.md#file-transfer). The kernel
  builds neither exFAT nor NTFS nor FUSE.

## What a stick can do

- **Its filesystem is written by whoever had it last.** Filesystem drivers
  are a well-worn target for crafted images, and the kernel's are shared by
  every zone: a bug reached through one mount is a bug in all of them.
- **Its filesystem can keep a reader busy.** Read by a program in the zone
  it was given to, a filesystem made to loop can keep that program spinning
  until the user stops it. Kryptik's reader stops at whatever claims more
  than the stick has room for, and the stick reaches nothing past that zone.
- **Its partition table** is parsed by the kernel and by libblkid in zone
  0 whatever is decided here. Those parsers are small and long fuzzed. A
  rule that skips eudev's probe for USB disks
  (`UDEV_DISABLE_PERSISTENT_STORAGE_BLKID_FLAG`, which eudev 3.2.15 honours)
  would leave zone 0 reading no superblock of a stick. It is a separate
  change, since the medium and a Kryptik installed on a USB disk need the
  probe for their own.
- **It can be more than storage.** A device that also presents a keyboard
  types into whatever has focus, as any USB keyboard does. That is a
  question of which USB devices are accepted at all, and not this design's.

## A descriptor, not a path

A zone cannot open the partition by name: the node is `root:disk` and in
zone 0's `/dev`, and a zone's seccomp filter refuses `mount`. So kryptikd
opens it, exclusively (`O_EXCL`, so nothing mounts it meanwhile), and the
zone gets a file descriptor. The descriptor is on a device-mapper linear
mapping of the partition, made for the grant. On eject kryptikd swaps that
mapping's table for the `error` target, so a zone that kept the descriptor
reads only I/O errors after. The mapping covers one partition, so the
partition table and SCSI pass-through stay out of reach without
`CAP_SYS_RAWIO`.

The zone then needs a reader that works on the descriptor itself. Opening
`/dev/fd/N` again does not help: for a device that reopens the node, whose
permissions refuse the zone's uid. mtools, exfat-fuse and ntfs-3g all take
a path, so the reader is Kryptik's own. In Rust, the `fatfs` crate reads
and writes FAT12, FAT16 and FAT32 with long names over anything that seeks.
exFAT, which sticks of 64 GB and more and every SD card over 32 GB come
formatted with, has a reader of Kryptik's own in the same program
(`tools/stick/src/exfat.rs`), as no crate reads it with the care a hostile
volume needs: the boot sector checked against the stick's size and by its
checksum, the up-case table by its length and checksum, each entry set by
its checksum before any field of it is used, every run and chain inside the
heap, and the directory clusters a command reads counted, so a chain that
loops through unused entries stops. NTFS waits.

## Options

- **Mount in zone 0** and transfer the files. The kernel's FAT driver
  parses a hostile filesystem in the kernel every zone shares, and the
  user picks files in zone 0, which is no place for a file manager.
  Rejected.
- **FUSE.** The kernel builds FUSE (`CONFIG_FUSE_FS`, new), and kryptikd
  mounts a FUSE filesystem at `~/usb` in the chosen zone. It does this from
  inside that zone's user and mount namespaces, so the zone's ids hold, and
  hands `/dev/fuse` and the partition's descriptor to a FUSE server in the
  zone, Kryptik's reader behind the `fuser` crate. Every program in the
  zone sees `~/usb`, Firefox's file picker included. Eject unmounts it.
  The cost is a kernel subsystem that every zone's server talks to.
  FUSE's kernel side was built for unprivileged, untrusted servers, so it
  is likely a smaller surface than a filesystem driver parsing a hostile
  image, but it is new code in the shared kernel. It also needs a
  privileged mount into a running zone, which kryptikd does nowhere today.
- **No mount.** The zone's reader copies files in and out on the
  descriptor: `kryptik-stick list`, `get PATH`, `put FILE` in the zone, run
  from a terminal or offered by the chrome. No kernel code is added, and
  no mount table changes. The cost is a copy step: a file on the stick
  reaches Firefox's file picker only once it is copied into the zone.

## The decision

ADR-025 decides: no mount. It adds nothing to the shared kernel, and the
reader would serve FUSE too, so the work is not lost if FUSE follows.
FUSE needs a decision of its own, weighed against the kernel code it adds,
if copying first proves too clumsy. FAT is read and written; exFAT is read,
and written only once its reader has been through acceptance.

- **The user picks the zone.** When a stick appears, the chrome names it
  from sysfs, not from its filesystem: vendor, model, size and its
  partitions' numbers, sizes and GPT names (`PARTNAME`). It asks which zone
  gets which partition, and whether to read only (the default) or to read
  and write. Nothing happens until the user picks, and no choice is
  remembered across plugs. The same gesture in the chrome ejects it. A
  stick nobody vouches for goes to `untrusted`, where a reader its
  filesystem subverts holds nothing worth taking.
- **Zones that never get one.** The net zone never does. A zone's file
  may refuse sticks (`[storage] removable = false`), as `vault`'s will.
- **The broker hands it over.** The zone asks with `stick`. The reply
  carries the descriptor only while the user's grant names that zone and
  that partition, the same way the microphone's grant is held. The grant
  ends with eject, with the stick pulled out, or with the zone's stop.

### The stick that holds the install medium

The medium is a GPT disk: its ESP, which is FAT, and Kryptik's own
partitions, which are not. Booted from, it is the root's own disk and is
never offered. Plugged into an installed machine, it is offered like any
stick. Its ESP can go to a zone as FAT files, read-only by default, and
the reader refuses its other partitions, which hold no FAT. Kryptik's own
tools keep to their one disk, so the medium's `kryptik-a` or
`kryptik-state` labels stand in for nothing, as now, and the kernel
mounts nothing when it appears, as now.

## Check

QEMU attaches a stick while the guest runs (`device_add usb-storage` on
the xHCI bus, a FAT32 image the host made), in `make zones-test`:

- zone 0 mounts nothing, and only kryptikd opens the partition, after the
  grant;
- the chrome names the stick from sysfs and asks;
- granted to `untrusted`, read-only, the zone lists the stick and copies
  out a file whose hash the host knows; a write is refused;
- `personal` asks for the stick and is refused, and no zone has a node for
  it;
- granted read-write, a file the zone puts lands in the image, which the
  host reads after the VM stops;
- after eject, the descriptor `untrusted` kept reads only I/O errors;
- a stick pulled out without eject leaves the reader with I/O errors, and
  the kernel log with no oops;
- a stick holding the install medium offers its ESP, and the reader
  refuses its other partitions.

## Not covered

- Phones and cameras over MTP, which is a protocol in userspace, not a
  disk.
- Internal disks: a second drive holding another OS is the
  [installer's](installer-choices.md) question.
- Which USB devices the kernel accepts at all, keyboards included.
- Optical discs: the kernel's ISO 9660 driver is built in for the medium
  and is not offered to zones.
