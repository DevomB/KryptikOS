# Encrypted persistent zones: LUKS2 volumes and key lifecycle

Status: implemented in `compartments/kryptikd/src/volume.rs`, with the
open-before-fork and close-after-wait steps in `spawn.rs`, the `volume` and
`gc` commands in `main.rs`, and the passphrase collected by `kryptik-launch`
or the trusted chrome (`tools/desktop/kryptik-launch.c`,
`tools/desktop/kryptik-chrome`). The shipped `dev`, `personal`, `vault` and
`work` zones are encrypted. Builds on
[the privileged launch design](privileged-launch.md) and
[resource limits and ephemeral zones](resource-limits-and-ephemeral-zones.md).
Tests use disposable volume files or virtual disks created per run; never a
real device.

## Ownership

- **The container and the dm mapping belong to zone 0.** A zone's volume is
  named by `storage.volume` in its zone file: a LUKS2 container that is
  either a regular file under `/var/lib/kryptik/volumes/` on the state
  partition (`<zone>.luks`, what the shipped zones use) or a block device.
  kryptikd (root) opens it with `cryptsetup open --type luks2` to
  `/dev/mapper/kryptik-zone-<zone>`, runs `e2fsck -p`, and mounts the ext4 inside
  `nosuid,nodev,noatime` at the zone's data directory under
  `/var/lib/kryptik/zones/<zone>`, owned by the zone's identity (see
  [the privileged launch design](privileged-launch.md)). Exec stays allowed
  on the home: `dev` and `untrusted` run what they build. The zone then
  receives it exactly as a persistent directory, bound at `/home/<zone>`
  through the descriptor. The zone never sees the container, the mapping
  or a loop device: nothing under its `/dev` names one, and `nodev` is on
  every mount it has. An unprivileged launch of an encrypted zone is
  refused, since it cannot open the volume.
- **Unlock happens in zone 0, before the zone exists.** On an installed
  system the passphrase is collected by `kryptik-launch --ask`, on the
  terminal when there is one and otherwise in a trusted window drawn by
  `kryptik-chrome --prompt`. It travels to the launch daemon
  (`kryptikd serve`) as a memfd over `SCM_RIGHTS` and reaches the launcher
  as `--passphrase-fd N`; it is never on a command line or in the
  environment. For tests, `--passphrase-file` names a file that must be
  owned by root (or the caller) with no group or other permission bits; a
  readable file, a link, an empty file or one over 4096 bytes is refused.
  kryptikd hands the passphrase to `cryptsetup` on stdin
  (`--key-file -`), and the buffer is zeroed with `explicit_bzero` when it
  is dropped. That is the whole claim about userspace key hygiene; the
  buffer is not `mlock`ed, and nothing about RAM after that is claimed
  ([the threat model](../threat-model.md): keys are in RAM while zones
  run).
- **Close happens after the zone is gone.** Order: `waitpid` on the
  intermediate (pid namespace dead, mount namespace released) ->
  `umount` of the data directory, retried for up to three seconds because
  the zone's mount namespace is released asynchronously after its pid 1
  exits; still `EBUSY` after that means a process escaped, which is
  reported as an invariant failure, not something to force with
  `MNT_DETACH` -> `cryptsetup close kryptik-zone-<zone>`. dm-crypt frees the
  key in kernel memory on close; that is what `wipe_keys = "on-stop"`
  means in the zone file, and it means *that*, not a memory-scrubbing
  guarantee. A launch that fails after the volume was opened closes it on
  the error path, so a failed launch never leaves plaintext mounted.
- **The vault is exclusive.** `vault`'s volume is opened only while `vault`
  runs. Refusing to start `vault` while any zone that can talk to a broker
  is running would be too restrictive for a daily driver. The invariant
  that matters is narrower and testable: while `vault` is **not** running,
  its plaintext is not mounted anywhere and its dm device does not exist.
  Other zones running is irrelevant to that, because they cannot reach
  zone 0's mounts at all (pivot_root).

## Key lifecycle

- One LUKS2 volume per zone, its own random volume key (created by
  `cryptsetup luksFormat --type luks2 --pbkdf argon2id`, at cryptsetup's
  default size, 512 bits for aes-xts-plain64), keyslot 0 = the
  user's passphrase. No key derivation across zones; a compromised
  passphrase for `untrusted` says nothing about `vault`. (Per-zone
  passphrases are a UX decision for later; the mechanism supports one
  passphrase in every volume's slot 0 *or* different ones, and kryptikd
  does not care.)
- `kryptikd volume init NAME [--size 512M] --passphrase-file F` creates the
  volume: a sparse 0600 file of the given size (at least 32 MiB) in a 0700
  directory, or an existing empty block device. It refuses anything that
  already carries a signature (`blkid -p` non-empty) or a non-empty file,
  then formats, opens, runs `mkfs.ext4 -E root_owner=<uid>:<gid>`, and
  closes. The guest tests and the update test create volumes this way; the
  installer does not create zone volumes.
- `kryptikd volume passwd NAME --passphrase-file OLD --new-passphrase-file NEW`
  runs `cryptsetup luksChangeKey`. Header backup:
  `kryptikd volume backup-header NAME FILE` writes the LUKS header only and
  refuses to overwrite an existing file; the backup contains the wrapped
  key and is therefore passphrase-protected but sensitive.
  `kryptikd volume restore-header NAME FILE` puts one back.
  `kryptikd volume status NAME` reports the volume's state.
- Wrong passphrase: `cryptsetup` exit 2 -> kryptikd prints
  `zone "work": volume did not unlock (wrong passphrase)` and the zone does
  not start. No retry loop inside kryptikd (the UI does that).
- Crash recovery: if a mapping `kryptik-zone-<zone>` already exists when a zone
  starts, the start is refused with a message naming the mapping and
  pointing at `kryptikd gc`. `kryptikd gc` unmounts and closes every
  `/dev/mapper/kryptik-zone-*` whose zone has no running launcher. An unclean
  ext4 gets `e2fsck -p` at the next open; if `e2fsck` wants manual
  intervention the zone refuses to start and names the device.

## Invariants and tests (VM, root, throwaway volume files or virtual disks)

| invariant | test | positive control |
| --- | --- | --- |
| unlock/start | `kryptikd run work --passphrase-file /run/dev-pass` -> `$HOME` writable, file persists across a stop/start | — |
| wrong key | wrong passphrase -> exit 1, message names the zone, **no** `/dev/mapper/kryptik-zone-work`, no mount, command did not run | unlock/start |
| locked data is unreachable | while `work` is stopped: `ls /dev/mapper/` has no `kryptik-work`; `mount` has no `zones/work`; the raw container has no ext4 signature (`blkid` shows `crypto_LUKS`); a byte pattern written while running is not found by `grep -a` over the raw container | the pattern *is* found on the plaintext mount while running |
| stop closes | after normal exit: dm device gone, mount gone | — |
| crash | `kill -9` kryptikd while `work` runs -> within 2 s no zone process; the next start is refused while the mapping exists, and `kryptikd gc` tears the mount and dm device down; the file written before the crash is intact after unlocking again | — |
| escape check | a zone process cannot see the container, `/dev/mapper` or `/dev/dm-*` (`ls`), cannot `open` them by path (ENOENT), and `mknod` of the dm major is refused (Landlock) | `/dev/null` opens |
| key change | `volume passwd`; the old passphrase fails, the new one unlocks | — |
| header backup/restore | back up, `dd` zeros over the header, restore, the volume unlocks with its data intact | — |
| double format refused | `volume init` on a container or device that already has a signature | on a zeroed device it works |
| vault exclusivity | with `vault` stopped, `kryptik-vault` absent regardless of other zones running | unlock/start for vault |
| ephemeral vs encrypted | a zone file with both `storage.volume` and `storage.size` is refused | — |

"Secure key erasure" is **not** a row above because nothing here can
demonstrate it, and no report may claim it.

The installed-system guest checks (`build/guest-tests/zones-check.sh`)
cover most of these rows on the real image: `volume init`, an encrypted
zone starting on its volume, the mapping present while it runs and gone
after stop, nothing mounted after stop, the wrong passphrase refused with no
mapping left, data surviving stop and restart, a second concurrent start
refused, `ENOSPC` inside a full volume with the zone and its data
surviving, a volume with both headers zeroed refusing to open and the
restored header opening it with data intact, the volume directory and
other zones' homes invisible from `untrusted`, and no passphrase in
`/run/kryptik` or in any process's command line.

## Kernel and base requirements

`DM_CRYPT=y`, `CRYPTO_XTS=y`, `CRYPTO_AES=y` (with `CRYPTO_AES_NI_INTEL`)
and `BLK_DEV_LOOP=y` for file-backed containers. Argon2 is userspace
(libargon2 via cryptsetup), not a kernel option. Base system: `cryptsetup`,
`e2fsprogs`, `util-linux` (`blkid`, `losetup`).

## Files

`volume.rs` (wraps `cryptsetup`, `e2fsck`, `mkfs.ext4`, `mount` and
`umount` via `Command` with a fixed argv, no shell), `spawn.rs` (open before
fork, close after wait, both only for `Encrypted`), `main.rs` (`volume`
subcommands, `gc`, `--passphrase-fd`, `--passphrase-file`), `serve.rs` (the
passphrase descriptor from the launch request), the launcher suite in
`compartments/tests/launcher.sh` (an encrypted fixture created with
`volume init`), and `build/guest-tests/zones-check.sh`.
