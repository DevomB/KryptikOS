# Encrypted volumes

A persistent zone can keep its data in a LUKS2 volume of its own, as the
shipped `dev`, `personal`, `vault` and `work` zones do. Zone 0 opens the
volume before the zone exists and closes it after the zone is gone. Builds on
[privileged launch](privileged-launch.md); the state partition's encryption
is [separate](state-encryption.md).

## Ownership

- **Zone 0 owns the container and the mapping.** `storage.volume` names a
  LUKS2 file under `/var/lib/kryptik/volumes/` (`<zone>.luks`) or a block
  device. kryptikd (root) opens it as `/dev/mapper/kryptik-<zone>`
  (`cryptsetup open --type luks2`), runs `e2fsck -p` (damage it cannot repair
  refuses the launch), and mounts the ext4 `nosuid,nodev,noatime` at the
  zone's data directory, owned by the zone's identity; exec stays allowed,
  since `dev` runs what it builds. The zone sees it at `/home/<zone>` and
  never sees the container, the mapping or a loop device: nothing in its
  `/dev` names one, and all its mounts are `nodev`.
- **Only a root launch opens a volume.** An unprivileged launch of an
  encrypted zone is refused, with or without `KRYPTIK_EXPERIMENTAL`, rather
  than run on a plain directory.
- **Unlock happens in zone 0.** `kryptik-launch --ask` collects the
  passphrase on the terminal or in a trusted window (`kryptik-chrome
  --prompt`) and hands it to the launch daemon as a memfd over `SCM_RIGHTS`;
  the launcher gets `--passphrase-fd N`. It is never on a command line or in
  the environment. For tests, `--passphrase-file` must be a non-empty regular
  file of at most 4096 bytes, owned by root or the caller, with no group or
  other bits. kryptikd passes the passphrase to `cryptsetup` on stdin and
  zeroes its buffer with `explicit_bzero`; nothing more is claimed: the
  buffer is not `mlock`ed, and keys are in RAM while zones run
  ([threat model](../threat-model.md)).
- **Close happens after the zone is gone.** After `waitpid` on the
  intermediate, kryptikd unmounts the data directory, retrying for up to 3 s
  because the zone's mount namespace is released asynchronously, then runs
  `cryptsetup close`. A mount still busy after that means a process escaped:
  an invariant failure, never forced with `MNT_DETACH`. dm-crypt frees the key
  in kernel memory on close; that is all "keys wiped on stop" means. A
  launch that fails after the volume was opened closes it on the way out.
- **`vault`'s volume is open only while `vault` runs.** Otherwise its
  plaintext is mounted nowhere and its dm device does not exist, whatever
  else runs; no zone can reach zone 0's mounts.

## Keys and commands

Each volume has its own random volume key (`luksFormat --type luks2 --pbkdf
argon2id`, cryptsetup's default 512-bit aes-xts-plain64 key) with the user's
passphrase in keyslot 0. Nothing is derived across zones. Whether zones share
a passphrase is a UX choice; kryptikd works either way.

- `kryptikd volume init NAME [--size 512M] --passphrase-file F` creates a
  sparse 0600 file of at least 32 MiB in a 0700 directory, or uses an empty
  block device, refusing anything with a signature (`blkid -p`); it formats,
  runs `mkfs.ext4 -E root_owner=<uid>:<gid>` and closes. The installer
  creates no zone volumes.
- `volume passwd` runs `cryptsetup luksChangeKey` with both passphrases in
  memfds. `volume backup-header NAME FILE` writes the header only and never
  over an existing file; the backup holds the wrapped key, so it is sensitive.
  `restore-header` and `status` complete the set.
- A wrong passphrase (`cryptsetup` exit 2) prints `zone "work": volume did not
  unlock (wrong passphrase)` and the zone does not start; the UI retries, not
  kryptikd.
- If `kryptik-<zone>` already exists at start, the start is refused and
  points at `kryptikd gc`, which unmounts and closes every
  `/dev/mapper/kryptik-*` whose zone has no running launcher.

Secure erasure of keys is not claimed: nothing here can demonstrate it.

## Tests

`volume.rs` unit tests cover the passphrase rules and, as root, a full
lifecycle. The launcher suite checks that an encrypted zone never runs
without its passphrase, even with `KRYPTIK_EXPERIMENTAL=1`, and as root that
a `volume init` fixture runs on its mapping, which is closed on exit.
`build/guest-tests/zones-check.sh` checks on the installed system the
mapping's lifetime, a wrong passphrase, persistence, a refused concurrent
start, `ENOSPC` in a full volume, header backup and restore, that `untrusted`
sees no volume or other home, and that no passphrase reaches the registry or
a command line; the update suite checks that a volume survives an update. No
suite covers `volume passwd`, the crash-and-`gc` path, or a byte search over
a locked container.

## Kernel and base requirements

`DM_CRYPT`, `CRYPTO_XTS`, `CRYPTO_AES` (with `CRYPTO_AES_NI_INTEL`) and
`BLK_DEV_LOOP` built in; Argon2 comes from cryptsetup's libargon2.
`cryptsetup`, `e2fsprogs` and `util-linux` in the base system.

## Files

`volume.rs` (fixed-argv calls to `cryptsetup`, `e2fsck`, `mkfs.ext4`,
`mount`, `umount`; no shell), `spawn.rs` (open before fork, close after
wait), `main.rs` (`volume`, `gc`, the passphrase options), `serve.rs`,
`tools/desktop/kryptik-launch.c`, `tools/desktop/kryptik-chrome`.
