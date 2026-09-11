# Design 04 — Encrypted persistent zones: LUKS2 volumes and key lifecycle (M4)

Status: security design for Opus. Depends on Designs 01, 02. Disposable
virtual disks only (`-drive file=...,if=virtio` of a file created per test
run); never a real device.

## Ownership

- **The block device and the dm mapping belong to zone 0.** kryptikd (root)
  opens `/dev/kryptik/<zone>` (a partition or LV on the VM's second disk;
  for tests, a 64 MiB file attached as `/dev/vdb` with one LUKS2 volume per
  zone in a GPT table) with `cryptsetup open --type luks2` to
  `/dev/mapper/kryptik-<zone>`, `fsck`s, and mounts it `ext4,nosuid,nodev,
  noexec?` — **no**: exec must stay allowed on the home (dev/untrusted run
  what they build) — `nosuid,nodev` at `/var/lib/kryptik/zones/<zone>`,
  owned `N:N` (Design 01). The zone then receives it exactly as today,
  bound at `/home/<zone>` through the descriptor. The zone never sees a
  block device or a dm node: nothing under its `/dev` names one, and
  `nodev` is on every mount it has.
- **Unlock happens in zone 0, before the zone exists.** The passphrase is
  read by kryptikd from the trusted UI (M5) or, for now, from a root-only
  0600 file named on the command line (`--passphrase-file`), which is a
  development mechanism and says so on stderr every time it is used. The
  passphrase buffer is `mlock`ed and zeroed after `cryptsetup` returns
  (`explicit_bzero` semantics via `libc::explicit_bzero`). That is the whole
  claim about userspace key hygiene; nothing about RAM after that is
  claimed (threat model L3).
- **Close happens after the zone is gone.** Order: `waitpid` on the
  intermediate (pid namespace dead, mount namespace released) ->
  `umount /var/lib/kryptik/zones/<zone>` (must succeed; `EBUSY` means a
  process escaped, which is an invariant failure, not something to retry
  with `MNT_DETACH`) -> `cryptsetup close kryptik-<zone>`. dm-crypt frees
  the key in kernel memory on close; that is what "keys wiped on stop"
  means in the zone file, and the handoff must say it means *that* and not
  a memory-scrubbing guarantee.
- **The vault is exclusive.** `vault`'s volume is opened only while `vault`
  runs; kryptikd refuses to start `vault` while any zone that can talk to a
  broker is running? No — that is too restrictive for a daily driver.
  The invariant that matters is narrower and testable: while `vault` is
  **not** running, its plaintext is not mounted anywhere and its dm device
  does not exist. Other zones running is irrelevant to that because they
  cannot reach zone 0's mounts at all (pivot_root). Keep it simple.

## Key lifecycle

- One LUKS2 volume per zone, its own random 512-bit volume key (created by
  `cryptsetup luksFormat --type luks2 --pbkdf argon2id`), keyslot 0 = the
  user's passphrase. No key derivation across zones; a compromised
  passphrase for `untrusted` says nothing about `vault`. (Per-zone
  passphrases are a UX decision for later; the mechanism supports one
  passphrase in every volume's slot 0 *or* different ones — kryptikd does
  not care.)
- `kryptikd volume init <zone> --device /dev/kryptik/<zone>` formats (refuses
  a device with any existing signature: `blkid` non-empty -> refuse), opens,
  `mkfs.ext4 -E root_owner=N:N`, closes. Development only; on a product this
  is the installer's job.
- `kryptikd volume passwd <zone>` = `cryptsetup luksChangeKey`. Header
  backup: `kryptikd volume backup-header <zone> <file>` writes the LUKS
  header only; documented as containing the wrapped key and therefore
  passphrase-protected but sensitive.
- Wrong passphrase: `cryptsetup` exit 2 -> kryptikd prints
  `zone "work": volume did not unlock (wrong passphrase)` and the zone does
  not start. No retry loop inside kryptikd (the UI does that).
- Crash recovery: on start (and in `kryptikd gc`, Design 02), for every
  `/dev/mapper/kryptik-*` that exists: if its zone has no live registry
  entry, `umount` its mount point if mounted, `cryptsetup close`. An
  unclean ext4 gets `fsck -p` at the next open; if `fsck` wants manual
  intervention the zone refuses to start and names the device.

## Invariants and tests (VM, root, `/dev/vdb` = throwaway 256 MiB file)

| id | invariant | test | positive control |
|---|---|---|---|
| V1 | unlock/start | `kryptikd run work --passphrase-file /run/dev-pass` -> `$HOME` writable, file persists across a stop/start | — |
| V2 | wrong key | wrong passphrase -> exit 1, message names the zone, **no** `/dev/mapper/kryptik-work`, no mount, command did not run | V1 |
| V3 | locked data is unreachable | while `work` is stopped: `ls /dev/mapper/` has no `kryptik-work`; `mount` has no `zones/work`; raw `/dev/vdb2` has no ext4 signature (`blkid` shows `crypto_LUKS`); a byte pattern written in V1 is not found by `grep -a` over the raw device | the pattern *is* found on the plaintext mount while running |
| V4 | stop closes | after normal exit: dm device gone, mount gone | — |
| V5 | crash | `kill -9` kryptikd while `work` runs -> within 2 s no zone process; the mount and dm device are torn down by the *next* `kryptikd run` or `gc` (record which); the file written before the crash is intact after V1 again | — |
| V6 | escape check | a zone process cannot see `/dev/vdb*`, `/dev/mapper`, `/dev/dm-*` (`ls`), cannot `open` them by path (ENOENT), and `mknod` of the dm major is refused (Landlock) | `/dev/null` opens |
| V7 | key change | `volume passwd`; old passphrase fails (V2), new one works (V1) | — |
| V8 | header backup/restore | back up, `dd` zeros over the header, restore, V1 works | — |
| V9 | double format refused | `volume init` on a device that already has a signature | on a zeroed device it works |
| V10 | vault exclusivity | with `vault` stopped, `kryptik-vault` absent regardless of other zones running | V1 for vault |
| V11 | ephemeral vs encrypted | a zone file with both `storage.volume` and `storage.size` is refused | — |

"Secure key erasure" is **not** a row above because nothing here can
demonstrate it. The morning report must not say it.

## Kernel and base requirements

`DM_CRYPT=y` (present), `CRYPTO_XTS`, `CRYPTO_AES` (arch default, verify),
`CRYPTO_ARGON2`? — no, argon2 is userspace (libargon2 via cryptsetup). Base
system: `cryptsetup`, `e2fsprogs`, `util-linux` (`blkid`, `losetup`).
`CONFIG_BLK_DEV_LOOP=y` for host-side tests without a second disk.

## Files

New `volume.rs` (wraps `cryptsetup` via `Command` with a fixed argv, no
shell), `spawn.rs` (open before fork, close after wait, both only for
`Encrypted`), `main.rs` (`volume` subcommands, `--passphrase-file`),
`launcher.sh` group V, `tools/vm/run-qemu.sh` (`--disk FILE` option that
creates the file if absent).
