# Authenticated encryption for the state partition

**A proposal, waiting for the owner's decision.** Nothing here is built.
[State encryption](state-encryption.md) leaves this for later: dm-integrity
under dm-crypt would make a modified block an I/O error, "so it waits for
that cost to be measured on real hardware". This note sets out:

- what an offline writer can do to the partition today;
- what dm-integrity would and would not change;
- the choices, and their cost from the tree;
- what the suites would need;
- a recommendation, and two sentences that need correcting either way.

On the owner's word the decision becomes an ADR in
[decisions](../decisions.md), numbered then.

## The partition today

`kryptik-install` formats the fourth partition, the rest of the disk after the
ESP and both slots (`tools/install/kryptik-install.sh:295-302`), with:

```sh
cryptsetup -q luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf argon2id --key-file=- "$P4"
```

That is `:328-329`, with ext4 inside (`:333`). It runs with no `--integrity`
and no `--sector-size`. `sysinit` opens it with no other flags
(`build/service-scripts/sysinit.sh:47`) and mounts it on `/var`. No discards
are sent anywhere in the tree.

Everything persistent is on it:

- `/home` and the `/etc` upper layer, which `prune_etc_upper` holds to a list
  on the verified root;
- the shadow file and the Wi-Fi passphrases;
- the zone volumes, LUKS2 again inside (`compartments/kryptikd/src/volume.rs:329-335`);
- the update channel's state, with the newest accepted statement in
  `/var/lib/kryptik/update/pointer`;
- the trial records in `/var/lib/kryptik/boot`;
- the release the clock's floor keeps, in `/var/lib/kryptik/time/release/`.

## What an offline writer can do

XTS keeps every byte secret from a reader, and authenticates nothing.
Someone holding the disk can do two things to it.

- **Damage a block.** Any change to the ciphertext turns the 16 bytes of
  plaintext it falls in to noise, and the rest of the sector is left as it
  was. Nothing notices unless ext4's metadata checksums cover that block
  (e2fsprogs 1.47.1 makes them by default). File contents have no checksum,
  so whatever reads the file reads the noise.
- **Put a sector back as it was.** With an earlier copy of the disk, from an
  earlier visit or a backup image, a sector's earlier ciphertext written back
  decrypts to its earlier contents, and nothing notices that either. This
  reaches, sector by sector:
  - the newest accepted statement, so an older one is taken again;
  - `trial.failed`, so a failed trial looks untried;
  - the clock floor's release;
  - a zone volume's LUKS2 keyslots, so a zone passphrase the user changed
    opens it again;
  - the shadow file, so an old login password works again.

So a writer cannot choose new contents for a block, but one with an earlier
copy chooses among the block's earlier contents.

The partition's own LUKS2 header is outside all this: it is in the clear, and
an earlier header brings back an earlier passphrase whatever the data layer
does.

## What dm-integrity changes, and what it does not

LUKS2's authenticated mode puts a dm-integrity device under dm-crypt. It
keeps a tag for every sector, computed over the sector's ciphertext and its
number.

- **A damaged block reads as an I/O error, never as noise.** ext4 reports it.
  If it hits ext4's superblock or journal, the mount fails and the machine
  boots degraded, as for any unmountable state today (`sysinit.sh:146-150`).
  The drive's own silent corruption is caught the same way.
- **A sector put back as it was still passes.** The tag is put back with it,
  and the key and the sector number have not changed. So is a whole
  partition replaced by an earlier image of itself. Freshness needs a record
  the disk cannot carry: a TPM counter, the territory of ADR-017 and of the
  [rollback floor](rollback-floor.md) proposal, not of dm-integrity.
- **The LUKS2 header is not covered.**

So dm-integrity closes damage, not replay. The parsers that read `/var` as
root then see errors instead of noise. Today they already have to treat
what they read as possibly damaged, and the `/etc` allow-list exists for
that reason.

## The choices

- **`--cipher aes-xts-plain64 --integrity hmac-sha256`.** XTS as today, plus
  an HMAC-SHA256 tag of 32 bytes a sector. It has no nonce to run out of, and
  its two keys share the one keyslot. Per byte, the HMAC costs far more CPU
  than XTS with AES-NI. This is the mode `state-encryption.md` names.
- **`--cipher aegis128-random --integrity aead`.** One authenticated pass,
  fast with AES-NI. Its tag is 32 bytes a sector (a 16-byte nonce and a
  16-byte tag). It needs `CRYPTO_AEGIS128` and its AES-NI variant, which no
  fragment sets.
- **`--cipher aes-gcm-random --integrity aead`.** 28 bytes a sector. A random
  96-bit nonce per sector write limits how much one key may write, a poor fit
  for a disk that lives for years.

cryptsetup 2.8 marks all of these "EXPERIMENTAL" (`cryptsetup-luksFormat(8)`,
`--integrity`). It also offers no discards in this mode, which costs Kryptik
nothing it has today.

Two settings go with any of them:

- **`--sector-size 4096`.** A tag then costs 32 of every 4096 bytes, 0.8%,
  instead of 32 of every 512, 6.25%. ext4 already uses 4096-byte blocks.
  Without the flag, cryptsetup chooses from what the drive reports.
- **The journal stays on.** dm-integrity writes a sector and its tag
  atomically by journaling both. `--integrity-no-journal` would leave a sector
  torn by a power loss reading as an I/O error. The softdog reset that
  state-test triggers is such a cut.

## What it costs, from the tree

**Kernel.**
- `CONFIG_DM_INTEGRITY`, absent from every fragment today. Under ADR-013 it
  is a module: the state partition is not the root.
- It is signed like every module (`build/config/kernel/hardening.fragment:34-37`).
- `sysinit` loads it before `unlock_state`, since `STATIC_USERMODEHELPER`
  leaves the kernel no helper to load it by itself (`hardening.fragment:31`).
- It selects `BLK_DEV_INTEGRITY`, built in and small, and `DM_BUFIO`, which
  dm-verity already brings.
- The bzImage has 1,099,418 bytes of headroom under its budget (23,087,770
  against the measured 21,988,352, `build/config/kernel/size-budget`). A
  module stays outside it.
- `hmac(sha256)` needs `CRYPTO_HMAC`. defconfig's IPsec options probably
  build it in already, beside the `CRYPTO_SHA256` that `boot.fragment` sets;
  the build's own `.config` (`/proc/config.gz` on the image) settles it.
- cryptsetup checks the composed mode through the kernel's crypto user API.
  `boot.fragment` sets the skcipher and hash interfaces, and the AEAD one,
  `CRYPTO_USER_API_AEAD`, would join them.

**Image.** Nothing new. cryptsetup 2.8.8 with the OpenSSL backend
(`build/recipes/cryptsetup.sh:6-7`) formats and opens the stack itself.
`integritysetup` is built by default and is not needed.

**Install.**
- `luksFormat` gains `--integrity hmac-sha256 --sector-size 4096`.
- It then writes the whole partition once, so that every sector has a valid
  tag before anything reads it. `--integrity-no-wipe` would skip that, and
  leave unwritten sectors failing their reads, which page-cache readahead
  trips over.
- So an install takes one more sequential write of most of the disk:
  minutes on an NVMe drive, longer on SATA, an hour or more on a spinning
  disk.
- The installer would say so before it starts, and show cryptsetup's
  progress.

**Space.** The tags take 0.8% with 4096-byte sectors. The journal takes 1/128
of the partition, at most 64 MiB (`drivers/md/dm-integrity.c`: `journal_sectors =
min(DEFAULT_MAX_JOURNAL_SECTORS, data_device_sectors >> DEFAULT_JOURNAL_SIZE_FACTOR)`
in 6.18). The "about 10%" in `state-encryption.md` is the 512-byte figure.

**Writes and reads.**
- Every sector is written twice, once to the journal and once in place, with
  its tag area, so sustained writes run at roughly half the drive's speed or
  less. `state-encryption.md` puts it at "roughly a third of a laptop SSD's
  write throughput".
- Every read checks a tag, with HMAC-SHA256 on the CPU.
- Nobody has measured either on the machines Kryptik targets.

**Existing machines.** None converts in place. This is the rule
`state-encryption.md:64-70` already keeps for a plain partition. A machine
gets it at its next install, after its data is copied off.

**Header backup.** `kryptik-recover --backup-state-header` copies the LUKS2
header (`tools/update/kryptik-recover:79-88`). The dm-integrity superblock
sits at the start of the data area, outside that copy. Whether a damaged one
has to be restored too, or whether the kernel formats it anew around tags
that are still valid, is one of the things the trial has to settle.

**Zone volumes.** They stay as they are. Their sectors are the outer layer's,
so the outer tags already cover them, and integrity inside as well would pay
the cost twice.

## What the suites would need

- **A check that fails on the old code.**
  1. After an install, change one byte of the state partition's data area
     from the host.
  2. Boot, and read the opened device in the guest
     (`dd if=/dev/mapper/kryptik-state of=/dev/null`).
  3. Expect an I/O error and the kernel's integrity checksum message. On XTS
     today the read succeeds.
  4. Put the byte back.
- **The install suite** sees the integrity segment in `cryptsetup luksDump`.
- **The state suite** keeps its degraded cases (header zeroed, wrong
  passphrase, missing label). It adds that a watchdog reset during writes
  comes back with no integrity error, which is the journal's job.
- **Header backup and restore** (integrity-test step 6, and the typed backup
  in medium-shell-test) stay as they are, unless the superblock question
  says otherwise.
- **CI time.** Every install in every VM suite pays one full write of its
  state partition. Test disks are sized by `tools/image/test-disk-size.sh`,
  up to about 17.5 GiB with payloads (its example, `17536M`). Suites that
  stage nothing could use the installer's minimum, the image plus 1152 MiB.

## Proposed decision

- Not for 1.0. The writes cost about half the drive's speed, and the install
  takes one more full write of most of the disk. cryptsetup calls the mode
  experimental. What it adds, errors instead of noise, matters less than the
  replay it leaves open.
- Measure it when Kryptik is tested on physical hardware:
  - sustained write throughput with and without `--integrity hmac-sha256
    --sector-size 4096`;
  - the install's added wipe time.

  Then adopt it for new installs if the writes keep at least half their speed
  and the wipe fits a stated time, with the check above.
- Treat freshness as its own problem, solved with the TPM, not with
  dm-integrity.
