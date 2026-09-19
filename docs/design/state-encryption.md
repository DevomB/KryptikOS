# The state partition, encrypted

Status: design. Nothing here is built. It is the "state partition is
encrypted" item of [version 1.0](../roadmap.md#version-10), written down
before the code because three of its choices are a person's to make (they
are marked **Decision**). Builds on
[boot, slots and updates](boot-and-updates.md) and
[encrypted volumes](encrypted-volumes.md).

## What is wrong today

`kryptik-state` is plain ext4 (`tools/install/kryptik-install.sh`,
`mkfs.ext4 -L kryptik-state`). It holds `/var`, the upper layer of `/etc`,
`/home` and root's home. So a laptop that is stolen, or a disk that is
pulled, gives up zone 0's home directory, the Wi-Fi passphrases
(`/var/lib/kryptik/wifi/`), the shadow file, the zone registry, the logs,
and the LUKS headers of every zone volume to attack at leisure. The zone
volumes themselves are encrypted; everything around them is not.

The root needs no such protection: it is public, identical on every
machine, and verified.

## What is built

- **LUKS2 on the partition**, `aes-xts-plain64` with a 512-bit key and
  argon2id, the ext4 inside it unchanged. The kernel already carries
  dm-crypt and XTS (they open the zone volumes), and the image already
  carries cryptsetup. The mapping is `/dev/mapper/kryptik-state`.
- **The installer creates it.** It asks for the passphrase twice on the
  console; an unattended install takes it from the control disk's preseed
  like the user and root hashes, which is the only place a passphrase is
  ever written down and exists for the tests. It reaches cryptsetup on a
  file descriptor (`--key-file=-`), never on a command line and never in a
  file on the target.
- **`sysinit` opens it**, where it mounts the partition today: after it has
  decided which partition on the root's own disk is this installation's
  state (`devices.sh`; a label is not an identity, and that rule does not
  change), it asks on the console, three times at most, and opens the
  mapping. Everything after that line is what it is now.
- **A failed unlock is the degraded state that already exists.** Three wrong
  passphrases, a damaged header or a missing mapping land where a missing
  partition lands today: `/var` is a tmpfs, `/run/kryptik/state-degraded`
  says why, first boot, the session and the updater refuse, the console
  says so in a box. Nothing new to reason about, and a machine that cannot
  be unlocked can still be logged into and repaired from the medium.
- **The header is the state.** `kryptik-recover --backup-state-header FILE`
  and `--restore-state-header FILE` from the install medium, and the
  installer says at the end that a lost header or a forgotten passphrase is
  a lost state partition: there is no escrow and no back door.
- **The passphrase can be changed** (`kryptik state passphrase`, zone 0,
  root): `cryptsetup luksChangeKey` on a descriptor, the old one asked first.

## What it does and does not give

Confidentiality against an offline reader: yes. Authentication: **no**. XTS
lets an offline writer corrupt a block but not choose what it decrypts to,
which is far less than they can do today, and is still not nothing. So the
rule that nothing deciding privilege is read from `/etc`'s upper layer
without the allow-list (`sysinit.sh`, `prune_etc_upper`) stays exactly as it
is. Encryption is added to that boundary; it does not replace it.

A zone volume inside the state partition is encrypted twice. That is kept:
the inner layer protects a stopped zone's data from zone 0's own processes
and from the other zones, which the outer layer does not.

It does not protect a running, unlocked machine, and it does not hide that
the machine runs Kryptik: the ESP, both root slots and the LUKS header are
in the clear by design.

## The decisions

**Decision 1: a passphrase at every boot.** This is what 1.0 can honestly
offer: the machine asks before it has any state, so the secret cannot be
the login password (the shadow file is inside). The alternative, unlocking
from the TPM against a measured boot with the passphrase as the fallback,
is in version 2 and needs measured boot first. *Recommended: yes, a separate
disk passphrase, asked once per boot on the console.*

**Decision 2: authenticated encryption now or later.** LUKS2 can put
dm-integrity under dm-crypt (`--integrity hmac-sha256`), which turns the
"no" above into a "yes": a modified block is an I/O error, not garbage. It
costs a journal (roughly a third of write throughput on a laptop SSD),
about 10% of the partition, a much slower first format, and
`CONFIG_DM_INTEGRITY` in the kernel. *Recommended: not in 1.0. Ship
confidentiality with the allow-list, measure the cost on real hardware once
there is some, and decide with numbers.*

**Decision 3: what the unattended tests do.** An installed system ignores
the control disk on purpose (`testctl.sh`), so nothing can hand it a
passphrase; the suites reach it through the serial console. They will
answer the prompt there, as a person would, which means every suite that
boots an installed disk gains one `expect`/`send` pair and the prompt's
text becomes part of what the suites depend on. The alternative, a key on
an attached disk, is a second unlock path that exists only to be tested.
*Recommended: the serial console, one path.*

## What proves it

- install-test: the fourth partition carries a LUKS2 header and no ext4
  superblock; a marker written into `/home` is not found by reading the raw
  partition from the host.
- state-test: three wrong passphrases give the degraded state, by name, and
  the right one at the next boot gives everything back; a header damaged
  from the host gives the degraded state; a restored header backup brings it
  back.
- integrity-test: its planted `/etc` entries now go in through a mapping
  opened on the host with the test's passphrase, and are still quarantined.
  The allow-list is tested behind the encryption, not instead of it.
- update-test and zones-test: unchanged in what they assert, with the prompt
  answered at each boot.
- A guest check that the passphrase is on no command line and in no file:
  `/proc/*/cmdline` during the unlock, and a grep of the state partition's
  clear part (the header) and of the root for the test's passphrase.

## What it touches

`tools/install/kryptik-install.sh`, `build/service-scripts/sysinit.sh` and
`devices.sh`, `tools/update/kryptik-recover`, the `kryptik` command,
`tools/image/*-test.sh` and `vm-drive.py`, `docs/BOOT_INSTALL_RECOVER.md`.
No kernel change for the recommended answers.
