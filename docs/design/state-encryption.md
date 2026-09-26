# Encrypted state partition

`kryptik-state` holds `/var`, the upper layer of `/etc` (with the shadow
file), `/home`, root's home, the Wi-Fi passphrases, the logs, update staging
and the zone volumes' LUKS headers. It is a LUKS2 container
(`aes-xts-plain64`, 512-bit key, argon2id) with ext4 inside, opened as
`/dev/mapper/kryptik-state`, so a stolen laptop or pulled disk gives none of
that up. The verified root needs no encryption: it is public, identical on
every machine, and verified. It uses the dm-crypt and XTS support the
[zone volumes](encrypted-volumes.md) already need. Builds on
[boot and updates](boot-and-updates.md).

## How it works

- **The installer creates it**, asking for the passphrase twice before its
  first write; an unattended test install takes it from the control disk
  (`state_passphrase=`, piped in by `installer-run.sh`), the only place one is
  ever written down. It reaches cryptsetup on stdin, never on a command line
  or in a file on the target.
- **`sysinit` opens it** once it has chosen the state partition on the root's
  own disk (`devices.sh`: a label is not an identity), asking on the console
  three times at most. It uses its own prompt (echo off with `stty`, the line
  passed to cryptsetup on a descriptor) because cryptsetup's prompt discards
  input typed as it appears. `kryptik-console`, the early getty, leaves the
  console to `sysinit` until it finishes, waiting at most 30 s for it to start.
- **Anything else is the degraded state**: three wrong passphrases, a damaged
  header, a missing partition, or a plain filesystem in its place (refused,
  since an unencrypted partition swapped in would otherwise be believed).
  `/var` is then a tmpfs, `/run/kryptik/state-degraded` says why, the console
  says so, and first boot, the session and the updater refuse to run. Repair
  is from the install medium.
- **The header is the state.** `kryptik-recover --backup-state-header FILE`
  and `--restore-state-header FILE` run from the medium, and the installer
  warns that a lost header or passphrase is a lost partition: there is no
  escrow and no back door.
- `kryptik state passphrase` (root) runs `cryptsetup luksChangeKey`, which asks
  for the old and new passphrases on the terminal.

## What it gives

Confidentiality against an offline reader, but not authentication: XTS lets an
offline writer corrupt a block, though not choose what it decrypts to. So
nothing deciding privilege is read from `/etc`'s upper layer without the
allow-list (`prune_etc_upper` in `sysinit.sh`); encryption adds to that
boundary rather than replacing it. Zone volumes are encrypted twice, and that
stays: the inner layer protects a stopped zone's data from zone 0 and the
other zones. It does not protect a running, unlocked machine, and the ESP, the
root slots and the LUKS header show that the machine runs Kryptik.

## Decisions

- **A passphrase at every boot.** The machine asks before it has any state,
  so the secret cannot be the login password (the shadow file is inside).
  Unlocking from the TPM against a measured boot is for version 2.
- **Authenticated encryption later.** dm-integrity under dm-crypt
  (`--integrity hmac-sha256`) would make a modified block an I/O error, at the
  cost of a journal (roughly a third of a laptop SSD's write throughput),
  about 10% of the partition, a much slower first format and
  `CONFIG_DM_INTEGRITY`, so it waits for that cost to be measured on real
  hardware.
- **A plain state partition is not converted**: it boots degraded, and that
  installation is reinstalled after its data is copied off. None exists
  outside test machines, and a converter would run once, on the partition
  holding everything, untested. Offered an update, its trial comes up
  degraded, is not committed and falls back with its data untouched
  (`boot-success.sh` knows the trial from the ESP), and the updater refuses
  that release as a failed trial.
- **The unattended tests answer the prompt on the serial console**, as a user
  would: an installed system ignores the control disk (`testctl.sh`), and a
  key on an attached disk would be a second unlock path only tests use.
  `vm-drive.py` answers it at every boot from `KRYPTIK_STATE_PASSPHRASE`, also
  under `run-ovmf.sh`'s smoke mode.

## Tests

- `install-test.sh`: partition 4 has a LUKS header and no ext4 superblock in
  the clear; a marker written under `/home` is not in the raw partition; the
  passphrase is on no command line, nowhere under `/run` or `/etc`, and not in
  the console transcript.
- `state-test.sh`: both header copies zeroed from the host give the degraded
  state and the restored bytes bring it back; three wrong passphrases give it
  after exactly three prompts, and the right one restores everything.
- `integrity-test.sh` plants its `/etc` entries through the mapping opened on
  the host (`suite-lib.sh`), and they are still quarantined.
- `update-test.sh` and `zones-test.sh` answer the prompt at each boot.
- Not covered yet: `kryptik state passphrase` and `kryptik-recover`'s header
  commands.

## Files

`tools/install/kryptik-install.sh`, `build/service-scripts/installer-run.sh`,
`sysinit.sh`, `devices.sh`, `boot-success.sh`, `kryptik-console` (from stage
04), `tools/update/kryptik-recover`, `tools/kryptik`, `tools/image/*-test.sh`,
`suite-lib.sh`, `vm-drive.py`, `run-ovmf.sh`, and the
[user guide](../user-guide.md).
