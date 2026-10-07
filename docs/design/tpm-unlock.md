# Disk unlock by the TPM

The state partition asks for its passphrase at every boot, and the
[state encryption design](state-encryption.md#decisions) leaves unlocking
from the TPM against a measured boot to Version 2. This document decides
what the TPM measures in a boot chain with no initramfs (ADR-014), what the
state partition's key is sealed to, how that survives A/B updates when every
new kernel measures differently, how the passphrase stays the fallback, and
how swtpm under QEMU tests it. The proposed decision is ADR-017 in
[decisions](../decisions.md); it changes the threat model, and the proposed
text is below.

## Where things stand

- **The boot chain.** The firmware verifies Kryptik's signed kernel and runs
  it as the EFI application. The command line is compiled in and carries the
  root slot and its dm-verity root hash, and dm-init builds the verified root
  with no initramfs ([boot and updates](boot-and-updates.md)).
- **The unlock.** `sysinit` finds `kryptik-state` on the root's own disk and
  asks for its passphrase up to three times on every console (`ask.sh`),
  handing each answer to `cryptsetup open` on stdin
  (`build/service-scripts/sysinit.sh`, `unlock_state`). Anything else is the
  degraded state. The partition is LUKS2 with the passphrase in keyslot 0;
  `kryptik state passphrase` changes it.
- **The kernel already has the TPM.** `TCG_TPM`, `TCG_TIS`, `TCG_CRB` and
  `HW_RANDOM_TPM` are built in as an entropy source (`hardening.fragment`),
  and `sysinit` mounts securityfs, where the kernel publishes the firmware's
  event log.
- **What differs between kernels.** Every release has new kernels. The two
  slots' kernels differ even within one release, since their command lines
  name `kryptik-a` or `kryptik-b`. `BOOTX64.EFI` is a byte copy of the
  committed slot's kernel. The install medium's kernel is signed with the
  same Secure Boot key and boots a root shell.
- **Boot variables change on every trial.** `kryptik-efiboot` writes
  `Boot####` entries and `BootNext` for each trial and forgets them after.

## What gets measured

The firmware extends Platform Configuration Registers (PCRs) before it runs
anything:

| PCR | holds | changes when |
| --- | --- | --- |
| 0, 2 | firmware code, option ROMs | the firmware is updated |
| 1 | firmware settings, `BootOrder` and each `Boot####` | every trial, since `kryptik-efiboot` writes entries |
| 4 | each boot application's Authenticode digest | the kernel changes: every update, and slot a against slot b |
| 5 | the boot disk's GPT | the disk is repartitioned |
| 7 | Secure Boot's state, PK, KEK, db, dbx, and the db entry that allowed each image | a dbx or key update, or Secure Boot turned off |

The kernel's EFI stub adds to PCR 9 an initrd, of which there is none, and
any non-empty `LoadOptions`. It measures them even though
`CMDLINE_OVERRIDE` ignores them (`efi_convert_cmdline` in
`drivers/firmware/efi/libstub/efi-stub-helper.c`), so PCR 9 depends on
which boot path the firmware took.

Kryptik's command line is inside the kernel image, so PCR 4's digest of the
kernel covers the root hash: **PCR 4 names exactly which kernel and which
root booted.** That is what ADR-014's single signed object buys here, and it
needs no stub or initramfs to measure anything more.

## Constraints

- **ADR-014.** Nothing runs between the firmware and the verified root. The
  unseal runs in `sysinit`, from the verified root, after dm-verity, so the
  code that unseals is itself named by PCR 4.
- **The threat model** defends the state partition against an offline
  reader with a passphrase at every boot, and puts a running or suspended
  machine, firmware implants and the hardware out of scope
  ([threat model](../threat-model.md)).
- **No escrow and no back door**, as now.
- **The zone volumes keep their own passphrases.** Unlocking the state
  partition from the TPM opens `/var`, `/home`, the `/etc` overlay, the
  Wi-Fi passphrases and the zone volumes' headers, not the zones' data.

## Options for the binding

### PCR 7 alone

Any kernel Kryptik's certificate verified, under the same db and dbx,
unseals the key. Updates need no resealing. But the install medium's kernel
is signed by the same key and verified by the same db entry, so whoever
holds the laptop boots the medium, gets its root shell and unseals the key.
Every older Kryptik kernel, with whatever holes it had, unseals it too.
Rejected.

### PCR 4 and PCR 7, authorized by the updater

The key unseals only for an exact kernel and root (PCR 4) under Kryptik's
Secure Boot policy (PCR 7). The medium, an older release, a foreign loader
and Secure Boot turned off all fail. The cost is that each update must
authorize its kernel before the trial boot.

A sealed object's policy cannot change after it is sealed, so the policy is
indirect. The key is sealed with `PolicyAuthorizeNV`: "whatever policy is
stored in this NV index". The index holds a `PolicyOR` of `PolicyPCR`
branches, one for each kernel allowed to unseal, as systemd-pcrlock does.
The updater rewrites the index. Its write authorization is a random secret
kept on the state partition, readable by root, so only a running, unlocked
Kryptik can change which kernels unseal.

To authorize a kernel that has not booted yet, the updater replays this
boot's event log with the boot application's digest replaced by the new
kernel's Authenticode digest. The firmware is the same and so are its other
events, so the prediction holds unless the firmware measures the trial's
`BootNext` path differently from the committed boot's. A wrong prediction
costs one passphrase prompt, after which the system offers to reseal to
what it measured.

### The same, with a PIN

`PolicyAuthValue` adds a PIN. The TPM's dictionary-attack lockout limits
guessing, so a short PIN stands where a long passphrase did. There is
still a prompt at every boot, but a short one.

### A signed policy

`PolicyAuthorize` with a Kryptik key would let the release process sign each
kernel's expected PCR 4 value, with no resealing. But every kernel ever
signed would stay able to unseal unless a counter revoked it, the signing
key would be one more key in the ceremony, and a value computed at release
time cannot know each machine's firmware events. Rejected.

## How it works

### Enrolment

`kryptik state tpm enrol [--pin]` (root, on the installed system) asks for
the passphrase and then:

1. creates a random 32-byte key and adds it as a second LUKS2 keyslot;
2. defines the NV index and writes the policy for the kernel that is
   running, from this boot's own measurements;
3. seals the key under the TPM's storage root key with `PolicyAuthorizeNV`
   on that index, `PolicyPCR` on PCR 15 at its reset value, and the PIN if
   asked for;
4. stores the sealed object, the index's handle and the PCR selection as a
   LUKS2 token of type `kryptik-tpm2` in the header (`cryptsetup token
   import`), and the index's write secret under `/var/lib/kryptik/tpm/`.

It refuses without a passphrase keyslot, on a degraded state and when the
firmware wrote no event log. `kryptik state tpm remove` kills the keyslot,
removes the token and undefines the index. The installer does not enrol:
it runs from the medium, whose PCR 4 is not the installed kernel's, so
enrolment happens on the installed system once it has booted.

### Unlock

`sysinit`, before it asks anything: if the header has a `kryptik-tpm2` token
and `/dev/tpmrm0` exists, it unseals the key through a session salted with
the storage root key, so the key does not cross a discrete TPM's bus in the
clear, and hands the key to `cryptsetup open` on stdin. Any failure (no
TPM, a PCR mismatch, lockout, a damaged token) falls through to the three
passphrase prompts as now, and the console says which failure it was. Once
the state partition is open, `sysinit` extends PCR 15 with a fixed event, so
nothing later in the same boot, root or an escaped zone, can unseal the key
again.

### Updates

1. `kryptik-update apply` verifies and writes the slot as now.
2. Before it arms the trial, it rewrites the index to two branches: the
   committed kernel and the trial kernel, predicted from the event log. A
   failed write is reported, and the trial asks for the passphrase.
3. The trial boots and unseals if the prediction held.
4. `boot-success` commits and rewrites the index to the new committed kernel
   alone. An unhealthy trial falls back, and the index goes back to the
   committed kernel.
5. `kryptik-update rollback` and `kryptik-recover --commit-slot` boot a
   kernel the index does not list. It asks for the passphrase once, and then
   offers to reseal.

A firmware or dbx update changes PCR 0, 2 or 7. The next boot asks for the
passphrase and then offers to reseal; it never reseals silently, since an
unexpected change is what the prompt is for.

### Tools

tpm2-tss (its ESAPI, built without FAPI, which needs curl) and the few
tpm2-tools commands `sysinit` and the updater call. A small Rust client in
the kryptikd tree, speaking the dozen TPM2 commands this needs, would be
smaller, but it would be new code for salted sessions and policy digests,
which tpm2-tss already does and has had reviewed. Each brings sources with
signatures to pin and review ([supply chain](../supply-chain.md)).

## The passphrase stays

Keyslot 0 is never removed, enrolment refuses without it, and every failure
of the TPM path ends at the same three prompts as today. `kryptik-recover
--backup-state-header` keeps working, and the backup now includes the token,
which is useless without the machine's TPM.

## What it changes in the threat model

With TPM unlock enrolled, a stolen machine boots to its login prompt with
the state partition open and the zone volumes closed. The attacker then
faces the running system: the login, the net zone's network-facing daemons,
USB and Thunderbolt devices (the IOMMU is strict), and the TPM itself. A
discrete TPM's bus can be read, which the salted session answers. Some
firmware TPMs have had their secrets extracted by voltage glitching, as
faulTPM showed on AMD's, and nothing here answers that. So TPM unlock is
something the user enrols in, not a default. Against an attacker with hours
and hardware tools, the passphrase alone is the defence.

Proposed text for the threat model's "Offline physical access" paragraph,
to apply with the change that builds this:

> **Defended at rest against a reader, not against a writer of the state
> partition.** dm-verity and Secure Boot make a modified root or a swapped
> kernel fail to boot. The state partition is LUKS2 and opens with its
> passphrase, or, if the user enrolled the TPM, without a prompt for the
> exact kernel and root Kryptik signed and the machine last authorized, under
> Secure Boot. A machine unlocked by its TPM boots to its login prompt with
> the zone volumes still closed, and is then a running machine (below). An
> attacker who can extract the TPM's secrets reads the state partition of a
> machine enrolled without a PIN; the passphrase alone does not have that
> weakness. The zone volumes inside the state partition are encrypted again
> with their own passphrases.

## Testing with swtpm under QEMU

swtpm emulates a TPM 2.0 behind a socket, and QEMU attaches it as a CRB
device:

```text
swtpm socket --tpm2 --tpmstate dir=<state> --ctrl type=unixio,path=<sock>
qemu ... -chardev socket,id=chrtpm,path=<sock> -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0
```

OVMF measures into it. The suite checks that the firmware wrote an event
log before it believes any result, since a firmware build without TPM
support would pass every refusal for the wrong reason. swtpm joins the
Distro workflow's host packages. A new suite, `tools/image/tpm-test.sh`, run
by `make acceptance`:

1. Install, boot with the passphrase, enrol. Reboot: the state opens and the
   console transcript has no passphrase prompt.
2. Apply an update: the trial boots without a prompt and commits; the next
   boot has none either.
3. Roll back to the older slot: one prompt.
4. Boot the install medium with the installed disk attached: the unseal
   fails from its root shell.
5. Boot with Secure Boot off in the firmware's variables: a prompt.
6. Give the VM a fresh swtpm state: a prompt, and the passphrase opens the
   state.
7. With a PIN: wrong PINs until lockout, then the passphrase opens the
   state.
8. Later in a TPM-unlocked boot, root's unseal attempt fails (PCR 15).
9. A relay between QEMU and swtpm records the unseal's traffic, and the key
   is not in it.

## Recommendation

PCR 4 and PCR 7 through a policy stored in an NV index that the updater
rewrites for each trial; PCR 15 extended once the state is open; an optional
PIN; the passphrase keyslot kept for good; tpm2-tss and tpm2-tools; and
enrolment by the user on the installed system, never by default.

## The check that proves it done

The TPM suite above passes in `make acceptance`: an enrolled machine boots
and updates without a prompt, and the medium, an older slot, Secure Boot
off, a fresh TPM and a second unseal in the same boot each end at the
passphrase, which still opens the state.
