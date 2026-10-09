# A floor under downgrades by whoever holds the disk

**A proposal, waiting for the owner's decision.** Nothing here is built. It
weighs two ways to stop an older signed release from running again on a
machine once a newer one has been committed: revoking superseded kernels in
the firmware's `dbx`, and the TPM unlock that ADR-017 proposes. It gives the
cost of each from the tree, what the suites would need, and a recommendation.
A third way, a new Secure Boot key at each floor, is kept for comparison. On
the owner's word the decision becomes an ADR in [decisions](../decisions.md),
numbered then.

## What is open

Every release's kernels stay signed and valid for good. A release signs four:
slot a, slot b, the USB medium and the ISO (`sbsign` in
`build/stages/06-iso.sh:311` and `:447`), all with the one Secure Boot key.
A production tag's run signs a 0.0.0 build of the same commit too, the
update suite's starting point (`.github/workflows/distro.yml:337`, `:484`).
The only version comparison that guards an install is `kryptik-update`'s,
made by the running system before it writes
(`tools/update/kryptik-update:229-235`); kryptikd compares versions only to
decide what to fetch. `rollback` makes
none, and `kryptik-recover --restore-slot` commits "at the medium's (maybe
older) version" (`tools/update/kryptik-recover:11`), from the medium's
passwordless root shell.

So whoever holds the disk can put an older release's kernel on the ESP and
its root image in a slot, or boot any older signed medium and run
`--restore-slot`, and the machine boots that release. It asks for the state
passphrase as at every boot, and the user types it. The older release then
runs with the user's data, and every defect fixed since is open again. Both
halves are valid: the kernel is signed, and its compiled-in command line
names its own root hash, so dm-verity and Secure Boot accept the pair
(ADR-014).

Nothing records the newest release a machine committed to where that person
cannot write it:

- The ESP records (`committed-slot`, `version-a`, `version-b`) are plain FAT
  (`build/service-scripts/esp-records.sh:2-5`), and the design says so: "This
  does not stop someone who rewrites the ESP itself"
  (`boot-and-updates.md:180-181`).
- The release the clock's floor keeps is on the state partition
  (`/var/lib/kryptik/time/release/`). Whoever holds the disk cannot read it,
  but can delete it ([time](time.md)), and nothing compares it with the
  running version at boot.
- Nothing is kept in an authenticated EFI variable, `dbx` or the TPM.
  `kryptik-efiboot` writes only `Boot####`, `BootNext` and `BootOrder`.

The threat model does not name the downgrade. Its offline section says
"dm-verity and Secure Boot make a modified root or a swapped kernel fail to
boot" (`docs/threat-model.md:51-52`). An older kernel is neither.

## What a floor has to be

- **Enforced before the older kernel runs, or by something it cannot get
  around.** Its own code has no check, or only the check it shipped with.
- **Kept where neither the disk nor a root shell can lower it.** That rules
  out the ESP and the state partition. It also rules out an ordinary EFI
  variable, which the medium's root shell writes through `efivarfs`.
- **Raised only with the project's signature.** A floor that anyone with a
  root shell could raise would let them forbid the machine's own kernel.

Two places meet all three: the firmware's `dbx`, which takes a write only
signed by a key in `KEK`, and the TPM, whose objects answer only to their
policy.

## Revoking superseded kernels in dbx

The firmware refuses any kernel whose Authenticode digest is in `dbx`, from
the ESP, a medium, or anywhere else.

**How it would work.**

- At signing, stage 06 records each signed kernel's Authenticode SHA-256,
  the digest the firmware compares. The release record keeps them, so later
  releases can name them.
- A release may declare a floor: a manifest field, `floor: VERSION`, signed
  with the rest. Every kernel of every release below that version is to be
  refused. The release then carries a `dbx` append listing those digests,
  signed as an authenticated variable by a Kryptik KEK.
- Once `boot-success` commits a release whose floor is above the last one
  this machine applied, it writes that append to `dbx` through `efivarfs`, as
  an append-write. It tries again at every boot until `dbx` holds it; the
  firmware drops digests it already has. From the next boot the firmware
  refuses those kernels, and `rollback` refuses a slot below the floor rather
  than arm a kernel the firmware will not start.
- A release with no floor changes nothing. So `rollback` and `--recovery` to
  the release before keep working, as they must for a release that turns out
  bad. A release that fixes a defect worth holding the line on sets its floor
  to itself.

**What it costs, from the tree.**

- **Enrolment.** Today the user puts `kryptik-sb` in `db`, "and, on most
  machines, PK/KEK" (`docs/user-guide.md:84-92`). Beside Windows it sits in
  `db` alone, under the OEM's and Microsoft's `KEK`. A `dbx` write needs a
  `KEK` the machine trusts, so every machine would need a Kryptik
  certificate in `KEK` as well. Most firmware setup screens can append a
  certificate to `KEK` from a file; on others it means clearing the keys and
  enrolling `PK`, `KEK` and `db` anew. A machine without it keeps working
  and gets no floor, and `kryptik update status` would say so.
- **A second key.** The KEK should not be `kryptik-sb`: the key that signs
  every kernel would otherwise also decide which kernels to forbid.
  `tools/make-release-keys.sh` would make a `kryptik-kek` pair, and the key
  medium would hold it beside the keys it holds now
  (`make-release-keys.sh:64-66`). The sign job would use it only for a
  release that declares a floor, inside the same `release` environment and
  approval (`distro.yml:423-497`).
- **Tools.** Nothing in the flow signs an EFI authenticated variable today:
  the runners install `sbsigntool` and `virt-firmware` only. The append is a
  timestamped `EFI_VARIABLE_AUTHENTICATION_2` over an `EFI_SIGNATURE_LIST`:
  efitools' `sign-efi-sig-list`, or a short script on OpenSSL. On the image,
  `kryptik-efiboot` would learn the append-write, a few dozen lines.
- **Firmware space.** Each digest takes 48 bytes in `dbx` (a 16-byte owner
  GUID and the hash), and each append adds a 28-byte list header (UEFI 2.11,
  §32.4.1.1). One append stores 220 bytes for a release's four kernels, and
  412 for a production tag's eight, since it signs 0.0.0 too, unless that
  build stops being signed with the production key. An append skips digests
  already there (§8.2.6). The space comes out of the same variable store the firmware keeps
  everything in, usually some tens of KiB, which Microsoft's own `dbx`
  updates also draw on. Some firmware mishandles large writes there, and no
  virtual machine shows which.
- **No way back.** A revoked kernel never boots on that machine again,
  older media included. `--recovery` below the floor ends. A user with only
  an old USB stick has to write a new one, and the guide has to say so.
  Taking a digest out of `dbx` again takes the firmware's key management,
  whose usual route, a reset to factory keys, drops the user's enrolment
  too.
- **What the floor does not cover.** A kernel not yet revoked, between a
  defect's fix and the next floor. And a kernel signed after the Secure Boot
  key was stolen, which is the key-revocation case `release-keys.md`
  already covers.

**Suites.** OVMF honours `dbx`. `tools/image/ovmf-vars.sh` builds the
variable store with `virt-fw-vars` (virt-firmware 26.9, already installed by
the prepare action). Its `--add-dbx-hash` covers an offline check:
`integrity-test.sh` step 2, which expects the firmware to refuse a kernel and
has a positive control, would boot release A's kernel against a store that
lists A's digest. The full path needs the update suite to:

1. make a store whose `KEK` is the test's key, as the development build's
   key already is;
2. apply a release B whose manifest sets `floor: B`;
3. commit it, and see the append in `dbx`;
4. then fail to boot A's kernel from the ESP.

About one more VM boot and one reboot per run.

## Through the TPM

ADR-017 seals a second keyslot of the state partition to PCR 4 and PCR 7:
the exact signed kernel, whose compiled-in command line names its root, and
Kryptik's Secure Boot state. The seal covers the committed kernel and, during
a trial, the predicted one ([TPM unlock](tpm-unlock.md),
`docs/decisions.md:314-340`). An older kernel is not in the policy, so it
cannot unseal: the downgraded machine asks for the passphrase.

That is a prompt, not a floor. The passphrase keyslot is never removed. The
design treats a firmware or `dbx` update, a rollback and a wrong prediction
as "one passphrase prompt" each (`decisions.md:332-336`), so users learn to
type it when asked. The older release still boots, and it gets the
passphrase.

What would make the TPM side a floor is to show the user, before they type,
whether the kernel asking is one they enrolled. At enrolment the user picks
a short phrase. It is sealed under the same policy and shown above the
passphrase prompt by the kernels the policy lists. An older kernel cannot
unseal it, so its prompt carries no phrase. A user told what that means does
not type the passphrase. This holds only for users who look, and the older
release still runs, without the data.

**What it costs.** Everything ADR-017 lists: tpm2-tss and tpm2-tools in the
image, the NV policy rewritten for every trial, and a prompt per firmware
update. On top of that come a second sealed object and the phrase at the
prompt. A machine without a TPM 2.0 gets nothing. The suites need `swtpm`,
which is not installed today, and OVMF's TPM support.

## A new Secure Boot key at each floor

The coarse version of `dbx` needs no new key or tool. At a floor, ship
kernels signed by a new Secure Boot key, and have every user enrol the new
certificate and remove the old one from `db`. `release-keys.md` already
describes those steps for replacing a key. Every kernel signed by the old key
stops booting at once. But each floor then costs every user a trip through
the firmware menu, and until they make it, both keys boot. That fits a stolen
key, not routine floors.

## Side by side

| | `dbx` at declared floors | TPM with a shown phrase | new key per floor |
| --- | --- | --- | --- |
| an older kernel boots | no | yes | no, once the old key is gone from `db` |
| it gets the passphrase | it never runs | only from a user who does not look | it never runs |
| older media | refused | boot, but cannot unseal | refused |
| rollback to the previous release | kept unless the floor says otherwise | costs a prompt | ends at the floor |
| needs | a Kryptik KEK on each machine; `kryptik-kek` in the key medium | TPM 2.0; ADR-017 accepted | each user in the firmware menu at each floor |
| reversible | no | yes, by resealing | yes, by enrolling the old certificate |
| a suite can show it | yes, OVMF | yes, with `swtpm` | yes, OVMF |

## Proposed decision

- Revoke superseded kernels in `dbx`, at releases that declare a floor, with
  a Kryptik KEK separate from the Secure Boot key. Machines whose firmware
  will not take the KEK keep working, with no floor, and say so.
- Until that is built, and whatever the decision, the threat model names
  the gap. In its offline section, after the sentence on dm-verity and
  Secure Boot:

  > An older Kryptik release is neither: its kernel stays signed, and it
  > boots with its own root. Whoever holds the disk can install one, from
  > the disk or by booting an older medium, and the user's passphrase then
  > opens the state partition to it. Nothing on the machine records the
  > newest release it ran where that person cannot write.

- The TPM phrase is decided with ADR-017, not instead of the floor.
  ADR-017's own text would say that a downgraded kernel gets a prompt, not a
  refusal.

Not decided here: how many releases a floor reaches back, beyond "everything
below it", and whether a floor release also stops `kryptik-recover` from a
medium older than the floor. `dbx` decides that by itself once the medium's
kernel is revoked.
