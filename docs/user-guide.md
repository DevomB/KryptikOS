# Kryptik: boot, install, update and recover

These instructions ship beside each tested release, next to `RELEASE.txt`
and `ACCEPTANCE-REPORT.md`. `make acceptance` ran every suite on the images
the hashes name, under QEMU with OVMF firmware, and the report has each item
and its result. Testing on physical hardware is planned for October 2026.

## What is in the release directory

| file | what it is |
| --- | --- |
| `kryptik-VERSION-usb.img` | the install medium as a raw disk image: GPT, an EFI system partition with the signed kernel, and the verified root image |
| `kryptik-VERSION.iso` | the same medium as an ISO for CD/DVD boot (its kernel looks for `/dev/sr0`; use the USB image for a USB stick) |
| `*.sha256`, `SHA256SUMS` | the hashes the release was tested under: each image's, and every file of this directory |
| `kryptik-VERSION.SHA256SUMS`, `.sig` | the media's hashes, signed by the release key |
| `release-signers` | the keys the release's images trust for updates, which check that signature |
| `kryptik-sb.crt`, `kryptik-sb.der` | the Secure Boot certificate that signed the kernels, to enrol in the firmware (section 1) |
| `root.json` | the verified root image's dm-verity record (root hash, salt, sizes) |
| `manifest-VERSION`, `.sig` | the signed release manifest of each of the two payloads the update test moved between |
| `payload/` | the update payload as the channel serves it (section 4) |
| `REVISION.txt` | the source revision the images were built and tested from |
| `RELEASE.txt` | a summary: the verdict, the revision, the media hashes, the firmware and the kernel |
| `RELEASE-NOTES.md` | what changed since the previous release |
| `INSTRUCTIONS.md` | these instructions |
| `ACCEPTANCE-REPORT.md`, `acceptance-logs/` | every suite, its result, the commands and their logs |

The repository's Releases page carries this directory's files laid out for a
download ([releases](releases.md)): the two images compressed, as
`kryptik-VERSION-usb.img.zst` and `kryptik-VERSION.iso.zst`, which `zstd -d`
restores to the files the signed checksums cover; the acceptance logs as one
archive; the payload's files beside the rest; and no `*.sha256`.

Verify before use:

```sh
ssh-keygen -Y verify -f release-signers -I kryptik-release -n kryptik-media \
    -s kryptik-VERSION.SHA256SUMS.sig < kryptik-VERSION.SHA256SUMS
sha256sum -c --ignore-missing kryptik-VERSION.SHA256SUMS
openssl x509 -in kryptik-sb.crt -noout -subject -fingerprint -sha256
```

The signed checksums cover both images, and `--ignore-missing` checks the one
you took. `SHA256SUMS` describes this directory as the acceptance run wrote
it, so `sha256sum -c SHA256SUMS` checks every other file there, and does not
fit a download from the page.

On macOS the hash check is `shasum -a 256 -c --ignore-missing`. On Windows,
run the `ssh-keygen` line in Command Prompt, on one line (PowerShell has no
`<`), and compare what `certutil -hashfile kryptik-VERSION-usb.img SHA256`
prints with the image's line in `kryptik-VERSION.SHA256SUMS`.

The signature is only as good as the `release-signers` it is checked with,
and whoever could change the download could change that file too. From 1.0.0
on, a release's anchor and certificate are the project's, and the source
repository holds them as `build/config/release/release-signers` and
`build/config/release/kryptik-sb.crt`: compare them. A machine that runs
1.0.0 or later holds the same anchor at
`/usr/share/kryptik/trust/release-signers`. A `0.x` build made its own keys,
so its anchor matches no other build's.

## 1. Boot the medium

The medium boots by UEFI firmware alone. There is no boot loader to
configure: the firmware loads `EFI/BOOT/BOOTX64.EFI`, which is the signed
Linux kernel with its command line compiled in. The kernel builds the
dm-verity root itself (no initramfs) and refuses to continue if the root
image does not match the hash it carries.

**USB stick.** Write the raw image, checked as above, to the whole device,
never to a partition, and only to a device you are sure of:

```sh
sudo dd if=kryptik-VERSION-usb.img of=/dev/sdX bs=4M status=progress oflag=sync
```

On macOS, find the stick with `diskutil list`, then
`diskutil unmountDisk /dev/diskN` and
`sudo dd if=kryptik-VERSION-usb.img of=/dev/rdiskN bs=4m`. On Windows, Rufus
writes a disk image as it is (DD mode), and so does balenaEtcher. Decline
any offer to initialise or format the stick afterwards.

**Optical.** Burn `kryptik-VERSION.iso` as an image.

**Secure Boot.** The kernel is signed with the build's Secure Boot key: a
release's, from 1.0.0 on, is the project's ([release keys](release-keys.md)),
enrolled once for every release after it; a development build's is made by
that build and is its own. A firmware that carries only Microsoft's keys
refuses either (the acceptance run proves the refusal:
`media-refused-foreign-keys`). To boot with Secure Boot on, enrol
`kryptik-sb.der` in the firmware's `db` (and, on most machines, PK/KEK) from
the firmware setup menu; or turn Secure Boot off. The medium reports which it
got: `KRYPTIK_SMOKE: secureboot=1` or `=0` on the console.

**Under QEMU** (a checkout of the source tree is needed):

```sh
tools/image/run-ovmf.sh --usb kryptik-VERSION-usb.img --mode console          # Secure Boot off
tools/image/ovmf-vars.sh --cert kryptik-sb.crt                                  # a variable store with that key enrolled
tools/image/run-ovmf.sh --usb kryptik-VERSION-usb.img --vars enrolled --mode console
```

These need QEMU, OVMF's 4M Secure Boot build (in `/usr/share/OVMF`, or
wherever `KRYPTIK_OVMF_DIR` names) and, for the enrolled store,
`virt-fw-vars`. They boot the medium and nothing else. To install and then
run the installed system, give the guest a disk, which is a file, and a
variable store that lasts from one run to the next, since an update's trial
boot is a firmware variable:

```sh
truncate -s 16G disk.img
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
tools/image/run-ovmf.sh --usb kryptik-VERSION-usb.img --disk disk.img --vars-file vars.fd --mode console   # install to /dev/vda (section 2)
tools/image/run-ovmf.sh --no-media --disk disk.img --vars-file vars.fd --allow-reboot --mode console        # the installed system
```

`--allow-reboot` lets `reboot` restart the guest instead of ending QEMU, and
`--net user` gives the net zone a network. For Secure Boot on, start
`vars.fd` from the enrolled store instead
(`tools/image/ovmf-vars.sh --cert kryptik-sb.crt --out DIR` writes
`DIR/enrolled.fd`). The console is the serial line and no window opens, so
the desktop is not seen this way.

The medium presents a root shell with no password, on the display and, if
the machine has one, on the serial console (the serial line under QEMU).
That shell exists only on install media; installed systems have root locked
at every terminal.

## 2. Install

At the medium's root shell, with the target disk attached and nothing on it
you want to keep:

```sh
lsblk                                  # find the target: a whole disk, not a partition
kryptik-install --target /dev/sdY      # add --dry-run to see the plan and write nothing
```

On a keyboard that is not a US one, `kryptik keyboard` lists the layouts and
`kryptik-install --keyboard NAME` installs with one: `ERASE` and the
passphrase are then typed under it, here and at every boot, and the desktop
uses it too. `kryptik keyboard NAME`, as root, changes it later
([keyboard layout](design/keyboard-layout.md)).

The installer refuses the disk the medium is on; anything with a mounted
partition, active swap, or a partition held open (an unlocked LUKS volume,
LVM); anything that is not a whole, writable disk; and a disk too small to
hold the boot partition, two root slots with room to grow, and a state
partition with space for one update and a gigabyte of data (about 8 GB for
the current image; the refusal names the exact minimum). A disk that already
holds a Kryptik installation or medium is refused too, since it may hold the
only copy of someone's encrypted state. To reinstall over one, add
`--replace-kryptik`: the installer names the Kryptik partitions it is about
to destroy and then asks for `ERASE` as usual.

Each root slot is sized for the image and half again, so that a later, larger
release still fits. `--slot-size MIB` makes both slots larger than that,
never smaller, and the state partition gets what is left.

It writes four GPT partitions: `kryptik-esp` (the medium's ESP, with the slot
A kernel as the boot file), `kryptik-a` (the verified root image, read back
and hashed against the medium's record), `kryptik-b` (empty until the first
update), and `kryptik-state` (LUKS2 with ext4 inside: users, zone volumes,
updates). Before its first write it asks you to type `ERASE` (`--yes`
skips that), then twice for the state partition's passphrase, which the
system then asks for at every boot. There is no escrow: without the
passphrase, or without the partition's header, the state is lost. It ends
with `kryptik-install: installed VERSION to /dev/sdY: boot it from firmware
with the medium removed.` and a reminder to keep a copy of that header. Make
the copy now, on a second removable disk (FAT or ext4): `/root`, `/var` and
`/tmp` on a medium are memory, and a file left there is gone at power-off.

```sh
mount /dev/sdZ1 /mnt
kryptik-recover --disk /dev/sdY --backup-state-header /mnt/kryptik-state-header
umount /mnt
poweroff
```

Remove the medium. The installed disk boots on its own; it does not need
the medium again unless it has to be recovered.

**Unattended install** (what the VM tests do): a small control disk labelled
`kryptik-testctl`, made with `tools/image/mk-testctl.sh --out FILE --key
KRYPTIK-TESTCTL KEY=VALUE...`, carrying `install_target=/dev/vda`, the state
passphrase as `state_passphrase=...` (required), and optionally
`preseed_user=`, `preseed_password_hash=` and `preseed_root_hash=` for the
first accounts. The file is signed by the release's `kryptik-testctl` key
([release keys](release-keys.md)), and a medium honours only a disk its own
anchor's key signed: anyone else's is named on the console and ignored, so a
disk attached to a machine that boots your medium cannot arm an install. An
install medium then reports `KRYPTIK_INSTALL: rc=0` on success; an installed
system ignores the disk either way. No release publishes that key, so an
unattended install is for media you built yourself, whose key your build
holds (`<work>/keys/release/kryptik-testctl` for a development build).

## 3. First boot and daily use

Every boot asks for the state passphrase, three times at most, before
anything else starts: on the display and, if the machine has one, on the
serial console, and the first answer counts. Root changes it with `kryptik
state passphrase`. A header backup made before the change, or any earlier
copy of the disk, still opens with the old passphrase: back the header up
again and destroy the older backups. That does not shut out anyone who
already copied the old header; only re-encrypting the partition under a new
key (`cryptsetup reencrypt`) does. On the
first boot, before the login prompt, a setup program asks in the same places
for a user name (lower-case letters, digits, `_` and `-` only) and that
user's password, then for root's password (root still cannot log in at a
terminal; the password is for `su`, below). After an
unattended install with a preseed, it creates those accounts from the preseed
instead. If setup is interrupted, a question waits unanswered for 10 minutes,
or a password is not set, boot again: every boot asks for whatever is still
missing until the user and root both have passwords. Over a serial line,
answer the setup's questions there: the serial console shows its login
prompt only once setup has ended.

Log in as the user on tty1. The desktop session starts from the profile:
dwl with the Kryptik chrome as its startup command. Every application
window belongs to a zone and carries that zone's border colour. The window
with focus has the full-width border; the others' borders are narrower, in
the same colour. Nothing else on screen names a window's zone, since dwl
draws no titlebar: to name it in words, press Alt+p, then type f and Enter.
The menu shows the zone's glyph and label and the window's title, which the
zone's proxy prefixes with the zone's name, as `[untrusted] ...`. A zone's
window that opens while another window has the keyboard does not take it,
nor does it get it when that window closes: Alt+j, Alt+k, a click or the
pointer moving onto it moves the keyboard there. Keys (Alt is the modifier):

| keys | what |
| --- | --- |
| Alt+p | the chrome menu: zones, their applications, stop a zone, move a clipboard between zones, and with f the zone of the window you last had |
| Alt+Shift+Return | a terminal (havoc) in the work zone |
| Alt+Shift+p | a terminal in the personal zone |
| Alt+Shift+u | the browser (lynx) in the untrusted zone |
| Alt+e | fullscreen (the window keeps its zone border, so the zone stays visible) |
| Alt+Shift+c | close the focused window |
| Alt+j / Alt+k | focus next / previous |
| Alt+, / Alt+. | the monitor to the left / right; with Shift, the focused window moves there |
| Alt+1 … Alt+9 / Alt+Shift+1 … 9 | show a tag / move the focused window to it; vault windows keep to tag 9 |
| Ctrl+Alt+F2 / Ctrl+Alt+F1 | the administration login / back to the desktop |
| Alt+Shift+q | leave the desktop, which logs you out |

Zone windows come from the menu: Alt+p, then a zone's number and `t` (a
terminal), `e` (the editor) or `b` (the browser), for example `1t`, then
Enter. A zone with encrypted storage asks for its passphrase when it starts,
in the menu's window or, for a key, in a small prompt window; the passphrase
never appears on a command line. The menu also names a release that has
arrived and waits to be installed, and says when the newest update statement
is more than 30 days old (section 4).

For administration, Ctrl+Alt+F2 gives a text login: log in as the user, and
`su` becomes root. There `kryptik list`, `kryptik status [ZONE]`, `kryptik
explain ZONE` and `kryptik doctor` describe the zones, and `kryptik stop ZONE`
stops one. `kryptik shell ZONE` and `kryptik run ZONE -- COMMAND` start the
zone through the launch service when run as the user, detached: its output
goes to `/var/log/kryptik/zone-ZONE.log`, which root can read. Run as root,
they use the terminal, for a zone without encrypted storage only.

Files move between zones only through the broker, from inside the sending
zone, and only when the zone's policy allows the direction and you allow it:
the chrome opens a question window, and only the two-digit code it shows,
typed and then Enter, allows the file. Anything else refuses, keys typed
before the code appears are dropped, and after a refusal that zone may not
ask again for a minute.

**The local network.** Every zone with a network reaches the internet through
the net zone. The network the machine itself is on, with its router, its
printers and the page a hotel's or café's Wi-Fi asks you to log in on, is
open to `untrusted` alone: open that page there (Alt+Shift+u).

**Degraded boot.** If the system cannot find exactly one `kryptik-state`
partition on its own disk, or cannot unlock or mount it, it boots degraded: it says
so on the console, creates no account, starts no desktop and refuses
updates. Nothing on the disk is written in that state. Fix the cause (no
partition labelled `kryptik-state` on the system's own disk, or more than
one, as after relabelling; a damaged filesystem or header) and boot again. A
clone of the disk attached alongside is ignored, not a cause. After three
wrong passphrases, just boot again.

## 4. Update

A system built with a channel address lets its net zone bring the channel's
statement of what is current, and fetches nothing until you ask, unless you
have turned automatic fetching on; installing is always yours. As the user,
at the administration login without `su`:

```sh
kryptik update status     # the running version, the newest release the channel names and how old that statement is, what has arrived
kryptik update fetch      # ask for that release: the net zone brings it onto the state partition; it is verified against the signed manifest before anything is installed
kryptik update status     # again, until the staged release reads "complete"
kryptik update apply      # install it, with the trial boot described below
kryptik update auto on    # fetch each newer release as it is announced; `auto off`, the default, waits for `fetch`
```

`fetch` only records the request, and the release arrives when the net zone
next asks; `apply` refuses a release that is still arriving. Then reboot, as
root (`su`, then `reboot`): the next boot is the trial.

When the newest statement is more than 30 days old, `status` says so, and so
does every login prompt: "kryptik update: no statement from the release key
for N days". Either nothing has been published, or something, the network or
the net zone, is keeping releases from this machine. A machine that has never
had one says so 30 days after it was installed.

A release brought by hand is a signed payload directory holding exactly
`manifest`, `manifest.sig`, `kryptik-root.img`, `kryptik-a.efi`,
`kryptik-b.efi` and `root.json` (what `make media` writes as
`images/payload-VERSION`, and what a release on the repository's page
carries). Bring it onto the state partition, for example under
`/var/lib/kryptik/updates/`, and as root (the administration login, then
`su`):

```sh
kryptik-update status
kryptik-update apply /var/lib/kryptik/updates/VERSION
reboot
```

`apply` verifies everything before its first write: the manifest signature
against the trust anchor on the verified root, every file's hash and size,
the role, that the version is newer, and that the new kernel embeds the new
root hash. It writes the inactive slot, reads it back, installs the slot's
kernel on the ESP under its own name and arms one trial boot (`BootNext`).
The next boot runs the new slot; `boot-success` judges it (state partition
usable, services up, the zone supervisor healthy) and only then makes it the
committed boot file. An unhealthy trial reboots into the previous slot by
itself. Persistent zone data on `kryptik-state` is never written by any of
this. `apply` refuses while another trial is armed (reboot first), while the
state partition is degraded, and on any slot but the committed one, such as
one picked in the firmware's boot menu: the refusal says to boot the
committed slot, or to make the running one committed from the medium. After
a trial that failed, one that did not boot or came up unhealthy, it refuses
that slot again until you pass `--retry`.

```sh
kryptik-update rollback                       # back to the other slot, if it is intact
kryptik-update apply DIR --recovery           # an older release, on purpose: still signed, still verified
```

## 5. Recover

If the installed disk no longer boots, boot the medium with the disk
attached and, at the medium's root shell:

```sh
kryptik-recover --disk /dev/sdY --status
kryptik-recover --disk /dev/sdY --commit-slot a     # the other slot is intact: make it the boot file
kryptik-recover --disk /dev/sdY --restore-slot a    # the slot's root is damaged: rewrite it from this medium
```

`--backup-state-header FILE` and `--restore-state-header FILE` save and put
back the state partition's LUKS2 header. FILE is on a disk mounted for it, as
in section 2: the medium keeps nothing of its own. Keep the backup somewhere
that is not the installed disk: a damaged header with no backup is a lost
state partition.

`--restore-slot` writes the medium's own root image and kernel into the
slot, as the installer does, then commits it. Every byte comes from the
medium, and the slot is committed only once it verifies against the root
hash the medium's signed kernel carries. A medium whose root or slot kernel
is not that release's is refused with the reason, and nothing is committed.
The state partition is not touched, so users and zone volumes survive. The
result is the medium's version, which may be older than what was installed:
the tool names the version it writes but does not compare it, so read
`--status` first.

A machine that stops responding resets itself after about a minute (the
software watchdog's timeout; a hardware watchdog keeps its own): a service
feeds the watchdog, and the kernel does not let it be switched off.
A shutdown that hangs for a minute therefore also ends in a reset. If the
reset happens during the first boot of an update, the firmware boots the
previous slot, because the one-time boot entry is used up.
`s6-svstat /run/service/watchdog` shows the feeder; `/sys/class/watchdog/`
shows each timer, its timeout and whether it is running.

## Known limitations of this release

- The keys that sign a release from 1.0.0 on are held on GitHub, in the
  repository's protected release environment: a release tag's build uses
  them once the maintainer approves it, so a release is as trustworthy as
  the maintainer's GitHub account and the runners that build it
  ([release keys](release-keys.md)). A development build, which every `0.x`
  release is, is signed with keys that build generated and then discarded,
  so its certificate is enrolled on its own and no other build's release
  updates it.
- No independent security review has been made.
- Tested under QEMU with OVMF firmware. Testing on physical hardware is
  planned for October 2026.
- The builds are not reproducible bit for bit; the hashes name what was
  tested, not what a rebuild would produce.
- A program in a zone cannot make its window fullscreen; Alt+e does, and
  the window then sits below a bar in its zone's colour that names the
  zone. Other windows show their zone by border colour alone, and the
  menu's f names it in words.
- A trial boot is judged by services and the zone supervisor coming up.
  After that, a watchdog resets a machine whose userspace has stopped
  running for a minute; it does not notice a single crashed service or a
  frozen desktop. The reset during a trial lands on the committed slot.
- While one zone floods the network, the others' traffic and name lookups
  can slow or fail: the net zone holds each zone to an eighth of its
  connection table, but every zone shares the uplink's bandwidth and its one
  resolver.
- A network, or a net zone it has taken over, can keep releases from the
  machine: that is reported after 30 days, by `kryptik update status` and
  above every login prompt, not prevented, and not reported at all if
  whoever withholds them also holds the channel's statement key.
- Anyone who holds the disk, or can boot a Kryptik install medium on the
  machine, can put an older release back, still signed
  (`kryptik-recover --restore-slot` restores the medium's own, older or
  not), and it boots and asks for your passphrase as the current one does
  ([a proposal against it](design/rollback-floor.md)).
- The state partition is encrypted, not authenticated: someone who holds
  the disk can damage it, or, with an earlier copy, put a block or its
  header back as it was, and nothing notices
  ([state partition](design/state-encryption.md)).
- The installer copies the medium's ESP as it is, and only the kernels on
  it are signed, so anything else someone put on a medium's ESP, files or
  its FAT structures, ends up on the installed disk: write the medium from a
  verified image and keep it out of others' hands.
- The keyboard layout is kept in the machine's firmware, not on the disk:
  after a firmware reset, or with the disk in another machine, the
  passphrase is asked under the `us` layout until `kryptik keyboard NAME`,
  as root, sets it again.
