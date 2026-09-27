# Kryptik: boot, install, update and recover

These instructions ship beside each tested release, next to `RELEASE.txt`
and `ACCEPTANCE-REPORT.md`. Everything below was exercised by
`make acceptance` on the images the hashes name, under QEMU with OVMF
firmware. Nothing has run on physical hardware yet.

## What is in the release directory

| file | what it is |
| --- | --- |
| `kryptik-VERSION-usb.img` | the install medium as a raw disk image: GPT, an EFI system partition with the signed kernel, and the verified root image |
| `kryptik-VERSION.iso` | the same medium as an ISO for CD/DVD boot (its kernel looks for `/dev/sr0`; use the USB image for a USB stick) |
| `*.sha256`, `SHA256SUMS` | the hashes the release was tested under |
| `kryptik-VERSION.SHA256SUMS`, `.sig` | the media's hashes, signed by the release key |
| `release-signers` | the keys the release's images trust for updates, which check that signature |
| `kryptik-sb.crt`, `kryptik-sb.der` | the developer Secure Boot certificate that signed the kernels. A test anchor, not a production key |
| `root.json` | the verified root image's dm-verity record (root hash, salt, sizes) |
| `manifest-VERSION`, `.sig` | the signed release manifest of each of the two payloads the update test moved between |
| `REVISION.txt` | the source revision the images were built and tested from |
| `RELEASE.txt` | a summary: the verdict, the revision, the media hashes, the firmware and the kernel |
| `RELEASE-NOTES.md` | what changed since the previous release |
| `INSTRUCTIONS.md` | these instructions |
| `ACCEPTANCE-REPORT.md`, `acceptance-logs/` | every suite, its result, the commands and their logs |

Verify before use:

```sh
ssh-keygen -Y verify -f release-signers -I kryptik-release -n kryptik-media \
    -s kryptik-VERSION.SHA256SUMS.sig < kryptik-VERSION.SHA256SUMS
sha256sum -c kryptik-VERSION.SHA256SUMS
sha256sum -c SHA256SUMS
openssl x509 -in kryptik-sb.crt -noout -subject -fingerprint -sha256
```

The signature is only as good as the `release-signers` it is checked with,
and whoever could change the download could change that file too. A machine
that already runs Kryptik holds the same file at
`/usr/share/kryptik/trust/release-signers`: compare the two.

## 1. Boot the medium

The medium boots by UEFI firmware alone. There is no boot loader to
configure: the firmware loads `EFI/BOOT/BOOTX64.EFI`, which is the signed
Linux kernel with its command line compiled in. The kernel builds the
dm-verity root itself (no initramfs) and refuses to continue if the root
image does not match the hash it carries.

**USB stick.** Write the raw image to the whole device, never to a
partition, and only to a device you are sure of:

```sh
sha256sum -c kryptik-VERSION-usb.img.sha256
sudo dd if=kryptik-VERSION-usb.img of=/dev/sdX bs=4M status=progress oflag=sync
```

**Optical.** Burn `kryptik-VERSION.iso` as an image.

**Secure Boot.** The kernel is signed with the developer key. A firmware
that carries only Microsoft's keys refuses it (the acceptance run proves the
refusal: `media-refused-foreign-keys`). To boot with Secure Boot on, enrol
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
`virt-fw-vars`.

The medium presents a root shell with no password, on the display and on
the serial console (the serial line under QEMU). That shell exists only on
install media; installed systems have root locked at every terminal.

## 2. Install

At the medium's root shell, with the target disk attached and nothing on it
you want to keep:

```sh
lsblk                                  # find the target: a whole disk, not a partition
kryptik-install --target /dev/sdY      # add --dry-run to see the plan and write nothing
```

The installer refuses the disk the medium is on; any disk that already
holds a Kryptik installation or medium, that is a partition labelled
`kryptik-state`, `kryptik-testctl` or `kryptik-media` (to reinstall over an
old Kryptik disk, clear its partition table first); anything with a mounted
partition or active swap; anything that is not a whole, writable disk; and a
disk too small to hold the boot partition, two root slots with room to grow,
and a state partition with space for one update and a gigabyte of data
(about 8 GB for the current image; the refusal names the exact minimum).

It writes four GPT partitions: `kryptik-esp` (the medium's ESP, with the slot
A kernel as the boot file), `kryptik-a` (the verified root image, read back
and hashed against the medium's record), `kryptik-b` (empty until the first
update), and `kryptik-state` (LUKS2 with ext4 inside: users, zone volumes,
updates). Before its first write it asks you to type `ERASE` (`--yes`
skips that), then twice for the state partition's passphrase, which the
system then asks for at every boot. There is no escrow: without the
passphrase, or without the partition's header, the state is lost. It ends
with `kryptik-install: installed VERSION to /dev/sdY: boot it from firmware
with the medium removed.` and a reminder to keep a copy of that header
(section 5). Then:

```sh
poweroff
```

Remove the medium. The installed disk boots on its own; it does not need
the medium again unless it has to be recovered.

**Unattended install** (what the VM tests do): a small control disk labelled
`kryptik-testctl`, made with `tools/image/mk-testctl.sh --out FILE
KEY=VALUE...`, carrying `install_target=/dev/vda`, the state passphrase as
`state_passphrase=...` (required), and optionally `preseed_user=`,
`preseed_password_hash=` and `preseed_root_hash=` for the first accounts. An
install medium honours it and reports `KRYPTIK_INSTALL: rc=0` on success; an
installed system ignores it.

## 3. First boot and daily use

Every boot asks for the state passphrase, three times at most, before
anything else starts: on the display and on the serial console, and the
first answer counts. Root changes it with `kryptik state passphrase`. On the
first boot, before the login prompt, a setup program asks in the same places
for a user name and that user's password, then for root's password (root still
cannot log in at a terminal; the password is for `su`, below). After an
unattended install with a preseed, it creates those accounts from the preseed
instead. If setup is interrupted, a question waits unanswered for 10 minutes,
or a password is not set, boot again: every boot asks for whatever is still
missing until the user and root both have passwords.

Log in as the user on tty1. The desktop session starts from the profile:
dwl with the Kryptik chrome as its startup command. Every application
window belongs to a zone and carries that zone's border colour. The window
with focus has the full-width border; the others' borders are narrower, in
the same colour. Nothing else on screen names a window's zone, since dwl
draws no titlebar: to name it in words, press Alt+p, then type f and Enter.
The menu shows the zone's glyph and label and the window's title, which the
zone's proxy prefixes with the zone's name, as `[untrusted] ...`. Keys (Alt
is the modifier):

| keys | what |
| --- | --- |
| Alt+p | the chrome menu: zones, their applications, stop a zone, move a clipboard between zones, and with f the zone of the window you last had |
| Alt+Shift+Return | a terminal (havoc) in the work zone |
| Alt+Shift+p | a terminal in the personal zone |
| Alt+Shift+u | the browser (lynx) in the untrusted zone |
| Alt+e | fullscreen (the window keeps its zone border, so the zone stays visible) |
| Alt+Shift+c | close the focused window |
| Alt+j / Alt+k | focus next / previous |
| Alt+1 … Alt+9 / Alt+Shift+1 … 9 | show a tag / move the focused window to it; vault windows keep to tag 9 |
| Ctrl+Alt+F2 / Ctrl+Alt+F1 | the administration login / back to the desktop |
| Alt+Shift+q | leave the desktop, which logs you out |

Zone windows come from the menu: Alt+p, then a zone's number and `t` (a
terminal), `e` (the editor) or `b` (the browser), for example `1t`, then
Enter. A zone with encrypted storage asks for its passphrase when it starts,
in the menu's window or, for a key, in a small prompt window; the passphrase
never appears on a command line.

For administration, Ctrl+Alt+F2 gives a text login: log in as the user, and
`su` becomes root. There `kryptik list`, `kryptik status [ZONE]`, `kryptik
explain ZONE` and `kryptik doctor` describe the zones, and `kryptik stop ZONE`
stops one. `kryptik shell ZONE` and `kryptik run ZONE -- COMMAND` start the
zone through the launch service when run as the user, detached: its output
goes to `/var/log/kryptik/zone-ZONE.log`, which root can read. Run as root,
they use the terminal, for a zone without encrypted storage only.

Files move between zones only through the broker, from inside the sending
zone, and only when the zone's policy allows the direction and you answer
yes to the question the chrome shows.

**Degraded boot.** If the system cannot find exactly one `kryptik-state`
partition on its own disk, or cannot unlock or mount it, it boots degraded: it says
so on the console, creates no account, starts no desktop and refuses
updates. Nothing on the disk is written in that state. Fix the cause (no
partition labelled `kryptik-state` on the system's own disk, or more than
one, as after relabelling; a damaged filesystem or header) and boot again. A
clone of the disk attached alongside is ignored, not a cause. After three
wrong passphrases, just boot again.

## 4. Update

An update is a signed payload directory holding exactly `manifest`,
`manifest.sig`, `kryptik-root.img`, `kryptik-a.efi`, `kryptik-b.efi` and
`root.json` (what `make media` writes as `images/payload-VERSION`). Bring it
onto the state partition, for example under `/var/lib/kryptik/updates/`,
and as root (the administration login, then `su`):

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
this. `apply` refuses while another trial is armed (reboot first, or roll
back) and while the state partition is degraded; after a trial that failed
to boot it refuses that slot again until you pass `--retry`.

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
back the state partition's LUKS2 header. Keep a backup somewhere that is not
this disk: a damaged header with no backup is a lost state partition.

`--restore-slot` writes the medium's own root image and kernel into the
slot, as the installer does, then commits it. Every byte comes from the
medium, and the next boot checks them: the kernel refuses a root that does
not match the hash it carries. The state partition is not touched, so users
and zone volumes survive. The result is the medium's version, which may be
older than what was installed: the tool names the version it writes but does
not compare it, so read `--status` first.

A machine that stops responding resets itself after about a minute (the
software watchdog's timeout; a hardware watchdog keeps its own): a service
feeds the watchdog, and the kernel does not let it be switched off.
A shutdown that hangs for a minute therefore also ends in a reset. If the
reset happens during the first boot of an update, the firmware boots the
previous slot, because the one-time boot entry is used up.
`s6-svstat /run/service/watchdog` shows the feeder; `/sys/class/watchdog/`
shows each timer, its timeout and whether it is running.

## Known limitations of this release

- Signed with a developer key generated by the build. There is no
  production signing, no key ceremony, and no independent security review.
- Tested under QEMU with OVMF only. No physical machine has booted it; no
  hardware support beyond what the virtual machine exercised is claimed.
- The builds are not reproducible bit for bit; the hashes name what was
  tested, not what a rebuild would produce.
- A fullscreen window is framed by its zone's border colour; there is no
  separate always-visible bar with the zone's name.
- A trial boot is judged by services and the zone supervisor coming up.
  After that, a watchdog resets a machine whose userspace has stopped
  running for a minute; it does not notice a single crashed service or a
  frozen desktop. The reset during a trial lands on the committed slot.
