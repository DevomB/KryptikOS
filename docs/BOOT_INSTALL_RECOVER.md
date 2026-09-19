# Kryptik: boot, install, update and recover

These are the instructions that ship beside a tested release (see
`RELEASE.txt` and `ACCEPTANCE-REPORT.md` in the same directory). Everything
below was exercised by `make acceptance` on the exact images the hashes name,
under QEMU with OVMF firmware. Nothing here has been run on physical
hardware; the hardware notes say what should hold, not what was measured.

## What is in the release directory

| file | what it is |
| --- | --- |
| `kryptik-VERSION-usb.img` | the install medium as a raw disk image: GPT, an EFI system partition with the signed kernel, and the verified root image |
| `kryptik-VERSION.iso` | the same medium as an ISO for CD/DVD boot (its kernel looks for `/dev/sr0`; use the USB image for a USB stick) |
| `*.sha256`, `SHA256SUMS` | the hashes the release was tested under |
| `kryptik-sb.crt`, `kryptik-sb.der` | the developer Secure Boot certificate that signed the kernels. A test anchor, not a production key |
| `root.json` | the verified root image's dm-verity record (root hash, salt, sizes) |
| `manifest-VERSION`, `.sig` | the signed release manifest of each payload the update test used |
| `REVISION.txt` | the source revision the images were built and tested from |
| `ACCEPTANCE-REPORT.md`, `acceptance-logs/` | every suite, its result, the commands and their logs |

Verify before use:

```sh
sha256sum -c SHA256SUMS
openssl x509 -in kryptik-sb.crt -noout -subject -fingerprint -sha256
```

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
tools/image/ovmf-vars.sh && tools/image/run-ovmf.sh --usb kryptik-VERSION-usb.img --vars enrolled --mode console
```

The medium's console (the serial line under QEMU, the display on a
machine) presents a root shell with no password. That shell exists only on
install media; installed systems have root locked at every terminal.

## 2. Install

At the medium's root shell, with the target disk attached and nothing on it
you want to keep:

```sh
lsblk                                  # find the target: a whole disk, not a partition
kryptik-install --target /dev/sdY      # add --dry-run to see the plan and write nothing
```

The installer refuses the disk the medium itself is on, anything with a
mounted partition or active swap, anything that is not a whole block
device, and a disk too small for the layout. It writes, in order: GPT
partition 1 `kryptik-esp` (the medium's ESP, with the slot A kernel as the
boot file), 2 `kryptik-a` (the verified root image, read back and hashed
against the medium's record), 3 `kryptik-b` (empty; the first update fills
it), 4 `kryptik-state` (ext4: users, zone volumes, updates). It ends with
`KRYPTIK_INSTALL: rc=0`. Then:

```sh
poweroff
```

Remove the medium. The installed disk boots on its own; it does not need
the medium again unless it has to be recovered.

**Unattended install** (what the VM tests do): a small control disk labelled
`kryptik-testctl` carrying `install_target=/dev/vda` and optional preseed
lines (`tools/image/mk-testctl.sh`). An install medium honours it; an
installed system ignores it.

## 3. First boot and daily use

On the first boot the system runs `kryptik-firstboot` on the first console:
it asks for a user name and password, and for root's password (root can
still not log in at a terminal; the password is for `su` from the user's
session). With a preseed on the control disk it creates that user instead. If the
setup was interrupted before a user existed, boot again: it runs until a
user exists. If a user exists but a password step failed, run
`kryptik-firstboot` again from that user's session with `su`.

Log in as the user on tty1. The desktop session starts from the profile:
dwl with the Kryptik chrome as its startup command. Every application
window belongs to a zone and carries that zone's border colour, pattern and
label; the title is prefixed with the zone name. Keys (Alt is the modifier):

| keys | what |
| --- | --- |
| Alt+p | the chrome menu: zones, their applications, stop a zone, move a clipboard between zones |
| Alt+Shift+Return | a terminal (havoc) in the work zone |
| Alt+Shift+p | a terminal in the personal zone |
| Alt+Shift+u | the browser (lynx) in the untrusted zone |
| Alt+e | fullscreen (the window keeps its zone border, so the zone stays visible) |
| Alt+Shift+c | close the focused window |
| Alt+j / Alt+k | focus next / previous |

Zones from a terminal: `kryptik list`, `kryptik explain ZONE`, `kryptik
shell ZONE`, `kryptik run ZONE -- COMMAND`, `kryptik stop ZONE`, `kryptik
doctor`. As an ordinary user these go through the session's launch service;
a zone with encrypted storage asks for its passphrase on the terminal when it
starts, and the passphrase never appears on a command line. Files move
between zones only through the broker, from inside the sending zone, and only
when the zone's policy allows the direction and you answer yes to the
question the chrome shows.

**Degraded boot.** If the system cannot find exactly one `kryptik-state`
partition on its own disk, or cannot mount it, it boots degraded: it says
so on the console, creates no account, starts no desktop and refuses
updates. Nothing on the disk is written in that state. Fix the cause
(a cloned disk attached, a relabelled partition, a damaged filesystem) and
boot again.

## 4. Update

An update is a signed payload directory holding exactly `manifest`,
`manifest.sig`, `kryptik-root.img`, `kryptik-a.efi`, `kryptik-b.efi` and
`root.json` (what `make media` writes as `images/payload-VERSION`). Bring it
onto the state partition, for example under `/var/lib/kryptik/updates/`,
and as root:

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
this.

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

`--restore-slot` writes the medium's own root image and kernel into the
slot, exactly as the installer does, then commits it. The state partition
is not touched: users and zone volumes survive. The result is the medium's
version, which may be older than what was installed; that is what
recovering from the medium means, and the tool says so.

Every byte written by recovery comes from the medium, which the firmware
verified.

A machine that stops responding entirely resets itself after about a
minute: a service feeds the watchdog, and nothing else does. The kernel is
built so that the watchdog cannot be switched off once it is running,
which also means a shutdown that hangs for a minute ends in a reset
rather than a machine that stays on. If that reset happens during the
first boot of an update, the firmware boots the previous slot, because
the one-time boot entry has been used up. `s6-svstat /run/service/watchdog`
shows the feeder, and the files under `/sys/class/watchdog/` show each
timer, its timeout and whether it is running.

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
