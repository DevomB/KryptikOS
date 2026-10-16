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

Neither macOS nor Windows comes with `zstd`. On macOS, `brew install zstd`
(Homebrew) adds it, and the hash check is `shasum -a 256 -c --ignore-missing`.
On Windows, `zstd.exe` from zstd's releases page runs `zstd -d` as above,
and 7-Zip 24 and later unpacks the image too, as the README says. Run the
`ssh-keygen` line in Command Prompt, on one line (PowerShell has no `<`), and
compare what `certutil -hashfile kryptik-VERSION-usb.img SHA256` prints with
the image's line in `kryptik-VERSION.SHA256SUMS`. `certutil -hashfile
kryptik-sb.der SHA256` prints the certificate's SHA-256 fingerprint: the hex
`openssl` shows, in lower case and without the colons.

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

**Firmware settings.** A firmware's fast boot can skip USB devices, so the
stick never shows in its boot menu: turn fast boot off for the install. Some
older machines set their disk controller to RAID (Intel RST), which hides an
NVMe disk from Linux, and `dmesg` at the medium's shell then says `Switch your
BIOS from RAID to AHCI mode`: set it to AHCI in the firmware setup. A Windows
kept on another disk must be made ready for AHCI first, or it stops booting. A
newer machine's RST (Intel VMD) needs no change.

**Secure Boot.** The kernel is signed with the build's Secure Boot key: a
release's, from 1.0.0 on, is the project's ([release keys](release-keys.md)),
enrolled once for every release after it; a development build's is made by
that build and is its own. A firmware that carries only Microsoft's keys
refuses either (the acceptance run proves the refusal:
`media-refused-foreign-keys`). To boot with Secure Boot on, enrol
`kryptik-sb.der` in the firmware's `db` (and, on most machines, PK/KEK) from
the firmware setup menu; or turn Secure Boot off. The medium says which it
got above its shell (`Secure Boot is on` or `off`), and as
`KRYPTIK_SMOKE: secureboot=1` or `=0` on a serial console.

**AMD processors.** Update the machine's firmware (BIOS) first. With a
firmware older than AMD's 2025 fix for microcode signatures, the kernel loads
only the microcode patches it holds a digest for, which leaves out every Zen 5
processor (Ryzen 9000, Ryzen AI 300 and Ryzen AI Max, EPYC 9005) and a few
older EPYC models: they keep the firmware's own microcode, the kernel log
says `No sha256 digest for patch ID`, and every login prompt says to update
the firmware.

A firmware that also keeps Microsoft's certificates in `db` boots whatever
Microsoft signs, so someone with the machine in hand can start such a system
and have it ask for the state passphrase as Kryptik does. Taking Microsoft's
certificates out of `db`, leaving Kryptik's alone there, and setting a
firmware password, so that neither the keys nor Secure Boot can be changed
without it, closes that where the password survives clearing the firmware's
settings: most business laptops' does, while on many desktop boards a jumper
or the battery clears it. Whatever Microsoft signed then no longer starts:
another operating system on the machine, and the firmware drivers (option
ROMs) that add-in graphics cards, and some network and storage cards, carry.
Where the screen hangs off such a card, mostly on a desktop, even the
firmware's own menus can stay dark until the firmware is reset or reflashed,
and on some machines for good. There `db` can hold that card's option ROM by
its hash in place of Microsoft's certificate (sbctl reads the hashes from the
TPM's event log), which keeps the screen and still boots nothing else
Microsoft signs.

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
the machine has one, on the serial console (the serial line under QEMU),
under a few lines naming the commands that list the disks, show the
install's plan and read an installed disk. That shell exists only on install
media; installed systems have root locked at every terminal. The medium uses
no network: a cable plugged in, or a radio, is left down.

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
([keyboard layout](design/keyboard-layout.md)). For the desktop alone,
`kryptik keyboard desktop us de`, as the user, gives it up to four layouts
from the next login, the first in force and Super+Space to switch; the
screen lock names the one in force, as a password typed in the other one
fails. The state passphrase at boot is always asked under the machine's one
layout. This release has no input method, so Chinese, Japanese and Korean
cannot be typed yet.

The installer refuses the disk the medium is on; anything with a mounted
partition, active swap, or a partition held open (an unlocked LUKS volume,
LVM); anything that is not a whole, writable disk; a disk with 4096-byte
logical sectors (an NVMe drive can be formatted so), where Linux does not
mount the medium's boot partition; and a disk too small to hold the boot
partition, two root slots with room to grow, and a state partition with
space for one update and a gigabyte of data (about 8 GB for the current
image; the refusal names the exact minimum). A disk that already holds a
Kryptik installation or medium is refused too, since it may hold the only
copy of someone's encrypted state. To reinstall over one, add
`--replace-kryptik`: the installer names the Kryptik partitions it is about
to destroy and then asks for `ERASE` as usual.

Each root slot is sized for the image and half again, so that a later, larger
release still fits. `--slot-size MIB` makes both slots larger than that,
never smaller, and the state partition gets what is left.

It writes four GPT partitions: `kryptik-esp` (the medium's ESP, with the
slot A kernel as the boot file), `kryptik-a` (the verified root image, read
back and hashed against the medium's record), `kryptik-b` (empty until the
first update), and `kryptik-state` (LUKS2 with ext4 inside: users, zone
volumes, updates, and the medium's software images). Its plan names the disk's model and what each of its
partitions holds (`holds  gpt: sda1 ntfs "Windows" 237G; ...`): read it, as
nothing else tells a backup disk from the one you mean. Before its first
write it asks you to type `ERASE` (`--yes` skips that), then twice for the
state partition's passphrase, which the system then asks for at every boot:
at least 8 characters, and a long phrase is better, as a stolen disk can be
guessed at offline (`kryptik state passphrase` changes it later). There is
no escrow: without the passphrase, or without the partition's header, the
state is lost. It ends with `kryptik-install: installed VERSION to /dev/sdY:
boot it from firmware with the medium removed.` and a reminder to keep a
copy of that header. Make the copy now, on a second removable disk: `/root`,
`/var` and `/tmp` on a medium are memory, and a file left there is gone at
power-off. The medium reads FAT and ext4, not exFAT or NTFS, which large
sticks and Windows disks often come as; `mkfs.ext4 /dev/sdZ1` at the
medium's shell makes such a partition ext4, erasing what it holds.

```sh
mount /dev/sdZ1 /mnt
kryptik-recover --disk /dev/sdY --backup-state-header /mnt/kryptik-state-header
umount /mnt
poweroff
```

Remove the medium. The installed disk boots on its own, by its
`EFI/BOOT/BOOTX64.EFI` or by the `Kryptik slot a` entry the installer gave
the firmware (a firmware that refused it is named in the install's output);
it does not need the medium again unless it has to be recovered.

**Unattended install** (what the VM tests do): a small control disk labelled
`kryptik-testctl`, made with `tools/image/mk-testctl.sh --out FILE --key
KRYPTIK-TESTCTL KEY=VALUE...`, carrying `install_target=/dev/vda`, the state
passphrase as `state_passphrase=...` (required), and optionally
`preseed_user=`, `preseed_password_hash=` and `preseed_root_hash=` for the
first accounts; the user's hash must be SHA-512 crypt, as `openssl passwd -6`
makes it, the only kind besides SHA-256 crypt that the screen lock checks.
The file is signed by the release's `kryptik-testctl` key
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
serial console, and the first answer counts. Root changes it with
`kryptik state passphrase`, which asks for the current one, then twice for a
new one of at least 8 characters. A header backup made before the change, or
any earlier copy of the disk, still opens with the old passphrase: back the
header up again and destroy the older backups. That does not shut out anyone
who already copied the old header; only re-encrypting the partition under a
new key (`cryptsetup reencrypt`) does. On the first boot, before the login
prompt, a setup program asks in the same places for a user name (lower-case
letters, digits, `_` and `-` only) and that user's password, then for root's
password (root still cannot log in at a terminal; the password is for `su`,
below). After an unattended install with a preseed, it creates those
accounts from the preseed instead. If setup is interrupted, a question waits
unanswered for 10 minutes, or a password is not set, boot again: every boot
asks for whatever is still missing until the user and root both have
passwords. Over a serial line, answer the setup's questions there: the
serial console shows its login prompt only once setup has ended.

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
| Alt+p | the chrome menu: zones, their applications, stop a zone, move a clipboard between zones, the Wi-Fi networks with w, and with f the zone of the window you last had |
| Alt+Shift+Return | a terminal (havoc) in the work zone |
| Alt+Shift+p | a terminal in the personal zone |
| Alt+Shift+u | the browser (Firefox) in the untrusted zone |
| Alt+Shift+l | lock the screen until the login password is typed |
| Super+Space | the next of your desktop's layouts, when you have more than one |
| volume keys, mute, microphone mute | the volume up or down a step, mute or unmute everything, and take the microphone back from whichever zone has it |
| brightness keys | the screen's backlight up or down a step |
| Alt+e | fullscreen (the window keeps its zone border, so the zone stays visible) |
| Alt+Shift+c | close the focused window |
| Alt+j / Alt+k | focus next / previous |
| Alt+, / Alt+. | the monitor to the left / right; with Shift, the focused window moves there |
| Alt+1 … Alt+9 / Alt+Shift+1 … 9 | show a tag / move the focused window to it; vault windows keep to tag 9 |
| Ctrl+Alt+F2 / Ctrl+Alt+F1 | the administration login / back to the desktop |
| Alt+Shift+q | leave the desktop, which logs you out |

Alt+Shift+l locks the screen. Nothing shows but the word LOCKED and a mark
for each character typed, and every key goes to the lock, so no window, zone
0's or a zone's, sees the password; Ctrl+Alt+F2 does nothing while locked.
The volume, mute, microphone and brightness keys still work under the lock.
Type the login password and Enter. After a wrong one the lock shows WRONG,
and the next try waits 2 seconds, doubling with each wrong one in a row up
to a minute (the lock shows WAIT and the seconds); Escape clears what was
typed. If the lock's program dies, the screen stays locked and the lock
starts again. The screen also locks by itself after ten minutes without a
key, a click or the pointer moving; to change that, write the minutes to
`~/.config/kryptik/lock-idle` (0 for never), which the next login reads. A
minute after it locks, the screens turn off; any key or movement turns them
on again, and that key goes to the lock.

`kryptik suspend`, from a terminal of zone 0's, locks the screen and puts
the machine to sleep with the state partition's key wiped from memory. On
waking the lock shows STATE PASSPHRASE: type the passphrase the machine asks
for at boot, not the login password, and Enter. Until then everything kept on
the state partition waits, the zones are frozen, and the lock takes nothing
else; a wrong passphrase waits as a wrong password does. The zones carry on
where they were once it is given, but an encrypted zone: its volume's key
is wiped with the sleep too, and the zone stays frozen until its own
passphrase is given again. Once the state passphrase is in, a window asks
for each such zone's passphrase in turn; Enter alone leaves a zone waiting,
and the menu (Alt+p) shows it WAITING and takes its passphrase later with
`p` and its number, or a launch into it asks. Stopping such a zone closes
its volume without the passphrase. The power key and
closing the lid do the same as `kryptik suspend`, locked or not. In a virtual
machine whose display is virtio-gpu the machine does not sleep: the screen
locks, and `kryptik suspend` says why. The machine
can also sleep by itself, as many minutes after the screen locks for being
idle as `~/.config/kryptik/lock-sleep` holds, from the next login; it is
off until resume is proven on physical hardware, and 20 is the value to
write then. Testing on physical hardware is planned for October 2026.

Zone windows come from the menu: Alt+p, then a zone's number and `t` (a
terminal), `e` (the editor) or `b` (the browser), for example `1t`, then
Enter. The browser is Firefox in `untrusted`, `personal` and `work`, which
carry its software image, and lynx in a terminal elsewhere; Firefox opens
PDFs too. A zone runs one Firefox: asked for again while it is open there,
it says that Firefox is already running, and a new window comes from the
open one (Ctrl+N). A zone with encrypted storage asks for its passphrase when it starts,
in the menu's window or, for a key, in a small prompt window; the passphrase
never appears on a command line. On a machine with a battery, a Power
line under the zones gives its charge and whether the machine runs on it;
on battery at 3% the zones are stopped, each closing its volume, and the
machine powers off, so save work before then: a window warns at 10% and
again at 5%, and closes once the machine is plugged in. Under the zones, a
Network line says what the net zone reports: whether it is ready, the
Wi-Fi network it joined (or
that Wi-Fi is switched off, by a switch or an airplane-mode key; switched on
again, it rejoins by itself, or that a saved network refused its passphrase),
its address on the uplink and whether there is DNS. The menu also names a
release that has arrived and waits to be installed, and says when the newest
update statement is more than 30 days old, or, with none ever accepted, when
the install is (section 4). With `w` it lists the Wi-Fi networks the net zone may join,
shows the ones in range with `s`, numbered, adds one by its name or that
number, asking for its passphrase in the menu's own window, adds an open one
with `o`, or forgets one, as `kryptik wifi` does at the administration login.
A name with a character a terminal would not show plainly is typed instead.

Every zone but `vault` and the net zone plays sound through zone 0's
mixer, and none hears another. No zone may record until you let it: in the
menu, `c` and the zone's number lets that zone use the microphone until it
stops, one zone at a time, and `c` alone takes it back, as does the
keyboard's microphone key. The menu's Sound line names the zone that may
record and says when it is recording, and while a zone may record, a window
of its own says so, and when it does; it closes when the zone stops or the
microphone is taken back. `v` and a digit sets the volume, 0 to 9, `v`, a
zone's number and a digit sets that zone's own, and `x` mutes or unmutes
everything. A USB sound device that is plugged in takes the sound once
nothing has played for a few seconds; pulled out, it gives the sound back to
the built-in one at once. This release has no Bluetooth: for calls, use a
USB or wired headset, or a Bluetooth headset that comes with a USB dongle,
which works as a USB sound card.

No zone sees the camera until you let it: `k` and the zone's number in the
menu gives that zone the camera, one zone at a time, until it stops, the
screen locks, or `k` alone takes it back, and while it has it a window of the
chrome's says so. A program the zone left holding the camera loses it then
as well. A window in full screen covers those windows, so the bar above it
names the zone that may use the microphone (`MIC`) and the zone that has the
camera (`CAM`), whichever zones they are. Built-in and USB cameras that speak the USB Video Class work, as
most do; the cameras of recent Intel laptops that need Intel's image
processing in userspace (MIPI cameras behind the IPU6) and infrared
face-login cameras do not. `vault` and the net zone never get the camera.

For administration, Ctrl+Alt+F2 gives a text login: log in as the user, and
`su` becomes root, where passwords change: `passwd NAME` for the user,
`passwd` for root's own. There `kryptik list`, `kryptik status [ZONE]`,
`kryptik explain ZONE` and `kryptik doctor` describe the zones, and `kryptik
stop ZONE` stops one. `kryptik shell ZONE` and `kryptik run ZONE -- COMMAND` start the
zone through the launch service when run as the user, detached: its output
goes to `/var/log/kryptik/zone-ZONE.log`, which root can read. Run as root,
they use the terminal, for a zone without encrypted storage only.
`kryptik status net` gives the menu's Network line too, which says whether a
network added with `kryptik wifi add` has joined.

Files move between zones only through the broker, from inside the sending
zone, and only when the zone's policy allows the direction and you allow it:
the chrome opens a question window, and only the two-digit code it shows,
typed and then Enter, allows the file. Anything else refuses, keys typed
before the code appears are dropped, and after a refusal that zone may not
ask again for a minute.

**Wi-Fi.** `kryptik wifi scan` lists the networks in range with their
security and signal, as the net zone hears them; it scans only when asked,
from a random address while no network is joined where the radio allows one,
and otherwise only listens.
`kryptik wifi add SSID` saves a network and asks for its
passphrase; the net zone restarts and joins it, by WPA3 where the network
offers it. If the network refuses the passphrase, the menu's Network line
says so: add the network again with the right one. A network with no passphrase, a café's or an airport's, is saved
with `kryptik wifi add SSID --open`: anyone in range can read what crosses it
unencrypted, so only what a zone encrypts itself, as HTTPS does, stays
private there. Each saved network sees the machine by an address of its own,
made when the network was saved and kept with it, never the radio's: two
networks cannot tell they saw one machine by its address or by what it asks
for a lease. Networks that share a name, a chain's cafés for one, are one
saved network and see one address. A radio that takes a new address, as most
do, never uses its own: a scan for networks, before one is joined, goes out
from a new random address each time, so a scan does not follow the machine
either. A network that hides its name, which no scan lists, is
saved with `kryptik wifi add SSID --hidden` (beside `--open` for one with no
passphrase): the machine then asks for that name in each scan until it
joins, wherever it is, so anyone listening nearby learns it knows that
network. A new passphrase keeps it so; forget the network to stop.
`kryptik wifi list` names the saved networks, and `kryptik wifi forget SSID`
removes one.

**The local network.** Every zone with a network reaches the internet through
the net zone. The network the machine itself is on, with its router, its
printers and the page a hotel's or café's Wi-Fi asks you to log in on, is
open to `untrusted` alone: open that page there (Alt+Shift+u).

**Monitors.** `kryptik display`, in a terminal of zone 0's, lists the
monitors by name with their scale, mode and place. `kryptik display NAME
SCALE` draws everything on that monitor SCALE times as large, from 0.5 to 4,
1.5 say on a laptop's high-resolution panel, and `kryptik display NAME SCALE
X Y` also puts its top left corner at X,Y. The choice is kept for every
login and made again whenever the monitor is plugged in; NAME `*` stands for
every monitor no other line names, and `kryptik display NAME auto` gives the
monitor back its own: 2 for a built-in panel of 192 dpi or more, 1 for the
rest. Zones are told the scale rounded up to a whole number, and draw that
much larger.

**USB sticks.** Zone 0 reads nothing on a USB stick or an SD card. Plugging
one in opens a window of the chrome that names each partition by what the
stick and its partition table say (maker and model, size, the partition's
number and name), never by what its files say. A letter and a zone's number
give that partition to that zone to read (`a1`), or to read and write
(`a1w`); nothing is given until you choose, and the menu's `d` opens the
same window later. In that zone's terminal, `kryptik-stick` says what the
zone was given, `kryptik-stick list [DIR]` lists a directory,
`kryptik-stick get PATH [DEST]` copies a file or a directory off it, and
`kryptik-stick put FILE [DIR]` copies a file onto it when the zone may
write; wait for `put` to say it has copied before pulling the stick out.
The stick goes back with `e` and the zone's number in that window, when the
zone stops, or when the stick is pulled out, and the zone reads nothing of
it after. FAT is read and written; exFAT, which SD cards over 32 GB come
with, is read, and `put` refuses it. Give a stick you do not know to
`untrusted`: whatever its filesystem
does to the reader stays in that zone. `vault` and the net zone are never
given one.

**Degraded boot.** If the system cannot find exactly one `kryptik-state`
partition on its own disk, or cannot unlock or mount it, it boots degraded: it says
so on the console, creates no account, starts no desktop and refuses
updates. Nothing on the disk is written in that state, and the network's
corrections to the clock stay out of the hardware clock. Fix the cause (no
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
kryptik update forget     # or stop fetching it and delete what has arrived; automatic fetching then passes that release over
kryptik update apply      # install it, with the trial boot described below
kryptik update auto on    # fetch each newer release as it is announced; `auto off`, the default, waits for `fetch`
```

`fetch` only records the request, and the release arrives when the net zone
next asks; `apply` refuses a release that is still arriving. Then reboot, as
root (`su`, then `reboot`): the next boot is the trial. The desktop's menu
(Alt+p) does the same under `u`: it shows the status and fetches, forgets,
installs (after a `y`) or turns automatic fetching on and off.

When the newest statement is more than 30 days old, `status` says so, and so
does every login prompt: "kryptik update: no statement from the release key
for N days". Either nothing has been published, or something, the network or
the net zone, is keeping releases from this machine. A machine that has never
had one says so 30 days after it was installed. A clock that reads more than
a day before the newest statement, or before the install, would refuse every
statement to come, so that is said instead: "no statement from the release
key can be accepted while this machine's clock reads N days before ...: set
the clock".

A release brought by hand is a signed payload directory holding exactly
`manifest`, `manifest.sig`, `kryptik-root.img.zst` (the root image,
compressed), `kryptik-a.efi`, `kryptik-b.efi` and `root.json`, and the
release's software images if it has any (`images.manifest`, its signature
and `NAME.img.zst` files): what `make media` writes as
`images/payload-VERSION`, and what a release on the repository's page
carries. Bring it onto the state partition, for example under
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
committed boot file. Until it is judged, `kryptik update status` and the
menu say the trial is armed or running. An unhealthy trial reboots into the
previous slot by itself, and they then say what it found.
Persistent zone data on `kryptik-state` is never written by any of
this. `apply` refuses while another trial is armed (reboot first), while the
state partition is degraded, and on any slot but the committed one, such as
one picked in the firmware's boot menu: the refusal says to boot the
committed slot, or to make the running one committed from the medium. After
a trial that failed, one that did not boot or came up unhealthy, it refuses
that slot again until you pass `--retry`. A firmware that leaves `BootNext`
unused never starts the slot, and the status says it was never started: after
`--retry`, pick "Kryptik slot X" in the firmware's boot menu to boot it once.

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

Start with `--status`. It shows which slot is committed, each slot's version
and whether its kernel and filesystem are there, which slot's kernel the
firmware boots by default, the firmware's Kryptik entries, whether the state
partition still has its LUKS2 header, and the medium's own version, the one
`--restore-slot` writes. Where something is wrong it names the repair: a
boot file that is not the committed slot's kernel is put back by
`--commit-slot`, a boot partition (the ESP) that no longer mounts is
rewritten by `--restore-slot`, and a state partition with no header takes a
backup with `--restore-state-header`. `--commit-slot` also writes the
firmware an entry for the slot it commits, which a firmware that boots a
fixed disk only from such an entry needs.

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
the tool does not compare versions, which is why `--status` shows both. An
ESP that no longer mounts is first rewritten from the medium, as the
installer does. The other slot then has no kernel there, so it cannot be
committed or rolled back to; the next update writes it again.

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
- A Kryptik guest whose display is virtio-gpu, as QEMU's virtio-vga is, does
  not sleep: the kernel's virtio-gpu driver has no suspend callbacks, so the
  display would not come back. The power key and the lid lock it instead.
- Tested under QEMU with OVMF firmware. Testing on physical hardware is
  planned for October 2026. QEMU has no lid, no microphone or brightness
  keys, no backlight, no built-in panel and no camera of the USB Video
  Class, so those parts wait for it.
- Laptop sound goes through the HD Audio driver and USB audio. On many
  recent laptops part of it does not work: built-in microphones on Intel's
  or AMD's audio processor, all built-in sound on Intel laptops whose audio
  chips sit on SoundWire, and speakers behind a smart amplifier. A USB
  headset or sound card works on all of them
  ([laptop sound](design/laptop-audio.md)). Nothing plays through a
  monitor's speakers over HDMI or DisplayPort.
- The laptop makers' own drivers (for ThinkPads, IdeaPads and ASUS, Dell
  and HP laptops) are not built. Some laptops, ThinkPads among them, send
  the microphone key only through one, so there that key does nothing;
  take the microphone back from the menu (`c`) instead. A mute light, or
  a key for the keyboard's backlight, may do nothing there too.
- A disk with 4096-byte logical sectors (4Kn) is refused, as the medium's
  boot partition is a FAT of 512-byte sectors that Linux does not mount
  there. Disks that present 512-byte sectors (512e), as most do, are fine.
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
  connection table and gives each a resolver of its own, but every zone
  shares the uplink's bandwidth.
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
- The installer copies the medium's ESP as it is, as does `kryptik-recover
  --restore-slot` when the disk's own no longer mounts, and only the kernels
  on it are signed, so anything else someone put on a medium's ESP, files or
  its FAT structures, ends up on the installed disk: write the medium from a
  verified image and keep it out of others' hands.
- The keyboard layout is kept in the machine's firmware, not on the disk:
  after a firmware reset, or with the disk in another machine, the
  passphrase is asked under the `us` layout until `kryptik keyboard NAME`,
  as root, sets it again.
