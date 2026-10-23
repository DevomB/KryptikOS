# Hardware

Which machines Kryptik has been run on, who ran it, and what each run
showed. The list is `docs/hardware/list.tsv`; beside it sits one report per
row, made on the machine by `kryptik-hwreport`, and
`tools/check-hardware.sh --list` holds every row to its report. The list is
empty. Testing on physical hardware is planned for October 2026.

What the kernel is built to drive is in the [README](../README.md#hardware).
This page is about what was seen to work.

## A report

`kryptik-hwreport` prints what a machine is made of and what the image lacks
for it: the maker and model, the firmware's Secure Boot state, the watchdogs
and whether one reset the boot before, the processor and its microcode, every
PCI and USB device with the driver that took it, the
disks and the drivers under them, the display and each graphics controller's
power state, the sound hardware, a laptop's
backlights, batteries and what they draw, sleep states and camera parts,
network and input
devices, the loaded modules and the kernel log. Its `missing` section is
the part to act on: the firmware the kernel asked for and did not find, each a
line for `build/config/firmware.list`, and the devices and disks that want a
driver's line in `build/config/kernel/boot.fragment`.

Nothing in it is one machine's alone. No serial number is read, and the
hardware addresses, serial numbers and UUIDs the kernel log prints are struck
before the report is written. Read it before you send it all the same.

There are two ways to take one:

- **From the USB medium, with no keyboard or screen.** Write the image to a
  stick, then make a folder named `kryptik-report` on the stick's first
  partition, from any computer. Boot the stick on the machine, wait a minute
  and switch off. The report is `kryptik-report/report-1.txt` on that
  partition, and the next boot writes `report-2.txt`. A stick without the
  folder is never written.
- **By command.** At the medium's root shell, `kryptik-hwreport --save` writes
  the same file. On an installed system, as root, `kryptik-hwreport > FILE`
  writes the report where you say.

## What a listing says

| level | what its report shows |
| --- | --- |
| `reported` | The machine by maker and model, the release and the kernel that ran, and every section whole, from the medium or an installed system. It says what the machine has and what the image lacks for it, not that Kryptik works there. |
| `certified` | All of that on an installed system: a release, not a dated build; booted by UEFI with Secure Boot on and the kernel locked down; the encrypted state partition in use; a display with an output connected; the default route leaving by a wired or wireless interface that has a carrier; and nothing under `missing`. |

A `certified` row says that the release installs on that model, boots there
with Secure Boot on, has a display to draw the desktop on and reaches a
network. It does not speak for what the report does not exercise (sound,
suspend, a camera), for Bluetooth, which 1.0 does not drive, for another
firmware version, or for the same model sold with another network card: the
report names the firmware version and every device, so a reader can compare.

A listing also says what confines a device's DMA: the IOMMUs in use, and
how a Thunderbolt port lets a device in, on a build with a Thunderbolt
driver, which 1.0 is not. The kernel turns the IOMMU on and strict, but a
machine whose firmware hides it boots all the same, with every device able
to reach all of memory.

A listing also names the machine's sound: its HD Audio codecs, and whether
microphones sit on Intel's DSP or AMD's coprocessor, codecs on SoundWire
(under HD Audio or behind AMD's coprocessor) or amplifiers in front of the
speakers, each with what drives it. No level asks for any of it.

Its `shstk` line says whether a program built for shadow stacks runs with
one there: the kernel turns them on where the processor has them, Intel's
from Tiger Lake and AMD's from Zen 3. The virtual machines that test each
release have none, so only such a machine shows how a program built for
them fares with a library built without. No level asks for it.

Its `gpu` lines give each graphics controller's power state. Nothing here
drives NVIDIA's graphics, and the kernel lets a device nothing drives sleep
only once runtime PM is allowed it (`control auto`), so beside Intel's or
AMD's on a laptop an NVIDIA chip stays powered, in D0. Only such a laptop
shows what that costs its battery, which the report's `battery` lines give.
No level asks for it.

## Trying a laptop

A listing's levels speak for installing, booting with Secure Boot, the display
and the network. Much of what a laptop adds, the virtual machines that test
each release cannot show ([status](status.md) says which parts wait for
physical hardware). On a laptop, try these too, on the installed system, and
let the row's note name what did not work:

| try | what should happen |
| --- | --- |
| close the lid, then open it | the screen locks and the machine sleeps; it wakes to the lock asking for the state passphrase, and the zones carry on once it is typed |
| the power key, and `kryptik suspend` | the same; the listing's `sleep` line says whether that sleep is deep or s2idle, and of a report taken after an s2idle sleep, whether that sleep reached the hardware's sleep state |
| the touchpad | the pointer moves, a tap clicks, two fingers scroll, and typing stills it for a moment |
| the brightness keys | the backlight steps up and down and never goes dark; of several, the kind the kernel prefers (firmware, then platform, then raw) |
| the volume, mute and microphone keys | the volume steps, mutes, and the microphone is taken back, under the lock too |
| a zone playing sound | the built-in speakers play it where the listing's `audio` line names an HD Audio codec and nothing beyond it |
| unplug the mains, then plug it in | the menu's Power line follows, with the battery's charge |
| a charger too weak for the machine, such as a phone's USB-C one | the Power line says on battery though plugged in, and the warnings at 10% and 5% come as they do unplugged |
| on an AMD laptop whose `sleep` line says s2idle, a sleep of two minutes | it wakes to the lock, not to a fresh boot: the watchdog does not feed AMD's TCO timer there, as it would count through the sleep, and the report's line for it says inactive |
| an SD card in the laptop's own reader | the window that asks which zone gets a stick opens, as for a USB stick |
| a USB headset, plugged in while a zone plays, then `c` and a zone's number in the menu | it takes what the zone plays within a second, and records there once granted |
| an external monitor on HDMI or DisplayPort, plugged in while the desktop runs | the desktop reaches it within seconds, and `kryptik display` lists it with its scale |
| an external monitor on a laptop with two GPUs, an AMD one beside the built-in | it shows the desktop, whose frames wlroots copies to the second GPU's ports; dark, the row's note names both, as the listing's `display` line does |
| a laptop with NVIDIA's graphics beside Intel's or AMD's | the desktop shows on the built-in screen; a monitor on a port the NVIDIA chip drives stays dark, as 1.0 drives none, and the listing's `gpu` line says whether that chip stayed powered |
| a USB-C or Thunderbolt dock: its monitor, its USB ports and its Ethernet | the monitor shows where the laptop drives USB-C itself; a Thunderbolt or USB4 dock's own USB ports and Ethernet stay dark, as 1.0 builds no Thunderbolt driver, and the row's note says which worked |
| closed on its dock, then the dock unplugged | it sleeps within seconds, as a lid closed undocked does |
| the state passphrase at boot, typed on the built-in keyboard | it unlocks, whether the keyboard is on PS/2 or on I2C behind Intel's LPSS or AMD's DesignWare controller; the row's note names which (`/proc/bus/input/devices`). One that types nothing there is among those status.md lists, and a plain USB keyboard is the way through |
| `k` and a zone's number in the menu, then a program there that records video | a USB camera records; one the listing's `camera` line puts behind an IPU does not, as 1.0 drives none |
| a USB camera given to a zone with `k` and its number, then pulled out | the grant ends at once, and the menu's Camera line says no zone has it; plugged back in, it waits for `k` again |
| Firefox in `untrusted`: Alt+p, its number and `b` | a window opens; where the listing's `shstk` line says yes, this is the only test of Firefox starting with shadow stacks on, and a failure names SHSTK in what it prints |

A laptop that wakes from the lid and from `kryptik suspend` is the proof that
the idle sleep, `~/.config/kryptik/lock-sleep`, waits for ([the user
guide](user-guide.md)).

## Who may vouch

Whoever ran it on a machine in front of them. A row names them and the day,
and they answer for the report being that machine's and unedited. For
`certified` they installed from the release's own medium, checked as
[releases](releases.md) describes, with the release's Secure Boot certificate
enrolled, and took the report on the installed system.

A row enters the list as a pull request that adds the report and its row. It
is read by someone other than its author, who runs `tools/check-hardware.sh`
on the report and compares what it prints with the row.

## The list

`docs/hardware/list.tsv` has one row per report:

```text
report  level  who  day  note
```

`report` is the file beside the list, named for the machine in lower case,
such as `lenovo-thinkpad-x1-carbon-gen-9.txt`. `level` is `reported` or
`certified`. `who` vouches, `day` is the day the report was taken, and the
note says what a reader should know that the report cannot: a dock, a
firmware setting that had to change. A machine that runs a later release gets
a new report and a new row.

`tools/check-hardware.sh REPORT` prints what a report shows and the level it
carries, with each reason it falls short of `certified`. One line each says
what confines a device's DMA, and what the machine's sound, laptop parts,
sleep, camera and Bluetooth are and what drives them; no level asks for any
of them yet. `--list` checks the
whole list: every row's report is there and carries the level the row claims,
was taken on the row's day and not in a virtual machine, no report holds a
hardware address, a UUID or a serial number, and no report is without a row.
