# Hardware

Which machines Kryptik has been run on, who ran it, and what each run
showed. The list is `docs/hardware/list.tsv`; beside it sits one report per
row, made on the machine by `kryptik-hwreport`, and
`tools/check-hardware.sh --list` holds every row to its report. The list is
empty until the hardware tests planned for October 2026.

What the kernel is built to drive is in the [README](../README.md#hardware).
This page is about what was seen to work.

## A report

`kryptik-hwreport` prints what a machine is made of and what the image lacks
for it: the maker and model, the firmware's Secure Boot state, the processor
and its microcode, every PCI and USB device with the driver that took it, the
disks and the drivers under them, the display, network and input devices, the
loaded modules and the kernel log. Its `missing` section is the part to act
on: the firmware the kernel asked for and did not find, each a line for
`build/config/firmware.list`, and the devices and disks that want a driver's
line in `build/config/kernel/boot.fragment`.

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
network. It does not speak for what 1.0 does not drive (sound, Bluetooth,
suspend), for another firmware version, or for the same model sold with
another network card: the report names the firmware version and every device,
so a reader can compare.

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
carries, with each reason it falls short of `certified`. `--list` checks the
whole list: every row's report is there and carries the level the row claims,
no report holds a hardware address, a UUID or a serial number, and no report
is without a row.
