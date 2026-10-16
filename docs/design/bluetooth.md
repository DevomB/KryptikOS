# Bluetooth

A call needs a headset as much as a camera, and many headsets speak only
Bluetooth. Kryptik builds none: the kernel has no Bluetooth, no
controller's firmware ships, and nothing pairs. The
[laptop design](laptop.md#bluetooth) put Bluetooth, when it comes, in a zone
of its own, carrying audio only. This design weighs that against shipping
without it, and against what the hand-off to zone 0's mixer would add
there.
[ADR-027](../decisions.md) decides it: none for 1.0, then a zone of its own.

## What a Bluetooth stack is

- **In the kernel:** the HCI core and the controller's transport (`btusb`,
  as nearly every laptop's controller sits on its internal USB), and the
  protocols above them: L2CAP, which carries A2DP's media and signalling,
  RFCOMM for the hands-free profile's commands, SCO for its call audio, SMP
  for pairing. What any device in radio range sends reaches this code once
  the controller is up and scanning, pairing or connected.
- **Firmware:** Intel, Realtek and MediaTek controllers load theirs from
  linux-firmware (`intel/ibt-*`, `rtl_bt/*`, `mediatek/BT_RAM_CODE_*`), which
  `build/config/firmware.list` leaves out.
- **In userspace:** BlueZ's `bluetoothd`, whose only interface is D-Bus,
  which keeps the pairing keys and runs each profile's signalling; and an
  audio server (PipeWire, PulseAudio or bluez-alsa) that registers with it
  over D-Bus, encodes SBC or AAC for the headset and decodes the call's
  audio (CVSD or mSBC).

## What reaches it

- **Anyone in radio range.** BlueBorne (CVE-2017-1000251) and BleedingTooth
  (CVE-2020-12351) were remote code execution in the kernel's L2CAP, needing
  no click, against a machine whose Bluetooth was on. A bug there is in
  every zone's kernel.
- **A keyboard.** BlueZ took an unauthenticated device's HID connection and
  its keystrokes (CVE-2023-45866): a keyboard over Bluetooth types into
  whatever has focus, the chrome included. ADR-027 leaves keyboards out.
- **The namespaces.** The kernel refuses `AF_BLUETOOTH` sockets outside the
  initial network namespace (`bt_sock_create`), and asks the initial user
  namespace for what BlueZ needs: `CAP_NET_ADMIN` for a trusted management
  socket, `CAP_NET_BIND_SERVICE` for the profiles' fixed L2CAP channels
  (A2DP's is 25). A zone, with a network and a user namespace of its own,
  has neither.

## Options

- **No Bluetooth for 1.0.** Calls go through a USB or wired headset, through
  the mixer as now. Many Bluetooth headsets sold for calls come with a USB
  dongle that presents itself as a USB sound card, the pairing kept inside
  the dongle; those work as USB headsets do, the kernel's Bluetooth code is
  not built, and only the dongle hears the radio. Keyboards and mice with a
  USB receiver work as USB devices already do.
- **A Bluetooth zone, with a kernel patch.** The laptop design's direction. A Kryptik
  patch lets one network namespace, the Bluetooth zone's, make Bluetooth
  sockets, and has each Bluetooth capability check ask that namespace's
  user namespace, so the zone's own root has what bluetoothd needs and no
  more. The zone holds the controller as the net zone holds the NICs and
  runs bluetoothd on a bus of its own, and a headset's audio goes to and
  from the mixer as below. The patch touches every Bluetooth socket family
  and capability check, and is rebased with linux-hardened at every release
  (ADR-009).
- **A Bluetooth zone in the initial network namespace.** No patch: the zone
  shares zone 0's network namespace, which holds no interface, and keeps
  every other namespace of its own. It would need `CAP_NET_ADMIN` and
  `CAP_NET_BIND_SERVICE` in the initial user namespace, which reach well
  past Bluetooth, netfilter and routing among them, and it reaches zone 0's
  abstract Unix sockets unless Landlock's scoping holds it off.
- **A host stack in userspace, on the controller's user channel.** kryptikd
  binds the controller's HCI user channel (`HCI_CHANNEL_USER`, which takes
  the controller from the kernel's stack) and passes the descriptor to a
  zone with namespaces of its own, as it passes a stick. The kernel's L2CAP,
  RFCOMM and SCO then never run for it. No free stack carries a headset's
  audio today: BTstack's licence allows only non-commercial use, and Bumble
  is built for testing.
- **BlueZ in zone 0.** Rejected by ADR-027: a large daemon, root, on D-Bus,
  which zone 0 does not run, parsing what the radio brings.

## The hand-off to the mixer

A Bluetooth zone adds to zone 0 what the mixer must do with a headset:

- **Output.** The mix goes to a socket the Bluetooth zone reads, 48 kHz
  stereo 16-bit as zones' streams are, once the user picks the headset.
  Zone 0 writes, and reads nothing back.
- **The microphone.** During a call the headset's microphone comes back
  from the Bluetooth zone in the same fixed format, decoded and resampled
  there, and the mixer reads it as it reads a zone's playback, passing it
  only to the zone granted the microphone. The gate stays in zone 0.
- **Control.** A few fixed lines: which headset is connected (its name came
  over the radio, so the chrome shows it as it shows a stick's), and a
  request to switch to the hands-free profile while a zone holds the
  microphone, and back.
- **Clocking.** No card paces a headset: the mixer writes as fast as the
  Bluetooth zone reads, and drops or pads to keep the delay bounded.

That is one more device and a parser of a few fixed lines in the mixer.
The radio, the codecs and pairing stay out of zone 0.

## The decision

ADR-027 decides: for 1.0, no Bluetooth. No `btusb`, no controller's
firmware, nothing pairs, and the guide says so: USB and wired headsets, and
Bluetooth headsets with a USB dongle that is a USB sound card. After 1.0,
the Bluetooth zone with the kernel patch, for a headset's audio alone. Its
modules are kept from loading by alias, as `uvcvideo` is (ADR-026), so the
controller is up and the kernel's Bluetooth code reachable only while the
user has turned Bluetooth on in the chrome, which says so for as long as it
is. That is the direction, not yet the patch: its code and the cost of
rebasing it are weighed again when the work starts, and a free host stack on
the user channel takes the zone's place if one carries a headset's audio by
then.

## Check, when it comes

QEMU has no Bluetooth controller. The kernel's `hci_vhci` makes virtual
ones, and BlueZ's emulator can play a headset on a second, as `vivid`
plays a camera:

- with Bluetooth off, no Bluetooth module is loaded and the controller is
  blocked;
- turned on, the headset pairs only through the chrome, and its name shows
  plainly;
- a tone a zone plays reaches the headset, and its microphone reaches only
  the zone granted the microphone;
- no zone but the Bluetooth zone can make a Bluetooth socket;
- turned off, the modules unload and the controller is blocked again.

## Not covered

- Keyboards and mice, which ADR-027 leaves out.
- File transfer, tethering, LE Audio and hearing aids.
- Which USB devices are accepted at all, the dongles among them.
