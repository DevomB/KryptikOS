# The laptop

The [roadmap](../roadmap.md)'s laptop item asks for per-zone sound brokered
like the clipboard, Bluetooth, suspend and resume with the volume keys
dropped across it, power management, hotplug and several monitors, and
keyboard layouts and input methods. Each part meets a rule the architecture
already set: [ADR-013](../decisions.md) builds no sound, the architecture
allows no shared D-Bus, the threat model gives up on a suspended machine,
there is no logind, and nothing reaches a zone except through its proxy and
its broker. One section each, with its options, its recommendation and its
check. The proposed decisions are ADR-021 and ADR-022 in
[decisions](../decisions.md).

## Sound

### Where things stand

`CONFIG_SOUND` is off ("no audio stack", `hardening.fragment`), ADR-013
lists sound among what Kryptik never builds, and ADR-012 left sound firmware
out. No zone has a sound device or a sound server.

### The kernel side

The drivers are modules, since nothing at boot needs them (ADR-013):
`snd-hda-intel` with its codecs, Intel's Sound Open Firmware drivers for
laptops with digital microphones, AMD's audio coprocessor drivers,
`snd-usb-audio`, and the smart-amplifier codecs (Cirrus, TI) many laptops
put on their speakers. Most of their firmware is in linux-firmware, but
Intel's SOF firmware and topology files are not: the SOF project publishes
them separately (sof-bin). That is a second firmware source, which ADR-012
has to name, with its own provenance row.

### Who holds `/dev/snd`

- **PipeWire in zone 0, with a socket per zone.** Its native protocol is
  large and its access control was built around portals that speak D-Bus.
  Every zone would talk to a big parser in zone 0. Rejected.
- **A sound zone, as the net zone holds the NICs.** The ALSA ioctls stay out
  of zone 0, but that zone hears every zone and holds the microphone. Once
  compromised it records whatever it likes and carries audio from one zone to
  another, and the microphone's gate would be enforced by the party it
  should restrain.
- **A small mixer in zone 0.** `kryptik-sound`, in Rust like kryptikd, runs
  as a user of its own in the `audio` group, never as root. It reads
  fixed-format sound from one socket per zone, mixes it, and plays it
  through alsa-lib, whose UCM configurations the SOF and AMD laptops need.
  The microphone's gate is trusted code, and only zone 0 reaches the sound
  drivers' ioctls.

### Recommendation: the mixer in zone 0, brokered like the clipboard

- **The channel.** `kryptik-sound` keeps one listening socket per configured
  zone. kryptikd binds that zone's socket into the zone at
  `/run/kryptik/sound` at launch, as it binds the broker and proxy sockets.
  The mixer checks the peer's uid against the zone's identity
  (`SO_PEERCRED`, as the [broker](broker.md#identity-is-the-peer-uid) does).
- **The wire.** One line, `play` or `record`, then raw interleaved frames:
  48 kHz, two channels, signed 16-bit little-endian, and nothing else. A
  fixed format leaves nothing to parse, and a zone that sends garbage plays
  noise in its own stream.
- **The microphone.** `record` is refused unless the user granted the
  microphone to that zone with a gesture in the chrome, as `m<N><M>` moves a
  clipboard. The grant lasts until the zone stops or the user takes it back,
  and only one zone holds it at a time. The chrome shows which zone is
  recording, and a zone hears nothing of any other zone.
- **Volume** and mute per zone are the chrome's, along with a key that mutes
  everything.
- **In the zone,** alsa-lib with a small PCM plugin as the default device
  writes to `/run/kryptik/sound`. Firefox built with `--enable-alsa` uses
  it directly. No PulseAudio or PipeWire runs in a zone.

### Check

QEMU's HDA device with its output written to a WAV file on the host (`-audiodev wav`):

- a tone played in `work` arrives in the file;
- two zones playing at once are mixed;
- `record` without a grant is refused, works after the chrome's gesture,
  and is refused again once the zone stops;
- a connection from another zone's uid is refused;
- no zone's `/dev` has a sound node.

## Bluetooth

### What the kernel and BlueZ allow

- **Sockets live in the initial namespace only.** `bt_sock_create` returns
  `EAFNOSUPPORT` in any network namespace but the initial one
  (`net/bluetooth/af_bluetooth.c` in 6.18). Every zone has its own network
  namespace, so no zone can use Bluetooth at all.
- **Management needs the initial namespace's capabilities.** The HCI
  management socket checks `CAP_NET_ADMIN` with `capable()`, against the
  initial user namespace (`hci_sock.c`).
- **BlueZ speaks only D-Bus.** bluetoothd offers its whole API on D-Bus,
  and the architecture allows no shared bus.
- **It faces a radio.** The kernel's Bluetooth stack and bluetoothd parse
  what any device in range sends. Remote kernel bugs in that stack have
  happened (BleedingTooth, in the L2CAP and A2MP code).
- **Keyboards are injection.** A Bluetooth keyboard is a uhid device that
  bluetoothd creates. Whoever controls bluetoothd can type into zone 0's
  chrome, the consent code included.

### Options

- **No Bluetooth.** As now: `CONFIG_BT` is not built. USB headsets and USB
  keyboards work.
- **bluetoothd in zone 0** with a private bus. A daemon that faces a radio
  would run in zone 0 with `CAP_NET_ADMIN` in the initial namespaces.
  Rejected.
- **A Bluetooth zone,** as the net zone holds the NICs. This needs a Kryptik
  kernel patch: `AF_BLUETOOTH` in the one network namespace kryptikd names,
  and the management socket's capability checked against that namespace's
  user namespace. bluetoothd and its own dbus-daemon run inside the zone; a
  bus inside one zone is not a shared bus. The zone carries audio only:
  bluealsa receives the mix from `kryptik-sound` as one more output and
  encodes it for the headset. The input plugin is left out and `/dev/uhid`
  never given, so a compromised Bluetooth zone hears what plays through the
  headset, and the headset's microphone when the user has chosen it, and
  types nothing anywhere.

### Recommendation

No Bluetooth until sound exists. Then a Bluetooth zone, audio only, with the
kernel patch carried on linux-hardened (ADR-009's rebase cost) and offered
upstream. Bluetooth keyboards and mice stay out for as long as a compromised
bluetoothd could type into the chrome.

### Check

The kernel's virtual HCI device (`hci_vhci`) gives the zones suite a
controller without a radio:

- the Bluetooth zone sees it, and every other zone gets `EAFNOSUPPORT`;
- zone 0 opens no Bluetooth socket;
- no `/dev/uhid` exists in any zone;
- an audio stream routed to the Bluetooth zone arrives at a test sink there.

## Suspend and resume, with the keys dropped

### Where things stand

Hibernation is off (`hardening.fragment`). Suspend to RAM comes from
defconfig, and no fragment turns it off. Nothing suspends the machine
today. The threat model says a suspended machine is not defended: its keys
are in RAM.

### Design

dm-crypt can suspend a mapping and wipe its key from kernel memory
(`cryptsetup luksSuspend`); `luksResume` needs a key again. With the root
on dm-verity, unencrypted and readable without any key, everything needed
to resume can run from the root while the state partition is suspended.

1. **Trigger.** The lid, the power key, an idle timeout or
   `kryptik suspend` asks the launch daemon, which runs the rest as root.
2. **Lock** the screen first (below).
3. **Freeze** every zone (`cgroup.freeze` on its leaf), so none is caught
   in the middle of I/O.
4. **Sync,** then suspend every open zone volume and then the state
   partition, wiping their keys.
5. **Sleep** (`/sys/power/state`).
6. **On waking,** the lock asks for the state partition's passphrase. The
   TPM is not used here: an unseal at resume would let whoever holds the
   machine resume it, and the TPM design extends PCR 15 at boot so that
   cannot happen anyway. `luksResume` brings `/var` and `/home` back, and
   the session thaws.
7. **Zones stay frozen** until the user gives each one's passphrase, when
   switching to it or from a list in the chrome. A zone the user never
   resumes is stopped when the user asks, and its volume closed.

**What runs while the state partition is suspended** must touch nothing
but the verified root and `/run`: the lock, the prompt, cryptsetup and the
launch daemon's resume path. Zone 0 programs that write to `/var/log` block
until resume, which is fine as long as none of them is on that path. The
suite proves it with a writer blocked on `/var` during the resume.

**The lock** does not exist yet. dwl 0.8 already implements
`ext-session-lock-v1`; what is missing is a lock client in zone 0, drawn by
the chrome. At resume the state passphrase is the unlock: whoever knows it
already owns the machine, so no PAM is needed. A lock without
suspend, on idle, takes the login password, checked by the launch daemon,
which can read the shadow file.

**The watchdog** must not reset a sleeping machine. The drivers stop their
timers across suspend; the suite proves it with a sleep longer than the
watchdog's timeout.

### What it changes in the threat model

Proposed text for "Coercion, and access to a running or suspended machine",
to apply with the change that builds this:

> Keys are in RAM while zones run. A suspended machine has wiped the keys of
> the state partition and of every zone volume, and resumes only with their
> passphrases; the TPM does not unlock it. What zone 0 and the zones held in
> memory is still there, and cold-boot and DMA attacks on a running or
> suspended machine stay out of scope. No software helps against coercion.

The "Offline physical access" section's "Not defended while running or
suspended" becomes "Not defended while running; while suspended, the disk's
keys are gone and memory is not".

### Check

The state suite under QEMU (`system_wakeup` resumes the VM):

- the suite formats the state partition and a zone volume with volume keys
  it chose, and a dump of the sleeping VM's memory taken from QEMU's monitor
  contains neither (`INIT_ON_FREE` zeroes what the kernel frees);
- a wrong passphrase leaves them suspended, and the right one resumes the
  state while the zones stay frozen until theirs are given;
- a writer blocked on `/var` does not stop the resume;
- the machine survives a sleep longer than the watchdog's timeout.

## Power management without logind

logind elsewhere handles seats and sessions (seatd does that here), the lid
and the power key, idle and inhibitors, suspend, and runtime directories
(the launch daemon creates them). What is left:

- **`kryptik-power`,** a small zone 0 service. It reads the lid switch and
  the power button from their input devices, and the battery and AC state
  from `/sys/class/power_supply`. It asks the launch daemon to suspend, and
  holds suspend off while `kryptik-update apply` writes a slot (the
  updater's lock). At critically low battery it shuts the machine down in
  order, zones stopped and volumes closed, since there is no hibernation.
- **Policy at boot.** A service writes a fixed policy from the verified
  root: `energy_performance_preference` set to `balance_power` on battery and
  `balance_performance` on AC (amd-pstate and intel_pstate both take it), and
  the kernel's defaults for PCIe link power and NVMe power states. No rule
  turns on USB autosuspend for input devices, which too often misbehave
  with it.
- **Brightness.** An eudev rule gives the `video` group write access to the
  backlight, the session user is in it, and dwl's keys run a small tool.
- **Idle.** dwl's idle notifier (`ext-idle-notify-v1`, in dwl 0.8) tells a
  zone 0 tool to blank the screen, then lock, then suspend. Zones may hold the screen awake through the
  proxy's idle inhibition (the browser design), and the chrome shows which
  zone does.
- The chrome shows the battery and AC state.

### Check

A test helper in zone 0 creates a lid switch and a power button through
uinput, and the kernel's test power supply (`test_power`, a test module like
`mac80211_hwsim`) reports a battery the suite can drain. Closing the lid
suspends, the update's lock holds that off, and a critical battery shuts the
machine down with every volume closed.

## Keyboard layouts and input methods

### Layouts

- **Today.** dwl's `xkb_rules` sets only `.options = NULL`
  (`build/desktop/dwl-config.h`), so libxkbcommon takes the layout from
  `XKB_DEFAULT_LAYOUT`, `XKB_DEFAULT_VARIANT` and `XKB_DEFAULT_OPTIONS`, or
  its default, `us`. The compositor compiles the keymap and sends it to
  each client as a descriptor in `wl_keyboard.keymap`, which the proxy
  passes on, so a zone receives a keymap zone 0 made and cannot change it.
- **The session's layout.** `kryptik-session` reads the user's layouts from
  their home (`~/.config/kryptik/keyboard`: layout, variant, options, and a
  list to switch between) and exports them to dwl. Switching is a
  compositor key. A keymap is not a privilege, so the state partition is a
  fine place for it.
- **The boot prompt's layout.** The state passphrase is typed before any
  state exists, on the console's keymap. The installer asks for a keymap
  and writes its name to the ESP; `sysinit` loads it with `loadkeys`, but
  only a name from the list of keymaps on the verified root. A bad name
  means the default, and a hostile one can do no more than make the prompt
  hard to type, which a writer of the ESP can already do.
- **Compose and dead keys** are the client's, from xkbcommon's compose
  tables, which the toolkit stack carries.

### Input methods

The protocols are `zwp_text_input_v3` (applications), `zwp_input_method_v2`
(the input method) and `zwp_virtual_keyboard_v1`, which some input methods
use to send keys.

- **One input method in zone 0, for every zone.** It sees every keystroke,
  as the compositor does, and its dictionary learns from all of them: words
  typed in `work` offered in `personal` link the two identities, and every
  zone's text is stored in zone 0. It would also be a large user program in
  zone 0 (ADR-003). Rejected.
- **One input method per zone, inside the zone.** That zone's proxy offers
  `zwp_input_method_manager_v2` to it alone. The compositor activates a
  zone's input method only while a text field of the same zone has focus,
  delivers its commits only to that zone's surfaces, and grants its
  keyboard grab only while that zone has focus. Its candidate window is a
  surface of that zone, with that zone's border. `zwp_virtual_keyboard_v1`
  is never offered: its keys go to whatever has focus, which may be another
  zone or the chrome.

Recommendation: one input method per zone, with `zwp_text_input_v3` and
`zwp_input_method_v2` offered only to zones whose file asks
(`[input] method = true`), and never the virtual keyboard. dwl has no
input-method support upstream; wlroots has the protocol helpers, and the
routing by zone is Kryptik's work. Whether fcitx5 or ibus work without the
virtual keyboard is checked before either is chosen.

### Check

`make gui-test` with a test input method in `work`:

- it receives keys only while a `work` window has focus;
- its commit lands in that window;
- it gets nothing while a `personal` window or the chrome has focus;
- binding `zwp_virtual_keyboard_manager_v1` through any proxy disconnects
  the client;
- a layout set in the session reaches a zone's client in its keymap.

## Hotplug and several monitors

dwl follows outputs as they come and go through wlroots' DRM backend and
eudev, and draws borders and the chrome on each. What needs deciding is
what zones learn. `wl_output` carries the monitor's make, model and name,
which come from its EDID and sometimes include a serial. Every zone sees the
same values, which links zones to each other and to the machine. The proxy
rewrites them to neutral values per output (`Monitor 1`) and keeps the
geometry and scale. Check: through any zone's proxy, `wl_output` reports no
make, model or serial from the EDID, and a second monitor plugged into the
VM appears in every zone.

## Order

1. Layouts, the lock and suspend with the keys dropped: they need nothing
   new in the kernel.
2. Power management.
3. Sound.
4. Input methods per zone.
5. Bluetooth audio, last, since it needs sound and a kernel patch.

The item is done when every check above passes in `make acceptance`.
