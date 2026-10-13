# The laptop

The [roadmap](../roadmap.md)'s laptop item asks for per-zone sound brokered
like the clipboard, Bluetooth, suspend from the lid, the power key and
idleness with the zone volumes' keys dropped too, power management, hotplug
and several monitors, and keyboard layouts and input methods. Each part
meets a rule the architecture already set: [ADR-013](../decisions.md) builds
no sound, the architecture allows no shared D-Bus, the threat model gives up
on a suspended machine's memory, there is no logind, and nothing reaches a
zone except through its proxy and its broker. One section each, with its
options, its recommendation and its check. In [decisions](../decisions.md),
ADR-021 is proposed and ADR-022, for suspend, accepted.

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
defconfig, and no fragment turns it off. `kryptik suspend` is the one way
the machine sleeps: the screen locks, the launch daemon freezes every zone,
suspends the state partition with its key wiped and puts the machine to
sleep, and on waking the lock asks for the state passphrase. A running
zone's volume keeps its key, as its zone is frozen, not stopped; dropping
those keys too comes next (below). Neither the lid, the power key nor
idleness suspends the machine yet (power management, below).

### Design

dm-crypt can suspend a mapping and wipe its key from kernel memory
(`cryptsetup luksSuspend`); `luksResume` needs a key again. With the root
on dm-verity, unencrypted and readable without any key, everything needed
to resume can run from the root while the state partition is suspended.

1. **Trigger.** `kryptik suspend` runs `kryptik-lock --suspend`; the lid,
   the power key and an idle timeout are to ask the same way. The launch
   daemon runs the rest as root (`suspend`), and refuses while a zone is
   starting or `kryptik-update apply` holds the updater's lock.
2. **Lock** the screen first: the lock asks for the suspend only once dwl
   has confirmed it, and checks nothing typed while the request is under
   way, so no session sleeps, or wakes, open.
3. **Freeze** every zone (`cgroup.freeze` on its leaf), so none is caught
   in the middle of I/O. A zone with no leaf, or one that is not frozen
   within 10 s, thaws the others and the suspend is refused.
4. **Sync,** then suspend the state partition, wiping its key. A zone
   volume's file is on the partition, so the sync writes the volume out
   through it first.
5. **Sleep** (`/sys/power/state`).
6. **On waking,** the lock asks for the state partition's passphrase. The
   TPM is not used here: an unseal at resume would let whoever holds the
   machine resume it, and the TPM design extends PCR 15 at boot so that
   cannot happen anyway. `luksResume` brings `/var` and `/home` back, and
   the zones thaw.
7. **Zone volumes, next.** Each open zone volume suspended before the state
   partition, its key wiped, and its zone frozen until the user gives its
   passphrase through the launcher's `--ask` flow, when switching to it or
   from a list in the chrome. A zone the user never resumes is stopped
   when the user asks, and its volume closed.

**What runs while the state partition is suspended** must touch nothing
but the verified root, `/run`, `/dev`, `/proc` and `/sys`: whatever reaches
`/var`, `/home`, `/root` or the upper layer of `/etc` waits for the
partition, and so does a lookup the dentry cache has let go of. The launch
daemon learns that the partition is suspended from device-mapper's
`suspended` file in sysfs, before it reads `/etc/group` for anything, and
until it has its key answers only the lock's two questions (`unlock-kind`,
`resume-state`), to whoever reached its root:kryptik socket; started again
in that time, it takes the socket's group from its directory. It runs
`cryptsetup luksResume` in a mount namespace of its own, without `/var`,
`/home`, `/root` and the overlay on `/etc`, so the loader and cryptsetup
read the verified root's `/etc` and nothing else. The lock talks to the
daemon's socket itself rather than through a program it starts, and the
watchdog's feeder waits with a shell builtin, not `sleep`. Zone 0 programs
that write to `/var/log` block until resume, which is fine as long as none
of them is on that path; the suite proves it with a writer blocked on
`/var` during the resume.

**The lock** is `kryptik-lock` (`tools/desktop/kryptik-lock.c`), a client of
dwl's `ext-session-lock-v1` in zone 0 that Alt+Shift+l starts. While it
runs, dwl shows only its surfaces, one per output, and gives them every key;
they show LOCKED and a mark per character typed, nothing else. The lock
takes the login password and hands it to the launch daemon over its socket
(`check-password`), which reads the shadow file and checks it against the
session user's own entry with crypt(3), so the lock never sees a hash and
no PAM is needed. After a wrong password the daemon checks nothing for 2 s,
doubling to 60 s, as the consent window does. dwl keeps a session locked
when its lock dies and then takes no keys, so the lock runs in a child that
starts again when a signal kills it. After a suspend the state passphrase
is the unlock instead: whoever knows it already owns the machine. The lock
asks the daemon what unlocks (`unlock-kind`) when it starts, at the first
key of each entry and before it sends what was typed; it shows LOCKED or
STATE PASSPHRASE, and drops what was typed under a label that no longer
holds, so the login password never reaches `luksResume` nor the state
passphrase the login check. The passphrase goes to the daemon in a pipe
beside `resume-state`, with its own pause after a wrong one, and on to
cryptsetup's standard input. On idle, the chrome starts `kryptik-lock
--idle`, which waits on dwl's `ext-idle-notify-v1` and locks after ten
minutes without input, or the minutes in `~/.config/kryptik/lock-idle` (0
never). A minute after the lock it turns the screens off through dwl's
`zwlr_output_power_manager_v1`, and the first key or movement turns them on
again; an unlock turns them on as well, should the watcher be gone. It
counts input alone (the protocol's version 2), so an idle inhibitor, which
the browser design would let a zone hold to keep the screen awake, never
keeps the session unlocked or the screens lit. No zone can bind the
notifier, which would tell it when the user is away.

The lock's check, in `make gui-test`:

- from the command line, the right password right after a wrong one is told
  to wait, the right one after the pause is taken, and neither reaches a
  log;
- Alt+Shift+l takes the keyboard from zone 0's window while a zone's popup
  holds a grab no input gave, and closes that popup;
- the screenshot shows nothing but the lock;
- a wrong password is refused;
- the lock's program killed leaves the session locked with no window given
  the keyboard, and the lock locks again;
- a grab a zone makes while locked keeps no key from the lock;
- the login password unlocks, and zone 0's window has the keyboard again;
- the chrome arms the idle lock at ten minutes, and an idle lock of 8 s
  locks the session, turns the screen off 4 s later as the compositor
  reports to it, turns it on at the first key, and locks again after the
  next 8 s once unlocked.

**The watchdog** must not reset a sleeping machine, nor one waiting at the
state prompt. The drivers stop their timers across suspend, and the feeder
starts no program, so it goes on feeding while the partition is suspended.

### In the threat model

A suspended machine has wiped the state partition's key and resumes only
with its passphrase; the TPM does not unlock it. A running zone's volume
keeps its key for now, and what zone 0 and the zones held in memory is
still there ([threat model](../threat-model.md#coercion-and-access-to-a-running-or-suspended-machine)).

### Check

`make suspend-test`, on the installed system with suspend to RAM offered
(`run-ovmf.sh --s3`; QEMU's `system_wakeup` wakes it). With the machine up,
first:

- `kryptikd suspend --awake` drops the state partition's key and freezes
  every zone, the net zone among them, and the dentry and inode caches are
  dropped after it;
- a lock dwl starts then asks for the state passphrase, a client's request
  is refused at once, and nothing but a writer on `/var` waits on the
  partition: not the lock, dwl, the chrome, the daemon, the watchdog's
  feeder or s6;
- a wrong passphrase leaves the partition suspended, and the right one,
  typed at the lock, resumes it, unlocks, and lets the writer and the zones
  go on.

Then for real, `kryptik-lock --suspend` as the user:

- the machine sleeps, and a dump of its memory taken from QEMU's monitor
  holds neither half of the state partition's key nor the passphrase typed
  at the lock before, and does hold the key of the zone volume a frozen
  zone keeps, which shows the search can find one (`INIT_ON_FREE` zeroes
  what the kernel frees);
- it sleeps past the watchdog's timeout, wakes with the lock asking for the
  state passphrase, and waits three minutes at it, the caches dropped again,
  without a reset;
- the passphrase resumes it, and the zones thaw.

## Power management without logind

logind elsewhere handles seats and sessions (seatd does that here), the lid
and the power key, idle and inhibitors, suspend, and runtime directories
(the launch daemon creates them). What is left:

- **`kryptik-power`,** a small zone 0 service. It reads the lid switch and
  the power button from their input devices, and the battery and AC state
  from `/sys/class/power_supply`. It asks for a suspend as `kryptik
  suspend` does, through the lock, and the launch daemon holds it off while
  `kryptik-update apply` writes a slot (the updater's lock). At critically
  low battery it shuts the machine down in
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
  zone 0 tool to blank the screen, then lock, then suspend. The lock and
  blanking are built (`kryptik-lock --idle`, above), in the other order: a
  screen turned off while unlocked would come back on to an open session at
  the first touch. Suspending when idle is not built.
- **Holding the screen awake.** A zone playing a video may hold off both the
  lock and the blanking, through the proxy's idle inhibition (the browser
  design), under these conditions. They come with the browser image, the
  first thing that needs them; until then no zone can, and both count input
  alone.
  - The zone's file on the verified root opts in (`[desktop] hold_awake =
    true`). It is off by default, and never set for `untrusted`, where
    unknown links open.
  - A hold counts only while the inhibiting surface is mapped and visible on
    a lit output and its zone's window has the keyboard; losing either ends
    it.
  - It is capped at four hours, after which the lock comes as usual, and any
    zone 0 action, a lid close or a suspend ends it. The chrome shows which
    zone holds the screen awake for as long as it does.
  - The moment no hold qualifies, the lock and the blanking count input
    alone again.
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
