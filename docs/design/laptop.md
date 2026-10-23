# The laptop

The [roadmap](../roadmap.md)'s laptop item asks for per-zone sound brokered
like the clipboard, Bluetooth, suspend from the lid, the power key and
idleness with the zone volumes' keys dropped too, power management, hotplug
and several monitors, and keyboard layouts and input methods. Each part
meets a rule the architecture already set: [ADR-013](../decisions.md) builds
in only what boot needs, the architecture allows no shared D-Bus, the threat model gives up
on a suspended machine's memory, there is no logind, and nothing reaches a
zone except through its proxy and its broker. One section each, with its
options, its recommendation and its check. In [decisions](../decisions.md),
ADR-021 decides sound, ADR-022 suspend, ADR-027 Bluetooth and ADR-028
input methods.

## Sound

### Where things stand

The kernel builds HD Audio and USB audio as signed modules
(`boot.fragment`), and the image carries alsa-lib without its use-case
manager and DSP topology parts; its MIDI and sequencer API is there for
Firefox's Web MIDI and finds no device, as the kernel builds no sequencer
and no zone has `/dev/snd`. `kryptik-sound` mixes
in zone 0 and every zone but the net zone plays through it, as the
recommendation below has it. The chrome's menu grants the microphone
(`c<N>`, and `c` takes it back), sets the volume of all and of each zone
(`v<D>`, `v<N><D>`) and mutes (`x`), and names the zone that may record and
whether it does; the keyboard's volume keys step the volume, its mute key
mutes, and its microphone key takes the microphone back, under the screen
lock too. Some laptops, ThinkPads among them, send the microphone key only
through their maker's platform driver (`thinkpad_acpi`, `ideapad-laptop`,
`asus-nb-wmi`, `dell-wmi`, `hp-wmi`), which the kernel does not build, so
there it does nothing. While a zone holds the microphone, a window of the
chrome's says so, and says when it records; it opens on the grant, so it
takes the keyboard from the menu the gesture was typed in, not from a
zone, and closes when the grant ends.

### The kernel side

The drivers are modules, since nothing at boot needs them (ADR-013). Built:
`snd-hda-intel`, with the codec drivers of the machines that boot UEFI
(Realtek, Conexant, Senarytech, IDT, Cirrus, and the HDMI and DisplayPort
codecs of Intel, AMD and NVIDIA graphics) and the generic parser for any
other codec, and `snd-usb-audio`; none of them needs firmware. The kernel
loads no module by itself (`STATIC_USERMODEHELPER`), and a codec binds only
to a driver loaded when the controller probes it, so modprobe loads every
codec driver ahead of `snd-hda-intel` (`build/config/modprobe.d/sound.conf`,
which stage 05 holds to the drivers built).

Not yet: Intel's Sound Open Firmware drivers for laptops with digital
microphones or SoundWire codecs, AMD's audio coprocessor drivers, and the
smart-amplifier codecs (Cirrus, TI) many laptops put on their speakers.
[Laptop sound past HD Audio](laptop-audio.md) says what each needs, what a
laptop does without it, and the order they come in after 1.0.

### Who holds `/dev/snd`

- **PipeWire in zone 0, with a socket per zone.** Its native protocol is
  large and its access control was built around portals that speak D-Bus.
  Every zone would talk to a big parser in zone 0. Rejected.
- **A sound zone, as the net zone holds the NICs.** The ALSA ioctls stay out
  of zone 0, but that zone hears every zone and holds the microphone. Once
  compromised it records whatever it likes and carries audio from one zone to
  another, and the microphone's gate would be enforced by the party it
  should restrain.
- **A small mixer in zone 0.** `kryptik-sound` runs as a user of its own
  in the `audio` group, never as root. It reads fixed-format sound from one
  socket per zone, mixes it, and plays it through alsa-lib, whose UCM
  configurations the SOF laptops would need. The microphone's gate is
  trusted code, and only zone 0 reaches the sound drivers' ioctls. It is C,
  built in stage 04 with the hardening flags like the screen lock, not Rust
  like kryptikd: alsa-lib is a glibc library that loads its plugins, and
  kryptikd is a static musl binary built outside the image.

### Recommendation: the mixer in zone 0, brokered like the clipboard

- **The channel.** `kryptik-sound` keeps one listening socket per zone,
  `/run/kryptik-sound/zones/NAME/socket`, for every zone whose file lets it
  play (`kryptikd sound zones`): not the nic zone, and not `vault`, whose
  file says `[sound] play = false`, as secrets have no use for a way out to
  the room that nothing mediates. Its service makes each socket's directory as
  root, and kryptikd binds that directory into the zone at
  `/run/kryptik/sound` at launch, as it binds the broker and proxy sockets:
  the directory, so the socket a restarted mixer makes is the one a running
  zone reaches, and one root owns, so the mixer cannot have it name another
  place. The mixer checks the peer's uid against the uid the zone's root
  maps to (`SO_PEERCRED`, as the [broker](broker.md#identity-is-the-peer-uid)
  does), and a zone holds at most eight streams.
- **The mixer's user** is uid 87 in group `audio` (11) and nothing else,
  fixed numbers set by its service, so no line under `/etc`, whose upper
  layer state can change, decides who it is. It refuses to run as root.
- **The wire.** One line, `play` or `record`, then raw interleaved frames:
  48 kHz, two channels, signed 16-bit little-endian, and nothing else. A
  fixed format leaves nothing to parse, and a zone that sends garbage plays
  noise in its own stream.
- **The microphone.** `record` is refused unless the user granted the
  microphone to that zone with a gesture in the chrome, as `m<N><M>` moves a
  clipboard. The grant lasts until the zone stops (kryptikd says `revoke
  NAME` when its zone exits) or the user takes it back, and only one zone
  holds it at a time. The chrome shows which zone is recording (the
  control socket's `status`), and a zone hears nothing of any other zone.
  It can tell one thing: the card stays open five seconds after the last
  sound, so how soon its own first sound is taken says whether any zone
  played in that time, a bit two zones could also signal through. Keeping
  the card open always would close it, at the codec's power saving.
- **Volume** and mute per zone are the chrome's, along with a key that mutes
  everything (`mute toggle`) and the volume keys' steps (`volume +5`,
  `volume -5`); the microphone key says `revoke`. The mixer applies the
  volumes, squared so the steps sound even, and
  sets the card's own controls to unity when it opens it, so a card that
  came up muted plays. The volumes and mutes outlast the mixer: it keeps a
  record of them in `/run`, where a restart starts from it, and its
  service's finish script carries it to the state partition
  (`/var/lib/kryptik-sound/levels`), reading it with the mixer's rights and
  keeping only the lines such a record holds, for the run script to put
  back after a boot. The microphone's
  grant is never kept, and neither script looks at the state partition
  while a sleep seals it.
- **The card** is a USB device when one is plugged in, as it is plugged in
  to be used, otherwise the first card with a device 0; an HDMI-only card
  has none. The mixer opens it only while something plays and closes it
  five seconds after, so the codec can power down. While a stream runs it
  looks again each second, so a headset plugged in during a call takes the
  call, and the recording too.
- **In the zone,** alsa-lib with a small PCM plugin as the default device
  writes to `/run/kryptik/sound/socket` (`/usr/etc/alsa/conf.d`, on the
  verified root, which every zone reads). Firefox built with
  `--enable-alsa` uses it directly. No PulseAudio or PipeWire runs in a
  zone.

### Check

QEMU's HDA device with its output written to a WAV file on the host (`-audiodev wav`),
in `make sound-test`, all of which it checks but the keys, which
`make gui-test` presses:

- the card registers at boot with its codec bound, every codec driver
  loaded ahead of the controller;
- a zone's `/proc/asound` is empty: the PCM status there would show when
  another zone plays or records, and the codec files name the model;
- a tone played in a zone arrives in the file;
- two zones playing at once are mixed;
- `record` without a grant is refused, works after the grant, shows in the
  status while it records, and is refused again once the zone stops;
- the chrome's menu grants the microphone, names the zone that has it and
  takes it back, and sets the volume of all and of one zone and mutes;
- a connection from another uid than the zone's is refused;
- no zone's `/dev` has a sound node, and no zone reaches the control
  socket;
- the mixer runs as uid 87 in group `audio` alone;
- the volume-down key steps the mixer's volume, and under the screen lock
  the volume-up and mute keys still act while Alt+p opens no menu
  (`make gui-test`, where the mixer runs without a card).

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
bluetoothd could type into the chrome. [Bluetooth](bluetooth.md) weighs this
again, and ADR-027 decides it: none for 1.0, then that zone.

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
defconfig, and no fragment turns it off. `kryptik suspend`, the power key
and a closed lid have the machine sleep, and so does idleness after the
lock when the user asks for it: the screen locks, the launch daemon freezes
every zone, suspends each open zone volume and then the state partition
with their keys wiped and puts the machine to sleep, and on waking the lock
asks for the state passphrase. A zone on a volume stays frozen after that
until its own passphrase is given (below). The lid is untested until the
tests on physical hardware.

### Design

dm-crypt can suspend a mapping and wipe its key from kernel memory
(`cryptsetup luksSuspend`); `luksResume` needs a key again. With the root
on dm-verity, unencrypted and readable without any key, everything needed
to resume can run from the root while the state partition is suspended.

1. **Trigger.** `kryptik suspend`, the power key and a closed lid run
   `kryptik-lock --suspend`: the power key through dwl's binding, the lid
   through a switch handler Kryptik adds to dwl. A lock that is up writes
   its supervisor's pid to `$XDG_RUNTIME_DIR/kryptik/lock.pid`, and
   `kryptik-lock --suspend` asks that lock instead (SIGUSR1) when the
   file is the user's own, mode 600, and names a process of this program
   run by the user. dwl runs only the volume and brightness keys while
   locked (`lockedkeys` in its configuration), so the lock takes the
   power key itself, but none for 10 s after a wake: on some machines the
   press that wakes it reaches the input layer as the power key, which
   would put it straight back to sleep. A lid that closes while an output
   other than the built-in panel is on, docked, is left alone, as is one
   libinput says is closed as the switch appears. dwl still knows either is
   shut: when a screen goes and five seconds later none but the panel is
   left, as when the dock is unplugged, the machine sleeps as a lid closed
   undocked would. The wait covers a dock that takes its screens away and
   back again around a sleep. Idleness asks too,
   `kryptik-lock --idle --sleep`, but
   only as many minutes after the lock as `~/.config/kryptik/lock-sleep`
   holds: a sleep that does not wake would cost open work nobody chose to
   risk, so it stays off until resume is proven on physical hardware, and 20
   is the value to use then. The launch daemon runs the rest as root
   (`suspend`), and refuses while a zone is starting or `kryptik-update
   apply` holds the updater's lock. It refuses first, before anything is
   frozen, on a machine whose display is virtio-gpu, as a virtual machine's
   often is: 6.18's driver has no suspend callbacks, so a sleep resets the
   device under it, and the compositor's next commit that waits on the
   device never finishes. The suspend suite's VM shows through std VGA's
   framebuffer for that reason.
2. **Lock** the screen first: the lock asks for the suspend only once dwl
   has confirmed it, and checks nothing typed while the request is under
   way, so no session sleeps, or wakes, open.
3. **Freeze** every zone (`cgroup.freeze` on its leaf), so none is caught
   in the middle of I/O. A zone with no leaf, or one that is not frozen
   within 10 s, thaws the others and the suspend is refused.
4. **Sync,** then suspend the state partition, wiping its key. A zone
   volume's file is on the partition, so the sync writes the volume out
   through it first. The kernel's own sync before it sleeps is turned off
   (`/sys/power/sync_on_suspend`), as it could wait on the suspended
   partition for good, and on again once the partition is back.
5. **Sleep** (`/sys/power/state`), written by a child of the daemon's, so
   the daemon goes on answering the lock while the kernel puts the machine
   to sleep, or refuses to: a task it cannot freeze, such as one waiting on
   the suspended partition's device, makes it give up after 20 s, and the
   lock says so. Asked again at the passphrase prompt, as a lid closed on
   it would, the daemon only sleeps. Most laptops made since about 2020
   offer only s2idle, which `mem` then means; there the platform's power
   controller driver (`amd-pmc`, `intel_pmc_core`, both modules) takes the
   SoC to its deepest state, without which a sleeping laptop drains its
   battery far sooner.
6. **On waking,** the lock asks for the state partition's passphrase. The
   TPM is not used here: an unseal at resume would let whoever holds the
   machine resume it, and the TPM design extends PCR 15 at boot so that
   cannot happen anyway. `luksResume` brings `/var` and `/home` back, and
   the zones thaw.
7. **Zone volumes.** After the flush the clean page cache goes
   (`drop_caches`), so no cached page of a volume's files outlives its key,
   and each open zone volume is suspended before the state partition, which
   holds its file, its key wiped. At resume the zones without a volume thaw
   with the state partition. One with a volume stays frozen until its own
   passphrase comes, through the launch daemon's `resume-zone` (or
   `kryptikd volume resume` as root); the daemon's `info` says `waiting yes`
   meanwhile, and a launch into it is told why. Once the state partition is
   back the chrome opens a window that asks for each waiting zone's
   passphrase in turn (`kryptik-launch --resume`, on its own terminal), as
   it does when a sleep fails after a zone volume's key went, which the
   daemon counts in `/run/kryptik-launch/left-waiting`;
   the menu shows the zone WAITING and takes it with `p<N>`, and
   `kryptik-launch --ask`, as the zone keys run it, asks for it instead of
   starting the zone again. Stopped without its
   passphrase, the zone's volume is first made to fail every read and write
   (`dmsetup wipe_table`), so nothing in it waits on the volume for good,
   and then closes as any other; the next start checks it. At power-off a
   mapping still waiting, a zone volume's or the state partition's, is made
   to fail the same way first, so the unmount does not wait on it. No zone
   keeps its key across a sleep: a zone file key to opt out would come with
   a workflow that needs it.

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
holds, and anything typed in the second after the label changes, so the
login password never reaches `luksResume` nor the state passphrase the
login check. The passphrase goes to the daemon in a pipe
beside `resume-state`, with its own pause after a wrong one, and on to
cryptsetup's standard input. On idle, the chrome starts `kryptik-lock
--idle`, which waits on dwl's `ext-idle-notify-v1` and locks after ten
minutes without input, or the minutes in `~/.config/kryptik/lock-idle` (0
never). A minute after the lock it turns the screens off through dwl's
`zwlr_output_power_manager_v1`, and the first key or movement turns them on
again; an unlock turns them on as well, should the watcher be gone. It
counts input, and a hold dwl counts for a zone under the conditions in
Holding the screen awake, below; an inhibitor of any other zone, or of
zone 0, never keeps the session unlocked or the screens lit. No zone can
bind the notifier, which would tell it when the user is away.

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
state prompt. Intel's timer stops across every sleep, and in ACPI's own
sleep states the firmware stops the rest.

On a machine that sleeps to idle, two timers would go on counting through
it, so the feeder leaves both unopened:
- AMD's timer, whose driver does not stop it;
- the software watchdog, whose clock runs while the s2idle loop handles an
  event that wakes nothing, amd_pmc's 2.5 s pause after each deepest sleep
  included.

The feeder starts no program, so it goes on feeding while the partition is
suspended.

### In the threat model

A suspended machine has wiped the state partition's key and every zone
volume's, and resumes only with their passphrases; the TPM does not unlock
it. The clean page cache went before the sleep, but what zone 0 and the
zones' processes hold in their own memory, the files they have mapped
included, is still there
([threat model](../threat-model.md#coercion-and-access-to-a-running-or-suspended-machine)).

### Check

`make suspend-test`, on the installed system with suspend to RAM offered
(`run-ovmf.sh --s3`; QEMU's `system_wakeup` wakes it). With the machine up,
first:

- `kryptikd suspend --awake` drops the state partition's key and the work
  zone volume's and freezes every zone, the net zone among them, and the
  dentry and inode caches are dropped after it;
- a lock dwl starts then asks for the state passphrase, a client's request
  is refused at once, and nothing but a writer on `/var` waits on the
  partition: not the lock, dwl, the chrome, the daemon, the watchdog's
  feeder or s6;
- a wrong passphrase leaves the partition suspended, and the right one,
  typed at the lock, resumes it, unlocks, and lets the writer and the zone
  without a volume go on;
- the work zone, on a volume, stays frozen with its volume suspended: the
  daemon's `info` says it waits, a launch into it is told why, a wrong
  passphrase leaves it waiting, and its own, typed in the window the
  chrome opens to ask for it, thaws it.

Then for real, `kryptik-lock --suspend` as the user:

- the machine sleeps, and a dump of its memory taken from QEMU's monitor
  holds no half of the state partition's key or of the zone volume's, no
  page the volume had cached, and not the passphrase typed at the lock
  before, and does hold bytes kept in a file on `/run`, which shows the
  search finds what is there (`INIT_ON_FREE` zeroes what the kernel
  frees);
- after the wake and the state passphrase, the work zone waits again; it
  stops without its passphrase, its volume closing, and starts again with
  it, the volume checking clean;
- it sleeps past the watchdog's timeout, wakes with the lock asking for the
  state passphrase, and waits three minutes at it, the caches dropped again,
  without a reset;
- the passphrase resumes it, and the zones thaw;
- asked to sleep again with the partition suspended and a read left waiting
  on its device, the kernel refuses, the refusal is told, and the passphrase
  still brings the partition back;
- the power button, pressed through QEMU's monitor, has the machine sleep
  with the session unlocked and with it locked, but not when pressed a
  moment after a wake, and again once 10 s have passed; `kryptik-lock --suspend`
  with a lock up hands the sleep to that lock, whose pid file is the user's
  own, mode 600, and goes at the unlock; and an idle watcher with
  `--sleep` has its lock ask. Each wake waits for the passphrase.

Whether the guest slept or the kernel refused is told either way, so a
refusal in the first sleep reads as one, not as a hang.

## Power management without logind

logind elsewhere handles seats and sessions (seatd does that here), the lid
and the power key, idle and inhibitors, suspend, and runtime directories
(the launch daemon creates them). What is left:

- **The lid and the power key** are dwl's, as input devices: the power key
  is a key, which dwl binds to `kryptik-lock --suspend`, and the lid a
  switch, which Kryptik's dwl patch turns into the same command when it
  closes (above). Nothing in zone 0 runs as root for them. Many Intel
  laptops send the power key, and the wake from s2idle by it, to Intel's
  HID event filter or virtual button device instead of ACPI's power
  button; `intel-hid` and `intel-vbtn`, modules eudev loads by those
  devices' ACPI IDs, make it a key there too.
- **The power service** (`build/service-scripts/power.sh`, the `power`
  service), in zone 0, reads the battery and the mains adapter or USB
  charger from `/sys/class/power_supply` every 30 s; a mouse's battery
  (scope `Device`) does not count, of two batteries the fuller does, and a
  battery whose capacity does not read counts by the energy or the charge
  it holds against full. A battery that says it discharges runs down
  whatever the adapter says, as on a charger that gives less than the
  machine uses, so the machine counts as on battery, and the chrome says
  it is plugged in. On battery at 10% and again at 5% it warns, once each
  a discharge: the chrome's status loop opens a window that says what
  comes at 3% and follows the charge until the machine is on mains. At 3%
  or under, seen twice running, it stops every zone as `kryptikd stop`
  does, each launcher closing its volume, and powers the machine off,
  since there is no hibernation. Each look is written to
  `/run/kryptik-power/state`, which the chrome reads, so the menu says what
  the service acts on.
- **A gauge that reads too low.** A worn battery whose gauge says 3% or less
  while it still holds charge powers the machine off a minute after every
  boot on battery. Requiring a reading above 3% earlier in the boot would
  stop that, at the cost of an unclean death for a boot that starts at 2%.
  Which to take is for the tests on physical hardware.
- **The energy preference.** The same service sets
  `energy_performance_preference` to `balance_power` without a charger and
  `balance_performance` with one whenever that changes, by the charger
  rather than the battery's running down, so a machine that outdraws its
  charger under load does not swing between the two, on each
  processor policy that offers it (amd-pstate and intel_pstate both do).
  PCIe link power and NVMe power states keep the kernel's defaults, and no
  rule turns on USB autosuspend for input devices, which too often
  misbehave with it.
- **Brightness.** An eudev rule (`70-kryptik-backlight.rules`) gives the
  session's group, `kryptik`, write access to the backlight's level, not
  `video`, which would hand the user the GPU's device nodes past seatd.
  dwl's brightness keys run `brightness.sh up|down`, a twentieth of the
  range a step and never down to dark, on the backlight the kernel's
  documentation prefers when a panel has several (firmware, then platform,
  then raw). The level a step leaves is kept in the user's configuration
  (`~/.config/kryptik/brightness`: the panel, the level and its range), and
  the session sets it again as the next login starts, as a share of the
  panel's range. A step taken under the lock that follows a sleep is not
  kept, as the home directory waits with the state partition.
- **Idle.** dwl's idle notifier (`ext-idle-notify-v1`, in dwl 0.8) tells a
  zone 0 tool to blank the screen, then lock, then suspend. All three are
  built (`kryptik-lock --idle`, above), lock first: a screen turned off
  while unlocked would come back on to an open session at the first touch.
  Suspending when idle is off unless the user asks for it (above).
- **Holding the screen awake.** A zone playing a video may hold off both the
  lock and the blanking, through the proxy's idle inhibition (the browser
  design), under these conditions. dwl counts a hold under them and tells its
  idle notifier so, and `kryptik-lock` waits on the notification that counts
  inhibitors: the lock, the blanking and a sleep after them all heed it.
  - The zone's file on the verified root opts in (`[desktop] hold_awake =
    true`): `personal` and `work`, where the browser plays video. It is off
    by default, and set false for `untrusted`, where unknown links open.
    kryptikd starts the zone's proxy with `--hold-awake` from that file, and
    dwl reads the same file through `zone-colours.h`, for the sockets it
    offers the inhibitor on and the holds it counts.
  - A hold counts only while the inhibiting window is mapped and visible on
    a lit output, a window of its zone has the keyboard and the session is
    unlocked; losing any of these ends it. A zone 0 window taking the
    keyboard ends it, and so do a lid close and a suspend, each of which
    locks first. A hold that ended begins again, with the four hours anew,
    once its window is back with the keyboard: after an unlock, the user is
    there.
  - It lasts four hours from when it began or a key or button was last
    pressed, whatever window took the press (`holdawakesecs` in dwl's
    configuration); then the lock comes as usual. dwl's status names the
    zone holding the screen awake (`<output> holdawake <zone>`), for the
    chrome to show for as long as it does, and the bar over a fullscreen
    window names it beside the microphone's and the camera's holders: a
    video in front covers the chrome.
  - The moment no hold qualifies, the lock and the blanking count input
    alone again.
- The chrome's menu has a Power line, from the power service's state: on
  mains or on battery, the charge, and on battery what happens at 3%.

### Check

A test helper in zone 0 creates a lid switch and a power button through
uinput, and the kernel's test power supply (`test_power`, a test module like
`mac80211_hwsim`) reports a battery the suite can drain. Closing the lid
suspends, the update's lock holds that off, and a critical battery shuts the
machine down with every volume closed.

`make power-test` does the battery's part with `test_power`: the service
follows the adapter both ways, the menu's Power line names the source and
the charge, a window warns at 10% and again at 5%, follows the charge and
closes on mains, a battery that runs down with the adapter on is on
battery and the line says the machine is plugged in, and with the battery
at 2% unplugged the service stops the zones and powers off; the host then
finds on the state partition that it said so and that a running zone's
volume was closed first. The guest also finds the power controllers'
drivers among the kernel's modules. The energy preference, which QEMU's
processors do not offer, and a battery whose capacity does not read are
checked against stand-in `/sys` trees (`tools/tests/power.sh`). QEMU has
no backlight: the brightness steps are checked the same way
(`tools/tests/brightness.sh`), and the rule and the keys wait for physical
hardware.

## Keyboard layouts and input methods

### Layouts

- **Today.** dwl's `xkb_rules` sets only `.options = NULL`
  (`build/desktop/dwl-config.h`), so libxkbcommon takes the layout from
  `XKB_DEFAULT_LAYOUT`, `XKB_DEFAULT_VARIANT` and `XKB_DEFAULT_OPTIONS`, or
  its default, `us`. The compositor compiles the keymap and sends it to
  each client as a descriptor in `wl_keyboard.keymap`, which the proxy
  passes on, so a zone receives a keymap zone 0 made and cannot change it.
- **The session's layouts.** `kryptik-session` reads the user's list from
  their home (`~/.config/kryptik/keyboard`, which `kryptik keyboard
  desktop` writes: up to four of the table's names) and exports them to
  dwl as one keymap's groups with Super+Space to switch, the screen lock
  naming the one in force ([keyboard layout](keyboard-layout.md)). A keymap
  is not a privilege, so the state partition is a fine place for it.
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
virtual keyboard is checked before either is chosen. Checked: neither does,
so [input methods](input-methods.md) binds the virtual keyboard to its zone
instead.

### Check

`make gui-test` with a test input method in `work`:

- it receives keys only while a `work` window has focus;
- its commit lands in that window;
- it gets nothing while a `personal` window or the chrome has focus;
- binding `zwp_virtual_keyboard_manager_v1` through any proxy disconnects
  the client;
- a layout set in the session reaches a zone's client in its keymap;
- with two layouts, Super+Space switches them at the lock, which names the
  one in force, and a password typed in the other fails (built; this is
  in `make gui-test`).

## Hotplug and several monitors

dwl follows outputs as they come and go through wlroots' DRM backend and
eudev, and draws borders and the chrome on each. `wl_output` carries the
monitor's make, model and name, which come from its EDID and sometimes
include a serial; every zone would see the same values, which link zones to
each other and to the machine. A zone's proxy names each output by its
number (`output-N`), blanks the make and model, and keeps the geometry and
scale.

A laptop's high-resolution panel at scale 1 draws everything at half the
size it should be, so a monitor's scale and place are the user's to pick.
`kryptik display NAME SCALE [X Y]` keeps a line in `~/.config/kryptik/display`
(`*` for any monitor no line names), and `kryptik-display`, a client of
wlroots' output management, which dwl serves to zone 0 alone, makes it: at
once, and, run by the chrome, at every login and whenever a monitor comes.
It changes a monitor only when it is not as chosen, and asks the same thing
once, so a monitor the idle lock turned off, which the output management
stops listing until it is on again, is never turned on by it. A monitor no
line names gets 2 if it is a built-in panel (eDP, LVDS, DSI) of 192 dpi or
more and 1200 lines or more, as GNOME decides, and 1 otherwise: a
television's EDID may give its aspect ratio as its size, so only built-in
panels are measured. Zones are told the scale through `wl_output`, rounded
up to a whole number, and draw that much larger; the compositor scales them
down to a fraction such as 1.5. dwl and the proxy needed no change.

Check: `make gui-test` writes the user's line for the first monitor at 1 and
`* 2`, plugs a second monitor in, and finds it at scale 2 and the first at 1;
through a zone's proxy both outputs are named `output-N`, with no make or
model, one of them at scale 2. `tools/tests/display.sh` checks what
`kryptik display` keeps and refuses. The panel's own default waits for
physical hardware, as QEMU has no built-in panel.

## Order

1. Layouts, the lock and suspend with the keys dropped: they need nothing
   new in the kernel.
2. Power management.
3. Sound.
4. Input methods per zone.
5. Bluetooth audio, last, since it needs sound and a kernel patch.

The item is done when every check above passes in `make acceptance`.
