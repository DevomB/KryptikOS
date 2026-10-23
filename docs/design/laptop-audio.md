# Laptop sound past HD Audio

Kryptik 1.0 plays and records through the HD Audio driver and USB audio
([the laptop](laptop.md#sound), ADR-021). Many laptops put part of their
sound where that driver cannot reach it: microphones and codecs behind
Intel's audio DSP, microphones on AMD's audio coprocessor, and amplifiers in
front of the speakers that need a driver and a tuning file of their own.
This note says what each needs from `boot.fragment`, `firmware.list` and
`kryptik-sound`, what that costs against ADR-013 and ADR-012, and why 1.0
ships without most of them. Of the amplifiers, Cirrus's CS35L54, CS35L56
and CS35L57 on I2C are built. Linux 6.18 and linux-firmware 20260916 are
the pinned versions; sof-bin, which nothing pins yet, is at 2026.09.2, its
newest release.

## What 1.0 does on each kind of laptop

Which driver takes Intel's audio controller is decided as it probes, by
`snd-intel-dspcfg`. Its table has rows for a platform only when that
platform's SOF driver is built, so with none built it finds no row and
`snd-hda-intel` takes every controller, as it takes AMD's.

- **An HD Audio codec alone,** as on desktops and many laptops: the
  speakers, the headphone jack and a headset's microphone work. The driver
  takes the HDMI and DisplayPort codecs too, but the mixer plays only to a
  card's device 0, the codec's own, so a monitor's speakers stay silent.
- **An HD Audio codec with digital microphones on Intel's DSP,** common on
  Intel laptops: the same, except the built-in microphones, which are wired
  to the DSP.
- **Codecs on SoundWire,** on many recent Intel laptops: the HD Audio link
  carries only the graphics' HDMI codec, so the speakers, the jack and the
  microphones are all silent, and as that card has no device 0 the mixer
  plays to none of it, a monitor's speakers included.
- **AMD laptops:** on most the codec is on HD Audio, so the speakers and
  the jack work. Where the built-in microphones are on the audio
  coprocessor (ACP), as on many consumer models (HP's OMEN and Victus among
  them), they do not. Some put them on the codec's digital-microphone input
  instead, as the kernel logs of HP's EliteBook 8 G1a and 845 G9 show, and
  HD Audio then drives them as it does a headset's microphone; no such
  laptop has run Kryptik yet. Some, from the coprocessor's 6.3 generation
  (Ryzen 7040) on, put their codecs on SoundWire behind the coprocessor
  instead, and there, as on Intel's SoundWire laptops, the speakers, the
  jack and the microphones are all silent.
- **Smart amplifiers** in front of the speakers (Cirrus's CS35L41, CS35L54,
  CS35L56 and CS35L57, TI's TAS2781), on Intel and AMD laptops alike:
  linux-firmware has tuning files for about 200 models, most of them ASUS,
  HP, Lenovo and Dell. The jack works either way.
  - For a CS35L54, CS35L56 or CS35L57 on I2C, the driver and every tuning
    file linux-firmware has for them are built. That is untested: QEMU has
    none, and no machine with one has run them yet.
  - For a CS35L41, a TAS2781, or any of them on SPI, the speakers stay
    silent.

USB audio works on all of them. A machine shows which kinds it is without
any of these drivers: the audio controller's PCI class (0x040100 or
0x040380 means a DSP, 0x040300 none), an `NHLT` table under
`/sys/firmware/acpi/tables`, and whether its ACPI tables describe SoundWire
links or amplifiers, which `ls /sys/bus/acpi/devices` lists: `CSC3551`,
`CLSA0100` and `CLSA0101` for Cirrus's CS35L41; `CSC3554`, `CSC3556` and
`CSC3557` for its CS35L54,
CS35L56 and CS35L57; `TIAS2781` and `TXNW2781` for TI's. On AMD, the codec
shows whether it has the microphones: the kernel's autoconfig line for a
Realtek codec lists `Internal Mic=0x12`, and pin 0x12 in
`/proc/asound/card*/codec#0` has an internal-microphone default rather than
0x411111f0, the value of a pin with nothing on it.
Testing on physical hardware is planned for October 2026. The Intel and AMD
laptops tested then will show which kinds they are.

## What each needs

### Amplifiers

- **Kernel:** the ASoC core (`SND_SOC`), which these HD Audio drivers
  depend on; `SND_HDA_SCODEC_CS35L41_I2C`, `SND_HDA_SCODEC_CS35L56_I2C` and
  `SND_HDA_SCODEC_TAS2781_I2C` with their `_SPI` twins; and
  `SERIAL_MULTI_INSTANTIATE`, which splits the one ACPI device a pair of
  amplifiers is described as into one per amplifier. Those on SPI need the
  SPI core and the platform's SPI controller (`SPI_PXA2XX` for Intel's
  LPSS, `SPI_AMD`). The drivers are modules. eudev loads them from the ACPI
  devices, and they join the Realtek codec's driver, already built, as its
  components, so `sound.conf` keeps its list.
- **Firmware:** the tuning files, each named for a laptop's PCI subsystem
  ID: about 750 files and 6 MB at the top of linux-firmware's `cirrus/`,
  and about 90 files and 4 MB in `ti/audio/tas2781/` with their links,
  before compression. The source and its licence rows are those ADR-012
  already has, and the list takes them whole, as it takes `amdgpu/*`.
- **Built so far:** the ASoC core, `SERIAL_MULTI_INSTANTIATE` and
  `SND_HDA_SCODEC_CS35L56_I2C`, which drives the CS35L54, CS35L56 and
  CS35L57. `firmware.list` takes their whole family: `cirrus/cs35l54-*`,
  `cs35l56-*` and `cs35l57-*`, which with the DSP images their links bring
  is 4.2 MB before compression. `SND_SOC_INTEL_SST_TOPLEVEL` is set off,
  since the ASoC core would otherwise build Intel's Atom driver.
  - Still to come: CS35L41's driver and its 1.8 MB of files, TAS2781's,
    and the `_SPI` twins with the SPI core.
- **Mixer:** nothing new, as the amplifiers play what the codec plays. The
  CS35L56 also sits on SoundWire, behind SOF, on some laptops; those come
  with SOF.

### AMD's microphones

- **Kernel:** the ASoC core and, per generation of the coprocessor, as
  modules: `SND_SOC_AMD_RENOIR` and `SND_SOC_AMD_RENOIR_MACH` (Renoir,
  Ryzen 4000); `SND_SOC_AMD_ACP6x` and `SND_SOC_AMD_YC_MACH` (Yellow Carp,
  Ryzen 6000); `SND_SOC_AMD_ACP63_TOPLEVEL`, `SND_SOC_AMD_PS` and
  `SND_SOC_AMD_PS_MACH` (ACP 6.3 and 7.x, Ryzen 7040 and later).
  `SND_AMD_ACP_CONFIG`, which they select, decides which driver takes a
  machine. None needs firmware.
- **Which laptops:** Yellow Carp's machine driver looks for the ACPI
  property `AcpDmicConnected`, then the method `_WOV`, then a table of 88
  laptops by DMI; the driver of the 7040 and later looks for
  `acp-audio-device-type` or `_WOV`. A laptop that says neither and is not
  in the table has no microphone until it is added upstream.
- **Mixer:** the microphones are a card of their own, for capture alone.
  `kryptik-sound` records from the first card it finds with a capture
  device 0, a USB one first, and nothing makes that the microphones' card
  rather than the codec's, whose input is the headset jack. It would have
  to prefer the built-in microphones, and the headset's while one is
  plugged in, which the codec's jack control says.
- **SoundWire behind the coprocessor:** `SOUNDWIRE_AMD`,
  `SND_SOC_AMD_SOUNDWIRE` and `SND_SOC_AMD_LEGACY_SDW_MACH`, which selects
  Realtek's SoundWire codec drivers (RT711, RT712, RT715, RT722, RT1316,
  RT1320), beside `SND_SOC_AMD_PS`. The coprocessor's ACPI device
  describes the links under its child at `_ADR` 5. The mixer needs what
  SoundWire needs on Intel: UCM, below.

### Intel's DSP: Sound Open Firmware

- **Kernel:** the ASoC core, `SND_SOC_SOF_TOPLEVEL`, `SND_SOC_SOF_PCI` and
  `SND_SOC_SOF_INTEL_TOPLEVEL`. Every Intel platform's option defaults to
  on with `SND_SOC_SOF_PCI`, so the fragment keeps the generations it
  supports (Tiger Lake, Alder Lake with Raptor Lake, Meteor Lake with Arrow
  Lake, Lunar Lake, Panther Lake with Wildcat Lake) and turns the older
  ones off. `SND_SOC_SOF_HDA_LINK` and `SND_SOC_SOF_HDA_AUDIO_CODEC` let
  SOF drive the HD Audio codec and HDMI, and
  `SND_SOC_INTEL_SKL_HDA_DSP_GENERIC_MACH` is the machine driver for a
  codec with digital microphones. SoundWire adds `SOUNDWIRE`,
  `SOUNDWIRE_INTEL`, `SND_SOC_SOF_INTEL_SOUNDWIRE` and
  `SND_SOC_INTEL_SOUNDWIRE_SOF_MACH`, the generic SoundWire machine driver,
  which selects about twenty codec drivers (Realtek's, Cirrus's CS42L43 and
  CS35L56, Maxim's) and needs `SND_SOC_INTEL_USER_FRIENDLY_LONG_NAMES` and
  the SPI core.
- **Loading:** SOF binds an HD Audio codec as `snd-hda-intel` does, by
  `request_module`, which `STATIC_USERMODEHELPER` turns away, so
  `sound.conf` gains the same softdep ahead of SOF's Intel PCI drivers, and
  stage 05 holds that list too. The machine drivers and SoundWire's codec
  drivers bind to devices eudev sees, and load by alias.
- **Firmware, from a second source:** linux-firmware 20260916 carries no
  Intel SOF file (its `WHENCE` has no `intel/sof` row). The SOF project
  publishes them in sof-bin, which amends ADR-012:
  - sof-bin publishes no signature: 2026.09.2 is a lightweight tag on an
    unsigned commit. Its tarball would be pinned by SHA-256 in
    `sources.lock` and join the sources the signature gate accepts by
    note.
  - Only the Intel-signed builds ship (the community-signed ones are for
    boards that take the SOF project's key), at the paths the kernel asks
    for, in sof-bin's layout under `intel/`, compressed like the rest.
  - From Tiger Lake on, that is 20 firmware files (14.0 MB) and 347
    topology files (18.7 MB): about 6.9 MB with each file compressed (xz
    -9, standing in for the image's zstd -19), against about 81 MB of
    firmware today. The firmware is most of it: the 41 generic HD Audio
    topologies are 0.1 MB compressed.
  - The kernel picks a machine's topology from its ACPI tables and its
    microphones, so the image carries every topology of the platforms it
    keeps.
- **Mixer:** an SOF card puts the codec, HDMI and the microphones on
  different devices of one card, and a SoundWire card splits the speakers
  from the jack, at numbers the topology sets. `kryptik-sound` opens device
  0 and sets only the controls it knows by name, while SoundWire codecs
  need controls set that ALSA's use-case manager (UCM) sets for each codec
  combination. So SOF brings UCM with it: alsa-lib built with it and
  `alsa-ucm-conf` pinned, read by the mixer alone, which picks its devices
  by UCM's names for them (speaker, headphones, microphones).
- **The handover:** once a platform's SOF driver is built,
  `snd-intel-dspcfg` gives SOF every controller of that platform whose ACPI
  tables describe digital microphones or SoundWire links, laptops whose
  speakers work under `snd-hda-intel` today among them. There, a firmware
  the board refuses or a topology the image lacks silences the machine, not
  only its microphones. The way back is `options snd_intel_dspcfg
  dsp_driver=1`, which root would have to write in `/etc/modprobe.d`.

## What else it touches

- **The zones: nothing.** No zone has `/dev/snd` (ADR-021). Every driver
  here is reached by zone 0's mixer alone, a user of its own in the `audio`
  group, and a zone's sound is still a fixed-format stream on its socket.
- **The kernel image: the SPI core.** The drivers are modules, as ADR-013
  asks, and two built-in parts are on the way. The parser of the ACPI
  `NHLT` table (`ACPI_NHLT`), which SOF reads, is in the image already:
  `snd-hda-intel` selects `SND_INTEL_DSP_CONFIG`, which selects it. The SPI
  core (`SPI`), which SoundWire's machine driver and the amplifiers on SPI
  need, is not, and it cannot be a module, which is ADR-013's exception;
  the controllers under it can. Stage 05's size step and its fragment
  check, which fails an option dropped or forced on, settle the cost on the
  branch that adds them; `size-budget` allows 23,087,770 bytes.
- **What runs beside the CPU.** The SOF firmware runs on the DSP, which
  reaches memory by DMA behind the IOMMU (on and strict, ADR-012), like the
  Wi-Fi and graphics firmware. The kernel parses the topology files, from
  the verified root. The tuning files go to the amplifiers' own DSPs.

## Recommendation: a named gap in 1.0

1.0 ships without most of them, and the user guide's known limitations say
so: no built-in microphones on Intel laptops with a DSP or on AMD laptops
whose microphones are on the coprocessor, no built-in sound on SoundWire
laptops, and no speakers behind smart
amplifiers other than Cirrus's CS35L54, CS35L56 and CS35L57 on I2C.

Those three are built ahead of the rule below, that each comes only once a
machine that has it has run it: the laptop of the first tests on physical
hardware is expected to have them, and it will run them. Testing on
physical hardware is planned for October 2026.

- **None of it can be tested first.** QEMU emulates no DSP, coprocessor,
  SoundWire link or amplifier, and every check runs in QEMU.
- **SOF changes what works today.** Built, it takes the Intel laptops with
  digital microphones from `snd-hda-intel`, whose speakers work now, and a
  fault there costs their speakers too.
- **It is three pieces of work, not a fragment line:** the kernel's, a
  firmware source with its provenance, and a mixer that picks its devices
  by role, with UCM for SOF.

After 1.0, ordered by what each gives for its cost, and each only once a
machine that has it has run it:

- the rest of the amplifiers, then AMD's microphones: a few modules on the
  ASoC core already built (and the SPI core for amplifiers on SPI),
  firmware from linux-firmware or none, and the mixer's choice of
  microphone;
- SOF for HD Audio laptops with digital microphones: sof-bin's firmware and
  generic topologies, the softdep, and the mixer's devices by role;
- SoundWire, Intel's and AMD's, with UCM in the mixer.

## Check, when each comes

- Stage 05: the fragment check, the size step, and `sound.conf` held to the
  codec drivers built and to SOF's PCI drivers.
- The acceptance's firmware check: what a module names and linux-firmware
  has ships, or `firmware-accepted.txt` says why not.
- On a machine of the kind: the speakers, the jack and each microphone
  through `kryptik-sound`, a zone's grant of the microphone among them, and
  again after a suspend.
- The sound suite keeps running in QEMU, where none of it loads.
