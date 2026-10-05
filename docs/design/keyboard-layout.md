# Keyboard layout

One setting names the keyboard layout. It is in force before the state
partition is unlocked, because the passphrase is the first thing typed, and
the same row of one table gives the console its keymap and the desktop its
xkb layout. The name is kept in a firmware variable; the table and the
keymaps are on the verified root.

## Why

The kernel's own keymap is a US one. At the passphrase prompt a German
keyboard's Z key then types `y` and its `-` key types `/`, so the passphrase
a person believes they set is not the one they typed. The desktop has the
same question with another answer: dwl compiles an xkb keymap, US unless it
is told otherwise, and hands it to every client of every zone.

The setting cannot live where settings live. The state partition is not
open when the passphrase is asked. The root is one signed image for every
machine. The kernel's command line is compiled into the signed kernel. What
is left is unauthenticated whatever is chosen, so the choice is about what
an attacker can do with it and what the boot has to parse to read it.

## Where the name is kept

**A file on the ESP.** It travels with the disk and needs no firmware
support. But the ESP is the one partition anyone holding the disk can
rewrite, and reading a file from it means mounting it: the kernel would
parse a FAT filesystem of the attacker's making, as root, at every boot,
before the passphrase is typed. Today the running system mounts the ESP only
to commit a trial or apply an update, after the state is open. A flaw in
that parser would be kernel code execution at the passphrase prompt, which
is what the offline attacker of the [threat model](../threat-model.md) wants
most. A whole keymap on the ESP would be worse than a name: `loadkeys` would
parse it too, and a keymap can bind keys to strings and to console actions.

**A firmware variable.** efivarfs hands over a few bytes behind four of
attributes; there is no filesystem to parse. Writing it takes code running
on the machine, root on the installed system or the medium's shell: the disk
in hand is not enough. It belongs to the machine, not the disk, so a disk
moved to another machine, or a firmware reset, asks under `us`; and a
firmware's variable store is finite, though an update already writes boot
entries there.

**Nothing kept: a list on the verified root alone.** The layout would be
the builder's choice, one for every machine, or the user's at every boot,
picked blind before a passphrase that shows no echo.

The variable holds the name and the root holds everything else. A name
counts only if the table on the verified root lists it, and what is loaded
is that row's keymap from the verified root: the variable's bytes pick a row
and never reach a command line.

**What changing the variable gains.** Whoever can write it (another system
booted on the machine, the medium's shell, firmware setup) can select
another layout the release ships, and nothing else. The passphrase typed
under it then fails to open the state: three tries and a degraded boot,
which is denial of service, and deleting the boot file does as much. Nothing
typed is disclosed, since the characters go to `cryptsetup` and nowhere
else. The prompt names the layout in force on every console, so the change
is in front of the user before they type.

**A name the release does not have** (a variable from another release or
another system, or bytes that are no name) loads `us`, and the prompt says
both: that the firmware names a layout this release does not have, and that
the layout is `us`.

## Design

```text
 firmware variable          verified root                         in force
 KryptikKeyboard = "de" ──▶ keyboard-layouts: de → console keymap ──▶ loadkeys, before the passphrase
                                               → xkb layout       ──▶ /run/kryptik-keyboard ──▶ dwl
```

**The table.** `/usr/share/kryptik/keyboard-layouts`, from
`build/config/keyboard-layouts`: a name, a console keymap of kbd under
`/usr/share/keymaps`, an xkb layout and its variant. `us` is first. Stage 04
parses every row's keymap with `loadkeys` and looks up every xkb layout and
variant in xkeyboard-config: a row that fails either fails the build.

**The variable.** `KryptikKeyboard` under Kryptik's own GUID
(`ec0aed97-b78d-446f-997d-10d0c35f5fb6`), non-volatile, holding the name in
ASCII: at most 32 bytes of lower-case letters, digits and `-`. No variable
means `us`.

**At boot.** `sysinit`, on an installed system and before its first
question, reads the variable, loads the row's keymap and says
`sysinit: keyboard layout NAME` on every console. It records the row in
`/run/kryptik-keyboard`, which a session's user can read. A medium does none
of this and keeps the kernel's keymap: it is the same medium on every
machine, and its shell is where a wrong name gets repaired.

**Installing.** `kryptik-install --keyboard NAME` loads the layout before
anything is typed, so `ERASE` and the new passphrase are typed under the
layout the installed system will ask under, and writes the name to the
variable before it writes to the disk. Without the option it records the
layout in force on the medium, `us` unless `kryptik keyboard NAME` changed
it there.

**Changing it.** `kryptik keyboard` lists the layouts and marks the one in
force. `kryptik keyboard NAME`, as root, loads it on the console and writes
the variable: the desktop has it at its next login and the passphrase prompt
at the next boot. On a medium it loads the keymap and records nothing.

**The desktop.** `kryptik-session` exports the row's `XKB_DEFAULT_LAYOUT`
and `XKB_DEFAULT_VARIANT`; dwl's rule names are empty, so libxkbcommon takes
them. Every zone's clients get the compositor's keymap through their proxy,
and no zone has a say in it.

**The serial console** is not touched: what arrives there was mapped by the
far end's terminal.

## Tests

- `tools/tests/keyboard.sh`: the names the table takes and refuses, what the
  variable may hold (a name; other characters, 40 bytes, nothing, a file
  shorter than its attributes), what a load gives `loadkeys` and records,
  what the session exports, what a store writes byte for byte, and the
  shipped table's form.
- Stage 04 checks every row against the keymaps and xkb data it installed.
- `tools/image/keyboard-test.sh`, in acceptance's install suite: an install
  with `--keyboard de`; the next boot names the layout and takes the
  passphrase as key presses on the guest's keyboard, placed where a German
  keyboard has `z`, `y` and `-`; from inside, the console's Y key gives `z`
  and the session's record and export say `de`; `kryptik keyboard` refuses a
  name the table lacks and changes back to `us`, which the next boot says;
  and a variable holding a name the release lacks boots under `us` and says
  so.

## Open points

- kbd's keymaps and xkb's layouts are two descriptions of a keyboard, paired
  by the table. They agree on the letters, digits and symbols printed on the
  keys; nothing checks that they agree on the AltGr level or on dead keys. A
  zone's volume passphrase is asked in the desktop, the state's on the
  console: one that uses those levels may type differently in the two.
- No suite presses keys in the desktop under a layout other than `us`.
- One layout at a time, Latin layouts only, and no input method.
- The variable belongs to the machine: a disk moved to another one asks
  under `us` until `kryptik keyboard` is run there.

## Files

`build/service-scripts/keyboard.sh`, `build/config/keyboard-layouts`,
`build/service-scripts/sysinit.sh`, `tools/install/kryptik-install.sh`,
`tools/kryptik` (`kryptik keyboard`), `tools/desktop/kryptik-session`,
`build/recipes/services.sh` (the table and its check),
`build/desktop/dwl-config.h` (the empty rule names).
