# Noticing a broken service or a frozen desktop

The watchdog resets a machine whose userspace has stopped, not one that is
merely broken. [Status](../status.md#known-gaps) names the gap: "A crashed
service or a frozen desktop is not detected, because a false reboot is worse
than the hang." This document weighs health checks per service under s6, a
heartbeat from the compositor, and telling the user that something is wrong
in place of a reset, and says what fails safe in each.

## Where things stand

- **The feeder checks nothing.** `build/services/watchdog` runs
  `watchdog.sh`, which opens every `/dev/watchdog*` and writes to each every
  10 s, checking nothing else. `WATCHDOG_NOWAYOUT` means closing a device
  does not stop it. A machine whose userspace is no longer scheduled resets,
  and the state suite proves it by stopping the feeder.
- **s6 restarts what dies.** `kryptikd-serve`, `net-zone`, `seatd`, `eudev`,
  the gettys and the feeder are longruns, and `s6-supervise` starts each
  again when it exits, at most once a second. A service that dies at every
  start is restarted forever and nobody is told.
- **A hung service is not restarted.** A process that is alive but stuck (a
  deadlocked launch daemon, a net zone whose launcher waits on something
  that never comes) is left alone: nothing asks it anything.
- **The desktop is not a service.** tty1's login runs `kryptik-session`,
  which execs dwl with the chrome as its status reader. A hung dwl draws
  nothing new and handles no keys, VT switching included: the switch is the
  compositor's job through seatd, and SysRq is not built. The user's only way
  out is the power button, which is the reset this design was meant to
  avoid, with less said.
- **Zones outlive the launch daemon.** `kryptikd serve` starts each zone's
  `kryptikd run` in a session of its own (`setsid` in `serve.rs`), so
  restarting the daemon leaves running zones alone.
- **The trial already judges health,** once, at boot: `boot-success` checks
  eudev, seatd, the launch daemon, the net zone and the login getty before it
  commits a slot ([boot and updates](boot-and-updates.md#updates)).

## What fails safe, and what does not

A false reset loses whatever the zones had not saved, and in the middle of
`kryptik-update apply` it lands on a half-written inactive slot, which the
update design survives, but only just. A hang loses nothing yet. So a reset
stays reserved for a userspace that is not scheduled at all, as now. Every
other failure gets a restart that keeps zones and their volumes, or a
message, and never a reboot.

## Options

### Feed the watchdog only while every check passes

The feeder stops writing when a service fails its check, and the machine
resets. This is simple, and it would catch everything. But it turns every
false positive into lost work. A check that times out under load (a large
build in `dev`, a slow disk) would reset a machine that was only busy.
Rejected: it is the false reboot the current design refused.

### Per-service checks under s6

- **Crash loops.** Each longrun gets a `finish` script that counts its
  recent deaths. After five within two minutes it exits 125, which tells
  `s6-supervise` not to restart the service, and writes a record under
  `/run/kryptik/health/`. The service stays down and says so, instead of
  cycling unseen.
- **Hangs.** A small service, `kryptik-health`, root in zone 0, runs fixed
  checks every 30 s:
  - the launch daemon answers `status` on its socket within 5 s;
  - the net zone's launcher holds its registry entry, and its readiness line
    has not said `NOT READY` for more than five minutes while an uplink
    exists;
  - seatd's socket accepts a connection.

  A failed check restarts that one service (`s6-svc -r`) and records it. A
  second failure within ten minutes stops the restarts and leaves the
  service as it is, recorded.
- **What a restart costs:** the launch daemon's restart keeps zones running
  (they are in their own sessions), and a request in flight fails and is
  asked again. The net zone's restart drops routed zones' interfaces for a
  moment and reattaches them, as the [net zone](net-zone.md#gateway-failure)
  design already does. seatd's restart takes the desktop with it, so seatd's
  check only records, and the user is told.

### A heartbeat from the compositor

dwl gets a timer in its event loop (`wl_event_loop_add_timer`) that writes
one byte to a pipe every 5 s, in a change applied like the zone-border
change. A small watcher, which `kryptik-session` starts as the same user
before it execs dwl, reads the pipe:

- no byte for 60 s means dwl's loop is stuck, since a busy frame does not
  take a minute;
- the watcher ends dwl with `SIGTERM`, then `SIGKILL`;
- seatd hands the VT back to text, the login on tty1 comes back, and the
  console says when and why the desktop was ended.

Zones keep running and their volumes stay open. Their windows go with the
proxies, which belong to the session. The user logs in again and starts a
terminal in a zone that is still there.

### Telling the user

- **The chrome** shows a mark for any record under `/run/kryptik/health/`,
  with the service's name, as it shows the focused zone. A record the user
  has seen stays until the service is healthy again.
- **`kryptik doctor`** lists the records with their times and the last
  lines of each service's log.
- **The console** carries the message after a desktop was ended, so it is
  the first thing seen on tty1.

## Recommendation

- Keep the watchdog as it is: a reset only when userspace is not scheduled.
- Crash loops end after five deaths in two minutes, recorded, through
  `finish` and exit code 125.
- `kryptik-health` checks the launch daemon, the net zone and seatd. It
  restarts the first two once, and only records the third.
- A heartbeat from dwl, watched by the session, ends a desktop that has been
  stuck for a minute and returns tty1 to its login, with zones still
  running.
- Every record shows in the chrome and in `kryptik doctor`. None of this
  reboots.

What still fails unseen: a hung kernel that the lockup detectors miss and no
hardware timer catches, and a health service that hangs itself. The second
leaves the machine where it is today, which is the safe direction.

## The check that proves it done

The state suite, extended:

- a launch daemon made to exit at every start is stopped after five deaths,
  with a record that `kryptik doctor` prints;
- a launch daemon stopped with `SIGSTOP` is restarted once within a minute,
  and a zone that was running keeps running through it;
- a dwl stopped with `SIGSTOP` is ended after a minute, tty1 shows the login
  and the message, and a zone started before it is still running;
- a busy machine (every CPU loaded in `dev` for ten minutes) gets no restart
  and no record;
- the machine is never reset in any of these.
