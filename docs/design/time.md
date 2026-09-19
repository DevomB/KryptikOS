# A clock that is right

Status: design. Nothing here is built yet; the roadmap's "A clock that is
right" is the item it finishes. Builds on [the net zone](net-zone.md), which
asks, and [the broker](broker.md), which carries the answer.

## The problem

The image has no time synchronisation. Two things assume the time anyway:
certificate validation in every zone that speaks TLS, and the freshness of an
update (a signed "latest release" statement is only worth something against
a clock). A machine whose RTC battery is dead boots in 1970 or 2000, every
certificate is "not yet valid", and nothing on the system can fix it.

The obvious fix does not fit. `CLOCK_REALTIME` is one clock for the whole
machine: a time namespace covers the monotonic and boot clocks, not the wall
clock, so no zone can have a private one, and only a process with
`CAP_SYS_TIME` in the initial user namespace may set it. That is zone 0, and
zone 0 has no network. The one zone that can reach a time server is the net
zone, which is treated as hostile and could not set the clock if it wanted
to.

## The threat

NTP without NTS is unauthenticated: anything on the path can answer, and the
net zone itself may be compromised. So the answer that reaches zone 0 is a
claim, never a fact. What a wrong clock buys an attacker:

- **Backwards:** an expired or revoked certificate is valid again, and an old
  signed "latest release" statement is fresh again, which holds a machine on a
  release with a known hole. This is the direction that matters most.
- **Forwards:** every certificate has expired (denial of service), and
  anything the system refuses for being "from the future" is accepted.
- **Either way:** logs, file times and the update history lie.

The defence is not a better protocol. It is that zone 0 knows things the
network does not, and bounds what it will believe.

## The design

```text
 net zone                       broker (zone 0, in net's launcher)         zone 0
 chronyd -Q measures            `time-offset` verb: from the nic zone      decide: floor, bound,
 the OFFSET of the shared  ───▶ only, strictly parsed, rate limited  ───▶  consent; then
 clock, and cannot set it                                                   clock_settime + RTC
```

### The net zone measures an offset

`netzone-init.sh` runs `chronyd -Q -t 10 'pool <host> iburst maxsources 4'`
(one directive per configured source) once an uplink has an address, and
again on a long interval and when a radio associates. `-Q` measures and
prints `System clock wrong by N seconds` without touching the clock, runs as
the zone's root with no `CAP_SYS_TIME`, and writes no pid file. No such line
means no answer; the exit status says nothing either way.

What the zone reports is the **offset**, not a time. The zone reads the same
`CLOCK_REALTIME` zone 0 does, so an offset measured against it applies to
zone 0's clock exactly, and nothing is lost to the delay between measuring
and reporting. It sends `time-offset <seconds> <sources>` to its broker and
prints `time=<offset|no-answer>` in its readiness line. The sources come
from `/etc/kryptik/time.conf` on the verified root, bound read-only into the
nic zone.

NTS is not used: the image has no gnutls, and authenticating the server
would not authenticate a compromised net zone. It is a version 2 refinement,
not a substitute for the bounds below.

### The broker carries the claim

One new verb, accepted only from the zone whose file says `mode = "nic"`
(the peer's uid is in that zone's identity range, as for every verb):

```text
time-offset <seconds> <sources>
    seconds  a signed decimal, at most 10 integer digits and 6 fractional
    sources  how many servers chrony combined, 1-16
```

Anything else is refused at parse time. One claim is considered per
interval (the rest are refused unread), so a hostile zone cannot turn the
consent prompt into a flood. The reply says what zone 0 did: `ok stepped`,
`ok slewed`, `ok ignored`, `refused: <reason>`, `asked`.

### Zone 0 decides

A pure function of what zone 0 already knows: the current clock, the offset,
the floor, the bound.

1. **The floor is not negotiable.** No proposal is accepted that puts the
   clock before the running image's build date (`built_at` in
   `/etc/kryptik-image.json`, on the verified root), or before the date of
   the newest release this machine has committed to. The OS cannot have been
   built in the future of the present, and no consent prompt offers a time
   below the floor.
2. **Zone 0 repairs a clock below the floor by itself, with no network.**
   At boot, before anything asks the net zone, a clock that reads earlier
   than the floor is set to the floor. A dead RTC therefore starts at the
   build date rather than in 1970, and every later proposal is judged from
   there by the same rule as on any other machine.
3. **Small corrections are applied silently.** Under one second the clock is
   slewed (`adjtime`), so time never runs backwards for a running program;
   up to the bound it is stepped.
4. **Beyond the bound, the person decides.** The bound defaults to one hour
   in either direction: an RTC drifts seconds a day, so an honest correction
   larger than that means a dead battery or a machine unused for years, and
   a dishonest one is exactly what this is for. The question goes through
   the consent path the broker already uses for file transfers
   ([broker](broker.md)): the trusted chrome draws, in the one colour no zone
   can have, *"The network says it is 2027-03-02 14:05. This machine says
   2026-09-19 08:12. Set the clock?"* - both times, so a person with a watch
   can answer. No session to ask, no answer, or "no" is a refusal, and the
   clock stays where it was.
5. **Applying it** is `clock_settime(CLOCK_REALTIME)` in kryptikd, the only
   process that holds `CAP_SYS_TIME`, then the RTC (`RTC_SET_TIME` on
   `/dev/rtc0`, where there is one). What was done - when, the offset, how
   many sources, stepped or slewed or asked - is one line appended to
   `/var/lib/kryptik/time/history`, which `kryptik doctor` reads.

### What this does not defend against

A hostile net zone can lie by up to the bound per interval, in either
direction, and keep lying: over a day of accepted claims it can walk the
clock a long way. So the bound is on the **total** movement too: the sum of
corrections accepted without consent since the last consented or
floor-derived time may not exceed the bound, after which the next one asks.
It can also refuse to answer at all, which leaves the clock to the RTC; that
is reported (`time=no-answer`), not repaired.

## Tests

| check | expected |
|---|---|
| a proposal below the image's build date | refused, never offered for consent |
| a clock below the floor at boot | set to the floor with no network involved |
| an offset under one second | slewed; the clock never steps backwards |
| an offset under the bound | stepped; one history line |
| an offset over the bound with nobody to ask | refused; clock unchanged |
| over the bound, consent given through the chrome | stepped; the question showed both times |
| many small offsets that sum past the bound | the one that crosses it asks |
| `time-offset` from a zone that is not the nic zone | refused by identity |
| a malformed or oversized claim; a second claim inside the interval | refused at parse time; refused unread |
| the net zone behind QEMU user networking | `time=` in the readiness line says what happened; no answer is reported as that, not as a pass |

The decision is a pure function and is unit-tested exhaustively; the verb's
refusals run in the serve and boundary suites; the clamp and the step run as
root in the VM, where the guest check sets the clock wrong on purpose and
reads it back.

## Open points

- Whether `chronyd -Q` makes a call the base seccomp policy denies outright
  (`adjtimex` and `clock_adjtime` are on the list no zone policy may
  re-allow). If it does even to read, the answer is a smaller client, not a
  wider policy.
- The interval and the bound are configuration with defaults, in
  `/etc/kryptik/time.conf`; the floor is not configurable.
- The clamp at boot belongs in kryptikd (`kryptikd time floor`), called once
  by a boot service, so the rule lives in one place with its tests.

## Files

`compartments/kryptikd/src/time.rs` (the decision, the clamp, applying it),
`broker.rs` (the verb), `consent.rs` (a second kind of question),
`tools/desktop/kryptik-chrome` (drawing it), `tools/net/netzone-init.sh`
(asking), `rootfs.rs` (`/etc/kryptik/time.conf` into the nic zone),
`compartments/zones/policy/net.seccomp` if chrony needs anything, a boot
service for the clamp, and the rows above in the suites.
