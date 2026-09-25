# Clock

Only zone 0 may set the wall clock, and zone 0 has no network. The net zone
can reach time servers but is treated as hostile. So the net zone measures
how far the clock is off, the [broker](broker.md) carries that as a claim,
and zone 0 decides by rules that do not depend on the claim being true.

## Why

TLS in every zone and the freshness of an update
([update channel](update-channel.md)) depend on the clock, and a machine with
a dead RTC battery boots in 1970 or 2000. `CLOCK_REALTIME` is one clock for
the whole machine (time namespaces cover only the monotonic and boot clocks),
settable only with `CAP_SYS_TIME` in the initial user namespace.

NTP without NTS is unauthenticated and the net zone may be compromised. A
clock set backwards revives expired or revoked certificates and makes an old
signed "latest release" statement look fresh, holding the machine on a
release with a known hole; that direction matters most. Forwards, every
certificate expires. Either way logs, file times and the update history lie.
The defence is what zone 0 knows without the network, the image's build
date, and bounds on what it believes.

## Design

```text
 net zone                       broker (zone 0, in net's launcher)         zone 0
 an SNTP query measures         `time-offset` verb: from the nic zone      decide: floor, bound,
 the OFFSET of the shared  ───▶ only, strictly parsed, rate limited  ───▶  consent; then
 clock, and cannot set it                                                   clock_settime + RTC
```

**Measuring.** `netzone-init.sh` runs `tools/net/sntp-offset.py`, a plain
SNTP query (RFC 4330) with no state and no clock to set, once an uplink has
an address, then hourly (every 5 minutes until something answers) and when a
radio associates. A reply counts only if it echoes the timestamp sent to that
server (an off-path sender cannot forge that), comes from a synchronised
server and is not a kiss-of-death. The offset is `((t1 - t0) + (t2 - t3)) / 2`,
positive when this clock is behind, and the median over the servers is
reported, so one liar among three is outvoted. The servers come from
`/etc/kryptik/time.conf` on the verified root (`server HOST` or `pool HOST`,
a pool giving up to four addresses; the public pool without the file). The
zone reports an offset, not a time: it reads the same `CLOCK_REALTIME` as
zone 0, so nothing is lost to the delay before zone 0 acts. It is a script
rather than an NTP daemon because a daemon is a whole package for one number,
and the script can be tested against a real server on loopback. NTS is not
used: the image has no gnutls, and it would not authenticate a compromised
net zone.

**The claim.** `time-offset <seconds> <sources>`: a signed decimal with at
most 10 integer and 6 fractional digits, and the number of servers (1 to 16)
whose median it is. It is accepted only from the zone whose file says
`mode = "nic"`, and only one claim per 10 minutes is considered, so a hostile
zone cannot flood the user with questions. The reply is `ok ignored`,
`ok slewed`, `ok stepped`, `ok stepped after consent` or `error: <reason>`,
and the net zone prints `time=<offset|no-answer|...>` in its readiness line.

**The decision** (`time::decide`, a pure function):

1. Nothing is applied or offered that puts the clock before the floor, the
   running image's build date (`built_at` in `/etc/kryptik-image.json`). With
   no floor known, every claim is refused.
2. At boot, before the net zone starts, the `time-floor` service raises a
   clock below the floor to it, with no network. A dead RTC starts at the
   build date.
3. Under 5 ms nothing happens; under 1 s the clock is slewed (`adjtime`), so
   it never runs backwards; up to the bound it is stepped.
4. Beyond the bound, one hour either way, the user decides: an RTC drifts
   seconds a day, so a genuine correction that large means a dead battery or
   years unused. The chrome asks through the broker's consent path and shows
   both the network's time and the machine's, so a user with a watch can
   answer. No session, no answer or "no" leaves the clock alone.
5. The bound also caps the total moved without asking since the clock was
   last anchored (by consent or by the floor), so small lies cannot add up.
6. kryptikd, the only process with `CAP_SYS_TIME`, applies it with
   `clock_settime(CLOCK_REALTIME)` and after a step sets the RTC
   (`RTC_SET_TIME` on `/dev/rtc0` if present). Each claim considered adds a
   line to `/var/lib/kryptik/time/history`; `kryptikd time status` prints the
   clock, the floor and the last line.

A net zone that never answers leaves the clock to the RTC; that is reported
(`time=no-answer`), not repaired.

## Tests

`time.rs` unit tests cover every rule above: the floor, the clamp, slew and
step, the bound per claim and in total, consent, the interval and the claim
grammar. The boundary suite checks that the verb is refused from a zone
without the network and that a malformed claim is refused.
`tools/test-netzone-time.sh` runs the query and its
caller against loopback servers five minutes ahead or behind, a day out among
three, unsynchronised, sending kiss-of-death, not echoing, or silent, under
every POSIX shell on the host. On the installed system,
`build/guest-tests/zones-check.sh` sets the clock to 2000 and checks the
clamp, then that a claim steps the clock, one below the floor is refused, a
day's jump waits for consent, and a clock 300 s fast is put right.

## Open points

- The bound and the interval are constants (`DEFAULT_BOUND_SECS`,
  `CLAIM_INTERVAL_SECS`); `time.conf` names only servers. The floor is not
  configurable.
- The date of the newest release the machine has committed to would be a
  better floor after an update than the running image's; it is not used yet.

## Files

`compartments/kryptikd/src/time.rs` (`kryptikd time floor | status`),
`broker.rs`, `consent.rs`, `tools/desktop/kryptik-chrome`,
`tools/net/sntp-offset.py`, `tools/net/netzone-init.sh`, `rootfs.rs`
(`time.conf` into the zones' `/etc`), `build/services/time-floor` and
`build/service-scripts/time-floor.sh`.
