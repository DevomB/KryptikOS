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
date and the date of the newest release it has committed to, and bounds on
what it believes.

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
zone 0, so nothing is lost to the delay before zone 0 acts. It is a script,
not an NTP daemon, because a daemon is a whole package for one number and a
script can be tested against a real server on loopback. NTS is not used: the
image has no gnutls, and it would not authenticate a compromised net zone.

**The claim.** `time-offset <seconds> <sources>`: a signed decimal with at
most 10 integer and 6 fractional digits, and the number of servers (1 to 16)
whose median it is. It is accepted only from the zone whose file says
`mode = "nic"`, and only one claim per 10 minutes is considered, so a hostile
zone cannot flood the user with questions. The reply is `ok ignored`,
`ok slewed`, `ok stepped`, `ok stepped after consent` or `error: <reason>`,
and the net zone prints `time=<offset|no-answer|...>` in its readiness line.

**The decision** (`time::decide`, a pure function):

1. Nothing is applied or offered that puts the clock before the floor: the
   running image's build date (`built_at` in `/etc/kryptik-image.json`), or
   the signed date of the newest release this machine has committed to when
   that is later (below). With no build date known, every claim is refused.
2. At boot, before the net zone starts, the `time-floor` service raises a
   clock below the floor to it, with no network. A dead RTC starts at the
   floor.
3. Under 5 ms nothing happens; under 1 s the clock is slewed (`adjtime`), so
   it never runs backwards; up to the bound it is stepped.
4. Beyond the bound, one hour either way, the user decides: an RTC drifts
   seconds a day, so a genuine correction that large means a dead battery or
   years unused. The chrome asks through the broker's consent path and shows
   both the network's time and the machine's, so a user with a watch can
   answer. No session, no answer or "no" leaves the clock alone.
5. The bound also caps the total moved without asking since the clock was
   last anchored (by consent or by the floor), so small lies cannot add up.
   That total and the time of the last claim live in
   `/var/lib/kryptik/time/state`, and a claim is written there, with what it
   adds, before the clock moves or the user is asked. A claim that cannot be
   written is refused: unwritten, the next claim would meet neither the
   interval nor the bound.
6. kryptikd, the only process with `CAP_SYS_TIME`, applies it with
   `clock_settime(CLOCK_REALTIME)` and after a step sets the RTC
   (`RTC_SET_TIME` on `/dev/rtc0` if present). Each claim considered adds a
   line to `/var/lib/kryptik/time/history`; `kryptikd time status` prints the
   clock, the floor and the last line.

A net zone that never answers leaves the clock to the RTC; that is reported
(`time=no-answer`), not repaired.

**The newest release committed to.** After a rollback or a recovery the
running image is older than a release this machine has already run, and the
clock cannot be earlier than that release either. `kryptik-update apply`
keeps the manifest and signature it verified for the slot it writes
(`/var/lib/kryptik/boot/release-<slot>/`). Once `boot-success` has committed
a slot, `kryptikd time committed` copies that pair to
`/var/lib/kryptik/time/release/` if it names the running release and its
signed `created` date is later than the kept one's. The date is believed on
the release key's signature alone. Each process that needs the floor runs
`kryptik-update check-release` on the kept pair once, not per claim, and
again when the pair changes or a minute after a check that failed; it
checks the signature and the role against the running root's trust anchor
as `apply` does, in any version order. The state partition is not
authenticated ([state encryption](state-encryption.md)), so whoever can write
it can delete or damage the pair, which leaves the build date as the floor,
or put another release's genuine pair there, whose date has passed as well;
it cannot make the floor a date the release key did not sign. A release
signed by a key the running image does not list is not used.

The [statement of what is current](update-channel.md) is signed and newer
still, but its key is online and a statement may be dated a day ahead of the
clock: as a floor, a stolen key could walk the clock forward a day at a
time. A release built with a wrong date keeps the floor there through a
rollback; root deleting `/var/lib/kryptik/time/release` returns it to the
build date.

**Constants.** The bound (`DEFAULT_BOUND_SECS`), the interval
(`CLAIM_INTERVAL_SECS`) and the floor are not settings, and `time.conf` names
only servers. A value in `time.conf` would change only with a release, as a
constant does (a copy under `/etc` is quarantined at boot). One on the state
partition could be set by whoever writes that partition: a wider bound lets
lies through unasked, a shorter interval brings question after question, and
a moved floor holds the clock wrong.

## Tests

`time.rs` unit tests cover every rule above: the floor and the release that
raises it, which release a commit keeps, the clamp, slew and step, the bound
per claim and in total, consent, the interval and the claim grammar. The
boundary suite checks that the verb is refused from a zone without the
network and that a malformed claim is refused.
`tools/tests/update-manifest-snapshot.sh` runs `check-release` with the real
`ssh-keygen`: any version order, and the refusals `check-manifest` makes.
`tools/tests/boot-success.sh` checks that only a commit hands the slot's pair
on. `tools/tests/netzone-time.sh` runs the query and its
caller against loopback servers five minutes ahead or behind, a day out among
three, unsynchronised, sending kiss-of-death, not echoing, or silent, under
every POSIX shell on the host. On the installed system,
`build/guest-tests/zones-check.sh` sets the clock to 2000 and checks the
clamp, that a release dated 2099 and signed by a key the anchor does not list
leaves the floor alone, then that a claim steps the clock, one below the
floor is refused, a day's jump waits for consent, and a clock 300 s fast is
put right. The update suite (`tools/image/update-test.sh`) checks that the
floor is B's signed date once B is committed, and still is after the
recovery to A.

## Files

`compartments/kryptikd/src/time.rs` (`kryptikd time floor | status |
committed`), `broker.rs`, `consent.rs`, `tools/desktop/kryptik-chrome`,
`tools/net/sntp-offset.py`, `tools/net/netzone-init.sh`, `rootfs.rs`
(`time.conf` into the zones' `/etc`), `build/services/time-floor`,
`build/service-scripts/time-floor.sh`, `boot-success.sh` and
`tools/update/kryptik-update` (`check-release`, the kept manifest).
