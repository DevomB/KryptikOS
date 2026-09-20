# An update channel

Status: implemented in `kryptikd` (`update.rs`, the broker's three verbs,
`kryptik update`), in `kryptik-update` (`check-manifest`, `check-pointer`)
and in the net zone (`update-fetch.py`), with the rules, the verbs' refusals
and the fetcher tested offline. Not yet exercised on the installed system:
the last row of the test table, and the release tooling that publishes a
pointer, are open. Builds on [boot and updates](boot-and-updates.md), whose
verification it does not change, on [the broker](broker.md), which carries
the bytes, and on [the clock](time.md), without which freshness means
nothing.

## The problem

`kryptik-update apply DIR` verifies a release and installs it, and says so
in its first lines: "the payload arrives as files (the net zone fetches,
this verifies)". Nothing fetches. A release reaches a machine today on a
disk someone carries to it.

The pieces that make fetching hard are the ones that make Kryptik what it
is:

- **Zone 0 has no network**, and will not get one for this.
- **The net zone is hostile.** Whatever it hands over is what an attacker
  on the path, or in that zone, chose to hand over.
- **Nothing flows into the net zone.** No zone may send it a file, and zone
  0 has no channel to it at all: zones call their broker, never the
  reverse. So zone 0 cannot say "fetch this"; the net zone has to ask.
- **The net zone cannot hold a release.** Its storage is a 512 MB tmpfs that
  dies with it, and a root image is larger than that. It can only stream.
- **Zone 0 must not store what it has not authenticated**, or a hostile net
  zone fills the state partition with a "release" that was never one.

## What is not changed

Everything `kryptik-update apply` checks, in the order it checks it: the
manifest's signature against the trust anchor on the verified root, the
role, the version against the running one (a downgrade is refused unless
`--recovery` asks for it), every file's size and hash, nothing unlisted,
both kernels embedding the root image's hash - all before the first write.
A fetched payload is treated exactly as a disk someone handed over. The
channel's whole job is to get a directory onto the state partition that
`apply` can be pointed at; if the channel is wrong in every way it can be,
the result is a directory `apply` refuses.

## The design

```text
 the release host          net zone                     broker (zone 0)                 zone 0
 latest, latest.sig  ───▶  fetch the pointer     ───▶   update-latest: verify, compare
 <version>/manifest…       poll: is one wanted?  ◀───   update-poll: idle | fetch <v> …  ◀── `kryptik update fetch`
                           stream it, file by    ───▶   update-put: manifest first, then
                           file, holding nothing        only what it lists, at its sizes ──▶ staged directory
                                                                                          `kryptik update apply`
                                                                                          = kryptik-update apply DIR
```

### A signed statement of what is current

The release host serves two small files beside the payloads:

```text
latest        KRYPTIK-LATEST-1
              role: production
              version: 1.0.3
              issued: 2027-03-02T14:05:00+00:00
              manifest-sha256: <64 hex>
              base: https://<host>/<channel>/1.0.3/
latest.sig    an OpenSSH signature over those bytes, namespace kryptik-latest
```

`base` may be absolute or relative. A relative one is resolved against the
channel address on the verified root, never against anything the net zone
reports, so a mirror can move without the pointer being signed again; and
since the pointer carries the manifest's hash, where the bytes come from
decides nothing about what they must be.

It is signed in a namespace of its own, so a manifest's signature can never
be replayed as a pointer nor a pointer's as a manifest. Which key signs it
is an open decision (below).
The channel's address is zone 0's to give (`channel = <address>` in
`/etc/kryptik/update.conf`, visible read-only in the nic zone like the time
sources), so the net zone is not told where to look by anything it could
have written. With no such file there is no channel: the net zone asks
nobody and `update-poll` answers `idle`.

Zone 0 accepts a pointer when its signature verifies against the same trust
anchor releases are verified against, its role is the one this image
requires, and its `issued` is not earlier than the newest pointer this
machine has already accepted. That last rule is what stops a hostile zone
replaying last year's pointer: zone 0 remembers the highest `issued` it has
seen (`/var/lib/kryptik/update/pointer`), and an older one is refused however
valid its signature.

**Freshness needs the clock.** A net zone that simply withholds new pointers
holds a machine on an old release, and no signature detects an absence. The
release process re-issues the pointer on a schedule even when nothing has
changed, and zone 0 reports a pointer older than a bound (30 days) as what
it is: "no statement from the release key for N days: either nothing has
been published, or something is keeping it from this machine". It cannot
tell which, and says both. This is why the clock comes first
([time](time.md)): with a clock the net zone could set, it could make any
pointer fresh.

### The net zone asks; zone 0 never calls

Three verbs on the broker, all from the zone that holds the network and no
other, like `time-offset`:

```text
update-latest <plen> <slen>\n<pointer><signature>
    at most 8 KiB each; one considered per hour
    -> ok current | ok available <version> | error: <reason>

update-poll
    -> idle
     | fetch <version> <base> need <name> <offset> [<name> <offset> ...]

update-put <name> <offset> <len>\n<bytes>
    -> ok <name> <received>/<size> | ok <name> complete | error: <reason>
```

The net zone fetches the pointer daily and hands it over. When the person
has asked for the release (`kryptik update fetch`, or a policy that asks on
their behalf), `update-poll` answers with what is wanted: the version, the
base address **from the verified pointer**, and which files are still
missing and from which byte. The net zone polls because nothing can call it.

### Bytes cross in an order that bounds them

`update-put` takes `manifest` and `manifest.sig` first and nothing else,
64 KiB at most each. When both are there zone 0 verifies them exactly as
`kryptik-update` does (the same code: a `kryptik-update check-manifest`
subcommand that runs the signature, role and version steps and prints the
file list) and checks the manifest's SHA-256 against the pointer's. Only
then does it accept anything large, and then only:

- a name the signed manifest lists,
- at an offset equal to what it already holds of that file (so a broken
  download resumes and nothing is written twice or out of order),
- never past the size the signed manifest gives for that file,
- with the whole staging area bounded by the manifest's total, checked
  against the state partition's free space before the first byte.

So the most a hostile net zone can make zone 0 store is the declared size
of a release that the release key signed, once, in one staging directory
(`/var/lib/kryptik/update/incoming/<version>/`, root only). Wrong bytes of
the right length are caught where they always were: `apply` hashes every
file against the manifest before it writes a slot.

The net zone holds nothing: it reads from the HTTPS connection and writes
to the broker socket in the same loop (HTTP range requests give it the
offset zone 0 asked for). TLS authenticates the host with the image's CA
bundle and keeps the download private; nothing about the payload's
authenticity rests on it. A `development` image may name an `http://`
address, which is what the test network serves; a `production` one may not.

A release is hundreds of megabytes through a socket the launcher also
supervises its zone with. It crosses in pieces of at most 1 MiB, each one
request that the launcher answers between two looks at its zone, under the
same five-second deadline as every other request. Supervision, the zone's
other verbs and its death are therefore never further away than one piece,
and there is no second process, no long-lived connection and no state
between pieces other than the staged file's length.

### The person, and what they see

`kryptik update status | fetch | apply` go through the launch service like
`kryptik wifi`. `status` says the running version, the version the newest
accepted pointer names and how old that pointer is, and what is staged and
how much of it has arrived. `fetch` marks the release wanted. `apply` runs
`kryptik-update apply` on the staged directory - the trial boot, the
health-judged commit and the fallback are the existing ones - and the
staging area is removed once the new release has committed. Nothing is
downloaded or installed without the person having asked, unless they have
set the policy that asks for them.

## What a hostile net zone can still do

- **Withhold.** No pointer, no payload. Reported through the pointer's age,
  not prevented.
- **Waste bandwidth and one release's worth of disk**, once per version
  wanted: bytes of the right length and the wrong content, refused at
  `apply`, after which the staging directory is discarded and the file is
  needed again. Bounded, visible in `status`, and the same attacker could
  have cut the cable.
- **Learn that this machine runs Kryptik and which release it asked for.**
  It carries the traffic; it always knew.

What it cannot do: install anything the release key did not sign, install
an older release, present an old statement as current, or make zone 0 keep
a byte the signed manifest did not provide for.

## Tests

| check | expected |
|---|---|
| a pointer signed by another key, in the manifest's namespace, or for another role | refused |
| a validly signed pointer older than one already accepted | refused: replay |
| a pointer older than the bound, against the clock | accepted as the newest known, and reported as stale |
| `update-put` of anything before the manifest and its signature have verified | refused |
| a name the manifest does not list; an offset that is not what is held; a byte past the listed size | refused; nothing written |
| a manifest whose hash is not the pointer's | refused: not the release that was announced |
| more than the state partition can hold | refused before the first byte |
| the three verbs from a zone that does not hold the network | refused by identity |
| a download cut at any byte | resumes from that byte; the staged file is identical |
| right sizes, wrong bytes | staged, then refused by `apply`; the slot is never written |
| the whole path on the installed system | the host serves release B over the test network; the net zone fetches it, zone 0 stages and applies it, the machine trial-boots B and commits |

The rules about pointers and offsets are pure functions and unit-tested; the
verbs' refusals run in the boundary suite against a real zone; the fetcher
runs against a local server in an offline suite, with the interrupted and
the hostile cases; the last row joins the update suite.

## A decision for the owner: which key signs the pointer

Detecting a withheld update needs the pointer re-issued on a schedule, and a
schedule needs a key that is available on a timer. The roadmap's production
release key is meant to live offline. Those two pull against each other, and
the choice is about how the keys are held, which is the owner's:

- **The release key signs pointers too.** One key, one trust anchor, and it
  has to come online every time the pointer is refreshed. The freshness
  check costs the offline key its offline-ness.
- **A separate freshness key**, certified by the release key and honoured
  only in the `kryptik-latest` namespace. It lives online and re-signs on
  the timer; the release key stays offline and signs releases. If the
  freshness key is stolen, the thief can keep asserting that an old release
  is current - the same freeze a hostile net zone can already cause by
  withholding, made to look fresh - and nothing more: it cannot sign a
  manifest, so it cannot install anything, and zone 0 still refuses a
  pointer older than one it has accepted. Revoking it is a release.
- **No schedule.** The pointer is signed by the offline key only when a
  release is made, and a withheld update is simply not detectable. Honest,
  and weaker.

The design above works with any of the three; only who holds which key, and
whether `status` can say "stale", changes.

## Open points

- The release process that publishes `latest`, its signature and the
  payload tree, and re-issues the pointer on a schedule, is release tooling
  (`tools/release-manifest.sh` is where the manifest is made today).
- Whether `fetch` should be automatic by default. The design asks the
  person; a machine nobody watches wants the policy.
- Delta updates. A root image is downloaded whole; dm-verity's block
  structure would allow fetching only changed blocks, and nothing here
  prevents it later.

## Files

`compartments/kryptikd/src/update.rs` (the pointer and staging rules, and
what zone 0 keeps under `/var/lib/kryptik/update`), `broker.rs` (the verbs),
`serve.rs`, `tools/desktop/kryptik-launch.c` and `tools/kryptik` (`kryptik
update`), `tools/update/kryptik-update` (`check-manifest`, `check-pointer`),
`tools/net/update-fetch.py` and `tools/net/netzone-init.sh` (the net zone's
half), `rootfs.rs` (`/etc/kryptik/update.conf` into the nic zone's `/etc`;
the CA bundle under `/etc/ssl/certs` was already there), and the suites:
the `update.rs` and `broker.rs` unit tests, `make test-update-verify`, `make
test-update-fetch`, and the update rows of the boundary suite.
