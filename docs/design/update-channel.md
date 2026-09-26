# Update channel

How a release reaches a machine over the network without changing what
`kryptik-update apply` verifies. The net zone fetches, the
[broker](broker.md) carries the bytes, and zone 0 decides what to believe and
store. Builds on [boot and updates](boot-and-updates.md) and the
[clock](time.md).

## Constraints

Zone 0 has no network and gets none for this. The net zone is hostile.
Zones call their broker, never the reverse, so zone 0 cannot say "fetch
this": the net zone has to ask. Its 512 MB tmpfs is smaller than a root
image, so it can only stream. Zone 0 must not store what it has not
authenticated, or a hostile net zone could fill the state partition.

`apply` still checks everything before its first write (the signature, the
role, the version, every file's hash and size, nothing unlisted, the root
hash in both kernels), and a fetched payload is treated exactly like one on a
disk. The channel only puts a directory on the state partition; a channel
wrong in every possible way yields a directory `apply` refuses.

```text
 the release host          net zone                     broker (zone 0)                 zone 0
 latest, latest.sig  ───▶  fetch the pointer     ───▶   update-latest: verify, compare
 <version>/manifest…       poll: is one wanted?  ◀───   update-poll: idle | fetch <v> …  ◀── `kryptik update fetch`
                           stream it, file by    ───▶   update-put: manifest first, then
                           file, holding nothing        only what it lists, at its sizes ──▶ staged directory
                                                                                          `kryptik update apply`
                                                                                          = kryptik-update apply DIR
```

## The statement of what is current

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

- Its own namespace means a manifest's signature can never pass as a
  pointer's, or the reverse.
- Zone 0 names the channel: `channel = <address>` in
  `/etc/kryptik/update.conf`, bound read-only into the zones' `/etc` like
  `time.conf`. Only the verified root's copy lasts (one root writes at run
  time is quarantined at the next boot), and no build ships one yet. Without
  it the net zone asks nobody and `update-poll` answers `idle`. The address
  is not a trust anchor.
- `base` is absolute, or relative to the channel address and staying under
  it, never resolved against anything the net zone says. The pointer carries
  the manifest's hash, so where the bytes come from decides nothing about what
  they must be. Only a `development` image may use plain `http`.
- Zone 0 accepts a pointer when its signature verifies against the release
  trust anchor (before anything in it is parsed), its role is this image's,
  it is dated at most a day ahead of the local clock, and its `issued` is not
  earlier than the newest accepted (`/var/lib/kryptik/update/pointer`). An
  older one is a replay, however valid its signature; one dated far ahead
  would turn every later statement into a replay.
- A net zone that withholds pointers holds the machine on an old release, and
  no signature can show an absence. The pointer is therefore re-issued on a
  schedule, and one older than 30 days is reported: "no statement from the
  release key for N days: either nothing has been published, or something is
  keeping it from this machine". That needs a clock the net zone cannot set.

**Which key signs it.** Re-signing on a schedule needs a key a timer can
reach, and the release key is meant to stay offline, so the build uses two:
stage 04 enrols `kryptik-release namespaces="kryptik-release"` and
`kryptik-latest namespaces="kryptik-latest"` and checks on every build that
each verifies only in its own namespace, and `tools/release-manifest.sh
pointer` signs with the second. A stolen statement key can only keep
claiming an old release is current, the freeze a withholding net zone causes
anyway: it cannot sign a manifest, zone 0 still refuses a statement older
than one it accepted, and replacing the key takes a release. Using one key
for both means listing the release key on the second line.

## The verbs

Taken only from the zone that holds the network, like `time-offset`:

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

The net zone brings the pointer every 30 minutes until one is accepted, then
daily, and polls every minute. Once the user has asked (`kryptik update
fetch`), `update-poll` names the version, the base from the verified pointer,
and each missing file with the byte to resume from.

## Bytes in an order that bounds them

`update-put` first takes only `manifest` and `manifest.sig`, whole, at most
64 KiB each. Zone 0 runs `kryptik-update check-manifest` (the signature, role
and version checks of `apply`, with no downgrade: nothing from the network is
a recovery) and requires the manifest to be for the wanted version, to hash
to the pointer's `manifest-sha256`, and to fit in the free space. A refused
manifest clears the stage, and for an hour after a refusal the next one is
refused without being verified. Then it
takes only a listed name, at exactly the offset it holds (so a cut download
resumes and nothing is written twice), never past the signed size.

So a hostile net zone can make zone 0 store at most the declared size of a
release the release key signed, once, in one root-only directory
(`/var/lib/kryptik/update/incoming/<version>/`); wrong bytes of the right
length fail `apply`'s hashes. The net zone streams HTTPS straight into the
broker, resuming with range requests. TLS, with the image's CA bundle, keeps
the download private; authenticity does not rest on it. Each piece of at
most 1 MiB is one request the launcher answers between looks at its zone,
under the 5 s deadline, so supervision is never more than a piece away.

## What the user sees

`kryptik update status | fetch | apply` go through the launch service.
`status` shows the running version, the newest pointer's version and age,
and what has arrived. `fetch` asks for the release the newest pointer names.
`apply` runs `kryptik-update apply` on the complete stage, with the usual
trial boot and fallback; the stage goes once the machine runs that release.
Nothing is fetched or installed unless the user asks.

## What a hostile net zone can still do

Withhold (reported through the pointer's age, not prevented); waste bandwidth
and one release's worth of disk per version, with right-sized wrong bytes that
`apply` refuses; and see that the machine runs Kryptik and which release it
wants. It cannot install anything the release key did not sign, install an
older release, present an old statement as current, or make zone 0 keep a byte
the signed manifest does not provide for.

## Tests

- `update.rs` unit tests cover every rule above; `broker.rs` unit tests and
  the boundary suite check the verbs' bounds and that only the network zone
  may use them.
- `make test-update-manifest-snapshot`: `check-manifest` and `check-pointer`
  with the real `ssh-keygen` refuse the other namespace, an unenrolled key,
  another role, a downgrade and a listed path that climbs.
- `make test-update-fetch`: the fetcher against a loopback server, including
  resuming after a cut, a server that ignores ranges, and a refused piece.
- Stage 06 checks that the image's anchor refuses `not-a-pointer`, the
  statement signed by the release key, and the update suite checks that
  `check-pointer` refuses it on the installed system.
- The update suite's network step (`tools/image/update-test.sh`): nothing is
  fetched until asked, then the release arrives whole, is applied,
  trial-booted and committed.

## Open points

- Release tooling to publish `latest` and the payloads and re-issue the
  statement on a schedule; today stage 06 writes one statement per build.
- Whether fetching should be automatic; an unattended machine would want it.
- Delta updates: dm-verity's block structure would allow fetching only
  changed blocks instead of the whole image.

## Files

`compartments/kryptikd/src/update.rs`, `broker.rs`, `serve.rs`,
`rootfs.rs` (`update.conf`), `tools/kryptik` and
`tools/desktop/kryptik-launch.c` (`kryptik update`),
`tools/update/kryptik-update` (`check-manifest`, `check-pointer`),
`tools/net/update-fetch.py`, `tools/net/netzone-init.sh`,
`tools/release-manifest.sh` (`pointer`), `build/stages/04-base-system.sh`
(the keys) and `06-iso.sh` (the statement per build).
