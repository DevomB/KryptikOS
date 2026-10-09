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
 <version>/manifest…       poll: is one wanted?  ◀───   update-poll: idle | fetch <v> …  ◀── `kryptik update fetch`, or `auto on`
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
  time is quarantined at the next boot). A build names it with
  `KRYPTIK_CHANNEL` (`make media KRYPTIK_CHANNEL=https://<host>/<channel>/`).
  Before it builds anything, stage 06 refuses an address the image could not
  use. Both readers append names to the address as a string, so it must be
  `http(s)://host[:port][/path]`, with no `user@`, query or fragment, in
  printable ASCII of at most 512 bytes, and plain `http` only on an image
  whose role is `development`. Zone 0 itself checks only the scheme. Without
  a channel, the image ships no `update.conf`, the net zone asks nobody and
  `update-poll` answers `idle`. The address is not a trust anchor.
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
  keeping it from this machine", by `kryptik update status` and above every
  login prompt, from `/run/issue.d/kryptik-update.issue`, which the launch
  service writes as it starts and checks hourly. A machine whose image names a
  channel and that has accepted none reports it 30 days after its install,
  the time the installer wrote `/var/lib/kryptik/install.json`. That needs a
  clock the net zone cannot set.

**Which key signs it.** Re-signing on a schedule needs a key a timer can
reach, and the release key signs only in a release run its maintainer
approves, so the build uses two.
The anchor stage 06 puts on the image lists the release key as
`kryptik-release namespaces="kryptik-release,kryptik-media"` (manifests, and
the media's checksums) and the statement key as
`kryptik-latest namespaces="kryptik-latest"`, each honoured in its own
namespaces only, and no key under both. While a key is replaced it lists the
old one and the new one. A development build proves the split with a probe
signed by each key in each namespace, and a production build refuses a key
medium whose anchor says anything else. `tools/release-manifest.sh pointer`
signs with the statement key. A stolen statement key can keep claiming an old release is
current, the freeze a withholding net zone causes anyway, and with a way to
hand machines its statements, such as a net zone it holds, it hides that
freeze: fresh statements keep the 30-day report from appearing. It cannot
sign a manifest, zone 0 still refuses a statement older than one it
accepted, and replacing the key takes a release. So it lives where only
main's workflows reach it.

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
daily, and polls every minute. Once a release is asked for (`kryptik update
fetch`, or by [automatic fetching](#automatic-fetching)), `update-poll` names
the version, the base from the verified pointer, and each missing file with
the byte to resume from. For an hour after a refused manifest it answers
`idle`, since the next one would be refused unread.

## Bytes in an order that bounds them

`update-put` first takes only `manifest` and `manifest.sig`, whole, at most
64 KiB each. Zone 0 runs `kryptik-update check-manifest` (the signature, role
and version checks of `apply`, with no downgrade: nothing from the network is
a recovery) as `nobody`, with no new privileges, on copies in a directory of
its own under `/run`, one check at a time, and ends whatever still runs as
`nobody` after it, as it runs `check-pointer` and `check-release`: they read
what the net zone sent with `ssh-keygen` and the shell's text tools, and
refuse to run as root. `apply`, which runs as root, has the staged pair's
signature checked the same way (`kryptikd check-release`) before it reads the
manifest itself. Zone 0 then requires the manifest to be for the wanted version, to hash
to the pointer's `manifest-sha256`, and to fit in the free space. A refused
manifest clears the stage, and for an hour after a refusal none is asked for
and one sent anyway is refused without being verified, so a release that does
not fit is tried hourly, not at every poll. Then it takes only a listed name,
at exactly the offset it holds (so a cut download resumes and nothing is
written twice), never past the signed size.

So a hostile net zone can make zone 0 store at most the declared size of a
release the release key signed, once, in one root-only directory
(`/var/lib/kryptik/update/incoming/<version>/`); wrong bytes of the right
length fail `apply`'s hashes, and the launch service then discards what had
arrived, so the release is fetched again and one bad download does not hold
the machine at its release until the next one is announced. The net zone streams HTTPS straight into the
broker, resuming with range requests. TLS, with the image's CA bundle, keeps
the download private; authenticity does not rest on it. A redirect from https
is followed only to https, so a server cannot move a production image's
download into the clear. Each piece of at
most 1 MiB is one request the launcher answers between looks at its zone,
under the 5 s deadline, so supervision is never more than a piece away.

## What the user sees

`kryptik update status | fetch | apply | auto on|off` go through the launch
service. `status` shows the running version, the newest pointer's version and
age, whether fetching is automatic, and what has arrived. `fetch` asks for the
release the newest pointer names. `apply` runs `kryptik-update apply` on the
complete stage, with the usual trial boot and fallback; the stage goes once
the machine runs that release and its trial is judged, so after a failed
trial the `--retry` the refusal prints names a stage that is still there.
Nothing is installed unless the user asks, and nothing is fetched unless the
user asks or has turned automatic fetching on.

## Automatic fetching

`kryptik update auto on` lets an unattended machine fetch each release as it
is announced; installing it stays the user's act, and off is the default.
While it is on, each `update-poll` first asks for the release the newest
accepted statement names, when that is newer than the running release and not
the one asked for, as `fetch` would ask for it; what `fetch` would refuse
(nothing newer, or a base this image does not fetch from) stays unasked, and
the poll answers `idle`. A release is asked for at the first poll after its
statement is accepted, so within a day of being published, and a newer one
replaces it, stage and all. `auto off` asks for nothing more; a release
already asked for keeps arriving, as one asked for by hand does.

- **Where it lives.** `/var/lib/kryptik/update/auto`, beside `wanted`: on the
  state partition, root's alone, and the machine's own. Not in `update.conf`,
  which is on the verified root when the build names a channel, so the same
  on every machine of a build: a copy written under `/etc` at run time is
  quarantined at the next boot (`prune_etc_upper`,
  [state encryption](state-encryption.md)), and adding it to that allow-list
  would let the state partition name the channel too. Only `on` turns it on,
  so a block an offline writer damages reads as off.
- **Who changes it.** Whoever may use `fetch`: the launch service takes
  `update-auto on|off` from those it takes `update-fetch` from (group
  `kryptik`) and logs the change, which allows nothing `fetch` does not. No
  zone can change it, the net zone included: the broker has no verb for it.
  `on` is refused on an image that names no channel.
- **What a hostile net zone gains.** The timing, not the amount. Without it,
  zone 0 stores nothing until the user asks; with it, a release is staged
  once an accepted statement names it. Disk use is bounded as before, by one
  release's worth per version: the declared size of a release the release key
  signed, one release at a time (asking for a newer one removes the older
  stage), taken only if it fits in the free space when its manifest
  verifies. Statements are signed and never go backwards, so the net zone
  cannot choose the version or make zone 0 fetch, drop and fetch again; and
  it could already spend the bandwidth.
- **How the user learns.** `kryptik update status` says
  `staged <version>: ... complete; kryptik update apply installs it` once a
  release has arrived whole, and while it waits the chrome's launcher names
  it and where to apply it. Once the newest accepted statement is more than
  30 days old, or, on a machine that names a channel and has accepted none,
  once its install is, `status` says so and the launcher shows one line with
  that age: statements are re-signed on a schedule, so either nothing has
  been published or something is keeping them from this machine.

## What a hostile net zone can still do

Withhold (reported through the pointer's age, which `status` and the
launcher show, not prevented); waste bandwidth
and one release's worth of disk per version, with right-sized wrong bytes that
`apply` refuses (with automatic fetching on, without the user asking first);
and see that the machine runs Kryptik and which release it wants. Whoever can
crash the net zone from the network can also fail a new release's trial and
hold the machine on its old release, as withholding does
([boot and updates](boot-and-updates.md) says why the net zone is checked all
the same). It cannot install anything the release key did not sign, install an
older release, present an old statement as current, make zone 0 keep a byte
the signed manifest does not provide for, or turn automatic fetching on.

## Publishing

A channel is a directory served as it stands: `latest`, `latest.sig`, and one
directory per version, which the statement's `base` names relative to the
channel. `tools/release-channel.sh` is the only thing that writes one:

- `publish` verifies a payload as the image will (`--exact --strict`, and not
  older than the version the channel names), links it in under its version
  by way of a temporary name, and only then signs a new statement. A
  published version never changes: a client may be part way through it.
- `reissue` signs the same statement again with the current date. It runs
  from a timer, daily, on the machine that holds the statement key, so the
  30-day report means something went wrong rather than that nobody re-signed.

Each new statement is checked against the image's anchor, as a client checks
it, before it replaces the old pair, so a failure leaves the channel as it
was. Both commands build only on a statement that verifies, and refuse a date
clients would refuse (before the current statement's, or more than a day
ahead). One run at a time holds the channel. Stage 06 publishes each build
into `images/channel-<version>/` the same way, and the update suite serves
that directory.

## The release host

The channel Kryptik ships lives on GitHub, in two parts a statement's `base`
joins: the payload's files are among the release's files on the Releases
page (`tools/release-publish.sh` uploads them under the manifest's names, so
`https://github.com/<owner>/<repo>/releases/download/v<version>/` serves
`manifest`, `kryptik-root.img` and the rest), and the statement is served by
the repository's Pages site at `https://<owner>.github.io/<repo>/stable/`,
which is the address an image is built with. The statement key is the
`github-pages` environment's `KRYPTIK_LATEST_KEY` secret, an environment that
deploys from `main` alone, and the `Update channel` workflow
(`.github/workflows/channel.yml`) is the timer: dispatched with a release's
tag it publishes that release into the channel, dispatched with none or on
its daily schedule it signs the current statement again, and its dry run
proves the host with throwaway keys under `test/`. `tools/channel-host.sh`
does the work: it mirrors what the site serves before it writes, so a date
only moves forward and a deployment keeps every channel, and it verifies the
payload it fetched from the page as the image will before naming it. A
`publish` with `--base` and a `reissue` with `--manifest` are the
`release-channel.sh` forms it uses, since the payload is not under the
channel's directory.

## Tests

- `update.rs` unit tests cover every rule above; `broker.rs` unit tests and
  the boundary suite check the verbs' bounds and that only the network zone
  may use them.
- `make test-update-manifest-snapshot`: `check-manifest` and `check-pointer`
  with the real `ssh-keygen` refuse the other namespace, an unenrolled key,
  another role, a downgrade and a listed path that climbs.
- `make test-update-fetch`: the fetcher against a loopback server, including
  resuming after a cut, a server that ignores ranges, and a refused piece;
  and its redirect rule: from https to http or ftp refused, to https followed.
- A development build's stage 06 checks that the image's anchor refuses
  `not-a-pointer`, the statement signed by the release key, and the update
  suite checks that `check-pointer` refuses it on the installed system.
- The update suite's network step (`tools/image/update-test.sh`), from the
  channel stage 06 published: nothing is fetched while that is left to the
  user; with automatic fetching on, the release arrives whole without a
  `fetch`, is applied, trial-booted and committed, and the setting outlasts
  the update. A production image fetches nothing over plain http, asked or
  automatically.
- `tools/tests/release-channel.sh`: `publish` and `reissue` with throwaway
  keys. A wrong key, an older release, a tampered payload, a replaced
  manifest, a replayed or far-ahead date, and a second run at once are each
  refused, and each leaves the old pair.
- The desktop suite runs the launcher with a stored statement from today and
  with one 45 days old, and with none and the install 45 days old: only the
  last two name the age.
- `tools/tests/channel-setting.sh`: the addresses stage 06 takes and refuses
  for `KRYPTIK_CHANNEL` for each role, and, for every address it takes, the
  fetcher reading the written `update.conf` into requests it can send.

## Open points

- A way to stop a release that is arriving: once asked for, by hand or
  automatically, it is fetched until it is whole or a newer statement names
  another.
- Delta updates: dm-verity's block structure would allow fetching only
  changed blocks instead of the whole image.

## Files

`compartments/kryptikd/src/update.rs`, `broker.rs`, `serve.rs`,
`rootfs.rs` (`update.conf`), `tools/kryptik` and
`tools/desktop/kryptik-launch.c` (`kryptik update`),
`tools/desktop/kryptik-chrome` (the launcher's lines for a release that waits
and for a stale statement),
`tools/update/kryptik-update` (`check-manifest`, `check-pointer`),
`tools/net/update-fetch.py`, `tools/net/netzone-init.sh`,
`tools/release-manifest.sh` (`pointer`), `tools/release-channel.sh`,
`tools/channel-host.sh` with `.github/workflows/channel.yml` (the host),
`build/recipes/openssh.sh` (ssh-keygen, which verifies them) and `build/stages/06-iso.sh` (each build's
channel, and `update.conf` from `KRYPTIK_CHANNEL`).
