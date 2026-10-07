# Broker

The broker is how a zone talks to zone 0. It carries clipboards and file
transfers, and, from the net zone only, the [clock](time.md) and
[update](update-channel.md) verbs. A transfer needs the user's consent in the
trusted chrome, a cross-zone paste is a gesture in zone 0, and each zone
started from the desktop gets its own Wayland proxy. Builds on
[privileged launch](privileged-launch.md) and the
[zone registry](zone-registry.md).

## Identity is the peer uid

Every zone has its own host uid range (`[identity] uid_base`). A connection
accepted in zone 0 carries `SO_PEERCRED`, whose uid the kernel asserts and a
zone cannot choose, so no token, handshake or crypto is needed. Each zone's
broker accepts only the uid its launcher mapped the zone to; any other peer
gets `error: unidentified peer` and nothing more. The peer pid is never used
(it is a zone 0 pid and may be reused). On an unprivileged developer launch
every zone maps to the same user, so identity distinguishes nothing there.

## The channel

The launcher binds one socket per zone in its registry entry
(`/run/kryptik/zones/<zone>/broker`, 0600, owned by the zone's identity) and
bind-mounts that file into the zone at `/run/kryptik/broker`. The
intermediate opens it (`O_PATH`) in its own mount namespace, before the id
switch. A zone reaches only its own endpoint: under `/run/kryptik` it has the
broker socket and, for a desktop launch, the proxy socket, and nothing else.
Zones inherit only fds 0 to 2 and reach the broker with `connect(2)`.

`kryptikd run` serves one request per connection between `waitpid` polls:
one header line, one reply, a 5 s deadline, every refusal decided from the
header before a payload byte is read, every attached descriptor closed after.
No general RPC:

```text
version\n                              -> kryptik-broker 1 zone=NAME\n
clipboard-set <mime> <len>\n<bytes>    -> ok\n
clipboard-get\n                        -> ok <mime> <len>\n<bytes>  |  empty\n
transfer <zone> <name>\n  (+1 fd)      -> ok <final name>\n
clipboard-move ...                     -> error: clipboard-move is a zone 0 act, not a zone verb\n
time-offset, update-latest,
update-poll, update-put                   the net zone only; see the clock and update channel
anything else                          -> error: <reason>\n
```

## File transfer

The zone sends `transfer <dest> <name>` with one `SCM_RIGHTS` descriptor it
opened `O_RDONLY`. Because it sends a descriptor, not a path, kryptikd never
resolves a path the zone controls. Checks, in order, stopping at the first
failure:

1. `dest` has the alphabet of a zone name; `name` is one path component of
   1 to 255 bytes, printable ASCII without spaces, not `.` or `..`, not
   starting with `.`.
2. Exactly one descriptor, and `dest` is not the sender.
3. The sender's `[transfer] to` lists `dest`, a configured zone (absent means
   no transfers). The zone holding the NIC receives nothing: `kryptikd check`
   refuses a `[transfer]` list that includes it, and the broker refuses it
   again. The only shipped policy is `dev`'s `to = "work"`.
4. The descriptor is a regular file, `O_RDONLY` and not `O_PATH`, on the
   sender's data mount (`st_dev` of `/home/<zone>`, read through the zone's
   pid 1 root at request time), and within the size limit (below).
   `/proc/self/fd/N` is never consulted.
5. The destination is running. A refusal here tells the sender whether a
   zone in its own `[transfer] to` is running, which timing would tell it
   anyway.
6. The user consents ([consent](#consent)). Asked last, so a request that
   would be refused anyway never becomes a question. After a question the
   user saw and did not allow, the same launch asks nothing for a minute:
   every question takes focus in zone 0, so a zone may not raise them in a
   loop. A refusal that showed nothing (no channel, nobody watching) does not
   pause.

No file larger than 1 GiB is carried, and a zone may lower that for itself
with `[transfer] max_bytes = N`, a whole number of bytes from 1 to 1073741824;
zero, a sign, a fraction, a unit or more than 1 GiB is refused when the zone
file is read. A zone's limit bounds every file it sends and every file it
receives, so a transfer is held to the smallest of the cap, the sender's limit
and the receiver's. The receiver's applies because the receiver is the one
that has to hold the file (an ephemeral zone in a tmpfs of fixed size), and no
sender can raise it; the sender's, because it bounds what can leave the zone
in one transfer. The sender's is read from its file at launch and the
receiver's at the request, and a refusal names whose limit it was. No shipped
zone sets one.

After the user answers, the destination is looked up again, so nothing holds
its mounts through the wait and a zone that stopped meanwhile gets nothing.
The file lands in its `incoming/`, resolved with `openat2` from its root
(`/proc/<pid 1>/root`) with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS`: a symlink the destination planted on the way is
refused, never followed, so nothing zone 0 writes can leave the destination's
tree. As root, the copy runs with the destination's filesystem uid and gid,
which is also what lets it create files in an ephemeral zone's tmpfs home.
The name is taken with `O_CREAT|O_EXCL|O_NOFOLLOW`; a collision or planted
link moves on to `-2`, `-3`, and so on, with no stat-then-create, temporary
file or `rename`. The file is 0600, owned by the destination. The copy is the
size `fstat` found, which the question showed, read from the file's first
byte whatever the descriptor's position (`copy_file_range` with its own
offset and a running count). A file that grew or shrank since is refused, and
any failure removes the partial file. The sender still owns the file, so it
can change bytes within that size; only the size is fixed. The sender learns
only the outcome and the final name.

## Consent

The user is reached through the desktop session, an ordinary user in group
`kryptik` that zone 0 cannot call into, so question and answer are files:

```text
/run/kryptik-consent/<id>.ask      from=ZONE to=ZONE name=NAME bytes=N
/run/kryptik-consent/<id>.code     the code the window asks for (the chrome's)
/run/kryptik-consent/<id>.answer   yes | no        (written by the chrome)
```

sysinit creates the directory `root:kryptik 2770`, outside `/run/kryptik`,
which the registry keeps 0700. No zone has a path to it. The chrome's watcher
sees each `.ask`, opens a trusted window (`kryptik-chrome --confirm ID`, with
the unzoned border no zone can have) and writes the answer. The broker waits
at most 60 s; silence, a malformed answer or a missing directory is a
refusal, and a question whose sender goes away is withdrawn.

The window takes focus when it maps, so a zone could time a request to land
under keys the user meant for the zone's own window. The window therefore
drops whatever was typed in its first second, half-typed lines included, then
asks for a two-digit code drawn for that question alone. Only the code, typed
after it shows, answers yes. No zone sees a zone 0 window, so none can type
the code. The code is kept beside the question for zone 0's tests, which
grants nothing: whatever can read the directory could write the answer.

The session's group can write in that directory, so nothing found there is
trusted. The broker opens the directory once and uses names relative to it
without following links. The question goes to an `O_EXCL` temporary name with
a random nonce that is also in its id, so no answer can be planted in
advance, and an answer that is not a plain file (a link, a FIFO) is a
refusal. The chrome's own writes there only create, never follow or clobber
(`set -C`), and its watcher removes a `.dialog`, `.code` or `.answer` that
outlived its question. The watcher holds `watcher.lock` exclusively while it
runs, so a broker that can take the lock shared knows nobody is watching and
refuses at once. `--auto-approve-transfers` approves everything for tests
without a session, and the launcher warns about it.

## Clipboard

kryptikd holds one payload per zone, as the file `clipboard` in its registry
entry: MIME type on the first line, at most 1 MiB, 0600, written to a fresh
`O_EXCL|O_NOFOLLOW` file and renamed into place. A zone sets and gets only its
own. The MIME type must be one of `text/plain`, `text/plain;charset=utf-8`,
`text/html`, `text/uri-list`, `image/png`, `image/jpeg`,
`application/octet-stream`, because a free-form label would itself be a
channel.

A cross-zone paste is a user gesture in zone 0: the chrome's `m<N><M>` (move
zone N's clipboard to zone M) runs `kryptik-launch --clipboard-move FROM TO`,
which the launch daemon carries out (as root, `kryptikd clipboard move FROM
TO` does the same). Both zones must be running. The payload leaves the source
and replaces the destination's: one payload crosses, once, and a second
gesture finds nothing to move. No zone can fetch another's payload or trigger
a move: the verb does not exist on the zone-facing socket. Zone 0 has no
transfer command either; the `kryptik` tool refuses `transfer`, `clipboard`
and `mount` and points at the broker.

## Compositor proxy

`kryptik-launch` starts one `kryptik-wlproxy --zone NAME` per desktop zone,
as the session user, at `$XDG_RUNTIME_DIR/kryptik/<zone>/wayland-0`, and the
launcher binds it into the zone at `/run/kryptik/wayland-0`
(`--wayland-socket`, with `--wayland-inode` naming the inode it must be).
The compositor's own socket is never reachable from a zone, and each proxy
serves exactly one zone. The proxy advertises only `wl_compositor`,
`wl_subcompositor`, `wl_shm`, `wl_seat`, `wl_output`, `xdg_wm_base`,
`zxdg_decoration_manager_v1` and `wp_viewporter`, disconnects a client that
binds anything else, bounds objects, pending bytes and descriptors per
client, and rewrites every window's title to `[zone] ...` and its app_id to
`kryptik.<zone>.<claimed>`, from which the compositor draws the zone's border.

## Tests

- `broker::tests` drive `serve_connection` over socketpairs with real
  `SCM_RIGHTS`: every refusal above with its exact reply, the transfer
  landing 0600 and byte-identical, numbered names, planted symlinks as the
  name and as `incoming`, a file growing past the cap mid-copy, the sender's
  and the receiver's `max_bytes` each refusing a file over it, descriptor
  leaks, and no second question within a minute of a refusal. `consent.rs`
  tests yes, no, silence, a missing channel or watcher, a vanished sender,
  planted names and a non-file answer.
- `tools/tests/chrome-confirm.py` runs the chrome's real question window on a
  pty: the code shown allows, a plain `y` refuses, and keys or a half line
  typed before the question showed are dropped, for the clock question too.
- The launcher suite's broker section: `version` reports the zone, an unknown
  verb is refused, the socket is 0600, a foreign peer is refused on a
  privileged launch.
- `build/guest-tests/gui-check.sh` on the installed desktop: the proxy hides
  every global outside the list and refuses a screencopy bind; a clipboard
  stays its zone's until the move gesture; a transfer outside policy is
  refused without a question; the code typed delivers byte-identical, a plain
  `y` refuses, and no question is left behind.
- The two hand-written parsers of zone bytes have seeded mutation tests, so a
  failure repeats on every machine. The broker's test damages each request in
  `compartments/kryptikd/fuzz-corpus/broker-requests` a hundred-odd ways and
  sends it over a real connection: no panic, no overrun of the deadline, one
  well-formed reply. It does so for a plain zone, for a sender whose policy
  and data mount let transfers through with a descriptor on every request,
  and, only when unprivileged, for the nic zone, whose time and update verbs
  would otherwise reach the host's clock and update state. The proxy's tests
  (`protocol.rs`, `session.rs`) damage a valid body of every message in the
  generated tables (no panic, no read past the body, only exact parses
  accepted) and feed a damaged opening through a live session in arbitrary
  fragments (only whole messages reach the compositor). Inputs that ever
  break a parser join the corpus.
- `.github/workflows/fuzz.yml` fuzzes both parsers under libFuzzer weekly,
  twenty minutes each, on a nightly pinned by date. `compartments/kryptikd/fuzz`
  takes the request parser, seeded from that corpus, and holds every request
  it accepts to the bounds its refusals enforce; `compositor/wlproxy/fuzz`
  takes the framing, every signature in the tables and the writer the
  rewrites use. An input that breaks one is kept as the run's artifact. Each
  is a package with a lockfile of its own, so libfuzzer-sys is in nothing that
  ships.

## Not built

- A zone-side client in the image. Zones speak the wire format directly; the
  tests use `build/guest-tests/broker-client.py`.

## Files

`compartments/kryptikd/src/broker.rs`, `consent.rs`, `spawn.rs` (the socket
and the serving loop), `main.rs` (`clipboard move`), `serve.rs`,
`tools/desktop/kryptik-chrome`, `tools/desktop/kryptik-launch.c`,
`compositor/wlproxy`.
