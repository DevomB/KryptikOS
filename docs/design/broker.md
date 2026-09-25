# Broker authentication and the trusted desktop boundary

Status: implemented. The broker (`compartments/kryptikd/src/broker.rs`)
serves identity, the clipboard and file transfer; the consent prompt
(`consent.rs`, answered by `tools/desktop/kryptik-chrome`) asks the person
before a transfer; the clipboard move is a zone 0 gesture in the chrome and
the launch daemon; the per-zone Wayland proxy (`compositor/wlproxy`) is
bound into zones started from the desktop. Not built: a per-zone transfer
size limit and a zone-side client shipped in the image; see
[As built](#as-built). Builds on
[the privileged launch design](privileged-launch.md) (identity),
[resource limits and ephemeral zones](resource-limits-and-ephemeral-zones.md)
(lifecycle) and [the net zone](net-zone.md).

## The one mechanism: identity is the peer uid

Every zone has a unique host uid range (`[identity] uid_base`; see
[the privileged launch design](privileged-launch.md)). An `AF_UNIX` socket
accepted in zone 0 yields `SO_PEERCRED`, whose `uid` is in exactly one
zone's range. That is the authentication of the sender: **kernel-asserted,
unforgeable from inside a zone, needs no token, no handshake, no crypto.**
The pid in `SO_PEERCRED` is ignored (it is a pid in zone 0's namespace and
may be reused), and the gid is checked only for consistency.

## The channel

- The launcher binds one listening socket **per zone**, in zone 0, in the
  zone's registry entry at `/run/kryptik/zones/<zone>/broker` (0600, zone
  identity), and binds that socket file into the zone's tree at
  `/run/kryptik/broker` (a file bind on the sealed root tmpfs, like
  `/etc/ld.so.cache`). A zone can only reach its own endpoint; there is no
  shared socket directory. The broker socket and, for a zone started from
  the desktop, the Wayland proxy socket are the only things a zone sees
  under `/run/kryptik`.
- The descriptor rule stands: zones inherit fds 0, 1, 2 and nothing else.
  The broker is reached by `connect(2)`, not by an inherited fd.
- Protocol: one header line per request, one request per connection,
  replies likewise, `SCM_RIGHTS` for file payloads. No general RPC: three
  verbs, `transfer`, `clipboard-set`, `clipboard-get`, plus `version`.

## File transfer (the smallest authenticated, policy-checked channel)

- The zone sends `transfer <dest> <name>` with one `SCM_RIGHTS` fd, opened
  `O_RDONLY` by the zone. Passing an fd instead of a path is what removes
  every path race: kryptikd never resolves a path the zone controls.
- kryptikd checks, in order, refusing on the first failure:
  1. Sender = zone from the `SO_PEERCRED` uid. The header is parsed:
     `dest` has the alphabet of a zone name, and `name` is one path
     component, no `/`, not `.`/`..`, 1 to 255 bytes, printable ASCII
     without spaces, no leading `.` (so a zone cannot plant dotfiles).
  2. Exactly one descriptor is attached; `dest != sender`.
  3. Policy: `[transfer] to = "work personal"` in the *sender's* zone file
     (space-separated names, validated against the zone set; absent = no
     transfers) must name `dest`, and `dest` must be a configured zone. The
     zone that holds the NIC receives nothing, ever: `kryptikd check`
     refuses a zone directory whose `[transfer]` list names it, and the
     broker refuses it again at request time. `vault` receives only what a
     zone's policy explicitly sends it and the person approves. The one
     shipped policy is `dev`'s `to = "work"`; every other shipped zone
     sends nothing.
  4. The fd: `fstat` says regular file; `fcntl(F_GETFL)` is `O_RDONLY` and
     not `O_PATH`; `st_dev` equals the sender's data mount (the `st_dev` of
     `/home/<zone>`, read through the zone's pid 1 root at request time);
     `st_size` is within the 1 GiB cap. `/proc/self/fd/N` is not consulted
     for anything.
  5. The destination is running.
  6. Consent: the person is asked through the trusted chrome (below). It is
     asked only now, after every check a machine can decide, the
     destination's being there included, so a request that would be
     refused anyway never becomes a question.
- Copy: the destination is looked up again after the answer, so nothing
  holds its mounts through the wait, and a zone that stopped meanwhile
  gets nothing. The file lands in `<destination home>/incoming/`, resolved with
  `openat2` from the destination's root (`/proc/<pid 1>/root`, an `O_PATH`
  descriptor into its mount namespace) with
  `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. A planted
  symlink anywhere on the way is refused or skipped, never followed, so
  nothing zone 0 writes can leave the destination's tree whoever runs the
  copy. The design first called for a forked helper that `setresuid`s to
  the destination identity so that the destination's own links could not
  redirect the write; resolving inside the destination's root makes that
  helper unnecessary. The name is chosen with `O_CREAT|O_EXCL|O_NOFOLLOW`
  (a collision or a planted link moves to `-2`, `-3`, …, never by
  stat-then-create), and no temp file or `rename` is used. The file is 0600
  owned by the destination identity; the cap is enforced on bytes actually
  copied (`copy_file_range` in a loop with a running byte count), so a
  racing writer that grows the file after the `fstat` is stopped; any
  failure unlinks the partial file. Ephemeral and persistent destinations
  are reached the same way.
- The source zone never learns anything about the destination except
  success or failure and the final name.

## Consent

The last word on a transfer is the person's, reached through the desktop
session, an ordinary user in group `kryptik` that zone 0 cannot call into.
So the question is a file and the answer is a file, in a directory only
zone 0 and that group can see:

```text
/run/kryptik-consent/<id>.ask      from=ZONE to=ZONE name=NAME bytes=N
/run/kryptik-consent/<id>.answer   yes | no        (written by the chrome)
```

sysinit creates the directory (root:kryptik, 2770), beside
`/run/kryptik-launch` rather than under `/run/kryptik`, which the registry
keeps 0700. No zone has a path to it, so nothing a zone controls can answer
for the person. The chrome's watcher (`kryptik-chrome`, started with the
session) sees each `.ask`, opens a trusted window (`kryptik-chrome
--confirm ID`, drawn with the unzoned border, the one colour no zone can be
given) and writes the answer. The broker waits at most 60 seconds and
treats no answer, a malformed answer or a missing directory as a refusal;
"no" is reported to the zone as refused by the user in zone 0.

Nothing found in that directory is trusted, because it is shared with the
session's group. The directory is opened once and every name is used
relative to it without following links; the question's temporary file is
created `O_EXCL` under a name that carries a random nonce, and the nonce is
in the question's id too, so no answer can be lying ready under a name
nobody could have known; an answer that is not a plain file (a link, a FIFO
that would never end) is a refusal, not something to read.

Whether anyone is there to ask is a lock, not a guess: the watcher holds
`watcher.lock` in that directory exclusively for as long as it runs, and a
broker that can take the lock shared knows nobody is watching and refuses at
once. Without it, a transfer offered while no desktop session was up waited
the whole minute for a window that could never open.

`--auto-approve-transfers` is a development flag for tests without a
session: it approves every transfer the zone offers without asking, and the
launcher warns about it at launch.

## Clipboard

- kryptikd holds **one** payload per zone, in the zone's registry entry as
  the file `clipboard` (first line the MIME type, from a fixed list; at most
  1 MiB; 0600, written to a fresh `O_EXCL|O_NOFOLLOW` file and renamed into
  place, read with `O_NOFOLLOW`). A zone sets and gets only its own payload
  (`clipboard-set`, `clipboard-get`).
- A cross-zone paste is a **user gesture in zone 0**. In the desktop it is
  the chrome's launcher (`m<N><M>`: move zone N's clipboard to zone M),
  which calls `kryptik-launch --clipboard-move FROM TO`, which the launch
  daemon (`kryptikd serve`) carries out; as root it is
  `kryptikd clipboard move FROM TO`. Both zones must be running. No zone can
  ask for another zone's clipboard or trigger a move: `clipboard-move` on
  the zone-facing socket is answered with an error, because the verb does
  not exist there.
- After a move, the source's payload stays (copy semantics for the user)
  and the destination's previous payload is replaced. One payload, once.

## Compositor proxy

Each zone started from the desktop gets its own Wayland proxy,
`kryptik-wlproxy --zone NAME`, started by `kryptik-launch` as the session
user and listening at `$XDG_RUNTIME_DIR/kryptik/<zone>/wayland-0`. The
launcher binds that socket into the zone at `/run/kryptik/wayland-0`
(`--wayland-socket`, with `--wayland-inode` naming the device and inode it
must be, or the launch fails). The compositor's own socket is never
reachable from a zone. The design had the proxy learn the zone from the
peer uid; as built, the zone is fixed per proxy instance and socket, since
only that zone has the socket in its tree. The proxy filters the protocol
(a global allowlist, bounds, descriptor accounting) and stamps every
window's app_id as `kryptik.<zone>.<claimed>`, from which the compositor
draws the zone's border. Capture, clipboard, layer-shell, virtual-input,
dmabuf-export, gamma, output-management and session-lock globals never
reach a zone.

## Invariants and tests (VM, root; two routed zones `a`, `b`, plus `vault`)

| invariant | test | positive control |
| --- | --- | --- |
| sender identity is the peer uid | `a` sends `transfer`; the request has no sender field to forge; the file lands in `b`'s `incoming/` with `a` recorded as the sender in kryptikd's log; a peer that is not the zone gets `error: unidentified peer` | — |
| destination authorization | `a -> vault` refused; `a -> b` with no `[transfer]` in `a` refused; with `to = "b"` allowed | round trip |
| round trip | `a` sends 4 KiB; `b` reads `incoming/<name>` byte-identical; owned by `b`'s identity, 0600 | — |
| not a regular file | `a` passes an fd to a directory, a FIFO, `/dev/null`, an `O_PATH` fd, an `O_RDWR` fd | each refused with a distinct reason |
| wrong filesystem | `a` passes an fd to `/tmp/x` (its tmpfs, not its data mount) | refused: `st_dev` mismatch |
| payload limit | `a` sends a file of cap + 1 bytes; and a file that reports a small `st_size` but grows past the cap during the copy by a racing writer | both refused/aborted; partial file removed |
| destination-side race | `b` pre-creates `incoming/report.pdf` as a symlink to `/home/b/.profile`; then `a` sends `report.pdf` | lands as `report.pdf-2`; `.profile` untouched |
| name validation | names `../x`, `.hidden`, `a/b`, 256 bytes, `\n` | refused |
| cross-zone denial | `b` cannot connect to `a`'s broker socket (path does not exist in `b`), and `a` cannot `clipboard-get` `b`'s payload (no such verb) | `a` gets its own |
| clipboard move is a zone 0 act only | inside `a`: `clipboard-move` verb -> error; from zone 0 it works | — |
| the broker socket is the only new thing in the tree | an exact listing of `/run/kryptik` inside a zone shows the broker socket, plus `wayland-0` for a desktop launch, and nothing else | — |
| the NIC zone and `vault` receive nothing by default | transfers to the NIC zone refused regardless of policy; `vault` only with explicit policy **and** consent | — |
| consent | a transfer the person approves lands; one the person refuses is refused; with no watcher running the transfer is refused at once; no question file is left behind | — |

## The two parsers, attacked

The broker's request line and `kryptik-wlproxy`'s wire decoder are the two
parsers in Kryptik that were written by hand and read bytes a zone wrote.
Both are attacked by their own unit suites, on every push, with no tool but
cargo:

- **The broker** (`broker.rs`,
  `no_request_a_zone_can_send_breaks_the_broker`). The seeds are real
  requests, one per line, in `compartments/kryptikd/fuzz-corpus/broker-requests`.
  Each is damaged in a hundred-odd ways (a flipped bit, a cut, a NUL, a
  number past 64 bits, six hundred bytes of padding) and sent down a real
  connection with a payload that may or may not be what the header
  promised. The broker must not panic, must not hold the launcher past the
  request deadline, and must answer every one with a single well-formed
  reply.
- **The proxy** (`protocol.rs` and `session.rs` in `compositor/wlproxy`).
  The corpus is the protocol: one well-formed body for every message in
  the generated tables, built from its signature, then damaged with the
  lengths steered at their edges. The decoder must not panic or read past
  the body, and accepts only a body that parses exactly to its end. A
  second test sends a damaged opening conversation through a live session
  in fragments of arbitrary size: the session may refuse, and whatever it
  forwarded to the compositor by then must be whole, well-formed messages.

The generators are seeded, so a failure is the same failure on every
machine. That is also the limit: this is mutation from a fixed seed, not
coverage-guided fuzzing, and it finds what a few thousand damaged inputs
find. A request or a message that ever breaks either parser is added to
the corpus (a line in the file; a case in the test) and stays there.
Coverage-guided runs with libFuzzer need a nightly toolchain and belong in
a scheduled job, not in the build.

## As built

This section records what exists, in the words of the wire. Where it
differs from the design above, it is the current truth.

- **Identity.** Every connection is `SO_PEERCRED`-checked against the one
  uid the launcher mapped its zone to; anything else gets
  `error: unidentified peer` and nothing more (`broker::serve_connection`).
  On an unprivileged developer launch every zone maps to the launching
  user, so identity distinguishes nothing there; on the target each zone's
  range is disjoint and the check is the authentication.
- **One socket per zone**, in the zone's registry entry, bound into the
  zone at `/run/kryptik/broker` (0600, zone identity), through a
  descriptor the child opens after `unshare(CLONE_NEWNS)` and before the
  identity switch. The launcher (`kryptikd run`) serves it between
  `waitpid` polls while it supervises the zone; one request per
  connection, a 5-second deadline end to end, every refusal from the
  header before a payload byte is read, every attached descriptor closed
  afterwards.
- **Wire format**: one header line; `clipboard-set` carries `len` bytes
  after it, `transfer` carries one `SCM_RIGHTS` descriptor with it:

  ```text
  version\n                            -> kryptik-broker 1 zone=NAME\n
  clipboard-set <mime> <len>\n<bytes>  -> ok\n
  clipboard-get\n                      -> ok <mime> <len>\n<bytes>   |  empty\n
  transfer <zone> <name>\n  (+1 fd)    -> ok <final name>\n
  clipboard-move ...                   -> error: clipboard-move is a zone 0 act, not a zone verb\n
  anything else                        -> error: <reason>\n
  ```

- **MIME types** accepted for a clipboard payload: `text/plain`,
  `text/plain;charset=utf-8`, `text/html`, `text/uri-list`, `image/png`,
  `image/jpeg`, `application/octet-stream`. A free-form label would itself
  be a channel.
- **Transfer** follows the checks and copy described above, in that order.
  Zone 0 has no transfer command: a transfer is always offered by the zone
  that holds the file, and the `kryptik` tool refuses `transfer`,
  `clipboard` and `mount` and points at the broker.

### Evidence

- Unit: `broker::tests` drive `serve_connection` over socketpairs with
  real `SCM_RIGHTS`: clipboard round trip, a payload in pieces, every
  clipboard refusal with the exact reply; the transfer landing, the `-2`
  name, the planted symlink as a name and as `incoming` itself, every
  transfer refusal with its reason and nothing created, the
  descriptor-leak check, the copy cap. `consent.rs` tests cover yes approving and no refusing, silence and a
  missing channel or absent watcher refusing, files a group member plants
  under a guessable name being neither written through nor believed, and
  an answer that is not a plain file being a refusal.
  `zone::tests` cover the policy list and the zone directory invariants.
- The launcher suite (`compartments/tests/launcher.sh`, broker channel
  section): a zone's broker answers `version` naming that zone, an unknown
  verb is refused rather than echoed, the socket is 0600, and on a
  privileged launch a peer that is not the zone is refused.
- VM probes during development checked the broker's identity and the
  zone's tree, the clipboard through the launcher including the zone 0
  move between two concurrently running zones, and a transfer between two
  concurrently running zones read back byte-identical and 0600 from inside
  the destination, with the refusals for consent, policy, a directory
  descriptor, a bad name, a file from the zone's tmpfs, and a destination
  that is not running.
- The installed-desktop guest checks (`build/guest-tests/gui-check.sh`): a
  zone's client connects to `/run/kryptik/wayland-0` (the proxy) and sees
  none of the hidden globals; a zone sets its clipboard through its broker,
  another zone's clipboard stays empty until the move gesture
  (`kryptik-launch --clipboard-move`) and then holds the one payload moved;
  a transfer not named in the sender's policy is refused with no question
  asked; after the person says yes the file is in the destination's
  `incoming/` byte-identical, after the person says no it is refused, and
  no question is left behind.

### Not built

- **`transfer.max_bytes`** per zone: the cap is the 1 GiB default only.
- **A zone-side client in the image.** Zones speak the wire format
  directly; the tests use a small Python client
  (`build/guest-tests/broker-client.py`). A `kryptik-clip` /
  `kryptik-send` shipped in the image does not exist yet.
