# Design 05 — Broker authentication and the trusted desktop boundary (M5)

Status: security design for Opus; **do not start before Designs 01–03
pass** (identity, lifecycle, net). GUI is out of scope for this pass except
the identity mechanism the compositor will reuse.

## The one mechanism: identity is the peer uid

Every zone has a unique host uid range (Design 01, P3). A `AF_UNIX` socket
accepted in zone 0 yields `SO_PEERCRED`, whose `uid` is in exactly one
zone's range. That is the authentication of the sender: **kernel-asserted,
unforgeable from inside a zone, needs no token, no handshake, no crypto.**
The pid in `SO_PEERCRED` is ignored (it is a pid in zone 0's namespace and
may be reused). The same lookup will identify a Wayland client to the
compositor's proxy; that is why the identity design comes first.

## The channel

- kryptikd binds one listening socket **per zone**, in zone 0, at
  `/run/kryptik/zones/<zone>/broker` (0600 `N:N`), and bind-mounts that
  socket file into the zone's tree at `/run/kryptik/broker` (a file bind on
  the sealed root tmpfs, like `/etc/ld.so.cache`). A zone can only reach
  its own endpoint; there is no shared socket directory. This is the only
  addition to what a zone sees, and it is a socket, not a directory.
- The descriptor rule stands: zones inherit fds 0, 1, 2 and nothing else.
  The broker is reached by `connect(2)`, not by an inherited fd.
- Protocol: length-prefixed request, one request per connection, replies
  likewise, `SCM_RIGHTS` for file payloads. No general RPC: three verbs,
  `transfer`, `clipboard-set`, `clipboard-get`, plus `version`.

## File transfer (the smallest authenticated, policy-checked channel)

- The zone sends `transfer {dest: "work", name: "report.pdf"}` with one
  `SCM_RIGHTS` fd, opened `O_RDONLY` by the zone. Passing an fd instead of a
  path is what removes every path race: kryptikd never resolves a path the
  zone controls.
- kryptikd checks, in order, refusing on the first failure:
  1. sender = zone from `SO_PEERCRED` uid; `dest` is a running zone;
     `dest != sender`; `dest != "vault"` unless policy says so (**vault
     receives nothing by default**; `net` receives nothing ever).
  2. Policy: `[transfer] to = "work personal"` in the *sender's* zone file
     (space-separated names, validated against the zone set; absent = no
     transfers). Then the user prompt (M5 UI; in tests, `--auto-approve`
     is a development flag that prints a warning, like `--passphrase-file`).
  3. The fd: `fstat` says regular file; `st_dev` equals the sender's data
     mount (kryptikd knows it: it mounted it); `st_size <= limit`
     (`transfer.max_bytes`, default 1 GiB); `fcntl(F_GETFL)` is `O_RDONLY`
     and not `O_PATH`; `/proc/self/fd/N` is not consulted for anything.
  4. `name`: one path component, no `/`, not `.`/`..`, ≤ 255 bytes,
     printable, no leading `.` (so a zone cannot plant dotfiles).
- Copy: kryptikd opens `<dest data dir>/incoming/<name>` with
  `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW`, as **uid N_dest** (a forked helper
  that `setresuid`s to the destination identity, so a symlink or existing
  file planted by the destination zone cannot redirect the write outside
  its own tree — the helper cannot write outside it), `copy_file_range`
  in a loop with a running byte cap, `fsync`, then `rename` is **not** used
  (no temp file to race). On any error the partial file is unlinked by the
  helper. Reply carries the final name (a collision gets `-2`, `-3`, …
  chosen with `O_EXCL`, never by stat-then-create).
- The source zone never learns anything about the destination except
  success/failure and the final name.

## Clipboard

- kryptikd holds **one** payload per zone (`clipboard-set`, ≤ 1 MiB, MIME
  string validated to a fixed list). A cross-zone paste is a **user
  gesture in zone 0** (the compositor, M5 UI) that calls
  `clipboard-move <from> <to>` inside kryptikd; the destination zone then
  sees it via `clipboard-get`. No zone can ask for another zone's clipboard;
  the verb does not exist on the zone-facing socket. In tests the gesture
  is `kryptikd clipboard move a b` run as root.
- After a move, the source's payload stays (copy semantics for the user),
  the destination's previous payload is replaced. One payload, once.

## Compositor proxy (identity only, for later)

Each zone gets a per-zone Wayland proxy socket bound the same way
(`/run/kryptik/zones/<zone>/wayland-0`, bound into the zone at
`$XDG_RUNTIME_DIR/wayland-0`). The proxy learns the zone from the peer uid
and tags every surface with the zone's `border_color`. Nothing else is
designed here; "prefer existing components" means the proxy should be an
existing Wayland protocol filter if one fits, not a compositor.

## Invariants and tests (VM, root; two routed zones `a`, `b`, plus `vault`)

| id | invariant | test | positive control |
|---|---|---|---|
| B1 | sender identity is the peer uid | `a` sends `transfer` claiming (in the request body) to be `b` — the body has no sender field to forge; the test instead connects from `a` and verifies the file lands with `a` recorded as sender in kryptikd's log and `b`'s `incoming/` | — |
| B2 | destination authorization | `a -> vault` refused; `a -> b` with no `[transfer]` in `a` refused; with `to = "b"` allowed | B3 |
| B3 | round trip | `a` sends 4 KiB; `b` reads `incoming/<name>` byte-identical; owned `N_b:N_b` 0600 | — |
| B4 | not a regular file | `a` passes an fd to a directory, a FIFO, `/dev/null`, an `O_PATH` fd, an `O_RDWR` fd | each refused with a distinct reason |
| B5 | wrong filesystem | `a` passes an fd to `/tmp/x` (its tmpfs, not its data mount) | refused: `st_dev` mismatch |
| B6 | payload limit | `a` sends a file of `max_bytes + 1`; and a sparse file that reports small `st_size` but the copy would exceed the cap after truncate-and-grow by a racing writer | both refused/aborted; partial file removed |
| B7 | destination-side race | `b` pre-creates `incoming/report.pdf` as a symlink to `/home/b/.profile`; then `a` sends `report.pdf` | lands as `report.pdf-2`; `.profile` untouched |
| B8 | name validation | names `../x`, `.hidden`, `a/b`, 256 bytes, `\n` | refused |
| B9 | cross-zone denial | `b` cannot connect to `a`'s broker socket (path does not exist in `b`), and `a` cannot `clipboard-get` `b`'s payload (no such verb) | `a` gets its own |
| B10 | clipboard move is a zone-0 act only | inside `a`: `clipboard-move` verb -> `EOPNOTSUPP`; from zone 0 it works | — |
| B11 | broker socket is the only new thing in the tree | E3a-style exact listing of `/run/kryptik` inside a zone shows one socket | — |
| B12 | `net` and `vault` receive nothing | transfers to either refused regardless of policy for `net`; `vault` only with explicit policy **and** prompt | — |

## Files

New `broker.rs` (accept loop, `SO_PEERCRED`, verbs), `transfer.rs`
(checks and the uid-switching copy helper), `zone.rs` (`[transfer]`),
`rootfs.rs` (socket bind), `main.rs` (`broker` service mode, `clipboard`
commands), `launcher.sh` group B. The broker runs inside the long-lived
kryptikd (which M1 turns into a supervisor); the seccomp allowlist already
permits `AF_UNIX`, `sendmsg`/`recvmsg`.
