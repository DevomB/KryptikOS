# Separating the compositor's privileges

The [architecture](../architecture.md#known-weaknesses) names the shared
compositor as a known weakness: "Code execution in it reaches zone 0." This
document looks at what a compromised `kryptik-wlproxy` or dwl can reach
today, and weighs four changes: a socket per zone with the compositor's own
filter, the proxies as users of their own under seccomp and Landlock, the
compositor as a user of its own and confined as zones are, and moving the
Wayland protocol out of zone 0 so that only pixels and input cross. It gives
their costs and an order. ADR-024 in [decisions](../decisions.md) decides
the first two, which are built; the third and fourth are later.

## What a compromise reaches today

- **dwl and the chrome run as the login user.** `kryptik-session` execs dwl
  as that user, who is in groups `seat` and `kryptik`; the chrome is dwl's
  status reader, the same user again. The proxies do not: the launch daemon
  starts each zone's as a user of its own (below).
- **dwl's own socket offers everything.** dwl 0.8 creates screencopy,
  export-dmabuf, data-control, primary selection, the virtual keyboard and
  pointer, layer-shell, session lock and the rest, and its own socket in the
  user's runtime directory offers them all. Each zone's socket, in
  `/run/kryptik-compositor/<uid>/`, offers only the globals the proxy passes
  on (`tools/desktop/dwl-zone-borders.py`) and takes only the session and
  that zone's proxy, so the proxy (`compositor/wlproxy/src/policy.rs`) and
  dwl must both be wrong before a zone's client binds a hidden one.
- **So a proxy bug gives a zone what it had.** A zone that gains code
  execution in its proxy runs as that proxy's uid, with no file to open,
  no network and no group. It reaches its own zone's socket of dwl's,
  with the same globals and the same zone as before, and nothing else:
  not dwl's own socket, the consent directory, the launch daemon, the
  user's home or another zone's socket.
- **A dwl bug gives the desktop:** screencopy, the virtual keyboard, the
  consent directory, the launch daemon, the user's home, and every pixel
  and every key.

The proxy parses every message a zone sends, so its parser is the first
thing a zone attacks. It is Rust, bounded, and fuzzed with a corpus
([broker](broker.md#tests)), and it is still the place to cut first.

## Constraints

- **The compositor is trusted for what the user sees and types.** It draws
  the borders, routes the keys and shows the consent question. No separation
  makes a compromised compositor safe. Separation can make it harder to
  reach, and make reaching it give less than the whole of zone 0.
- **ADR-004 and the proxy's rules stay:** no capture, no injection, no
  layer-shell for zones, and every window attributable to its zone.
- **ADR-003:** zone 0 runs no user application. A confined compositor is
  still zone 0's.
- **seatd** hands out the DRM and input devices, so nothing here needs root
  at run time.

## Options

### A socket per zone, filtered by the compositor

Built. dwl serves one more socket per zone, in
`/run/kryptik-compositor/<uid>/`, for each zone in its colour table, which
are the root's zones. It filters every client on those sockets with
libwayland's global filter (`wl_display_set_global_filter`) to the same
list the proxy allows, and binding another global by its number ends the
connection. dwl knows a client's zone from the socket it came through, and
takes the border, the fullscreen bar's name, the zone its status gives the
chrome and the window rules' match from that, not from the app_id the proxy
wrote.

- A client of a zone's socket gets the allowed globals, under that zone's
  identity: a window stamped `kryptik.vault.` through `work`'s socket gets
  `work`'s border and stays on the tags `work`'s windows use, as dwl's rules
  see `kryptik.work.` and no title for it; only the vault's socket puts a
  window on the vault's tag. The zone's proxy uid and the session's own
  programs alone are taken on it.
- **Cost:** a change to dwl (sockets per zone, the filter, the border from
  the socket), the proxy's upstream argument, and the desktop suite's
  checks. The proxy and the compositor check the same list twice: two
  implementations must both be wrong before a zone gets a hidden global.

### The proxies as users of their own, confined

Built. The launch daemon starts each zone's proxy for the session that asks
for a display (`compartments/kryptikd/src/proxy.rs`), as it starts zones,
since the session user cannot switch uid:

- as the top uid of the zone's block, `uid_base + 65535`, which no zone
  maps, with no supplementary group. No account names it, as an account a
  release adds never reaches an installed system's `/etc/passwd`;
- in empty network and IPC namespaces and a cgroup of its own, with 128 MiB
  of memory, which its clients' queues fit, room for one process, and
  descriptors for its 32 clients and no more;
- with `no_new_privs`, under a seccomp filter of its own calls, about
  thirty of a zone's, with sockets only `AF_UNIX`, `sendto` only to the
  connected peer, `ioctl` only to make a descriptor nonblocking and no
  memory made executable; CI runs the static
  proxy through its live tests under strace and fails on a call the list
  lacks (`tools/tests/proxy-calls.sh`). A Landlock ruleset grants only
  reading and executing its own program, which exec needs, so once it runs
  it opens no other file;
- with its listening socket made by the daemon at
  `/run/kryptik-proxy/<uid>/<zone>/wayland-0` and passed as `--listen-fd`.
  The zone's directory is root's alone, so the socket is reached only
  through the launcher's bind into the zone; the log is beside the
  directory, the session's to read. Neither tree is under `/run/kryptik`,
  which the zone registry keeps root's alone;
- with dwl's socket for the zone passed as a descriptor, opened by the
  daemon without following a link and taken only if the session owns it:
  the session owns that directory, and could otherwise point the proxy at
  another user's compositor. A new socket there, as when dwl starts again,
  gets a new proxy at the next start;
- with the move gesture's socket made by the daemon at
  `/run/kryptik-proxy/<uid>/<zone>.control`, the session's alone (0600),
  and passed listening as `--control-fd`, with `--control-uid` naming the
  one uid the proxy answers there.

`connect(2)` to the zone's compositor socket is not a Landlock access, so
new clients still reach dwl, which takes a client on a zone's socket only
from the session's uid or that zone's proxy uid (`SO_PEERCRED`), and no
more than 64 at once, so not even the proxy fills dwl's descriptors. A
zone's proxy uid is one whoever the session is, so while one session's
desktop shows a zone, the daemon refuses another session a display for
it. Stopping the zone ends its proxy.

- A compromised proxy can no longer read the user's files, answer consent
  questions, reach the launch daemon or dwl's own socket, or connect to
  another zone's socket.
- **Cost:** the launch daemon starts and stops proxies, and a uid per zone
  is reserved. kryptikd confines the proxy before the exec with its own
  seccomp and Landlock code, so no crate is shared. The filter's list
  follows the calls the C library and Rust's standard library make, which
  the trace in CI checks at every change.

### The compositor as a user of its own, confined as zones are

dwl runs as a `compositor` user in group `seat`, not as the login user and
not in group `kryptik`. The chrome and `kryptik-launch` stay with the login
user and reach dwl's own socket through its group. After start-up, dwl
confines itself as a zone is confined:

- a seccomp filter from the calls `kryptikd seccomp-trace` finds it making
  under the desktop suite;
- Landlock with read-only `/usr` (keymaps compile from
  `/usr/share/X11/xkb`) and nothing else. Built: once the spawner runs, dwl
  may read below `/usr` (keymaps, cursors), `/sys`, `/run/udev` and
  `/etc/udev` (wlroots and libinput read these when a screen or an input
  device is plugged in), and the microphone's and the camera's marks
  (`/run/kryptik-sound`, `/run/kryptik-camera`). It may also read and
  remove the chrome's request for a browser in front, in
  `$XDG_RUNTIME_DIR/kryptik/front`, which it makes first. It writes no file,
  opens no TCP, and, where the kernel has Landlock ABI 6, reaches no
  abstract socket outside its own domain. The zones' sockets and its own are
  made before then, and its own socket and lock stay behind when it exits,
  until the next login's dwl takes them over. A rule holds a directory as it
  was at login: one that is made again while dwl runs is not covered.
  Landlock binds the calling thread alone, so dwl confines itself only while
  it has one thread, and says how many it had. A kernel without Landlock
  leaves dwl as it was, and the session log says so;
- no exec. dwl's `spawn` keys and its status command move to a small
  spawner, started before the sandbox, that runs only a fixed table of
  commands. Built: dwl forks the spawner once the status command runs,
  closes everything in it but one end of a socket, and sends it a key's
  command as its index in `spawncmds` (`build/desktop/dwl-config.h`). Then
  dwl sets no-new-privileges and a filter, on every thread, that refuses
  exec, ptrace and `process_vm_writev`, and kills calls of another
  architecture. `kernel.yama.ptrace_scope = 3` already refuses dwl
  `/proc/PID/mem`, `pidfd_getfd` and `process_vm_readv` into the chrome and
  the lock, forked before the filter, so the filter is a second wall there.
  The spawner is not dumpable and ends with dwl. If it goes, dwl ends the
  login rather than run on with keys and a lid that no longer lock.

seatd passes it its devices, including hotplugged ones, as descriptors, so
dwl never opens `/dev`. Running it under `kryptikd run` as a zone of its own
would reuse the launch path and give it a memory limit, but zone 0's
definition names the compositor, so that is the architecture's decision,
not this document's.

- A compromised dwl can no longer reach the launch daemon or the consent
  directory directly, or read the user's files. It still sees every pixel
  and can type into the chrome, so it can approve what the chrome approves,
  in plain sight on a screen it controls. That raises the cost and does not
  remove it.
- **Cost:** a change to dwl for the sandbox and the spawner; the session
  asks the launch daemon to start dwl as its user; the filter has to follow
  wlroots' calls at every update.

#### What is left, and in what order

With the spawner, the no-exec filter and Landlock built, a compromised dwl
can no longer exec, read the user's files or write any file. What it still
reaches comes from the groups it runs with. In group `kryptik` it can
connect to the launch daemon's socket and start programs in zones as the
user. Landlock does not stop it, as connecting to a socket is not one of
Landlock's accesses. It also runs as the login user, so it can signal the
user's other processes.

The next part takes the group away first, and the uid after:

1. **dwl without group `kryptik`.** The session starts the spawner itself,
   as the login user with every group, and starts the chrome on the read
   end of a pipe. It then asks the launch daemon for the desktop: the verb
   that today moves the asker into `kryptik-desktop` instead starts
   `/usr/bin/dwl` there. It runs as the same uid with the user's groups less
   `kryptik`, with no-new-privileges, and gets the spawner's socket and the
   pipe's write end as descriptors. The daemon answers when dwl exits, so
   the login still ends with it. dwl gains an option to take its spawner's
   socket instead of forking one, and keeps the rest of its confinement.
   The microphone's holder moves too: dwl reads it through the group today,
   as `/run/kryptik-sound/control` is the group's alone. The record moves
   out of that directory and becomes readable by anyone on the host, as the
   camera's grant already is. It names only the zone that holds the
   microphone, which the screen shows anyway, and no zone sees
   `/run/kryptik-sound`. A check reads dwl's `Groups:` and finds no
   `kryptik`, and the microphone's mark still shows.
2. **Signals.** Landlock's signal scope (ABI 6) keeps dwl from signalling
   any process outside its own domain: the lock, the chrome, the user's
   zones' launchers. It waits for the first part. dwl's one signal ends
   its startup command's process group when it exits, and the chrome,
   forked before dwl confines itself, is outside that domain, so with the
   scope the chrome would outlive dwl. Once the session starts the chrome,
   dwl sends no signal at all. A kernel without ABI 6 keeps the rest of the
   ruleset.
3. **A user of its own,** the end state above. Its sockets and directory
   then need an owner other than the session (dwl's socket reached through
   a group, the zones' socket directory made for that user), and seatd's
   group moves to it. This is the largest of the three, and it gains less
   once the first two are built, so it comes last.

### Only pixels and input cross

The last step changes what crosses. Each zone runs its own small Wayland
server, a headless wlroots compositor inside the zone, which composites the
zone's clients. Zone 0 receives only finished windows over a fixed protocol:
create and destroy a window, its size and title, damaged rectangles of
pixels in shared memory, and input events back. That is what Qubes does
between its domains. dwl then parses that protocol and nothing else from
zones, and the proxy goes away.

- **Gain:** Wayland's protocol, every extension included, is parsed in the
  zone. A bug there compromises that zone alone. Zone 0 parses a format
  small enough to fuzz completely.
- **Cost:** a zone-side compositor to build and keep; pixel copies across
  the boundary (bounded by damage, but no zero-copy GPU buffers, which the
  browser design defers anyway); a new protocol and its fuzzing; popups,
  input methods, cursors and copy and paste reworked through it. It is the
  largest change in this list.

### Splitting rendering from input inside zone 0

The usual proposal is to split dwl into an input process, which holds the
devices and decides focus, and a renderer.
The renderer would still draw the borders and the chrome, so a compromised
renderer could still show a false border or a false question, and the input
process would deliver the user's keys to whatever the renderer showed.
Nothing a zone reaches gets smaller: zones talk to the renderer. Rejected in
favour of moving the protocol into the zones, which does shrink it.

## Order

1. **A socket per zone with the compositor's filter.** It is the smallest
   change, and the identity of a window stops depending on the proxy.
   Built.
2. **Proxies as their own users, confined.** Together with the first step, a
   proxy bug gives the zone nothing it did not have. Built.
3. **The compositor as its own user, confined,** with the spawner. Built
   so far: the spawner; a filter that refuses dwl exec, ptrace and
   `process_vm_writev`; and Landlock. Still to do: its own user, and a
   filter of the calls it is traced making.
4. **Only pixels and input cross,** when the zone-side compositor and its
   protocol are designed on their own.

The first two close the path from the proxy, the parser zones reach first,
to the whole desktop. The third makes a dwl bug cost more. The fourth takes
Wayland parsing out of zone 0.

## The check that proves it done

`make gui-test`, extended step by step. It checks the first two:

- the proxy's upstream is its zone's socket. Through `untrusted`'s, a probe
  is offered only the allowlist, and binding screencopy, the virtual
  keyboard or the session lock by the number zone 0's list gives it ends
  its connection, while zone 0's client binds screencopy's;
- a client on `personal`'s socket that claims a `kryptik.vault.` app_id is
  personal's: it stays on the tag in view, takes the keyboard from
  personal's window, as personal's own would, and the chrome names it
  personal; a client on `vault`'s socket that claims personal's app_id maps
  on the vault's tag, out of view, and Alt+9 shows it named the vault's;
- `untrusted`'s proxy has its own uid and no group, `Seccomp: 2`,
  `NoNewPrivs: 1`, a network namespace of its own and its cgroup's limits.
  That uid lists neither the user's home (0700) nor the consent
  directory, and connects to neither the launch daemon's socket nor dwl's
  own; `personal`'s proxy uid is turned away from `untrusted`'s socket.

The next steps add:

- once the compositor runs as its own user, the same is true of dwl's uid,
  and the desktop suite passes with dwl confined;
- a zone's client that starts a window still gets it, with its border, after
  each step.
