# Separating the compositor's privileges

The [architecture](../architecture.md#known-weaknesses) names the shared
compositor as a known weakness: "Code execution in it reaches zone 0." This
document looks at what a compromised `kryptik-wlproxy` or dwl can reach
today, and weighs four changes: a socket per zone with the compositor's own
filter, the proxies as users of their own under seccomp and Landlock, the
compositor as a user of its own and confined as zones are, and moving the
Wayland protocol out of zone 0 so that only pixels and input cross. It gives
their costs and an order. The proposed decision is ADR-024 in
[decisions](../decisions.md).

## What a compromise reaches today

- **Everything runs as the login user.** `kryptik-session` execs dwl as that
  user, who is in groups `seat` and `kryptik`. `kryptik-launch`, run by
  the same user, forks one `kryptik-wlproxy` per zone with `--upstream`
  naming dwl's own socket (`tools/desktop/kryptik-launch.c`). The chrome is
  dwl's status reader, the same user again.
- **dwl's own socket offers everything.** dwl 0.8 creates screencopy,
  export-dmabuf, data-control, primary selection, the virtual keyboard and
  pointer, layer-shell, session lock and the rest on the one socket in the
  user's runtime directory. Kryptik's change to dwl draws borders and
  filters nothing (`tools/desktop/dwl-zone-borders.py`). The proxy is what
  keeps those globals from zones (`compositor/wlproxy/src/policy.rs`).
- **So a proxy bug gives a zone the desktop.** A zone that gains code
  execution in its proxy runs as the login user. It can connect to dwl's own
  socket and bind screencopy, which captures every zone, and the virtual
  keyboard, which types into any window, the chrome's consent question
  included. It can also write answers into `/run/kryptik-consent` (group
  `kryptik`), ask the launch daemon to move clipboards or apply an update,
  and read the user's home. It can stamp its windows `kryptik.vault.`,
  because the zone a window belongs to is whatever its proxy wrote.
- **A dwl bug gives the same,** and also every pixel and every key.

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

dwl serves one more socket per zone, created when the launch path starts the
zone's proxy. It filters every client on that socket with wlroots' global
filter (`wl_display_set_global_filter`) to the same list the proxy allows.
dwl knows a client's zone from the socket it came through, and draws the
border from that, not from the app_id the proxy wrote.

- A compromised proxy then gets what its zone already had: the allowed
  globals, under its own zone's identity. A window stamped `kryptik.vault.`
  through `work`'s socket gets `work`'s border.
- **Cost:** a change to dwl (sockets per zone, the filter, the border from
  the socket), the proxy's upstream argument, and two gui-test cases. The
  proxy and the compositor then check the same list twice, on purpose: two
  implementations must both be wrong before a zone gets a hidden global.

### The proxies as users of their own, confined

Each proxy runs as a uid of its own, one per zone, outside every zone's
mapping and outside groups `kryptik` and `seat`. It runs under a seccomp
filter as short as its loop needs (socket reads and writes with descriptor
passing, epoll, close, exit), with a Landlock ruleset that grants no file
access once its sockets are open, and in an empty network namespace.
`connect(2)` to the zone's compositor socket is not a Landlock access, so
new clients still reach dwl. The launch daemon starts proxies, as it starts
zones, since the session user cannot switch uid.

- A compromised proxy can no longer read the user's files, answer consent
  questions, reach the launch daemon or dwl's own socket, or touch another
  zone's proxy.
- **Cost:** the launch daemon starts and stops proxies; uids are reserved
  per zone; and kryptikd's seccomp and Landlock code gains a second caller,
  which then justifies a small shared crate.

### The compositor as a user of its own, confined as zones are

dwl runs as a `compositor` user in group `seat`, not as the login user and
not in group `kryptik`. The chrome and `kryptik-launch` stay with the login
user and reach dwl's own socket through its group. After start-up, dwl
confines itself as a zone is confined:

- a seccomp filter from the calls `kryptikd seccomp-trace` finds it making
  under the desktop suite;
- Landlock with read-only `/usr` (keymaps compile from
  `/usr/share/X11/xkb`) and nothing else;
- no exec. dwl's `spawn` keys and its status command move to a small
  spawner, started before the sandbox, that runs only a fixed table of
  commands.

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

The order this document was asked to weigh includes splitting dwl into an
input process, which holds the devices and decides focus, and a renderer.
The renderer would still draw the borders and the chrome, so a compromised
renderer could still show a false border or a false question, and the input
process would deliver the user's keys to whatever the renderer showed.
Nothing a zone reaches gets smaller: zones talk to the renderer. Rejected in
favour of moving the protocol into the zones, which does shrink it.

## Order

1. **A socket per zone with the compositor's filter.** It is the smallest
   change, and the identity of a window stops depending on the proxy.
2. **Proxies as their own users, confined.** Together with the first step, a
   proxy bug gives the zone nothing it did not have.
3. **The compositor as its own user, confined,** with the spawner.
4. **Only pixels and input cross,** when the zone-side compositor and its
   protocol are designed on their own.

The first two close the path from the proxy, the parser zones reach first,
to the whole desktop. The third makes a dwl bug cost more. The fourth takes
Wayland parsing out of zone 0.

## The check that proves it done

`make gui-test`, extended step by step:

- through any zone's compositor socket, a probe is offered only the
  allowlist, and binding screencopy disconnects it;
- a client on `work`'s socket that claims a `kryptik.vault.` app_id is drawn
  with `work`'s border and title prefix;
- a proxy's process has its own uid, `Seccomp: 2` and `NoNewPrivs: 1`. That
  uid cannot open dwl's own socket, the consent directory, the launch
  daemon's socket or the user's home;
- once the compositor runs as its own user, the same is true of dwl's uid,
  and the desktop suite passes with dwl confined;
- a zone's client that starts a window still gets it, with its border, after
  each step.
