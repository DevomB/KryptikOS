# Browser and graphics in zones

Version 2 promises "a graphical browser and the toolkit stack under it, per
zone, with GPU rendering decided zone by zone" ([roadmap](../roadmap.md)).
Today a zone gets a terminal and a text browser, drawn into shared memory
and composited on the CPU. This document chooses the browser, the toolkit
under it, how a zone is given the GPU and what the proxy must then carry,
how Xwayland runs inside a zone (ADR-004), and what all of it costs the
root. The decision is ADR-016 in [decisions](../decisions.md).

## Where things stand

- **The compositor renders with pixman.** dwl 0.8 on wlroots 0.19.3 is built
  with no GPU renderer and no Xwayland (`-Drenderers=[] -Dxwayland=disabled`
  in `build/recipes/wlroots.sh`); its DRM backend scans out dumb buffers, and
  `kryptik-session` sets `WLR_RENDERER=pixman`.
- **The proxy offers ten globals.** `kryptik-wlproxy` advertises
  `wl_compositor`, `wl_subcompositor`, `wl_shm`, `wl_seat`, `wl_output`,
  `xdg_wm_base`, `zxdg_decoration_manager_v1`, `wp_viewporter` and
  `wp_cursor_shape_manager_v1`, and `wl_data_device_manager` as a global of
  its own, which it serves itself while the compositor's stays hidden
  (below). A cursor named through `wp_cursor_shape_manager_v1` is drawn by
  the compositor from its own theme, while an image a zone draws is never
  taken. It disconnects a client
  that binds anything else, and bounds shared-memory pools at 128 MiB each
  and 1 GiB per connection and per zone, which Firefox on two 4K heads fits
  (`compositor/wlproxy/src/policy.rs`,
  [resource limits](resource-limits-and-ephemeral-zones.md#wayland-shared-memory)).
- **A zone has no GPU device.** Its `/dev` holds `null`, `zero`, `full`,
  `random`, `urandom`, `tty`, its own `/dev/shm` and a devpts instance
  (`DEVICES` in `compartments/kryptikd/src/rootfs.rs`).
- **The zone filter kills what it does not know.** `clone` with namespace
  flags and `unshare` are killed, `seccomp(2)` is not in the base list but a
  policy may add it, and the SysV shared-memory calls are addable too
  (`seccomp.rs`, [zone policy files](zone-policy-files.md)).
- **The GPU drivers are modules.** i915, xe, amdgpu and virtio-gpu load at
  coldplug with their firmware from the verified root (ADR-012, ADR-013).
- **ADR-004:** no Xwayland is built; if Version 2's applications need one,
  it runs inside the zone.

## Constraints

- **ADR-002.** A kernel privilege escalation breaks every zone. Every kernel
  interface given to a zone adds to that risk for the whole machine.
- **The shared compositor** is a known weakness: code execution in it
  reaches zone 0 ([architecture](../architecture.md#known-weaknesses)).
  Whatever zones may send it widens that.
- **ADR-004.** X11 never crosses a zone boundary.
- **ADR-001 and ADR-010.** Built from source here; Rust comes from the pinned
  release toolchain, as for kryptikd.
- **The slot size** of machines already installed (below), and the software
  images of ADR-015 (`docs/design/software-delivery.md`), beside this
  design.

## The browser

### Firefox

- **Build.** Firefox builds with GCC 11.1 or newer on Linux, so stage 04's
  GCC 14 can compile it. It still needs clang and libclang, since bindgen
  generates its style system's bindings through libclang whatever the
  compiler; the pinned Rust toolchain and cbindgen; Node.js, which the
  build runs for the devtools debugger's modules, `--disable-nodejs` or
  not; Python 3; and nasm for its codecs' SIMD. Its wasm-sandboxed
  libraries (RLBox: graphite, hunspell, expat, ogg, woff2 and others run as
  WebAssembly compiled back to native code) need clang's `wasm32` target and
  a WASI sysroot. They are worth keeping: a font or spelling parser bug stays
  inside that sandbox.
- **Wayland only.** `--enable-default-toolkit=cairo-gtk3-wayland-only` builds
  without any X11 library. `--disable-dbus` and `--enable-alsa` (for the
  sound path in the laptop design) leave out D-Bus and PulseAudio.
- **Its sandbox inside a zone.** Firefox confines its content processes with
  seccomp-bpf, installed with `seccomp(2)` and `SECCOMP_FILTER_FLAG_TSYNC`,
  and adds a namespace layer (chroot, no network) where it can create user
  namespaces.
  - At start it probes for user namespaces by calling
    `clone(CLONE_NEWUSER)` in its own process (`SandboxInfo.cpp`). The zone
    filter answers `clone` and `unshare` with namespace flags with `EPERM`,
    as the kernel answers an unprivileged caller, so the probe fails and the
    browser starts; Chromium and bubblewrap probe the same way, and an
    `EPERM` grants nothing.
  - `seccomp(2)` is not in the base list. The browser image needs it
    (`build/images/browser.needs`), and the zones that run the browser,
    `untrusted`, `personal` and `work`, grant it with
    `allow-syscall seccomp`, which `kryptikd check` holds them to.

  Firefox's filters then stack under the zone's, and the stricter answer
  wins. Its namespace layer stays off, the price of no nested user
  namespaces (`hardened.fragment`).
- **Updates.** The extended-support release (ESR) has a security release
  every four weeks, like the rapid channel, with fewer feature changes.

### A second launch where Firefox is open

With no remote, a second `firefox` in a zone whose browser is open finds
its profile locked and says that Firefox is already running. The browser
key (Alt+Shift+u) and the menu's `b` should instead put that zone's open
Firefox window in front, and start Firefox only when the zone has none. A
design, not yet built:

- **Who knows the window.** dwl alone. For every window it holds the zone,
  taken from the socket the client came through and never from the client,
  the `app_id` Firefox sets, its tags and monitor, and the focus order. The
  `app_id` is the client's own word, but a match is only sought among one
  zone's windows, so a zone that claims it can bring forward only its own
  window. The chrome sees only the focused window of each output, from
  dwl's status. The launch daemon sees the zone's processes, not its
  windows.
- **The key.** A dwl action in place of `spawn`, focus-or-launch, given the
  zone, the `app_id` and the launch command. It takes the first window in
  the focus order whose zone and `app_id` match, so the one used last. If
  that window is not shown, dwl first views its first tag on its monitor,
  as Alt and the tag's number would, then gives it the keyboard. With no
  such window, it starts the command as the key does now. No channel to
  dwl is needed.
- **The menu.** The chrome keeps the launch, as the zone's passphrase is
  asked on its terminal. It needs two things from dwl:
  - dwl's status gains a line naming each zone's open `app_id`s. The
    chrome's status reader records it beside the focus record, in the
    session's runtime directory, and `b` looks there first.
  - When the browser is open, the chrome writes a one-line request, the
    zone and that `app_id`, to a file in that directory. dwl watches it the
    way it watches the microphone and camera marks: inotify on the
    directory, and a file that must be the session user's own and not
    writable by group or others. dwl reads it, removes it and acts on it as
    the key does. The runtime directory is the session user's alone, mode
    0700, so no zone can make the request.
- **On another tag or monitor.** dwl views the window's tag on the monitor
  it is on, and the keyboard follows it there. A window is never moved
  between tags, so the vault keeps its tag.
- **A waiting zone.** The window of a zone frozen after a sleep, its volume
  waiting for the passphrase, comes forward all the same and does not
  answer. The menu already says the zone is waiting and asks with `p`.
- **Not chosen.** Firefox's remote over a D-Bus session bus private to the
  zone would hand the second launch to the open browser, but it puts D-Bus
  back into the image and the zone, which the build leaves out on purpose.
  A Wayland protocol for the chrome, wlroots' foreign-toplevel management
  or one of Kryptik's own, is more code than a status line and a watched
  file, and foreign-toplevel management carries no zone: the chrome would
  have to trust the titles.

### Chromium

Google builds and supports Chromium with clang alone, and it needs Rust and
Node.js; the build is several times Firefox's. Its sandbox requires either
unprivileged user namespaces or a setuid helper, and a zone has neither
(`unshare` is refused, mounts are `nosuid`, `no_new_privs` is set). It would
run only with `--no-sandbox`, which turns off its seccomp layer too.
Rejected.

### A WebKitGTK browser

WebKitGTK builds with GCC and needs neither Rust nor Node.js, but it pulls in
GStreamer, libsoup and ICU, and its process sandbox is bubblewrap, which
needs user namespaces: in a zone it would run with its sandbox off. Its
security releases also trail the two large engines. Rejected as the main
browser.

## The toolkit stack

GTK 3 for Firefox, built with `-Dx11_backend=false`, so no X11 library
enters the image, and without the accessibility bridge, which talks D-Bus.
It is the `toolkit` software image (`build/images/toolkit.sh`), which the
browser image is built over:

- glib (with pcre2, without its JIT), pango, harfbuzz, fribidi, freetype,
  fontconfig, cairo (pixman is the root's), gdk-pixbuf with libpng, libepoxy
  and ATK from at-spi2-core, built alone with a patch that drops its
  unused libxml2;
- the Khronos EGL headers from libglvnd, which libepoxy and GTK's Wayland
  backend compile against. No EGL library comes with them: a zone has no
  GPU, so GL stays unavailable there;
- gdk-pixbuf reads PNG alone, built in: GTK's theme and icons are PNG, and
  each other loader is a parser more. JPEG, GIF and the rest come only if a
  program the image carries needs them; Firefox decodes its own;
- the hicolor theme. An icon theme with symbolic icons needs librsvg, so
  GTK falls back to its built-in icons until one is chosen;
- fontconfig's and GTK's configuration under `/usr/etc`, as an image adds
  nothing outside `/usr`; fontconfig keeps its cache in the user's home;
- GSettings with the memory backend by default, or the keyfile backend
  (`GSETTINGS_BACKEND=keyfile`), since dconf needs D-Bus;
- printing to a file alone, which GTK requires; no CUPS;
- fonts: DejaVu is the root's; Noto for wider scripts costs tens of
  megabytes, and CJK fonts a hundred or more, so they are a choice, not a
  default.

gtk3-demo and gtk3-widget-factory come with it, the first GUI programs a
zone can run. The zones suite runs `fc-match` and `gtk-query-immodules-3.0`
in a zone that names the image, which loads every library GTK needs.

Firefox's own copies of NSS, NSPR, libvpx, dav1d and opus stay bundled: they
are built from source in its tree either way, and every library made
separate is a recipe and a pin review of its own. H.264 needs FFmpeg's
decoder, which Firefox loads if it is present; whether to ship it is a
licensing question as much as a size one, and is left open.

## The document viewer

PDFs open in the browser's own viewer, pdf.js, which runs as page script
inside the content process's sandbox. No image of its own is needed until a
workflow needs a format pdf.js does not read. zathura, the light viewer that
was the alternative, moved to GTK 4 in 2026 and now also needs json-glib,
libmagic, sqlite and xxhash. Building it would mean a second toolkit image,
or pinning a GTK 3 branch nobody maintains any more.

## How the browser image is built

Firefox ESR 153 is the `browser` software image, built over the toolkit
image and over build-only layers that never reach a zone (`image_ships=no`,
[software delivery](software-delivery.md)). Stage 04 already treats cmake
this way: a pinned binary the build runs and never installs. ESR 153's own
floors are given with each layer.

- **Its layers.**
  - **`rust`:** the pinned release toolchain for `x86_64-unknown-linux-gnu`,
    vouched for by the same Rust key as kryptikd's. ESR 153 needs 1.90 or
    newer.
  - **`clang`:** LLVM's release build, for libclang. bindgen loads it to
    generate the style system's bindings, and its `wasm32` target compiles
    the sandboxed libraries. It is about a gigabyte compressed, in the
    sources cache. A source build of clang and libclang would instead cost
    an hour each time the base system changes.
  - **`cbindgen`:** 0.29.4 or newer, built with the `rust` layer. Its crate
    and the crates its lock file names are fetched before the build, since
    the chroot has no network, and checked against that lock.
  - **`nasm`:** for dav1d's AV1 decoder.
  - **`node`:** Node.js's release build, the program alone, which the build
    runs for the devtools debugger's modules. ESR 153's configure still
    takes `--disable-nodejs`, but the build then stops at those modules.
    12.22.12 or newer; the pin keeps to an LTS line, and one of the
    releasers whose keys Node.js lists signs its checksum list.
- **The build.**
  - Stage 04's GCC with the hardening flags; an exception each flag needs
    goes into `hardening-exceptions.txt` with its reason. Firefox drops
    `-fno-delete-null-pointer-checks`, under which GCC 14 cannot evaluate
    SpiderMonkey's compile-time checks (Mozilla's own builds go without it
    too), and carries the few changes a GCC
    build needs (`build/patches/firefox-153.5.0`).
  - `--enable-default-toolkit=cairo-gtk3-wayland-only`, `--disable-dbus`,
    `--enable-release`, `--disable-tests`, `--disable-crashreporter`,
    `--disable-updater` (updates are the image's) and `--disable-eme`.
    With neither D-Bus nor X11 Firefox has no remote: a second launch in a
    zone whose browser is open is not handed to it, and says that Firefox is
    already running (`0004` in the patch set).
  - `--disable-jemalloc`, as the image preloads hardened_malloc for every
    process.
  - `--enable-audio-backends=alsa`: a zone's default ALSA device is zone
    0's mixer (the laptop design's sound path). Firefox needs alsa-lib in
    any case, as Web MIDI on Linux links ALSA's sequencer API; with no
    sequencer in the kernel and no `/dev/snd` in a zone, it reaches no
    device.
  - The first build is `--without-wasm-sandboxed-libraries`. The next adds
    a WASI sysroot to the `clang` layer, since a font or spelling parser
    bug should stay inside that sandbox.
  - The build's Glean step caches what it parses in SQLite, through
    Python's `sqlite3`, which the base system's Python lacks, as zone 0 has
    no SQLite. The recipe compiles that module from the base system's own
    Python source and the SQLite Firefox carries, into the build's root
    alone, and `browser.strip` keeps it out of the image.
- **Time.**
  - On four cores with GCC, without LTO or PGO, ESR takes some hours. The
    images build in a job of their own, between stages 04-05 and stage 06,
    since a runner gives a job six hours and a stage 04 built from nothing
    (a tag's, or a run after a new pin) beside the browser and stage 06
    would not fit one job. Not every run should pay it.
  - The trees of the shipped images go into a cache of their own, keyed by
    their fingerprints, which include the base system's stamp up to
    `wlroots`, the last step an image builds against. A run restores a tree
    whose inputs have not changed, so only a change to the browser, the
    toolkit or the base system up to `wlroots` rebuilds it; zone 0's own
    programs, which stage 04 builds after it, do not.
- **Updates.** ESR has a security release every four weeks. Its pins are the
  images' (`build/images/versions.env`), so a bump rebuilds the browser and
  leaves stage 04 and its cache alone.
- **Choices taken.**
  - **The Rust tarballs are image sources.** The `rust` layer lists the
    rustc, cargo and rust-std tarballs `build/config/rust.lock` pins, so the
    signature and currency gates cover them, and kryptikd's compiler with
    them. A CI check holds both locks to the same hashes, so the shipped
    daemon and the browser are built by one release, bumped every six weeks.
  - **cbindgen is built inside the chroot, offline.** Its crate and the
    crates its own lock file names are fetched beforehand and checked
    against that lock. In the chroot each is unpacked into a vendored source
    directory, and `cargo build --offline --locked` uses the `rust` layer.
    Stage 03's runner and stage 04's cache key stay as they are.
  - **The images' sources have a cache of their own.** They go under
    `sources/images/`, keyed by `build/images/sources.lock`, each named in
    `sources/` by a link, so every tool finds it where it always has. The
    root's set is keyed by `sources.lock` alone and saved with `images/` set
    aside, so a browser bump copies neither set into the other's entry. A job
    that builds no image fetches the root's alone (`fetch-sources.sh --root`).
  - **Mozilla's key comes from Mozilla.** The fingerprint is pinned like
    every other, confirmed by Mozilla's security blog post of August 2026.
    The key material is taken from the `KEY` file beside the release rather
    than from the keyserver, whose copy lacks the new subkey and the old
    one's revocation. That is an `origin` row in `tools/key-provenance.tsv`,
    a kind only a pinned key may have: the pin says who signs, the row only
    where the key is fetched from on every run, so a later revocation lands.
    Rust's and LLVM's keys come from their own sites the same way.

## GPU rendering, zone by zone

### What software rendering gives

With `wl_shm` alone, Firefox renders pages with its software WebRender into
shared-memory buffers. Video decodes on the CPU (dav1d for AV1, libvpx for
VP9). WebGL needs Mesa's llvmpipe in the zone or stays off. That works with
the proxy as it is.

### What a render node gives, and exposes

Binding `/dev/dri/renderD128` into a zone lets the zone's Mesa drive the
GPU: hardware rendering, video decoding through VA-API, WebGL. It also gives
the zone:

- **the GPU kernel driver's ioctls.** i915, xe and amdgpu are among the
  largest and most often fixed drivers in the kernel, and a privilege
  escalation through one breaks every zone (ADR-002). Under the threat model
  the zones that run a browser are the zones most likely to be compromised
  through it, and a GPU driver bug is the obvious next step;
- **memory outside its limits.** amdgpu and xe count VRAM to the dmem cgroup
  controller (`CGROUP_DMEM`), which kryptikd does not enable yet; integrated
  GPUs allocate system memory, and whether that is charged to the zone's
  memory cgroup has to be measured, as the shared-memory charge is today
  ([resource limits](resource-limits-and-ephemeral-zones.md#tests));
- **a channel to other zones on the same GPU.** Local memory left behind
  between contexts (as LeftoverLocals showed on several GPUs) and timing are
  shared, and the IOMMU does not separate contexts on one device.

### What the proxy must then pass

- `zwp_linux_dmabuf_v1`, version 4, with the feedback that names the
  render node. The proxy parses each buffer's parameters (one descriptor per
  plane, offsets, strides, modifiers) and bounds them as it bounds
  shared-memory pools, with corpus entries for its fuzz tests.
- Synchronisation: `wp_linux_drm_syncobj_manager_v1` for explicit sync, or
  the implicit fences the buffers carry.
- Only to a zone that has the render node. Any other zone binding it is
  disconnected, as today.

### What the compositor must then do

A GPU buffer can be composited only by a GPU renderer: pixman cannot read
one. Importing zones' buffers means wlroots' GLES2 (or Vulkan) renderer, and
with it Mesa's EGL, GBM and GPU driver inside the compositor, in zone 0.
Copying each frame into shared memory in the proxy instead would read GPU
memory through CPU mappings that most drivers make write-combined, which is
slow to read, and works only for linear buffers; on a discrete GPU it is
unlikely to keep up.

The compositor's own rendering is a separate question with its own cost.
pixman composites every frame on the CPU, which a large screen and battery
life will feel. A GLES2 compositor would help every zone, render node or
not, at the price of Mesa in zone 0, parsing only shared-memory pixels from
zones until some zone gets dmabufs.

### Who decides

The zone file on the verified root:

```toml
[display]
gpu = "render"      # absent: no GPU device in the zone
```

kryptikd binds the render node of the GPU the compositor drives, found by
its device numbers, and the Landlock base rule on `/dev` already allows its
ioctls. `kryptikd check` refuses `gpu` for the zone that holds the NICs and
for a zone that names no software image with Mesa in it; the shipped
`untrusted` file never sets it, and a test keeps it so. A setting on the
state partition may take the GPU away from a zone, never give it.

### Recommendation for the GPU

Software rendering in every zone first. No shipped zone that runs a browser
gets the render node. A render node comes next, for a zone whose content is
trusted more than the web, a media or games zone with a file of its own, and
only after the compositor's renderer has been decided on its own grounds.
The proxy's dmabuf support is built then, not before.

## Xwayland inside a zone

- **Rootless** Xwayland gives each X window its own Wayland surface, but
  then the compositor must be the X window manager: wlroots connects to the
  X server as an X client and parses X11 from it. The zone's X server would
  be talking to zone 0. Rejected.
- **Rootful** Xwayland (`Xwayland -geometry WxH -shm`) shows the whole X
  screen as one `xdg_toplevel`, with a window manager running inside it, in
  the zone. The compositor sees one ordinary window with the zone's border,
  and X11 stays in the zone. It needs only `wl_compositor`, `wl_shm`,
  `wl_seat`, `wl_output` and `xdg_wm_base` from the proxy, all offered now;
  without dmabufs it runs with `-shm` and no glamor.
- **Inside the zone:** the X socket's abstract name (`@/tmp/.X11-unix/X0`)
  belongs to the zone's network namespace and the file socket to its
  private `/tmp`, so no other zone can reach them. MIT-SHM needs the SysV
  shared-memory calls, which a policy file can add. Xwayland runs `xkbcomp`
  at start to compile its keymap.
- **Packaging:** the X server, `xkbcomp` and the X client libraries go into
  an image of their own, never the root, so a zone without it has no X at
  all.

Recommendation: rootful Xwayland in the zone, from its own image, once an
application needs X11. None of the planned ones does, so nothing is built
yet; ADR-004's cost text says so.

## What the proxy must offer for a usable browser

Four things are needed, each with its own review. The first two are built.

- **Popups.** Every GTK menu, dropdown and tooltip is one, a surface with
  no border of its own, so a zone's is held to its window. The proxy lets
  `xdg_surface.get_popup` through, sixteen at a time to a connection. dwl
  places a zone's popup inside its window, below the border, and clips it
  there before every frame, since a client may draw a buffer of any size
  wherever its popup is placed. A popup lasts while its window has the
  keyboard: wlroots grants a popup's keyboard grab without checking its
  serial, and a grab keeps the keyboard where it is, so every popup closes
  before the keyboard moves, the new window's own as well
  (`tools/desktop/dwl-zone-borders.py`). `make gui-test` opens one larger
  than the screen from a window that does not have the keyboard: the
  screenshot shows it only inside its window's frame, and the menu still
  takes the keyboard and closes it, as does Alt+j to the popup's own window.
- **Copy and paste inside a zone.** The proxy serves
  `wl_data_device_manager` itself (`compositor/wlproxy/src/clipboard.rs`),
  as a global of its own: the compositor's data device stays hidden, and a
  zone needs none from it. There is one selection per zone, kept among the
  zone's own clients and never forwarded to the compositor, so it reaches
  neither zone 0 nor another zone. Only the client with the keyboard copies, and a client is offered
  the selection just before the keyboard enters it, as a compositor offers
  its own; a paste is passed to the copying client with the reader's
  descriptor. The compositor sees a `wl_display.sync` where each served
  object is made, which keeps its object ids dense. Drag and drop is not
  served: a drag's source is cancelled at once. `make gui-test` copies in
  one of a zone's windows and pastes in another; neither another zone's
  window nor zone 0's is offered it. Between zones the zone 0 move gesture
  carries it: one zone's proxy hands what its windows copied to another's
  ([broker](broker.md#clipboard)).
- **`wp_fractional_scale_v1`**, for sharp text on high-density screens.
- **`zwp_idle_inhibit_manager_v1`**, so video keeps the screen awake; the
  chrome shows which zone holds it. It comes with the browser image, under
  the conditions the [laptop design](laptop.md#power-management-without-logind)
  sets for holding the screen awake; until then nothing a zone does holds
  off the lock or the blanking.

`xdg_activation_v1` stays hidden: it lets a client take focus, and a zone
must not raise a window over another zone's. Input methods are in the
laptop design.

## What it costs the root

From the installed sizes other distributions ship, to be replaced by the
first build's measurement: Firefox about 250 MB, the GTK 3 stack about
100 MB with its translations and a small icon theme, and Mesa with libLLVM
about 200 MB more for GPU zones. Stage 06 adds about 14 % for the
filesystem and the hash tree.

- In the root, the software-rendered browser takes the image from about
  1,560 MiB to about 2,000 MiB. A machine installed from today's medium has
  2,368 MiB slots (the image plus half again), so it fits with about
  400 MiB left. Mesa and libLLVM leave about 200 MiB; a mail client after
  that does not fit, and the release that crosses the line needs a
  reinstall: a major version under [releases](../releases.md).
- As a software image (ADR-015), the browser costs the root
  nothing, and the state partition about twice the image while an update is
  in flight.
- **Build time.** Firefox is one of the largest builds there is, and it
  brings LLVM and clang with it, for bindgen. Each needs a job and a cache of
  its own in the Distro workflow, where a job has six hours. The same LLVM
  build serves Mesa's AMD driver and a Clang-built kernel (the kernel CFI
  design, `docs/design/clang-kernel.md`, proposed beside this one).

## Recommendation

1. Firefox ESR, built by stage 04's GCC, Wayland only, on GTK 3 without X11
   or D-Bus, rendering in software, with its own seccomp sandbox inside the
   zone's.
2. Shipped as a software image named by `personal`, `work` and `untrusted`,
   where the threat model opens unknown links.
3. The zone filter answers `clone` and `unshare` with namespace flags with
   `EPERM` instead of killing, and the browser zones' policy files add
   `allow-syscall seccomp`.
4. The proxy lets a zone's popups through only where they cannot leave the
   zone's own window, and serves copy and paste within a zone, fractional
   scaling and idle inhibition; it keeps activation hidden.
5. No render node in any shipped browsing zone. GPU zones wait for the
   compositor's renderer to be decided, and then go by zone file, never to
   `untrusted`.
6. Rootful Xwayland inside a zone, from its own image, when an application
   needs X11.

## The check that proves it done

`make gui-test` on the installed desktop, extended:

- Firefox started in `untrusted` loads a page from the test network's server
  and maps a window with the zone's border and `[untrusted]` title prefix;
- its content processes show a second seccomp filter in
  `/proc/<pid>/status` (`Seccomp_filters`), and the browser starts without
  `MOZ_ASSUME_USER_NS` set;
- `kryptikd seccomp-trace --zone untrusted -- firefox --headless --screenshot`
  prints no denial;
- `kryptikd check` refuses a browser zone whose policy lacks
  `allow-syscall seccomp`;
- no process in any zone holds a `/dev/dri` node, and a client binding
  `zwp_linux_dmabuf_v1` through any zone's proxy is disconnected;
- a menu opened in Firefox is drawn inside its window's border, and a popup
  a zone's client places outside its window is refused or clipped to it;
- text copied in one window of a zone pastes in another window of the same
  zone, and does not paste in another zone until the zone 0 gesture moves
  it;
- acceptance records the root image's size beside the slot size the
  installer makes for it.

When GPU zones come, the same suite adds: a zone without `gpu` has no
render node; a zone with it renders a GL test through a dmabuf; and
`untrusted` with `gpu` set is refused. When Xwayland comes: an X client in
one zone cannot reach another zone's X server, and the compositor shows the
X screen as one window with the zone's border.
