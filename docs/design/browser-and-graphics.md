# Browser and graphics in zones

Version 2 promises "a graphical browser and the toolkit stack under it, per
zone, with GPU rendering decided zone by zone" ([roadmap](../roadmap.md)).
Today a zone gets a terminal and a text browser, drawn into shared memory
and composited on the CPU. This document chooses the browser, the toolkit
under it, how a zone is given the GPU and what the proxy must then carry,
how Xwayland runs inside a zone (ADR-004), and what all of it costs the
root. The proposed decision is ADR-016 in [decisions](../decisions.md).

## Where things stand

- **The compositor renders with pixman.** dwl 0.8 on wlroots 0.19.3 is built
  with no GPU renderer and no Xwayland (`-Drenderers=[] -Dxwayland=disabled`
  in `build/recipes/wlroots.sh`); its DRM backend scans out dumb buffers, and
  `kryptik-session` sets `WLR_RENDERER=pixman`.
- **The proxy offers eight globals.** `kryptik-wlproxy` advertises
  `wl_compositor`, `wl_subcompositor`, `wl_shm`, `wl_seat`, `wl_output`,
  `xdg_wm_base`, `zxdg_decoration_manager_v1` and `wp_viewporter`,
  disconnects a client that binds anything else, and bounds shared-memory
  pools at 64 MiB each, 128 MiB per connection and 256 MiB per zone
  (`compositor/wlproxy/src/policy.rs`). The clipboard global is not among
  them: the broker carries clipboards between zones, and nothing carries one
  between two windows of the same zone.
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
  images proposed as ADR-015 in `docs/design/software-delivery.md`, beside
  this design.

## The browser

### Firefox

- **Build.** Firefox builds with GCC 11.1 or newer on Linux, so stage 04's
  GCC 14 can compile it. It still needs clang and libclang, since bindgen
  generates its style system's bindings through libclang whatever the
  compiler; the pinned Rust toolchain and cbindgen; Node.js, unless the
  build passes `--disable-nodejs`, which upstream warns will become an
  error; Python 3; and nasm for its codecs' SIMD. Its wasm-sandboxed
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
  namespaces. Two things stop it in a zone today:
  - At start it probes for user namespaces by calling
    `clone(CLONE_NEWUSER)` in its own process (`SandboxInfo.cpp`), unless
    `MOZ_ASSUME_USER_NS` says the answer. The zone filter kills that call,
    and the browser with it.
  - `seccomp(2)` is not in the base list, so the call is killed too.

  The fix for the first is general: answer `clone` and `unshare` with
  namespace flags with `EPERM`, as the kernel itself answers an unprivileged
  caller, instead of killing. Chromium, bubblewrap and Firefox all probe this
  way, and an `EPERM` grants nothing. The second is a policy line,
  `allow-syscall seccomp`, in the zones that run the browser. Firefox's
  filters then stack under the zone's, and the stricter answer wins. Its
  namespace layer stays off, the price of no nested user namespaces
  (`hardened.fragment`).
- **Updates.** The extended-support release (ESR) has a security release
  every four weeks, like the rapid channel, with fewer feature changes.

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
enters the image, and without the accessibility bridge, which talks D-Bus:

- glib, pango, harfbuzz, fribidi, freetype, fontconfig, cairo (pixman is
  already built), gdk-pixbuf with libpng and libjpeg-turbo, libepoxy, ATK
  from at-spi2-core;
- shared-mime-info, the hicolor theme and one small icon theme;
- GSettings with its keyfile backend, since dconf needs D-Bus;
- fonts: DejaVu is shipped; Noto for wider scripts costs tens of megabytes,
  and CJK fonts a hundred or more, so they are a choice, not a default.

Firefox's own copies of NSS, NSPR, libvpx, dav1d and opus stay bundled: they
are built from source in its tree either way, and every library made
separate is a recipe and a pin review of its own. H.264 needs FFmpeg's
decoder, which Firefox loads if it is present; whether to ship it is a
licensing question as much as a size one, and is left open.

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

Firefox does not run on the proxy as it is: the proxy refuses
`xdg_surface.get_popup` and ends the session, and every GTK menu, dropdown
and tooltip is a popup. Four things are needed, each with its own review:

- **Popups.** The proxy refuses them because a popup is a surface with no
  border, which the compositor will place over other windows, zone 0's
  among them. A browser needs them back in a form that cannot leave its own
  window: inside the zone's toplevel, under its border, or refused. How the
  proxy and the compositor hold that is not designed here, and it is the
  first thing this design needs.
- **Copy and paste inside a zone.** The proxy serves
  `wl_data_device_manager` itself, keeping selections among its own zone's
  clients and never forwarding them to the compositor, and joins it to the
  broker's per-zone clipboard so the zone 0 move gesture still carries a
  payload between zones.
- **`wp_fractional_scale_v1`**, for sharp text on high-density screens.
- **`zwp_idle_inhibit_manager_v1`**, so video keeps the screen awake; the
  chrome shows which zone holds it.

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
- As a software image (ADR-015, proposed), the browser costs the root
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
