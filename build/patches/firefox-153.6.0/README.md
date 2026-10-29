# Firefox 153.6.0 ESR: building with GCC 14

Applied by `s_browser_firefox` in the browser image through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

Mozilla builds Firefox with clang; Kryptik builds it with stage 04's GCC 14, as
every other program is built. The first three are the changes Gentoo's Firefox
153 patch set carries for a GCC build, each a few lines; the fourth and fifth
are Kryptik's:

- `0001`: `features.h` leaves the list of system headers Firefox wraps. Wrapped,
  glibc's `_FORTIFY_SOURCE` checks do not take effect, which stage 06's audit
  would report as objects without FORTIFY.
- `0002`: ffvpx, Firefox's copy of FFmpeg, passes pointers of mismatched types in
  places, which GCC 14 makes an error by default; the warning was already
  silenced for clang, and is for GCC too.
- `0003`: two headers use fixed-width integer types without including
  `<cstdint>`, which newer libstdc++ headers no longer bring in on the way.
- `0004`: without D-Bus, the GTK build takes the X11 remote server and client
  (`nsGTKRemoteServer`, `nsXRemoteClient`), which include `gdk/gdkx.h`, and the
  toolkit image's GTK has no X11 backend. They are built with X11 only, and a
  build with neither gets no remote at all, as on a platform without one: a
  second `firefox` with the same profile is not handed to the first, and says
  that Firefox is already running.
- `0005`: the camera in a zone, which refuses inotify (a watch on the `/usr`
  it shares with zone 0 would see every program started). WebRTC's V4L2 code
  learned of cameras only by inotify, so a camera granted after a page loaded
  was never listed and pages got no `devicechange`. Without inotify it now
  looks for `/dev/video<n>` once a second and reports a change, and the
  zone's `/dev/video0` link, dangling with no grant, reads as absent. Its
  capture thread also polled a camera that was taken away in a busy loop,
  since the node answers `POLLERR` and never `POLLIN`; it now stops there.
  Told the camera is gone, Firefox can end the track and close the node,
  which the next grant waits for (`camera.rs`); whether it does is for the
  tests on physical hardware.

The flag stage 04 adds that this build cannot take, `-fno-delete-null-pointer-checks`,
is dropped for Firefox alone in `build/config/hardening-exceptions.txt`.
