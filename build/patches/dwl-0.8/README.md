# dwl 0.8: a window closed with its decoration still alive no longer crashes dwl

Applied by `s_dwl` in stage 04 through `apply_repo_patches`, before
`tools/desktop/dwl-zone-borders.py`; `SHA256SUMS` is verified before anything
is applied.

dwl 0.8 frees a client in `destroynotify` without removing the two listeners
it put on the client's xdg-decoration, and `destroydecoration` leaves
`c->decoration` set. When a client disconnects, wlroots destroys its toplevel
first: `destroynotify` frees the client, then the decoration is destroyed and
its destroy signal walks into the freed listeners. Under glibc the freed
memory still held the old links, so nothing showed. The image preloads
hardened_malloc, which does not keep them: dwl died the first time a zone's
havoc window closed, and every later window, in any zone, found no display.

Both patches are upstream's, generated with `git format-patch` and unchanged;
they apply to the 0.8 tarball with a one-line offset:

- `0001`: f4dfdabd0bdd632d0b137ede22ff1beb73122efb, "NULL out decoration on
  destroy"
- `0002`: 04279f28e06f6948acf6d4960834165f6d268080, "Remove decoration event
  listeners on destroynotify" (https://codeberg.org/dwl/dwl/issues/1205);
  it relies on `0001` to know whether the decoration is still there.

Checked on headless dwl 0.8 with wlroots 0.19.3 and hardened_malloc 14
preloaded: without the patches dwl dies of SIGSEGV when a havoc window's
client disconnects, with them it carries on. The desktop suite's
`compositor-survives-close` checks the same on the image. Delete this
directory when the dwl pin moves to a release that contains both commits.
