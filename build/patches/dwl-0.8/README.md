# dwl 0.8: a window closing does not leave dwl reading what it freed

Applied by `s_dwl` in stage 04 through `apply_repo_patches`, before
`tools/desktop/dwl-zone-borders.py`; `SHA256SUMS` is verified before anything
is applied.

dwl 0.8 frees a client in `destroynotify` without removing the two listeners
it put on the client's xdg-decoration, and `destroydecoration` leaves
`c->decoration` set. When a client disconnects, wlroots destroys its toplevel
first: `destroynotify` frees the client, then the decoration is destroyed and
its destroy signal walks into the freed listeners. glibc leaves the old links
in freed memory, so nothing shows. hardened_malloc, which the image preloads,
does not: dwl dies the first time a zone's window closes, and every later
window, in any zone, finds no display.

The first two are upstream's, generated with `git format-patch` and
unchanged; they apply to the 0.8 tarball with a one-line offset:

- `0001`: f4dfdabd0bdd632d0b137ede22ff1beb73122efb, "NULL out decoration on
  destroy"
- `0002`: 04279f28e06f6948acf6d4960834165f6d268080, "Remove decoration event
  listeners on destroynotify" (https://codeberg.org/dwl/dwl/issues/1205);
  it relies on `0001` to know whether the decoration is still there.

Checked on headless dwl 0.8 with wlroots 0.19.3 and hardened_malloc 14
preloaded: without the patches dwl dies of SIGSEGV when a havoc window's
client disconnects; with them it carries on. The desktop suite's
`compositor-survives-close` checks the same on the image.

- `0003`: 4847f97678f705352a8ffa3995c69b5bb2226207, "Clear surface->data on
  unmap to fix idle-inhibitor use-after-free", as Codeberg serves the commit
  (its `.patch`, without format-patch's version line); it applies after the
  other two with a two-line offset. `unmapnotify` frees a window's scene tree
  and leaves the surface pointing at it, and `checkidleinhibitor` reads that
  tree for every inhibitor at the next arrange. A zone whose file lets it hold
  the screen awake is offered the inhibitor (docs/design/laptop.md), so it can
  keep one on a surface whose window it unmaps; Kryptik's check of a hold
  (`dwl-zone-borders.py`) skips a surface whose pointer this clears.

Delete this directory when the dwl pin moves to a release that contains all
three commits.
