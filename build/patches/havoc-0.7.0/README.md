# havoc 0.7.0: Kryptik's config, and text with its charset

Applied by `s_havoc` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied. Both patches are
Kryptik's own, and `tools/tests/havoc-config.py` checks what they add.

- `0001`: Kryptik's config is read. havoc reads `havoc.cfg` from `-c`, then
  from `$XDG_CONFIG_HOME/havoc/`, `$XDG_CONFIG_HOME/`, `~/.config/havoc/`
  and `~/.config/`, and last from the working directory (`open_config()` in
  `main.c`). Nothing in Kryptik passes `-c`, and no home holds a file, so
  unpatched, every terminal, the chrome's included, runs on havoc's
  compiled-in defaults: its embedded ASCII-only font, no scrollback, and no
  key for copy or paste. The patch makes `/usr/share/kryptik/havoc.cfg` the
  last place looked, in place of the working directory, so a user's own file
  still wins. Every zone reads `/usr` from the verified root, so a zone's
  terminal gets the same file. A `havoc.cfg` in whatever directory a terminal
  starts in does not configure it. The file itself is
  `build/desktop/havoc.cfg`, which the recipe installs.
- `0002`: text with its charset is taken and offered. havoc takes a
  selection offered as `UTF8_STRING` or bare `text/plain` (`do_offer()` and
  `pso_offer()`). Zone 0's move gesture carries one type into another zone,
  the first of `MOVE_TYPES` (`compositor/wlproxy/src/policy.rs`) that the
  source offers, which from Firefox and GTK programs is
  `text/plain;charset=utf-8`. Unpatched, Ctrl+Shift+v in a terminal pastes
  nothing moved in from another zone. The patch takes that type as well, and
  havoc's own copies (`d_copy()`) offer it, so text moved out of a terminal
  arrives as UTF-8 rather than as bare `text/plain`, which is US-ASCII.
