# havoc 0.7.0: Kryptik's config is read

Applied by `s_havoc` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

havoc reads `havoc.cfg` from `-c`, then from `$XDG_CONFIG_HOME/havoc/`,
`$XDG_CONFIG_HOME/`, `~/.config/havoc/` and `~/.config/`, and last from the
working directory (`open_config()` in `main.c`). Nothing in Kryptik passes
`-c`, and no home holds a file, so every terminal, the chrome's included, ran
on havoc's compiled-in defaults: its embedded ASCII-only font, no scrollback,
and no key for copy or paste.

The patch makes `/usr/share/kryptik/havoc.cfg` the last place looked, in
place of the working directory, so a user's own file still wins. Every zone
reads `/usr` from the verified root, so a zone's terminal gets the same file.
A `havoc.cfg` in whatever directory a terminal starts in no longer configures
it. The file itself is `build/desktop/havoc.cfg`, which the recipe installs.

The patch is Kryptik's own.
