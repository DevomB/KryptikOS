# at-spi2-core 2.62.1: ATK alone, without libxml2

Applied by `s_tk_atk` in the toolkit image (`build/images/toolkit.sh`)
through `apply_repo_patches`; `SHA256SUMS` is verified before anything is
applied.

GTK 3 requires ATK, which now ships in at-spi2-core. Its `atk_only` option
builds ATK without the D-Bus accessibility bridge, which the toolkit leaves
out, but `meson.build` still requires libxml2 at the top level, though only
the bridge's tests use it. The patch makes it optional in an `atk_only`
build, so the image carries no XML parser for nothing. Delete this directory
when the pin moves to a release whose `meson.build` does the same.
