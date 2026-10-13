#!/usr/bin/env bash
# The Rust toolchain the browser is built with: rustc, cargo and the standard library for
# x86_64-unknown-linux-gnu, the very tarballs build/config/rust.lock pins for kryptikd. A layer that
# only builds use; no zone gets it (docs/design/browser-and-graphics.md).
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="${V_RUST}"
# shellcheck disable=SC2034
image_ships=no
# shellcheck disable=SC2034
image_rows=(
    "rust" "s_rust_toolchain"
)

# Each component's own installer, under /usr.
s_rust_toolchain() {
    local src
    for src in "$(unpack "rustc-${V_RUST}-x86_64-unknown-linux-gnu.tar.xz" "rustc-${V_RUST}-x86_64-unknown-linux-gnu")" \
               "$(unpack "cargo-${V_RUST}-x86_64-unknown-linux-gnu.tar.xz" "cargo-${V_RUST}-x86_64-unknown-linux-gnu")" \
               "$(unpack "rust-std-${V_RUST}-x86_64-unknown-linux-gnu.tar.xz" "rust-std-${V_RUST}-x86_64-unknown-linux-gnu")"; do
        "${src}/install.sh" --prefix=/usr --disable-ldconfig
    done
    rustc --version
    cargo --version
}
