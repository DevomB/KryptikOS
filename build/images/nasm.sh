#!/usr/bin/env bash
# nasm, for the assembly of Firefox's AV1 decoder (dav1d). A layer that only builds use; no zone gets
# it (docs/design/browser-and-graphics.md).
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="${V_NASM}"
# shellcheck disable=SC2034
image_ships=no
# shellcheck disable=SC2034
image_rows=(
    "nasm" "s_nasm"
)

s_nasm() {
    native_build "nasm-${V_NASM}.tar.xz" "nasm-${V_NASM}"
    nasm -v
}
