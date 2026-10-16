#!/usr/bin/env bash
# LLVM's release build, for the libclang bindgen loads to read Firefox's C++ headers: the library,
# clang's builtin headers, and clang, which names where they are; and llvm-objdump, which Firefox's
# configure requires and asks clang for. A layer that only builds use; no zone gets it
# (docs/design/browser-and-graphics.md).
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="${V_LLVM}"
# shellcheck disable=SC2034
image_ships=no
# shellcheck disable=SC2034
image_rows=(
    "libclang" "s_clang_libclang"
)

# Some 6 GB unpacked: only what bindgen and Firefox's configure read, under /usr/lib/llvm-MAJOR.
s_clang_libclang() {
    local top="LLVM-${V_LLVM}-Linux-X64" dir="/usr/lib/llvm-${V_LLVM%%.*}"
    mkdir -p "$dir"
    # LLVM compresses with a 1 GiB window, past zstd's default limit of 128 MiB. On standard input,
    # as zstd skips a file named by a link, and sources/ names an image's sources by links.
    zstd -d --long=31 -c < "${KRYPTIK_SOURCES}/LLVM-${V_LLVM}-Linux-X64.tar.zst" \
        | tar --no-same-owner -xf - -C "$dir" --strip-components=1 \
            --wildcards "${top}/bin/clang" "${top}/bin/clang-[0-9]*" "${top}/bin/llvm-objdump" \
            "${top}/lib/libclang.so*" "${top}/lib/clang/*/include/*"
    "${dir}/bin/clang" --version
    [[ -x "$("${dir}/bin/clang" --print-prog-name=llvm-objdump)" ]]
    "${dir}/bin/llvm-objdump" --version
}
