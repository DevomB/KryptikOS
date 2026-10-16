#!/usr/bin/env bash
# Node.js's release build, which Firefox's build runs to generate its devtools debugger's modules. A
# layer that only builds use; no zone gets it (docs/design/browser-and-graphics.md).
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="${V_NODE}"
# shellcheck disable=SC2034
image_ships=no
# shellcheck disable=SC2034
image_rows=(
    "node" "s_node"
)

# The program alone, under /usr/lib/node-MAJOR: the build needs neither npm nor the headers.
s_node() {
    local top="node-v${V_NODE}-linux-x64" dir="/usr/lib/node-${V_NODE%%.*}"
    mkdir -p "$dir"
    tar --no-same-owner -xJf "${KRYPTIK_SOURCES}/${top}.tar.xz" -C "$dir" --strip-components=1 "${top}/bin/node"
    # A script, not --version, which returns before the engine starts.
    "${dir}/bin/node" -e 'console.log(process.version)'
}
