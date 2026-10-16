#!/usr/bin/env bash
# cbindgen, which writes the C++ headers of Firefox's Rust code, built over the rust layer with no
# network: from the crates its own Cargo.lock names, which tools/fetch-sources.sh fetched and held to
# that lock's hashes. A layer that only builds use; no zone gets it (docs/design/browser-and-graphics.md).
# shellcheck disable=SC2034  # read by build/stages/04-images.sh
image_version="${V_CBINDGEN}"
# shellcheck disable=SC2034
image_ships=no
# shellcheck disable=SC2034
image_over=(rust)
# shellcheck disable=SC2034
image_rows=(
    "cbindgen" "s_cbindgen"
)

s_cbindgen() {
    local top crate name
    top="$(mktemp -d "${BUILDDIR}/cbindgen.XXXXXX")"
    tar -xzf "${KRYPTIK_SOURCES}/cbindgen-${V_CBINDGEN}.crate" -C "$top"
    # Each crate as cargo's vendored source: unpacked, beside the hash its lock gives, which cargo checks.
    mkdir -p "${top}/vendor"
    for crate in "${KRYPTIK_SOURCES}"/images/crates/*.crate; do
        name="$(basename "$crate" .crate)"
        tar -xzf "$crate" -C "${top}/vendor"
        printf '{"files":{},"package":"%s"}\n' "$(sha256sum "$crate" | cut -d' ' -f1)" > "${top}/vendor/${name}/.cargo-checksum.json"
    done
    mkdir -p "${top}/cbindgen-${V_CBINDGEN}/.cargo"
    printf '[source.crates-io]\nreplace-with = "vendored"\n\n[source.vendored]\ndirectory = "%s"\n' "${top}/vendor" \
        > "${top}/cbindgen-${V_CBINDGEN}/.cargo/config.toml"
    (cd "${top}/cbindgen-${V_CBINDGEN}" && CARGO_HOME="${top}/cargo-home" cargo build --release --offline --locked)
    install -D -m 0755 "${top}/cbindgen-${V_CBINDGEN}/target/release/cbindgen" /usr/bin/cbindgen
    rm -rf "$top"
    cbindgen --version
}
