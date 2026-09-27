#!/usr/bin/env bash
# The licence texts build/licences carries for what kryptikd and
# kryptik-wlproxy link are the ones the pinned Rust release and the locked
# crates carry: Rust's own files and its library's COPYRIGHT-library.html,
# each locked crate's licence files, and the COPYRIGHT of the musl that
# rust-std's musl target links.
#
#   ./tools/check-rust-licences.sh DIST
#
# DIST holds the tarballs build/config/rust.lock pins, unpacked (the Distro
# workflow's rust-dist). The crates are read from the cargo registry they were
# fetched into, so this runs after the build.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

DIST="${1:?usage: check-rust-licences.sh DIST}"
LIC="${KRYPTIK_ROOT}/build/licences"
REG="${CARGO_HOME:-${HOME}/.cargo}/registry/src"
# The release build/licences/musl/COPYRIGHT was taken from.
MUSL=1.2.5

bad=0
same() {  # same UPSTREAM OURS: OURS is UPSTREAM, byte for byte
    cmp -s "$1" "$2" && return 0
    err "${2#"${KRYPTIK_ROOT}/"} is not ${1#"${DIST}/"}"
    bad=$((bad + 1))
}

std="$(find "$DIST" -maxdepth 1 -type d -name 'rust-std-*-x86_64-unknown-linux-musl' 2>/dev/null | head -1 || true)"
rustc="$(find "$DIST" -maxdepth 1 -type d -name 'rustc-*-x86_64-unknown-linux-gnu' 2>/dev/null | head -1 || true)"
[[ -n "$std" && -n "$rustc" ]] || die "no unpacked rust-std for musl and rustc in ${DIST}"

for f in COPYRIGHT LICENSE-APACHE LICENSE-MIT; do
    same "${std}/${f}" "${LIC}/rust/${f}"
done
lib="$(mktemp)"
trap 'rm -f "$lib"' EXIT
gzip -dc "${LIC}/rust/COPYRIGHT-library.html.gz" > "$lib" 2>/dev/null || true
if ! cmp -s "${rustc}/rustc/share/doc/rust/COPYRIGHT-library.html" "$lib"; then
    err "build/licences/rust/COPYRIGHT-library.html.gz is not ${rustc##*/}'s COPYRIGHT-library.html"
    bad=$((bad + 1))
fi

# Each crate the shipped binaries' lockfiles fetch has build/licences/rust-NAME
# with exactly its licence files, and no other crate has one.
declare -A locked=()
while read -r name ver; do
    locked[$name]=1
    dir="$(find "$REG" -mindepth 2 -maxdepth 2 -type d -name "${name}-${ver}" 2>/dev/null | head -1 || true)"
    if [[ -z "$dir" ]]; then
        err "${name} ${ver} is not in ${REG}: run this after the build"
        bad=$((bad + 1)); continue
    fi
    mapfile -t files < <(find "$dir" -maxdepth 1 -type f \( -name 'LICEN[CS]E*' -o -name 'COPYING*' \
                             -o -name 'COPYRIGHT*' -o -name 'NOTICE*' \) -printf '%f\n' | LC_ALL=C sort)
    if [[ "${#files[@]}" -eq 0 ]]; then
        err "${name} ${ver} ships no licence file"
        bad=$((bad + 1)); continue
    fi
    for f in "${files[@]}"; do
        same "${dir}/${f}" "${LIC}/rust-${name}/${f}"
    done
    if [[ "$(find "${LIC}/rust-${name}" -maxdepth 1 -type f 2>/dev/null | wc -l || true)" -ne "${#files[@]}" ]]; then
        err "build/licences/rust-${name} holds files ${name} ${ver} does not ship"
        bad=$((bad + 1))
    fi
done < <(awk '/^\[\[package\]\]/ { n = v = "" }
              /^name = / { n = $3 } /^version = / { v = $3 }
              /^source = "registry\+/ { gsub(/"/, "", n); gsub(/"/, "", v); print n, v }' \
             "${KRYPTIK_ROOT}/compartments/kryptikd/Cargo.lock" "${KRYPTIK_ROOT}/compositor/Cargo.lock" | sort -u)
for d in "${LIC}"/rust-*/; do
    [[ -d "$d" ]] || continue
    d="$(basename "$d")"
    [[ -n "${locked[${d#rust-}]:-}" ]] || { err "build/licences/${d} is for a crate no lockfile fetches"; bad=$((bad + 1)); }
done

# grep -c reads to the end: -q would stop early and kill strings with SIGPIPE.
libc_a="${std}/rust-std-x86_64-unknown-linux-musl/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/libc.a"
[[ -f "$libc_a" ]] || die "no self-contained libc.a in ${std##*/}"
if [[ "$(strings -a "$libc_a" | grep -cx "$MUSL" || true)" -eq 0 ]]; then
    err "${std##*/} links a musl other than ${MUSL}, whose COPYRIGHT build/licences/musl carries"
    bad=$((bad + 1))
fi

[[ "$bad" -eq 0 ]] || die "${bad} licence text(s) do not match what the Rust binaries link"
ok "build/licences matches ${std##*/}, ${rustc##*/}, the locked crates and musl ${MUSL}"
