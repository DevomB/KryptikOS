#!/usr/bin/env bash
# build/config/rust.lock is what the Distro workflow checks Rust's tarballs
# against, as a SHA256SUMS file, and where it reads the version rustc must
# report: every line but the comments is a hash and a release tarball, and
# the four tarballs the build installs are there once each, of one version.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/build/config/rust.lock"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

tarball='^[0-9a-f]{64}  (rustc|cargo|rust-std)-([0-9]+\.[0-9]+\.[0-9]+)-x86_64-unknown-linux-(gnu|musl)\.tar\.xz$'
malformed=(); versions=(); names=()
while IFS= read -r l; do
    if [[ "$l" =~ $tarball ]]; then
        versions+=("${BASH_REMATCH[2]}"); names+=("${BASH_REMATCH[1]}-${BASH_REMATCH[3]}")
    else
        malformed+=("'${l}'")
    fi
done < <(grep -v '^#' "$LOCK")

[[ "${#malformed[@]}" -eq 0 ]] && ok "every line but the comments is a sha256 and a release tarball" \
    || bad "not a hash, two spaces and a tarball: ${malformed[*]}"
[[ "$(printf '%s\n' "${names[@]}" | LC_ALL=C sort | tr '\n' ' ')" == "cargo-gnu rust-std-gnu rust-std-musl rustc-gnu " ]] \
    && ok "rustc, cargo and both standard libraries, once each" || bad "the tarballs: ${names[*]}"
[[ "$(printf '%s\n' "${versions[@]}" | sort -u | wc -l)" -eq 1 ]] \
    && ok "all of one version, ${versions[0]:-none}" || bad "more than one version: ${versions[*]}"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
