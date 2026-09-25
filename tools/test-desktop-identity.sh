#!/usr/bin/env bash
# Check the shipped zone colours agree: zone-colours.h matches the zone files,
# the dwl border patch applies to the pinned dwl (if its tarball is in
# KRYPTIK_SOURCES), and `zoneid audit` passes. Exit 0 pass, 1 fail, 77 no cargo.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

rc=0
fail() { printf 'FAIL: %s\n' "$1"; rc=1; }

printf '== zone-colours.h matches the zone files ==\n'
if python3 tools/desktop/gen-zone-colours.py --check build/desktop/zone-colours.h compartments/zones; then
    :
else
    fail "build/desktop/zone-colours.h is stale or the zone files are malformed"
fi

printf '\n== the dwl border patch against the pinned dwl ==\n'
# shellcheck disable=SC1091
V_DWL="$(. build/config/versions.env && echo "${V_DWL:-}")"
SRC="${KRYPTIK_SOURCES:-$ROOT/sources}"
if [[ -n "$V_DWL" && -f "$SRC/dwl-v${V_DWL}.tar.gz" ]]; then
    tmp="$(mktemp -d)"
    if tar -xf "$SRC/dwl-v${V_DWL}.tar.gz" -C "$tmp" && python3 tools/desktop/dwl-zone-borders.py --check "$tmp/dwl-v${V_DWL}"; then
        :
    else
        fail "tools/desktop/dwl-zone-borders.py does not apply to dwl v${V_DWL}"
    fi
    rm -rf "$tmp"
else
    printf 'dwl v%s tarball not under %s; patch dry run not performed here (stage 04 performs it for real)\n' "${V_DWL:-?}" "$SRC"
fi

printf '\n== zoneid audit over compartments/zones ==\n'
if ! command -v cargo >/dev/null 2>&1; then
    printf 'test-desktop-identity: cargo is not installed; zoneid cannot be built here\n'
    [[ "$rc" -eq 0 ]] && exit 77
    exit "$rc"
fi
if cargo run --quiet --locked --manifest-path compositor/Cargo.toml -p zoneid -- audit --zones compartments/zones; then
    :
else
    fail "zoneid audit refused the shipped zone set"
fi

printf '\n'
if [[ "$rc" -eq 0 ]]; then
    printf 'test-desktop-identity: PASS\n'
else
    printf 'test-desktop-identity: FAIL\n'
fi
exit "$rc"
