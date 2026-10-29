#!/usr/bin/env bash
# havoc, patched as stage 04 builds it (build/recipes/havoc.sh), builds against the host's
# libwayland and xkbcommon with the pinned wayland-protocols, so a C error in Kryptik's patches
# shows here and not hours into a Distro build. A negative control proves the build can fail.
# Needs curl, gcc, make, patch, b2sum, pkg-config, wayland-scanner and the headers of
# wayland-client, wayland-cursor and xkbcommon, which CI installs; without them it exits 77.
# KRYPTIK_TEST_SOURCES names a directory that keeps the fetched tarballs between runs.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
for t in curl gcc make patch b2sum pkg-config wayland-scanner; do
    command -v "$t" >/dev/null 2>&1 || { echo "havoc-compile.sh: no $t here (77)"; exit 77; }
done
for p in wayland-client wayland-cursor xkbcommon; do
    pkg-config --exists "$p" || { echo "havoc-compile.sh: no $p headers here (77)"; exit 77; }
done
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
# shellcheck source=/dev/null
. "$REPO/build/config/versions.env"
# shellcheck source=tools/tests/lib/pinned.sh
. "$HERE/lib/pinned.sh"
HAV="$(fetch_pinned havoc "havoc-${V_HAVOC}.tar.gz" "$V_HAVOC")" || exit 1
WP="$(fetch_pinned wayland-protocols "wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz" "$V_WAYLAND_PROTOCOLS")" || exit 1

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

applied=1
for p in "$REPO/build/patches/havoc-${V_HAVOC}"/*.patch; do
    (cd "$HAV" && patch -Np1 -F0 --no-backup-if-mismatch -s -i "$p") || { red "${p##*/} does not apply"; applied=0; }
done
[[ "$applied" -eq 1 ]] && green "the patch set applies with -F0"
cp -r "$HAV" "$W/broken"

if make -C "$HAV" WAYLAND_PROTOCOLS_DIR="$WP" > "$W/make.log" 2>&1 && "$HAV/havoc" -v > "$W/version" 2>&1; then
    green "havoc builds with Kryptik's patches and runs: $(cat "$W/version")"
else
    red "havoc does not build or run: $(grep -m3 -E 'error|undefined' "$W/make.log" | tr '\n' ' ')$(tail -2 "$W/version" 2>/dev/null)"
fi

printf 'int kryptik_broken = ;\n' >> "$W/broken/main.c"
if make -C "$W/broken" WAYLAND_PROTOCOLS_DIR="$WP" > "$W/broken.log" 2>&1; then
    red "a C error in main.c did not fail the build"
else
    green "a C error in main.c fails the build"
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
