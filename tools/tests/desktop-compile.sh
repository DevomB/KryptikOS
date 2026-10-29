#!/usr/bin/env bash
# The desktop's own C programs build as stage 04 builds them (build/recipes/desktop.sh): its
# hardening flags, the host's libwayland and xkbcommon, and the client code wayland-scanner makes
# from the pinned wayland-protocols, dwl and wlroots. Each must print its usage, and kryptik-lock
# take only its --idle forms, so a C error shows here and not hours into a Distro build. A
# negative control proves the build can fail. Needs curl, gcc, b2sum, pkg-config, wayland-scanner
# and the headers of wayland-client and xkbcommon, which CI installs; without them it exits 77.
# KRYPTIK_TEST_SOURCES names a directory that keeps the fetched tarballs between runs.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
for t in curl gcc b2sum pkg-config wayland-scanner; do
    command -v "$t" >/dev/null 2>&1 || { echo "desktop-compile.sh: no $t here (77)"; exit 77; }
done
for p in wayland-client xkbcommon; do
    pkg-config --exists "$p" || { echo "desktop-compile.sh: no $p headers here (77)"; exit 77; }
done
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
# shellcheck source=/dev/null
. "$REPO/build/config/versions.env"
# shellcheck source=/dev/null
. "$REPO/build/config/hardening.env"
# shellcheck source=tools/tests/lib/pinned.sh
. "$HERE/lib/pinned.sh"
WP="$(fetch_pinned wayland-protocols "wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz" "$V_WAYLAND_PROTOCOLS")" || exit 1
DWL="$(fetch_pinned dwl "dwl-v${V_DWL}.tar.gz" "$V_DWL")" || exit 1
WLR="$(fetch_pinned wlroots "wlroots-${V_WLROOTS}.tar.gz" "$V_WLROOTS")" || exit 1
D="$REPO/tools/desktop"
B="$W/bin"
mkdir -p "$B"

PASS=0; FAIL=0
green() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

# scan DIR XML...: each protocol's client header and code, named as the recipe names them.
scan() {
    local gen="$1" x p
    shift
    mkdir -p "$gen"
    for x in "$@"; do
        [[ -f "$x" ]] || { red "no ${x#"$W"/} in the pinned sources"; return 1; }
        p="$(basename "$x" .xml)"
        wayland-scanner client-header "$x" "$gen/${p}-client-protocol.h" \
            && wayland-scanner private-code "$x" "$gen/${p}-protocol.c" \
            || { red "wayland-scanner refused ${p}"; return 1; }
    done
}
scan "$W/lock" "$WP/staging/ext-session-lock/ext-session-lock-v1.xml" \
    "$WP/staging/ext-idle-notify/ext-idle-notify-v1.xml" \
    "$DWL/protocols/wlr-output-power-management-unstable-v1.xml"
scan "$W/display" "$WLR/protocol/wlr-output-management-unstable-v1.xml"

# The recipe's commands, SOURCE then OUTPUT, so the control below builds with the same one.
# shellcheck disable=SC2086
plain_cc() { gcc ${CFLAGS} ${LDFLAGS} -o "$2" "$1"; }
# shellcheck disable=SC2086,SC2046
lock_cc() { gcc ${CFLAGS} ${LDFLAGS} -I"$W/lock" -o "$2" "$1" "$W/lock"/*-protocol.c $(pkg-config --cflags --libs wayland-client xkbcommon); }
# shellcheck disable=SC2086,SC2046
display_cc() { gcc ${CFLAGS} ${LDFLAGS} -I"$W/display" -o "$2" "$1" "$W/display"/*-protocol.c $(pkg-config --cflags --libs wayland-client); }

# check NAME CC [ARG]: built, its warnings shown, and its usage printed as the recipe asks.
check() {
    local name="$1" cc="$2" out
    shift 2
    if ! "$cc" "$D/$name.c" "$B/$name" 2> "$W/$name.err"; then
        red "${name} does not build: $(grep -m3 -E 'error|undefined' "$W/$name.err" | tr '\n' ' ')"
        return
    fi
    [[ -s "$W/$name.err" ]] && sed 's/^/        /' "$W/$name.err" | head -20
    out="$(XDG_RUNTIME_DIR="$W" WAYLAND_DISPLAY=nowhere "$B/$name" "$@" 2>&1)"
    [[ "$out" == *usage:* ]] && green "${name} builds with stage 04's flags and prints its usage" \
        || red "${name} built but prints no usage: ${out:0:200}"
}
check kryptik-launch plain_cc
check wlprobe plain_cc
check kryptik-lock lock_cc --help
check kryptik-display display_cc --help

# kryptik-lock's --idle forms: a refused one exits 2 before any display is sought; one it takes
# looks for the display, and with none here exits 1.
if [[ -x "$B/kryptik-lock" ]]; then
    for a in "--idle 0" "--idle 0 --blank 0" "--idle 0 --blank 4 --sleep 5" "--idle -1" "--idle 8 --blank"; do
        # shellcheck disable=SC2086
        XDG_RUNTIME_DIR="$W" WAYLAND_DISPLAY=nowhere "$B/kryptik-lock" $a > /dev/null 2>&1
        rc=$?
        [[ "$rc" -eq 2 ]] && green "kryptik-lock ${a} is refused" || red "kryptik-lock ${a}: exit ${rc}, not 2"
    done
    for a in "--idle 0 --blank 4" "--idle 8" "--idle 8 --blank 0 --sleep 60"; do
        # shellcheck disable=SC2086
        out="$(XDG_RUNTIME_DIR="$W" WAYLAND_DISPLAY=nowhere "$B/kryptik-lock" $a 2>&1)"
        rc=$?
        [[ "$rc" -eq 1 && "$out" == *"no Wayland display to watch"* ]] \
            && green "kryptik-lock ${a} is taken, and finds no display here" \
            || red "kryptik-lock ${a}: exit ${rc}: ${out:0:200}"
    done
fi

{ printf 'int kryptik_broken = ;\n'; cat "$D/kryptik-lock.c"; } > "$W/broken.c"
if lock_cc "$W/broken.c" "$B/broken" 2> /dev/null; then
    red "a C error in kryptik-lock.c did not fail the build"
else
    green "a C error in kryptik-lock.c fails the build"
fi

echo
echo "${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
