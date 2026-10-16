#!/usr/bin/env bash
# dwl as stage 04 builds it, run headless. The pinned wayland, wayland-protocols, pixman, libdrm,
# xkbcommon and wlroots (its headless backend alone) are built into a prefix, and dwl with Kryptik's
# patches and edits over them. dwl starts on a headless output, a client lists its globals and maps
# a window, and dwl stops on SIGTERM: a change that crashes or hangs dwl shows here, not in a Distro
# run. Needs meson, ninja, bison, gcc, pkg-config, curl, b2sum, python3, patch and sudo, and the
# headers of libffi, expat and libinput, which CI installs; without them it exits 77.
# KRYPTIK_TEST_SOURCES keeps the fetched tarballs between runs (tools/tests/lib/pinned.sh).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
for t in meson ninja bison gcc pkg-config curl b2sum python3 patch; do
    command -v "$t" >/dev/null 2>&1 || { echo "dwl-headless.sh: no $t here (77)"; exit 77; }
done
for p in libffi expat libinput; do
    pkg-config --exists "$p" || { echo "dwl-headless.sh: no $p headers here (77)"; exit 77; }
done
sudo -n true 2>/dev/null || { echo "dwl-headless.sh: no sudo here for the zones' socket directory (77)"; exit 77; }
W="$(mktemp -d)"
dwlpid=""
cleanup() { [[ -z "$dwlpid" ]] || kill -9 "$dwlpid" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
# shellcheck source=/dev/null
. "$REPO/build/config/versions.env"
# shellcheck source=tools/tests/lib/pinned.sh
. "$HERE/lib/pinned.sh"

PREFIX="$W/prefix"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/share/pkgconfig"
export LD_LIBRARY_PATH="$PREFIX/lib"
export PATH="$PREFIX/bin:$PATH"
# build NAME FILE VERSION MESON-OPTION...: fetched, built and installed into the prefix.
build() {
    local src
    src="$(fetch_pinned "$1" "$2" "$3")" || exit 1
    if ! { meson setup "$W/build-$1" "$src" --prefix="$PREFIX" --libdir=lib --buildtype=plain \
               -Dwerror=false "${@:4}" && ninja -C "$W/build-$1" install; } > "$W/build-$1.log" 2>&1; then
        echo "FAIL: $1 $3 does not build:"
        tail -25 "$W/build-$1.log"
        exit 1
    fi
    echo "built $1 $3"
}
build wayland "wayland-${V_WAYLAND}.tar.xz" "$V_WAYLAND" -Dtests=false -Ddocumentation=false -Ddtd_validation=false
build wayland-protocols "wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz" "$V_WAYLAND_PROTOCOLS" -Dtests=false
build pixman "pixman-${V_PIXMAN}.tar.gz" "$V_PIXMAN" -Dtests=disabled -Ddemos=disabled -Dgtk=disabled -Dlibpng=disabled
build libdrm "libdrm-${V_LIBDRM}.tar.xz" "$V_LIBDRM" -Dintel=disabled -Dradeon=disabled -Damdgpu=disabled \
    -Dnouveau=disabled -Dvmwgfx=disabled -Domap=disabled -Dexynos=disabled -Dfreedreno=disabled \
    -Dtegra=disabled -Dvc4=disabled -Detnaviv=disabled -Dcairo-tests=disabled -Dman-pages=disabled \
    -Dvalgrind=disabled -Dtests=false
build libxkbcommon "libxkbcommon-${V_LIBXKBCOMMON}.tar.gz" "$V_LIBXKBCOMMON" -Denable-x11=false \
    -Denable-wayland=false -Denable-docs=false -Denable-tools=false -Denable-xkbregistry=false \
    -Dxkb-config-root=/usr/share/X11/xkb -Dx-locale-root=/usr/share/X11/locale
# stage 04's options (build/recipes/wlroots.sh) but the backends: headless alone, and no session.
build wlroots "wlroots-${V_WLROOTS}.tar.gz" "$V_WLROOTS" -Dxwayland=disabled -Dexamples=false \
    -Drenderers=[] -Dallocators=[] -Dbackends=[] -Dsession=disabled -Dxcb-errors=disabled -Dlibliftoff=disabled

# dwl with the patches, edits and config stage 04 applies (build/recipes/dwl.sh).
DWL="$(fetch_pinned dwl "dwl-v${V_DWL}.tar.gz" "$V_DWL")" || exit 1
(
    cd "$DWL" || exit 1
    pdir="$REPO/build/patches/dwl-${V_DWL}"
    ( cd "$pdir" && sha256sum --check --quiet --strict SHA256SUMS ) || { echo "FAIL: ${pdir}: a patch does not match SHA256SUMS"; exit 1; }
    for p in "$pdir"/*.patch; do
        patch -Np1 -F0 --no-backup-if-mismatch -s -i "$p" || { echo "FAIL: ${p##*/} did not apply"; exit 1; }
    done
    python3 "$REPO/tools/desktop/dwl-zone-borders.py" . > /dev/null || { echo "FAIL: dwl-zone-borders.py did not apply"; exit 1; }
    cp "$REPO/build/desktop/zone-colours.h" zone-colours.h
    cp "$REPO/build/desktop/dwl-config.h" config.h
    make XWAYLAND= XLIBS= > "$W/build-dwl.log" 2>&1 || { echo "FAIL: dwl does not build:"; tail -25 "$W/build-dwl.log"; exit 1; }
) || exit 1
echo "built dwl ${V_DWL} with Kryptik's patches and edits"
gcc -O2 -o "$W/wlprobe" "$REPO/tools/desktop/wlprobe.c" || { echo "FAIL: wlprobe does not build"; exit 1; }

# The zones' sockets go in the directory kryptikd makes for the session.
sudo install -d -m 0711 -o "$(id -u)" -g "$(id -g)" "/run/kryptik-compositor/$(id -u)"
RT="$W/run"
mkdir -m 0700 "$RT"
export XDG_RUNTIME_DIR="$RT"
WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_HEADLESS_OUTPUTS=1 \
    "$DWL/dwl" -s "cat > '$W/status'" > "$W/dwl.log" 2>&1 &
dwlpid=$!

fail=0
check() {   # check NAME DETAIL: the last command's result
    if [[ "$1" == ok ]]; then echo "PASS: $2"; else echo "FAIL: $2"; fail=1; fi
}
for _ in $(seq 40); do [[ -S "$RT/wayland-0" ]] && break; sleep 0.5; done
[[ -S "$RT/wayland-0" ]] && check ok "dwl listens at its socket" || check no "dwl made no socket: $(tail -5 "$W/dwl.log" | tr '\n' ' ')"
WAYLAND_DISPLAY=wayland-0 timeout 20 "$W/wlprobe" list > "$W/list" 2>&1
grep -q ' wl_compositor ' "$W/list" && check ok "a client lists dwl's globals ($(grep -c '^global' "$W/list"))" \
    || check no "a client found no wl_compositor: $(tail -3 "$W/list" | tr '\n' ' ')"
WAYLAND_DISPLAY=wayland-0 timeout 20 "$W/wlprobe" oversize 0 3 kryptik-headless > "$W/window" 2>&1
grep -q '^committed ' "$W/window" && check ok "a client maps a window and draws it" \
    || check no "the window was not drawn: $(tail -3 "$W/window" | tr '\n' ' ')"
kill -0 "$dwlpid" 2>/dev/null && check ok "dwl still runs after its clients left" \
    || check no "dwl ended: $(tail -8 "$W/dwl.log" | tr '\n' ' ')"
[[ -s "$W/status" ]] && check ok "dwl prints its status to the status command" || check no "no status line reached the status command"
# What the compositor's own confinement adds, where this dwl has it: said, not required.
pgrep -x -P "$dwlpid" dwl-spawner > /dev/null && echo "INFO: dwl's spawner runs"
grep -h '^dwl: \(confined\|not confined\)' "$W/dwl.log" | sed 's/^/INFO: /'
kill -TERM "$dwlpid"
for _ in $(seq 20); do kill -0 "$dwlpid" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$dwlpid" 2>/dev/null; then
    check no "dwl did not stop on SIGTERM"
else
    wait "$dwlpid"; rc=$?
    dwlpid=""
    [[ "$rc" -eq 0 ]] && check ok "dwl stopped on SIGTERM" || check no "dwl stopped on SIGTERM with ${rc}: $(tail -5 "$W/dwl.log" | tr '\n' ' ')"
fi
exit "$fail"
