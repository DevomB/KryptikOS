#!/usr/bin/env bash
# dwl as stage 04 builds it, run headless. The pinned wayland, wayland-protocols, pixman, libdrm,
# xkbcommon and wlroots (without its DRM backend) are built into a prefix, and dwl with Kryptik's
# patches and edits over them. dwl starts on a headless output, a client lists its globals and maps
# a window, and dwl stops on SIGTERM: a change that crashes or hangs dwl shows here, not in a Distro
# run. Needs ninja, bison, gcc, pkg-config, curl, b2sum, python3, patch and sudo, and the headers of
# libffi, expat, libinput, libudev and libseat, which CI installs; without them it exits 77. Meson
# is the pinned one, run from its tree. KRYPTIK_TEST_SOURCES keeps the fetched tarballs between
# runs (tools/tests/lib/pinned.sh).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
for t in ninja bison gcc pkg-config curl b2sum python3 patch; do
    command -v "$t" >/dev/null 2>&1 || { echo "dwl-headless.sh: no $t here (77)"; exit 77; }
done
for p in libffi expat libinput libudev libseat; do
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
# The pinned meson, run from its tree: a host's may be older than xkbcommon asks.
MESON_SRC="$(fetch_pinned meson "meson-${V_MESON}.tar.gz" "$V_MESON")" || exit 1
# build NAME FILE VERSION MESON-OPTION...: fetched, built and installed into the prefix.
build() {
    local src
    src="$(fetch_pinned "$1" "$2" "$3")" || exit 1
    if ! { python3 "$MESON_SRC/meson.py" setup "$W/build-$1" "$src" --prefix="$PREFIX" --libdir=lib --buildtype=plain \
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
# stage 04's options (build/recipes/wlroots.sh) but DRM's backend: dwl's code includes libinput's
# and the session's headers, and runs here on the headless backend, which every build has.
build wlroots "wlroots-${V_WLROOTS}.tar.gz" "$V_WLROOTS" -Dxwayland=disabled -Dexamples=false \
    -Drenderers=[] -Dallocators=[] -Dbackends=libinput -Dsession=enabled -Dxcb-errors=disabled \
    -Dlibliftoff=disabled

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
# A window starts on a whole pixel of its output (dwl-zone-borders.py's snaptopixel). At 1 the one
# window fills the 1280x720 output inside its border. At 1.25, set as the chrome sets it, the
# output is 1024x576, and the window gives up the pixels from its border's inner edge to the next
# multiple of 4 across and down.
bw="$(sed -n 's/^static const unsigned int borderpx *= *\([0-9]*\);.*/\1/p' "$REPO/build/desktop/dwl-config.h")"
conf() { grep -o 'for a [0-9]*x[0-9]* configure' "$1" | tail -1 | grep -o '[0-9]*x[0-9]*'; }
want="$((1280 - 2 * bw))x$((720 - 2 * bw))"
[[ "$(conf "$W/window")" == "$want" ]] && check ok "at scale 1 the window fills the output inside its border (${want})" \
    || check no "at scale 1 the window was configured $(conf "$W/window"), not ${want}"
WLR="$(fetch_pinned wlroots "wlroots-${V_WLROOTS}.tar.gz" "$V_WLROOTS")" || exit 1
xml="$WLR/protocol/wlr-output-management-unstable-v1.xml"
mkdir -p "$W/proto" "$W/conf/kryptik"
# shellcheck disable=SC2046
if wayland-scanner client-header "$xml" "$W/proto/wlr-output-management-unstable-v1-client-protocol.h" \
   && wayland-scanner private-code "$xml" "$W/proto/wlr-output-management-unstable-v1-protocol.c" \
   && gcc -O2 -I"$W/proto" -o "$W/kryptik-display" "$REPO/tools/desktop/kryptik-display.c" \
          "$W/proto/wlr-output-management-unstable-v1-protocol.c" $(pkg-config --cflags --libs wayland-client); then
    echo '* 1.25' > "$W/conf/kryptik/display"
    XDG_CONFIG_HOME="$W/conf" WAYLAND_DISPLAY=wayland-0 timeout 20 "$W/kryptik-display" apply > "$W/display" 2>&1
    WAYLAND_DISPLAY=wayland-0 timeout 20 "$W/wlprobe" oversize 0 3 kryptik-grid > "$W/window-grid" 2>&1
    step=$(( (4 - bw % 4) % 4 ))
    want="$((1024 - step - 2 * bw))x$((576 - step - 2 * bw))"
    [[ "$(conf "$W/window-grid")" == "$want" ]] && check ok "at 1.25 the window starts on a whole pixel (${want})" \
        || check no "at 1.25 the window was configured $(conf "$W/window-grid"), not ${want}; kryptik-display: $(tr '\n' ' ' < "$W/display")"
else
    check no "kryptik-display does not build here"
fi
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

# The session's split, wired as kryptik-launch --desktop wires it: the spawner (dwl -X) waits for
# dwl's display and starts its command there on dwl's status; dwl (-S) names its display to it,
# and dwl's end ends the spawner and the command.
if grep -q 'spawnerloop' "$DWL/dwl.c"; then
    python3 -I - "$DWL/dwl" "$W" > "$W/split.out" 2>&1 <<'EOF'
import fcntl, os, signal, socket, subprocess, sys, time
dwl, w = sys.argv[1], sys.argv[2]
env = dict(os.environ, WLR_BACKENDS="headless", WLR_RENDERER="pixman", WLR_HEADLESS_OUTPUTS="1")
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
r, wr = os.pipe()
# Above 9 first, so placing one at 3 or 4 cannot overwrite the other; bash, as dash takes no
# descriptor above 9 in a redirection.
hi = [fcntl.fcntl(fd, fcntl.F_DUPFD, 10) for fd in (a.fileno(), r, b.fileno())]
cmd = ["/bin/sh", "-c", f'echo "$WAYLAND_DISPLAY" > {w}/split-display; exec cat > {w}/split-status']
spawner = subprocess.Popen(["/bin/bash", "-c", 'exec "$@" 3<&"$A" 4<&"$R"', "bash", dwl, "-X", "3", "--"] + cmd,
                           pass_fds=hi[:2], env=dict(env, A=str(hi[0]), R=str(hi[1])), stdout=subprocess.DEVNULL)
comp = subprocess.Popen(["/bin/bash", "-c", 'exec "$@" 3<&"$B"', "bash", dwl, "-S", "3"],
                        pass_fds=hi[2:], env=dict(env, B=str(hi[2])), stdout=wr, stderr=open(f"{w}/split-dwl.log", "w"))
a.close()
b.close()
for fd in (r, wr, *hi):
    os.close(fd)
def waited(test, seconds):
    end = time.time() + seconds
    while time.time() < end and not test():
        time.sleep(0.2)
    return test()
shown = waited(lambda: os.path.exists(f"{w}/split-status") and os.path.getsize(f"{w}/split-status") > 0, 20)
named = open(f"{w}/split-display").read().strip() if os.path.exists(f"{w}/split-display") else ""
comm = open(f"/proc/{spawner.pid}/comm").read().strip() if spawner.poll() is None else "gone"
print("PASS" if shown and named.startswith("wayland-") else "FAIL",
      f": the spawner started its command on dwl's display ({named or 'none'}) with dwl's status")
print("PASS" if comm == "dwl-spawner" else "FAIL", f": the spawner names itself dwl-spawner ({comm})")
comp.send_signal(signal.SIGTERM)
dwl_rc = comp.wait(timeout=10)
ended = waited(lambda: spawner.poll() is not None, 10)
print("PASS" if dwl_rc == 0 and ended else "FAIL", f": dwl stopped ({dwl_rc}), and its spawner with it ({spawner.poll()})")
EOF
    sed 's/^\(PASS\|FAIL\) :/\1:/' "$W/split.out"
    grep -h '^dwl: \(confined\|not confined\)' "$W/split-dwl.log" 2>/dev/null | sed 's/^/INFO: the split: /'
    # A dwl that confined itself on a kernel with Landlock's scopes signals nothing outside its
    # domain when split, as it starts nothing itself, whatever headers built it.
    conf="$(grep -h '^dwl: confined' "$W/split-dwl.log" 2>/dev/null)"
    if [[ "$conf" =~ ABI\ ([0-9]+)\)$ ]] && (( BASH_REMATCH[1] >= 6 )); then
        [[ "$conf" == *", signals nothing outside it ("* ]] \
            && check ok "the split dwl signals nothing outside its domain (Landlock ABI ${BASH_REMATCH[1]})" \
            || check no "the split dwl took no signal scope at Landlock ABI ${BASH_REMATCH[1]}: $conf"
    fi
    grep -q '^FAIL' "$W/split.out" && { fail=1; tail -5 "$W/split-dwl.log" 2>/dev/null; }
    grep -q '^PASS' "$W/split.out" || { echo "FAIL: the split did not run: $(tail -3 "$W/split.out" | tr '\n' ' ')"; fail=1; }
fi

# The calls dwl makes once its filter is on, for that filter's list: dwl again under strace, a
# client listing its globals and drawing a window, and each call named once (said, not required).
if command -v strace > /dev/null 2>&1; then
    : > "$W/trace-status"
    WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_HEADLESS_OUTPUTS=1 \
        strace -f -qq -o "$W/trace" "$DWL/dwl" -s "cat > '$W/trace-status'" > "$W/trace-dwl.log" 2>&1 &
    tracer=$!
    # The first status line comes once dwl has confined itself; the confined dwl before it could
    # not remove its socket, so the socket is no sign of this one.
    for _ in $(seq 60); do [[ -s "$W/trace-status" ]] && break; sleep 0.5; done
    traced="$(pgrep -x -P "$tracer" dwl)"
    WAYLAND_DISPLAY=wayland-0 timeout 20 "$W/wlprobe" list > /dev/null 2>&1
    WAYLAND_DISPLAY=wayland-0 timeout 20 "$W/wlprobe" oversize 0 3 kryptik-trace > /dev/null 2>&1
    [[ -n "$traced" ]] && kill -TERM "$traced"
    for _ in $(seq 40); do kill -0 "$tracer" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$tracer" $traced 2>/dev/null
    wait "$tracer" 2>/dev/null
    # dwl's own lines (the trace's first pid) after its seccomp call.
    calls="$(awk 'NR == 1 { me = $1 } $1 == me && /seccomp\(SECCOMP_SET_MODE_FILTER/ { on = 1; next }
                  on && $1 == me && match($2, /^[a-z_0-9]+\(/) { print substr($2, 1, RLENGTH - 1) }' "$W/trace" | sort -u)"
    echo "INFO: dwl's calls once confined ($(wc -w <<<"$calls")): $(tr '\n' ' ' <<<"$calls")"
fi
# What dwl called outside its filter's list in every run above, which the filter logs (audit
# type 1326) and lets through: by number, with how often (said, not required).
unlisted="$(sudo dmesg 2>/dev/null | grep -a 'type=1326' | grep -a 'comm="dwl"' | grep -ao ' syscall=[0-9]*' \
    | sort | uniq -c | awk '{ printf "%s%s x%s", s, substr($2, 9), $1; s = ", " }')"
echo "INFO: dwl's calls outside its list: ${unlisted:-none}"
exit "$fail"
