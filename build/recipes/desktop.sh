#!/usr/bin/env bash

# The launch client, session and chrome scripts, and the Wayland proxy built outside (as kryptikd).
s_desktop() {
    local wl="$1" wl_sha="${2:-absent}" launch_sha="${3:-none}" session_sha="${4:-none}" chrome_sha="${5:-none}" probe_sha="${6:-none}" lock_sha="${7:-none}" dwl_ver="${8:-none}"
    local display_sha="${9:-none}" wlroots_ver="${10:-none}"
    [[ "$wl" == "none" ]] && wl=""
    local d="${KRYPTIK_ROOT}/tools/desktop"
    echo "inputs: wlprobe.c ${probe_sha}"
    echo "        kryptik-launch.c ${launch_sha}"
    echo "        kryptik-session   ${session_sha}"
    echo "        kryptik-chrome    ${chrome_sha}"
    echo "        kryptik-lock.c    ${lock_sha}"
    echo "        kryptik-display.c ${display_sha}"
    echo "        wlroots' protocols v${wlroots_ver}"
    echo "        dwl's protocols   v${dwl_ver}"
    echo "        kryptik-wlproxy   ${wl:-<none>} (${wl_sha})"
    local f
    for f in kryptik-launch.c kryptik-session kryptik-chrome wlprobe.c kryptik-lock.c kryptik-display.c; do
        [[ -f "$d/$f" ]] || { echo "missing ${d}/${f}"; return 1; }
    done
    install -d -m 0755 /usr/libexec/kryptik

    # The launch client, with the stage's hardening flags (step() set them).
    # shellcheck disable=SC2086
    gcc ${CFLAGS} ${LDFLAGS} -o /usr/bin/kryptik-launch "$d/kryptik-launch.c"
    chmod 0755 /usr/bin/kryptik-launch
    local out; out="$(/usr/bin/kryptik-launch 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: kryptik-launch does not run here: ${out}"; return 1; }
    echo "kryptik-launch: built and runs"

    # The boundary tests' probe: the globals a client is offered and what binding a hidden one gets.
    # shellcheck disable=SC2086
    gcc ${CFLAGS} ${LDFLAGS} -o /usr/libexec/kryptik/wlprobe "$d/wlprobe.c"
    chmod 0755 /usr/libexec/kryptik/wlprobe
    out="$(/usr/libexec/kryptik/wlprobe 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: wlprobe does not run here: ${out}"; return 1; }
    echo "wlprobe: built and runs"

    # The screen lock: a client of ext-session-lock-v1 and ext-idle-notify-v1, and of wlroots'
    # screen power control, whose description dwl's pinned source carries; wayland-scanner
    # makes their code, and xkbcommon reads the user's keyboard layout.
    local gen p xml dwlsrc
    gen="$(mktemp -d)"
    dwlsrc="$(unpack "dwl-v${V_DWL}.tar.gz" "dwl-v${V_DWL}")"
    for xml in /usr/share/wayland-protocols/staging/ext-session-lock/ext-session-lock-v1.xml \
               /usr/share/wayland-protocols/staging/ext-idle-notify/ext-idle-notify-v1.xml \
               "${dwlsrc}/protocols/wlr-output-power-management-unstable-v1.xml"; do
        [[ -f "$xml" ]] || { echo "FAIL: no ${xml}"; rm -rf "$gen" "$dwlsrc"; return 1; }
        p="$(basename "$xml" .xml)"
        wayland-scanner client-header "$xml" "$gen/${p}-client-protocol.h"
        wayland-scanner private-code "$xml" "$gen/${p}-protocol.c"
    done
    # shellcheck disable=SC2086,SC2046
    gcc ${CFLAGS} ${LDFLAGS} -I"$gen" -o /usr/bin/kryptik-lock "$d/kryptik-lock.c" "$gen"/*-protocol.c \
        $(pkg-config --cflags --libs wayland-client xkbcommon)
    rm -rf "$gen" "$dwlsrc"
    chmod 0755 /usr/bin/kryptik-lock
    out="$(/usr/bin/kryptik-lock --help 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: kryptik-lock does not run here: ${out}"; return 1; }
    echo "kryptik-lock: built and runs"

    # The monitors' scale and place: a client of wlroots' output management, whose description
    # wlroots' pinned source carries. dwl serves it to zone 0 alone; no zone's proxy offers it.
    local wlrsrc
    gen="$(mktemp -d)"
    wlrsrc="$(unpack "wlroots-${V_WLROOTS}.tar.gz" "wlroots-${V_WLROOTS}")"
    xml="${wlrsrc}/protocol/wlr-output-management-unstable-v1.xml"
    [[ -f "$xml" ]] || { echo "FAIL: no ${xml}"; rm -rf "$gen" "$wlrsrc"; return 1; }
    wayland-scanner client-header "$xml" "$gen/wlr-output-management-unstable-v1-client-protocol.h"
    wayland-scanner private-code "$xml" "$gen/wlr-output-management-unstable-v1-protocol.c"
    # shellcheck disable=SC2086,SC2046
    gcc ${CFLAGS} ${LDFLAGS} -I"$gen" -o /usr/bin/kryptik-display "$d/kryptik-display.c" "$gen"/*-protocol.c \
        $(pkg-config --cflags --libs wayland-client)
    rm -rf "$gen" "$wlrsrc"
    chmod 0755 /usr/bin/kryptik-display
    out="$(/usr/bin/kryptik-display --help 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: kryptik-display does not run here: ${out}"; return 1; }
    echo "kryptik-display: built and runs"

    install -m 0755 "$d/kryptik-session" /usr/bin/kryptik-session
    install -m 0755 "$d/kryptik-chrome" /usr/bin/kryptik-chrome
    sh -n /usr/bin/kryptik-session || { echo "FAIL: kryptik-session has a syntax error"; return 1; }
    sh -n /usr/bin/kryptik-chrome || { echo "FAIL: kryptik-chrome has a syntax error"; return 1; }
    echo "kryptik-session, kryptik-chrome: installed"

    install -d -m 0755 /etc/kryptik
    if [[ -z "$wl" ]]; then
        echo "KRYPTIK_WLPROXY_BIN is not set: kryptik-wlproxy was NOT installed."
        echo "Zones cannot be given a display. Build it outside the chroot:"
        echo "  cd compositor && cargo build --release --target x86_64-unknown-linux-musl -p wlproxy --bin kryptik-wlproxy"
        echo "and pass KRYPTIK_WLPROXY_BIN=... to make system. Recorded as absent."
        : > /etc/kryptik/wlproxy-absent
        return 0
    fi
    [[ -f "$wl" ]] || { echo "KRYPTIK_WLPROXY_BIN=${wl} does not exist"; return 1; }
    local got_sha; got_sha="$(sha256_of "$wl")"
    if [[ "$wl_sha" != "absent" && "$got_sha" != "$wl_sha" ]]; then
        echo "kryptik-wlproxy changed during the build: fingerprinted ${wl_sha}, now ${got_sha}"
        return 1
    fi
    install -Dm755 "$wl" /usr/bin/kryptik-wlproxy
    rm -f /etc/kryptik/wlproxy-absent
    echo "--- installed kryptik-wlproxy (sha256 ${got_sha}) ---"
    readelf -l /usr/bin/kryptik-wlproxy 2>/dev/null | grep 'Requesting program interpreter' \
        || echo "  (static binary, no interpreter - good)"
    # It must run here; with no arguments it prints its usage and exits 2.
    out="$(/usr/bin/kryptik-wlproxy 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: the installed kryptik-wlproxy does not run here: ${out}"; return 1; }
    echo "kryptik-wlproxy: runs"
}
