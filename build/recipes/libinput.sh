#!/usr/bin/env bash

s_libinput() {
    meson_build "libinput-${V_LIBINPUT}.tar.gz" "libinput-${V_LIBINPUT}" \
        -Dlibwacom=false -Ddebug-gui=false -Dtests=false -Ddocumentation=false -Dzshcompletiondir=no
    # The Python tools import python-libevdev, pyudev or PyYAML, none of which the image has, and measure and
    # analyze only dispatch to them; debug-events, list-devices, record and quirks stay.
    local t
    for t in measure analyze analyze-buttons analyze-per-slot-delta analyze-recording analyze-touch-down-state list-kernel-devices \
             measure-fuzz measure-touchpad-size measure-touchpad-tap measure-touchpad-pressure measure-touch-size replay; do
        rm -f "/usr/libexec/libinput/libinput-${t}" "/usr/share/man/man1/libinput-${t}.1"
    done
    [[ -x /usr/libexec/libinput/libinput-debug-events ]] || { echo "FAIL: libinput debug-events is missing"; return 1; }
}
