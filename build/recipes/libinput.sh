#!/usr/bin/env bash

s_libinput() {
    meson_build "libinput-${V_LIBINPUT}.tar.gz" "libinput-${V_LIBINPUT}" \
        -Dlibwacom=false -Ddebug-gui=false -Dtests=false -Ddocumentation=false -Dzshcompletiondir=no
}
