#!/usr/bin/env bash
# libinput: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_libinput() {
    meson_build "libinput-${V_LIBINPUT}.tar.gz" "libinput-${V_LIBINPUT}" \
        -Dlibwacom=false -Ddebug-gui=false -Dtests=false -Ddocumentation=false -Dzshcompletiondir=no
}
