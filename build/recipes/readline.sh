#!/usr/bin/env bash

s_readline() {
    local src; src="$(unpack "readline-${V_READLINE}.tar.gz" "readline-${V_READLINE}")"
    cd "$src"
    # GNU's official patches, which the tarball does not carry (see the README).
    apply_repo_patches "readline-${V_READLINE}"
    [[ "$(tail -1 patchlevel)" == 6 ]] || { echo "FAIL: readline is not at patch level 6"; return 1; }
    # shobj-conf's rpath to /usr/lib is redundant: the loader looks there anyway.
    sed -i 's/-Wl,-rpath,[^ ]*//' support/shobj-conf
    # --with-shared-termcap-library, or libreadline names no curses and bc and python skip readline.
    ./configure --prefix=/usr --disable-static --with-curses \
        --with-shared-termcap-library
    make
    make install
    local dyn; dyn="$(readelf -d "/usr/lib/libreadline.so.${V_READLINE}")"
    if grep -q -E 'R(UN)?PATH' <<<"$dyn"; then
        echo "FAIL: libreadline still carries an rpath"; return 1
    fi
    grep -q 'NEEDED.*\[libncursesw\.so' <<<"$dyn" \
        || { echo "FAIL: libreadline does not name libncursesw"; return 1; }
}
