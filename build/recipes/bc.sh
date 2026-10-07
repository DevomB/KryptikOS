#!/usr/bin/env bash

s_bc() {
    local src; src="$(unpack "bc-${V_BC}.tar.gz" "bc-${V_BC}")"
    cd "$src"
    ./configure --prefix=/usr --with-readline --mandir=/usr/share/man \
        --infodir=/usr/share/info
    make
    make install
    # --with-readline gives up without a word when -lreadline fails to link.
    local dyn; dyn="$(readelf -d /usr/bin/bc)"
    grep -q 'NEEDED.*\[libreadline\.so' <<<"$dyn" \
        || { echo "FAIL: bc was built without readline"; return 1; }

    # The shape of linux/Kbuild's timeconst.h computation, which bc must answer.
    echo "--- bc answers ---"
    local got
    got="$(echo 'scale=0; 1000000000 / 250' | bc -q)"
    echo "  1000000000/250 = ${got}"
    [[ "$got" == "4000000" ]] || { echo "FAIL: bc computed ${got}, expected 4000000"; return 1; }

    # -l loads libmath, which the build generates with fix-libmath.sed.
    got="$(echo 's(0)' | bc -q -l)"
    echo "  s(0) = ${got}"
    [[ "$got" == "0" || "$got" == ".00000000000000000000" ]] \
        || { echo "FAIL: bc -l (libmath) is broken: ${got}"; return 1; }
    echo "  ok: bc evaluates, and libmath loaded"
}
