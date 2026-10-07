#!/usr/bin/env bash

s_python() {
    local src; src="$(unpack "Python-${V_PYTHON}.tar.xz" "Python-${V_PYTHON}")"
    cd "$src"
    # Only for glibc's configure; no PGO, which fails to link (libgcov), and no system expat yet.
    ./configure --prefix=/usr --enable-shared
    make
    make install
}

# The full python, once libffi, openssl, expat and readline exist; their modules must import.
s_python_final() {
    local src; src="$(unpack "Python-${V_PYTHON}.tar.xz" "Python-${V_PYTHON}")"
    cd "$src"
    ./configure --prefix=/usr --enable-shared --with-system-expat
    make
    make install
    local m
    for m in ctypes ssl pyexpat readline; do
        python3 -c "import ${m}" || { echo "FAIL: python3 was built without ${m}"; return 1; }
    done
    echo "python3 imports ctypes, ssl, pyexpat and readline"
}
