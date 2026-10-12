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
    # No test suite or test modules, which nothing runs, and no static libpython beside the shared one.
    ./configure --prefix=/usr --enable-shared --with-system-expat --disable-test-modules --without-static-libpython
    make
    make install
    # The first build's test files outlive it here, and tkinter cannot import without _tkinter, which nothing builds.
    local lib="/usr/lib/python${V_PYTHON%.*}"
    rm -rf "$lib"/test "$lib"/idlelib "$lib"/tkinter "$lib"/turtledemo "$lib"/turtle.py "$lib"/__pycache__/turtle.* \
        "$lib"/lib-dynload/{_test,_ctypes_test,xx}*.so /usr/bin/idle3 "/usr/bin/idle${V_PYTHON%.*}" \
        "$lib"/config-*/libpython*.a
    # Bytecode for python -O and -OO, which nothing runs; such a run compiles in memory on a read-only root.
    find "$lib" -name '*.opt-[12].pyc' -delete
    [[ ! -e "$lib/test" ]] && ! compgen -G "$lib/lib-dynload/_test*.so" > /dev/null \
        || { echo "FAIL: python's test suite is still installed"; return 1; }
    local m
    for m in ctypes ssl pyexpat readline; do
        python3 -c "import ${m}" || { echo "FAIL: python3 was built without ${m}"; return 1; }
    done
    echo "python3 imports ctypes, ssl, pyexpat and readline"
}
