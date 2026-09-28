#!/usr/bin/env bash
# python: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_python() {
    local src; src="$(unpack "Python-${V_PYTHON}.tar.xz" "Python-${V_PYTHON}")"
    cd "$src"
    # This python only serves glibc's configure. No --enable-optimizations: its
    # PGO pass fails to link (libgcov) and triples the build time. No
    # --with-system-expat: expat is not built yet.
    ./configure --prefix=/usr --enable-shared
    make
    make install
}

# The full python, rebuilt over the early one after libffi, openssl, expat and
# readline. The step fails unless ctypes, ssl, pyexpat and readline import.
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
