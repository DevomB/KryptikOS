#!/usr/bin/env bash
# cmake: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_cmake() {
    local bin
    if bin="$(prebuilt_cmake)"; then
        echo "the prebuilt cmake runs in this chroot: ${bin}"
        "$bin" --version
        return 0
    fi
    warn "the prebuilt cmake does not run in this chroot; building cmake from source"
    local src; src="$(unpack "cmake-${V_CMAKE}.tar.gz" "cmake-${V_CMAKE}")"
    cd "$src"
    sed -i '/"lib64"/s/64//' Modules/GNUInstallDirs.cmake
    ./bootstrap --prefix=/usr --parallel="${KRYPTIK_JOBS}" --no-system-libs \
        --docdir=/share/doc/cmake -- -DCMAKE_USE_OPENSSL=OFF -DCMAKE_BUILD_TYPE=Release
    make
    make install
    cmake --version
}
