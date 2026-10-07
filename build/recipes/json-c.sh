#!/usr/bin/env bash

s_json_c() {
    local cmake
    if ! cmake="$(prebuilt_cmake)"; then
        cmake="$(command -v cmake || true)"
        [[ -n "$cmake" ]] || die "json-c: no cmake - the prebuilt binary does not run here and none was built"
    fi
    echo "cmake: ${cmake}"
    local src; src="$(unpack "json-c-${V_JSON_C}.tar.gz" "json-c-json-c-${V_JSON_C}")"
    cd "$src"
    # CMAKE_POLICY_VERSION_MINIMUM: cmake 4 refuses the old minimums json-c's subdirectories set.
    # CMAKE_INSTALL_LIBDIR=lib: Kitware's binary would pick lib64, where nothing looks.
    "$cmake" -S . -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_STATIC_LIBS=OFF -DBUILD_TESTING=OFF -DBUILD_APPS=OFF \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    "$cmake" --build build
    "$cmake" --install build
    # cryptsetup's own check, made here where a failure names json-c.
    [[ -f /usr/lib/pkgconfig/json-c.pc ]] || { echo "no /usr/lib/pkgconfig/json-c.pc (installed under lib64?)"; return 1; }
    [[ -e /usr/lib64/libjson-c.so ]] && { echo "json-c installed into /usr/lib64, which this sysroot does not use"; return 1; }
    pkg-config --exists --print-errors json-c || return 1
    # It must round-trip a document; cryptsetup parses LUKS2 headers with it.
    cat > /tmp/jc.c <<'EOF'
#include <json.h>
#include <stdio.h>
#include <string.h>
int main(void){ struct json_object *o = json_tokener_parse("{\"a\":[1,2],\"b\":\"x\"}");
 if(!o) return 1; const char *s = json_object_to_json_string(o);
 return strcmp(s, "{ \"a\": [ 1, 2 ], \"b\": \"x\" }") == 0 ? 0 : 2; }
EOF
    # Through pkg-config, as cryptsetup's configure will find it.
    # shellcheck disable=SC2046
    gcc -o /tmp/jc /tmp/jc.c $(pkg-config --cflags --libs json-c)
    /tmp/jc || { echo "FAIL: json-c did not round-trip a document"; return 1; }
    rm -f /tmp/jc /tmp/jc.c
    echo "ok: json-c parses and prints"
}
