#!/usr/bin/env bash

# GCC with the hardening, same triplet and defaults as stage 02's so stage 05 and the stamps agree.
s_gcc_native() {
    local src; src="$(unpack "gcc-${V_GCC}.tar.xz" "gcc-${V_GCC}")"
    cd "$src"
    case "$(uname -m)" in
        x86_64) sed -e '/m64=/s/lib64/lib/' -i.orig gcc/config/i386/t-linux64 ;;
    esac
    mkdir -p build && cd build
    # LDFLAGS_FOR_TARGET: a native build passes CFLAGS to the target libraries, not LDFLAGS.
    # --with-stage1-ldflags=: else cc1 links stage 02's static libstdc++, which has no CET note.
    local want; want="$(uname -m)-kryptik-linux-gnu"
    ../configure --build="$want" --prefix=/usr LD=ld LDFLAGS_FOR_TARGET="$LDFLAGS" \
        --with-stage1-ldflags= \
        --enable-languages=c,c++ --enable-default-pie --enable-default-ssp \
        --enable-host-pie --enable-host-bind-now --enable-cet \
        --disable-bootstrap --disable-fixincludes --disable-multilib --disable-nls \
        --disable-libatomic --disable-libgomp --disable-libquadmath \
        --disable-libsanitizer --disable-libssp --disable-libvtv \
        --with-system-zlib
    make
    # No fixincludes here, so stage 02's fixed headers (searched first) would stay.
    rm -rf "/usr/lib/gcc/${want}/${V_GCC}/include-fixed" "/usr/libexec/gcc/${want}/${V_GCC}/install-tools"
    # -j1: install replaces the C++ headers one by one, and a parallel libcc1 rebuild can miss one.
    make -j1 install

    local triple t lib
    triple="$(gcc -dumpmachine)"
    [[ "$triple" == "$want" ]] || { echo "FAIL: the new gcc targets ${triple}, not ${want}"; return 1; }
    t="$(mktemp -d)"
    printf '#include <stdio.h>\nint main(void) { puts("c ok"); return 0; }\n' > "$t/c.c"
    # A throw, so the unwinder in libgcc_s runs, which --enable-cet changes.
    printf '#include <iostream>\nint main() { try { throw 42; } catch (int e) { std::cout << "c++ ok " << e << std::endl; } }\n' > "$t/p.cc"
    # shellcheck disable=SC2086  # the flags are lists of words
    { gcc $CFLAGS $LDFLAGS -o "$t/c" "$t/c.c" && "$t/c" \
        && g++ $CXXFLAGS $LDFLAGS -o "$t/p" "$t/p.cc" && "$t/p"; } \
        || { rm -rf "$t"; echo "FAIL: the new compiler cannot build and run a C and a C++ program that throws"; return 1; }
    # Captured, as grep -q can SIGPIPE readelf; CET survives only if every linked object has it.
    local out; out="$(readelf -h -n "$t/c")"; rm -rf "$t"
    [[ "$out" == *"Type:"*"DYN"* ]] || { echo "FAIL: its programs are not PIE"; return 1; }
    [[ "$out" == *"x86 feature: IBT, SHSTK"* ]] || { echo "FAIL: its programs carry no IBT and SHSTK: an object they link lacks the note"; return 1; }
    for lib in /usr/lib/libgcc_s.so.1 "$(readlink -f /usr/lib/libstdc++.so.6)"; do
        out="$(readelf -n "$lib")"
        [[ "$out" == *"x86 feature: IBT, SHSTK"* ]] || { echo "FAIL: ${lib} carries no IBT and SHSTK"; return 1; }
    done
    out="$(readelf -h -d "$(command -v gcc)")"
    [[ "$out" == *"Type:"*"DYN"* && ( "$out" == *BIND_NOW* || "$out" == *"Flags:"*" NOW"* ) ]] \
        || { echo "FAIL: gcc itself is not PIE with BIND_NOW"; return 1; }
    out="$(readelf -n "$(gcc -print-prog-name=cc1)")"
    [[ "$out" == *"x86 feature: IBT, SHSTK"* ]] || { echo "FAIL: cc1 carries no IBT and SHSTK"; return 1; }
    echo "ok: ${triple} gcc ${V_GCC}; libgcc_s, libstdc++ and cc1 carry IBT and SHSTK; gcc is PIE with BIND_NOW"
}
