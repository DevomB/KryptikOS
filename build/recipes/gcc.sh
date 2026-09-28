#!/usr/bin/env bash
# gcc: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# GCC again, in place of stage 02's temporary compiler, which set no flags:
# the same triplet and defaults, so stage 05 and the stamps see the same
# compiler, but now built with the hardening flags. Its binaries become PIE
# with BIND_NOW, and libgcc_s and libstdc++, which glibc's unwinder and every
# C++ program load, carry IBT and SHSTK.
s_gcc_native() {
    local src; src="$(unpack "gcc-${V_GCC}.tar.xz" "gcc-${V_GCC}")"
    cd "$src"
    case "$(uname -m)" in
        x86_64) sed -e '/m64=/s/lib64/lib/' -i.orig gcc/config/i386/t-linux64 ;;
    esac
    mkdir -p build && cd build
    # The target libraries take CFLAGS by themselves in a native build, but
    # not LDFLAGS: named, so libgcc_s and libstdc++ are linked with them too.
    # Without a bootstrap, cc1 and the drivers would link stage 02's static
    # libstdc++ and libgcc, which carry no CET note, and lose theirs; the
    # empty stage1 flags link the shared ones instead.
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
    # Stage 02's compiler ran fixincludes and this one does not, so its fixed
    # headers (searched before /usr/include) and its fixincl would stay.
    rm -rf "/usr/lib/gcc/${want}/${V_GCC}/include-fixed" "/usr/libexec/gcc/${want}/${V_GCC}/install-tools"
    # -j1: the install replaces /usr/include/c++'s headers one by one, and a
    # parallel job rebuilding libcc1 against them, which they now postdate,
    # can find one gone.
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
    # Whole outputs, not pipes into grep -q, which can end readelf with SIGPIPE.
    # A program keeps the CET note only if every object it links has it: the
    # crt files, libc_nonshared and libgcc.a included.
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
