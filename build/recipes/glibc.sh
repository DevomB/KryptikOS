#!/usr/bin/env bash
# glibc: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# glibc, rebuilt natively with the hardening flags (stage 01's was built
# without). After python, which glibc's configure requires.
s_glibc() {
    local src; src="$(unpack "glibc-${V_GLIBC}.tar.xz" "glibc-${V_GLIBC}")"
    cd "$src"

    local fhs="${KRYPTIK_SOURCES}/glibc-${V_GLIBC}-fhs-1.patch"
    [[ -f "$fhs" ]] && patch -Np1 -i "$fhs"

    # build/patches/glibc-2.40 (see its README): upstream's release/2.40/master
    # branch plus the bug 33088 fix, without which ld.so records its own map at
    # address 0 and unwinding aborts. The two checks below catch its return.
    apply_repo_patches "glibc-${V_GLIBC}"

    mkdir -p build
    cd build
    echo "rootsbindir=/usr/sbin" > configparms

    # --enable-stack-protector=strong: glibc builds its own stack protection.
    # --enable-cet: glibc compiles its CET support only when GCC defines __CET__
    # by default (Kryptik's does not), yet -fcf-protection=full in CFLAGS makes
    # rtld call it, so the link fails on _dl_cet_*. Dropping the flag instead
    # would leave the loader, which arms IBT and shadow stacks for everything,
    # without CET. Activation still depends on the CPU and kernel.
    ../configure \
        --prefix=/usr \
        --disable-werror \
        --enable-kernel=4.19 \
        --enable-stack-protector=strong \
        --enable-cet \
        --disable-nscd \
        libc_cv_slibdir=/usr/lib
    make

    # Upstream's check for bug 33088 (the test suite is not run): rtld must not
    # reach __ehdr_start or _end through a run-time relocation.
    echo "--- run-time relocations against __ehdr_start or _end in rtld.os ---"
    local rtld_relocs
    rtld_relocs="$(readelf -rW elf/rtld.os | grep -E 'R_X86_64_64.*(__ehdr_start|_end)' || true)"
    if [[ -n "$rtld_relocs" ]]; then
        printf '%s\n' "$rtld_relocs"
        echo "FAIL: rtld.os reaches __ehdr_start or _end through a relocated"
        echo "      constant (glibc bug 33088, GCC bug 120653); the loader"
        echo "      would record its own map as starting at address 0."
        return 1
    fi
    echo "  ok: none"

    # Skip glibc's test-installation script, as LFS does: it fails in a partly
    # built system.
    sed '/test-installation/s@$(PERL)@true@' -i ../Makefile
    touch /etc/ld.so.conf
    make install

    sed '/RTLDLIST=/s@/usr@@g' -i /usr/bin/ldd

    # Show the installed libc: a failed rebuild would leave stage 01's in place.
    echo "--- installed libc ---"
    ls -la /usr/lib/libc.so.6
    # grep reads the file itself: `strings | grep -m1` can fail on SIGPIPE.
    grep -a -m1 -o "GNU C Library.*" /usr/lib/libc.so.6 || \
        echo "(no GNU C Library banner found - check the install)"

    # Without the CET property note the loader arms IBT and shadow stacks for
    # nothing.
    echo "--- CET in the dynamic loader ---"
    local ldso=/usr/lib/ld-linux-x86-64.so.2
    if [[ -e "$ldso" ]]; then
        # No `readelf | grep -q`: the same SIGPIPE trap.
        local props
        props="$(readelf -n "$ldso" 2>/dev/null || true)"
        if [[ "$props" == *IBT* || "$props" == *SHSTK* ]]; then
            printf '%s\n' "$props" | sed -n '/IBT\|SHSTK/s/^/  /p'
            echo "  ok: the loader carries the CET property"
        else
            echo "FAIL: ${ldso} has no CET property note, but glibc was built"
            echo "      with -fcf-protection=full and --enable-cet."
            return 1
        fi
    else
        echo "FAIL: no dynamic loader at ${ldso}"
        return 1
    fi

    # The runtime form of that check: LD_TRACE_LOADED_OBJECTS (what ldd runs)
    # prints each map start, and with bug 33088 the loader's is 0.
    # tools/tests/libc-unwind.sh tests the consequence on the whole system.
    echo "--- the loader's own map start ---"
    local trace ldso_start
    trace="$(LD_TRACE_LOADED_OBJECTS=1 /usr/bin/bash 2>&1 || true)"
    ldso_start="$(printf '%s\n' "$trace" | sed -n 's/.*ld-linux[^ ]* (0x\([0-9a-f]*\)).*/\1/p' | head -1)"
    if [[ -z "$ldso_start" ]]; then
        printf '%s\n' "$trace" | sed 's/^/  /'
        echo "FAIL: LD_TRACE_LOADED_OBJECTS did not report the loader's map start"
        return 1
    elif [[ "$ldso_start" =~ ^0+$ ]]; then
        printf '%s\n' "$trace" | sed 's/^/  /'
        echo "FAIL: the loader records its own map as starting at address 0"
        echo "      (glibc bug 33088); _dl_find_object would attribute every"
        echo "      later dlopen()ed object to ld.so and the unwinder would abort."
        return 1
    fi
    echo "  ok: ld.so at 0x${ldso_start}"
}
