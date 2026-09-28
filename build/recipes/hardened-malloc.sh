#!/usr/bin/env bash
# hardened-malloc: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_hardened_malloc() {
    # ADR-005. Built here so it exists before anything links against it.
    local src; src="$(unpack "${V_HARDENED_MALLOC}.tar.gz" "hardened_malloc-${V_HARDENED_MALLOC}")"
    cd "$src"

    # CONFIG_NATIVE=false overrides upstream's -march=native: in the system
    # allocator, an instruction an older CPU lacks kills every process.
    make VARIANT=default CONFIG_NATIVE=false

    # Check the command line beat config/default.mk.
    if grep -qE '^\s*CONFIG_NATIVE\s*:?=\s*true' config/default.mk; then
        echo "note: config/default.mk still says CONFIG_NATIVE := true;"
        echo "      the command line above overrides it."
    fi
    local hm_comment
    hm_comment="$(readelf -p .comment out/libhardened_malloc.so 2>/dev/null || true)"
    if [[ "$hm_comment" == *march=native* ]]; then
        echo "FAIL: libhardened_malloc.so was built with -march=native"
        return 1
    fi

    install -Dm755 out/libhardened_malloc.so /usr/lib/libhardened_malloc.so

    # Not preloaded here, or every later package would build on it: stage 06
    # writes /etc/ld.so.preload into the image's root only.
    echo "installed to /usr/lib/libhardened_malloc.so (not yet preloaded)"
}
