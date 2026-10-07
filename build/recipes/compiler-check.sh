#!/usr/bin/env bash

# GCC PR target/116174's case, plus a plain control: each must start with endbr64 under the flags.
s_compiler_check() {
    local d; d="$(mktemp -d)"
    printf '%s\n' 'char *f(char *d, const char *s) { while ((*d++ = *s++)) ; return --d; }' \
                  'int plain(int a) { return a + 1; }' > "$d/t.c"
    # shellcheck disable=SC2086  # CFLAGS is a list of words
    gcc ${CFLAGS:?hardening flags not loaded} -S -o "$d/t.s" "$d/t.c" || return 1
    local bad
    bad="$(awk '/^(f|plain):/ {fn=$1; next}
                fn && /endbr64/ {fn=""; n++; next}
                fn && !/^\.L|\.cfi_|^[ \t]*$/ {print fn, $0; fn=""}
                END {if (n != 2) print "landing pads found:", n+0}' "$d/t.s")"
    rm -rf "$d"
    [[ -z "$bad" ]] || { echo "FAIL: a function entry is not endbr64: ${bad}"; return 1; }
    echo "ok   $(gcc --version | sed -n 1p): function entries are landing pads"
}
