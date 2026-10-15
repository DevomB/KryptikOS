#!/usr/bin/env bash

# kryptik-stick, the zones' reader of a USB stick's FAT filesystem (ADR-025), built outside (no
# Rust here); its path and hash are arguments, so the stamp covers them.
s_stick() {
    local src="$1" want_sha="${2:-absent}"
    [[ "$src" == "none" ]] && src=""
    echo "requested: ${src:-<none>} (sha256 ${want_sha})"
    if [[ -z "$src" ]]; then
        echo "KRYPTIK_STICK_BIN is not set: kryptik-stick was NOT installed, and no zone can read a USB stick."
        echo "Build it outside the chroot and point KRYPTIK_STICK_BIN at it:"
        echo "  cd tools/stick && cargo build --release --target x86_64-unknown-linux-musl"
        return 0
    fi
    [[ -f "$src" ]] || { echo "KRYPTIK_STICK_BIN=${src} does not exist"; return 1; }
    # The hash was taken outside the chroot; a mismatch means the file changed under the build.
    local got_sha; got_sha="$(sha256_of "$src")"
    if [[ "$want_sha" != "absent" && "$got_sha" != "$want_sha" ]]; then
        echo "kryptik-stick changed during the build: fingerprinted ${want_sha}, now ${got_sha}"
        return 1
    fi
    install -m 0755 "$src" /usr/bin/kryptik-stick
    local out; out="$(/usr/bin/kryptik-stick bogus 2>&1 || true)"
    [[ "$out" == *usage:* ]] || { echo "FAIL: kryptik-stick does not run here: ${out}"; return 1; }
    echo "kryptik-stick: installed, and runs"
}
