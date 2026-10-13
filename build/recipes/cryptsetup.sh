#!/usr/bin/env bash

s_cryptsetup() {
    local src; src="$(unpack "cryptsetup-${V_CRYPTSETUP}.tar.xz" "cryptsetup-${V_CRYPTSETUP}")"
    cd "$src"
    ./configure --prefix=/usr --disable-ssh-token --disable-asciidoc \
        --disable-static --with-crypto_backend=openssl --enable-internal-argon2
    make
    make install
    echo "--- what shipped ---"
    cryptsetup --version
    veritysetup --version
    # LUKS2 is the contract (docs/design/encrypted-volumes.md); captured, as grep -q can SIGPIPE it.
    cryptsetup benchmark --help >/dev/null 2>&1 || true
    local help; help="$(cryptsetup --help 2>&1 || true)"
    case "$help" in
        *luks2*) echo "ok: luks2 is a known type" ;;
        *) echo "FAIL: cryptsetup --help does not mention luks2"; return 1 ;;
    esac
}
