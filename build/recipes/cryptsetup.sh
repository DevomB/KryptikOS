#!/usr/bin/env bash
# cryptsetup: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

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
    # LUKS2 is the contract (docs/design/encrypted-volumes.md). The help text is
    # captured, not piped into grep -q, which can SIGPIPE cryptsetup.
    cryptsetup benchmark --help >/dev/null 2>&1 || true
    local help; help="$(cryptsetup --help 2>&1 || true)"
    case "$help" in
        *luks2*) echo "ok: luks2 is a known type" ;;
        *) echo "FAIL: cryptsetup --help does not mention luks2"; return 1 ;;
    esac
}
