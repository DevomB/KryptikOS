#!/usr/bin/env bash

# havoc, with Kryptik's config as the last place it looks (build/patches/havoc-0.7.0); the
# config is an input by digest, so editing it rebuilds havoc.
s_havoc() {
    local cfg_sha="${1:-none}"
    local cfg="${KRYPTIK_ROOT}/build/desktop/havoc.cfg"
    [[ -f "$cfg" ]] || { echo "desktop input missing: ${cfg}"; return 1; }
    local got; got="$(sha256_of "$cfg")"
    if [[ "$cfg_sha" != "none" && "$got" != "$cfg_sha" ]]; then
        echo "${cfg} changed during the build (fingerprinted ${cfg_sha}, now ${got})"
        return 1
    fi
    echo "inputs: havoc.cfg ${cfg_sha}"

    local src; src="$(unpack "havoc-${V_HAVOC}.tar.gz" "havoc-${V_HAVOC}")"
    cd "$src"
    apply_repo_patches "havoc-${V_HAVOC}"
    make PREFIX=/usr
    make PREFIX=/usr install
    install -Dm644 "$cfg" /usr/share/kryptik/havoc.cfg
    [[ -x /usr/bin/havoc ]] || { echo "no havoc binary"; return 1; }
}
