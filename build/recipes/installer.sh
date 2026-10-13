#!/usr/bin/env bash

# The installer runs in a booted Kryptik system, onto a second disk, never on the build host.
s_installer() {
    local src="${KRYPTIK_ROOT}/tools/install/kryptik-install.sh"
    [[ -f "$src" ]] || { echo "no installer at ${src}"; return 1; }

    install -D -m 0755 "$src" /usr/sbin/kryptik-install

    # Parsed by the target's sh, which is what runs it.
    sh -n /usr/sbin/kryptik-install || {
        echo "the installer does not parse under the target sh"
        return 1
    }
    echo "--- installer ---"
    ls -la /usr/sbin/kryptik-install
    /usr/sbin/kryptik-install --help
}
