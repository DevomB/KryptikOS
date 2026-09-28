#!/usr/bin/env bash
# installer: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# The installer runs inside a booted Kryptik system, onto a second disk; it is
# never run on the build host.
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
