#!/usr/bin/env bash

# The s6-rc database, the service scripts and the sysctl fragments, all on the verified root.
s_services() {
    local src="${KRYPTIK_ROOT}/build/services"
    [[ -d "$src" ]] || { echo "no service source tree at ${src}"; return 1; }

    # Outside the s6-rc source tree, where s6-rc-compile reads every directory as a service.
    local scripts="${KRYPTIK_ROOT}/build/service-scripts"
    install -d -m 0755 /usr/libexec/kryptik
    install -m 0755 "$scripts"/*.sh /usr/libexec/kryptik/
    echo "--- boot scripts ---"
    ls -la /usr/libexec/kryptik/

    # sysinit applies these, never anything under /etc, which state can shadow.
    install -d -m 0755 /usr/lib/kryptik/sysctl.d
    if compgen -G "${KRYPTIK_ROOT}/build/config/sysctl.d/*.conf" > /dev/null; then
        install -m 0644 "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf /usr/lib/kryptik/sysctl.d/
        echo "--- sysctl.d ---"
        ls -la /usr/lib/kryptik/sysctl.d/
    else
        echo "no sysctl.d fragments to install"
    fi

    # s6-rc-compile will not overwrite; build beside and swap, as a half-written one does not boot.
    local dbdir=/usr/lib/kryptik/s6-rc
    local tmpdb="$dbdir/compiled.new"
    rm -rf "$tmpdb"
    install -d -m 0755 "$dbdir"
    s6-rc-compile -v2 "$tmpdb" "$src"
    rm -rf "$dbdir/compiled.old"
    [[ -d "$dbdir/compiled" ]] && mv "$dbdir/compiled" "$dbdir/compiled.old"
    mv "$tmpdb" "$dbdir/compiled"
    rm -rf "$dbdir/compiled.old"

    # Read the database back: every service of the source tree must be in it.
    echo "--- compiled database ---"
    local all
    all="$(s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled list all)"
    printf '%s\n' "$all" | sed 's/^/  /'

    local d svc missing=0
    for d in "$src"/*/; do
        svc="${d%/}"; svc="${svc##*/}"
        if [[ $'\n'"${all}"$'\n' != *$'\n'"${svc}"$'\n'* ]]; then
            echo "MISSING from the database: ${svc}"; missing=$((missing + 1))
        fi
    done
    [[ "$missing" -eq 0 ]] || { echo "${missing} service(s) did not compile in"; return 1; }

    # The dependency graph must be the declared one.
    echo "--- what 'default' pulls in, in order ---"
    s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled pipeline default 2>/dev/null || true
    s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled dependencies default | sed 's/^/  /'

    echo "--- eudev-trigger must depend on eudev ---"
    if s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled dependencies eudev-trigger | grep -qx eudev; then
        echo "  ok"
    else
        echo "  FAIL: eudev-trigger does not depend on eudev"
        return 1
    fi
    echo "service database compiled and verified"
}
