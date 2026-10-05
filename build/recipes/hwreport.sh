#!/usr/bin/env bash
# hwreport: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# kryptik-hwreport runs on the machine under test; here it only has to parse
# and to head a report of an empty tree, not of the build machine.
s_hwreport() {
    local src="${KRYPTIK_ROOT}/tools/install/kryptik-hwreport.sh"
    [[ -f "$src" ]] || { echo "no report tool at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    install -D -m 0755 "$src" /usr/sbin/kryptik-hwreport
    sh -n /usr/sbin/kryptik-hwreport || { echo "the report tool does not parse under the target sh"; return 1; }
    local empty out
    empty="$(mktemp -d)"
    # Captured, not piped into head: pipefail would report the closed pipe.
    out="$(KRYPTIK_HWREPORT_ROOT="$empty" /usr/sbin/kryptik-hwreport 2>&1 || true)"
    rmdir "$empty"
    case "$out" in
        "kryptik-hwreport 1"*"== missing =="*"== kernel log =="*) echo "ok: kryptik-hwreport runs" ;;
        *) echo "FAIL: kryptik-hwreport does not run: ${out}"; return 1 ;;
    esac
}
