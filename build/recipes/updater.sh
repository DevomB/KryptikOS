#!/usr/bin/env bash
# updater: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

s_updater() {
    local src="${KRYPTIK_ROOT}/tools/update/kryptik-update"
    [[ -f "$src" ]] || { echo "no updater at ${src}"; return 1; }
    echo "source sha256: ${1:-unknown}"
    install -D -m 0755 "$src" /usr/sbin/kryptik-update
    sh -n /usr/sbin/kryptik-update || { echo "the updater does not parse under the target sh"; return 1; }
    # Captured, not piped: the usage exits non-zero, which pipefail reports.
    local out
    out="$(/usr/sbin/kryptik-update 2>&1 || true)"
    case "$out" in *"apply DIR"*) echo "ok: kryptik-update runs" ;; *) echo "FAIL: kryptik-update does not run: ${out}"; return 1 ;; esac
    # The recovery path runs from the medium, which is this same image.
    local rec="${KRYPTIK_ROOT}/tools/update/kryptik-recover"
    [[ -f "$rec" ]] || { echo "no recover tool at ${rec}"; return 1; }
    echo "recover sha256: ${2:-unknown}"
    install -D -m 0755 "$rec" /usr/sbin/kryptik-recover
    sh -n /usr/sbin/kryptik-recover || { echo "the recover tool does not parse under the target sh"; return 1; }
    out="$(/usr/sbin/kryptik-recover --help 2>&1 || true)"
    case "$out" in *restore-slot*) echo "ok: kryptik-recover runs" ;; *) echo "FAIL: kryptik-recover does not run: ${out}"; return 1 ;; esac
}
