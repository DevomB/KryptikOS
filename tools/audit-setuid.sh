#!/usr/bin/env bash
# Fail on any setuid/setgid binary not justified in the allowlist; with
# --strip, take the bit off each one instead. Stage 06 strips the image's root.
# Rationale: docs/hardening.md ("setuid elimination")
#
#   tools/audit-setuid.sh [--strip] ROOT

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

STRIP=0
[[ "${1:-}" == --strip ]] && { STRIP=1; shift; }
TARGET="${1:?usage: audit-setuid.sh [--strip] ROOT}"
ALLOWLIST="${KRYPTIK_ROOT}/build/config/setuid-allowlist.txt"

[[ -d "$TARGET" ]] || die "no directory at ${TARGET}"

allowed() {
    [[ -f "$ALLOWLIST" ]] || return 1
    grep -qxF "$1" <(grep -vE '^\s*(#|$)' "$ALLOWLIST" | awk '{print $1}')
}

log "Auditing setuid/setgid binaries under ${TARGET}"
violations=0
while IFS= read -r -d '' bin; do
    rel="/${bin#"$TARGET"/}"
    if allowed "$rel"; then
        ok "allowed: ${rel}"
    elif [[ "$STRIP" -eq 1 ]]; then
        chmod ug-s "$bin"
        warn "setuid/setgid removed: ${rel}"
    else
        err "unjustified setuid/setgid binary: ${rel} ($(stat -c '%A %U:%G' "$bin"))"
        violations=$((violations + 1))
    fi
# `|| true`: find exits non-zero on directories it cannot read, which a
# chroot-built tree always has; the ERR trap would otherwise make the audit
# look as if it had crashed rather than found something.
done < <(find "$TARGET" -type f -perm /6000 -print0 2>/dev/null || true)

echo
if [[ "$violations" -gt 0 ]]; then
    die "${violations} unjustified setuid/setgid binary(ies).
Use file capabilities or a kryptikd-brokered service instead. If a binary
genuinely must be setuid, add it to ${ALLOWLIST} with a justification."
fi
ok "no unjustified setuid/setgid binaries"
