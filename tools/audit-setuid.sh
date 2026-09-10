#!/usr/bin/env bash
# Fail the build on any setuid/setgid binary not explicitly justified.
# Rationale: docs/hardening.md ("setuid elimination")

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

TARGET="${1:-${KRYPTIK_OUT}/rootfs}"
ALLOWLIST="${KRYPTIK_ROOT}/build/config/setuid-allowlist.txt"

[[ -d "$TARGET" ]] || die "no rootfs at ${TARGET}
Build a system first, or pass a path: ./tools/audit-setuid.sh /path/to/rootfs"

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
    else
        err "unjustified setuid/setgid binary: ${rel} ($(stat -c '%A %U:%G' "$bin"))"
        violations=$((violations + 1))
    fi
done < <(find "$TARGET" -type f -perm /6000 -print0 2>/dev/null)

echo
if [[ "$violations" -gt 0 ]]; then
    die "${violations} unjustified setuid/setgid binary(ies).
Use file capabilities or a kryptikd-brokered service instead. If a binary
genuinely must be setuid, add it to ${ALLOWLIST} with a justification."
fi
ok "no unjustified setuid/setgid binaries"
