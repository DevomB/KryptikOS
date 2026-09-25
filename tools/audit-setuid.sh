#!/usr/bin/env bash
# Fail on any setuid/setgid binary the allowlist does not justify; with
# --strip, take the bit off each one instead (docs/hardening.md, "setuid
# elimination"). Stage 06 strips the image's root.
#
#   ./tools/audit-setuid.sh [--strip] ROOT

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
# find fails on unreadable directories; `|| true` keeps the ERR trap out of it.
done < <(find "$TARGET" -type f -perm /6000 -print0 2>/dev/null || true)

echo
if [[ "$violations" -gt 0 ]]; then
    die "${violations} unjustified setuid/setgid binary(ies).
Use file capabilities or a kryptikd-brokered service instead. If a binary
genuinely must be setuid, add it to ${ALLOWLIST} with a justification."
fi
ok "no unjustified setuid/setgid binaries"
