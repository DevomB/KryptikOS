#!/usr/bin/env bash
# Fail on any setuid/setgid binary the allowlist does not justify; with
# --strip, take the bit off each one instead (docs/hardening.md, "setuid
# elimination"). Stage 06 strips the image's root.
#
#   ./tools/audit-setuid.sh [--strip] ROOT

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

STRIP=0
[[ "${1:-}" == --strip ]] && { STRIP=1; shift; }
ARG="${1:?usage: audit-setuid.sh [--strip] ROOT}"
# Resolved, so that a trailing slash or a symlink still yields the paths the
# allowlist names; otherwise an allowed binary would be stripped as unknown.
TARGET="$(realpath -e -- "$ARG")" || die "no such path: ${ARG}"
[[ -d "$TARGET" ]] || die "not a directory: ${TARGET}"
# By device and inode, so a bind mount of / is refused as well as / itself.
[[ "$STRIP" -eq 0 || "$(stat -c %d:%i "$TARGET")" != "$(stat -c %d:%i /)" ]] \
    || die "--strip is for a staged image's root, never this machine's /"
ALLOWLIST="${KRYPTIK_ROOT}/build/config/setuid-allowlist.txt"

declare -A ALLOWED=()
if [[ -f "$ALLOWLIST" ]]; then
    # The last entry counts even without a newline after it.
    while read -r path _ || [[ -n "${path:-}" ]]; do
        [[ -z "$path" || "$path" == \#* ]] || ALLOWED["$path"]=1
    done < "$ALLOWLIST"
fi
# Stripping by a missing or empty list would take the bit off every binary.
[[ "$STRIP" -eq 0 || "${#ALLOWED[@]}" -gt 0 ]] || die "--strip needs ${ALLOWLIST} with at least one entry"

# The root's own filesystem only. A directory find cannot read may hold a
# binary, so an unread one fails the audit instead of passing it.
found="$(mktemp)"
find "$TARGET" -xdev -type f -perm /6000 -print0 > "$found" \
    || { rm -f "$found"; die "find could not read all of ${TARGET}"; }
mapfile -d '' -t bins < "$found"
rm -f "$found"

log "Auditing setuid/setgid binaries under ${TARGET}"
violations=0; kept=()
for bin in "${bins[@]}"; do
    rel="${bin#"${TARGET%/}"}"
    if [[ -n "${ALLOWED[$rel]:-}" ]]; then
        ok "allowed: ${rel}"
        kept+=("$bin")
    elif [[ "$STRIP" -eq 1 ]]; then
        chmod ug-s "$bin"
        warn "setuid/setgid removed: ${rel}"
    else
        err "unjustified setuid/setgid binary: ${rel} ($(stat -c '%A %U:%G' "$bin"))"
        violations=$((violations + 1))
    fi
done

# A stripped name that is a hard link to an allowed binary took the bit off
# both; the image would ship that binary broken.
for bin in "${kept[@]}"; do
    [[ -u "$bin" || -g "$bin" ]] \
        || die "${bin#"${TARGET%/}"} lost its bit: a stripped file is another name for it"
done

echo
if [[ "$violations" -gt 0 ]]; then
    die "${violations} unjustified setuid/setgid binary(ies).
Use file capabilities or a kryptikd-brokered service instead. If a binary
genuinely must be setuid, add it to ${ALLOWLIST} with a justification."
fi
ok "no unjustified setuid/setgid binaries"
