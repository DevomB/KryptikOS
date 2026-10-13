#!/usr/bin/env bash
# Fail on a setuid/setgid bit or file capability its allowlist does not justify, and on
# an entry the root does not need (docs/hardening.md).
#
#   ./tools/audit-setuid.sh ROOT

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

ARG="${1:?usage: audit-setuid.sh ROOT}"
# Resolved, so a trailing slash or a symlink cannot make an allowed binary look unknown.
TARGET="$(realpath -e -- "$ARG")" || die "no such path: ${ARG}"
[[ -d "$TARGET" ]] || die "not a directory: ${TARGET}"
ALLOWLIST="${KRYPTIK_ROOT}/build/config/setuid-allowlist.txt"
CAPLIST="${KRYPTIK_ROOT}/build/config/capability-allowlist.txt"

# listed FILE ARRAY: FILE's paths into ARRAY; an entry with no "# why" refuses the audit up front.
listed() {
    local -n into="$2"; local line path
    [[ -f "$1" ]] || return 0
    # shellcheck disable=SC2034  # into names the caller's array
    while IFS= read -r line || [[ -n "$line" ]]; do
        path="${line%%[[:space:]]*}"
        [[ -z "$path" || "$path" == \#* ]] && continue
        [[ "$line" == *[[:space:]]\#* ]] || die "${1}: ${path} has no justification; say after a # why it keeps its privilege"
        into["$path"]=1
    done < "$1"
}
declare -A ALLOWED=() CAP_ALLOWED=()
listed "$ALLOWLIST" ALLOWED
listed "$CAPLIST" CAP_ALLOWED

# The root's own filesystem only; a directory find cannot read may hide a binary, so it fails.
found="$(mktemp)"
find "$TARGET" -xdev -type f -perm /6000 -print0 > "$found" \
    || { rm -f "$found"; die "find could not read all of ${TARGET}"; }
mapfile -d '' -t bins < "$found"
# The same walk for capabilities, which find cannot see: they are an xattr.
python3 - "$TARGET" > "$found" <<'EOF' || { rm -f "$found"; die "could not read all of ${TARGET} for file capabilities"; }
import errno, os, stat, sys
root = sys.argv[1]
dev = os.lstat(root).st_dev
bad = []
for d, dirs, files in os.walk(root, onerror=bad.append):
    dirs[:] = [x for x in dirs if os.lstat(os.path.join(d, x)).st_dev == dev]
    for name in files:
        p = os.path.join(d, name)
        if not stat.S_ISREG(os.lstat(p).st_mode):
            continue
        try:
            os.getxattr(p, "security.capability", follow_symlinks=False)
        except OSError as e:
            if e.errno not in (errno.ENODATA, errno.ENOTSUP):
                bad.append(e)
            continue
        sys.stdout.buffer.write(os.fsencode(p) + b"\0")
for e in bad:
    print(e, file=sys.stderr)
sys.exit(1 if bad else 0)
EOF
mapfile -d '' -t capped < "$found"
rm -f "$found"

log "Auditing setuid/setgid binaries and file capabilities under ${TARGET}"
violations=0
declare -A SEEN=() CAP_SEEN=()
for bin in "${bins[@]}"; do
    rel="${bin#"${TARGET%/}"}"
    if [[ -n "${ALLOWED[$rel]:-}" ]]; then
        ok "allowed: ${rel}"
        SEEN["$rel"]=1
    else
        err "unjustified setuid/setgid binary: ${rel} ($(stat -c '%A %U:%G' "$bin"))"
        violations=$((violations + 1))
    fi
done
for f in "${capped[@]}"; do
    rel="${f#"${TARGET%/}"}"
    if [[ -n "${CAP_ALLOWED[$rel]:-}" ]]; then
        ok "capabilities allowed: ${rel}"
        CAP_SEEN["$rel"]=1
    else
        err "unjustified file capabilities: ${rel} ($(getcap "$f" 2>/dev/null | cut -d' ' -f2- || echo set))"
        violations=$((violations + 1))
    fi
done

# An entry with nothing behind it would let the next file of that name in unread.
for rel in "${!ALLOWED[@]}"; do
    [[ -n "${SEEN[$rel]:-}" ]] && continue
    err "${ALLOWLIST##*/} lists ${rel}, which has no setuid or setgid bit here: remove the entry"
    violations=$((violations + 1))
done
for rel in "${!CAP_ALLOWED[@]}"; do
    [[ -n "${CAP_SEEN[$rel]:-}" ]] && continue
    err "${CAPLIST##*/} lists ${rel}, which carries no capabilities here: remove the entry"
    violations=$((violations + 1))
done

echo
if [[ "$violations" -gt 0 ]]; then
    die "${violations} unjustified setuid/setgid binary(ies), file capabilities or stale entries.
Use a kryptikd-brokered service, or justify the privilege in ${ALLOWLIST} or ${CAPLIST}."
fi
ok "no unjustified setuid/setgid binaries or file capabilities, and no stale entries"
