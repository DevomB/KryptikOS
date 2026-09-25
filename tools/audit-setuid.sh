#!/usr/bin/env bash
# Fail on any setuid/setgid binary, or any file carrying capabilities, that
# its allowlist does not justify; with --strip, take the bit or the
# capabilities off each one instead (docs/hardening.md, "setuid elimination").
# Stage 06 strips the image's root.
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
CAPLIST="${KRYPTIK_ROOT}/build/config/capability-allowlist.txt"

# listed FILE ARRAY: the paths FILE names into the associative ARRAY. The last
# entry counts even without a newline after it.
listed() {
    local -n into="$2"; local path
    [[ -f "$1" ]] || return 0
    # shellcheck disable=SC2034  # into names the caller's array
    while read -r path _ || [[ -n "${path:-}" ]]; do
        [[ -z "$path" || "$path" == \#* ]] || into["$path"]=1
    done < "$1"
}
declare -A ALLOWED=() CAP_ALLOWED=()
listed "$ALLOWLIST" ALLOWED
listed "$CAPLIST" CAP_ALLOWED
# Stripping by a missing or empty list would take the bit off every binary.
[[ "$STRIP" -eq 0 || "${#ALLOWED[@]}" -gt 0 ]] || die "--strip needs ${ALLOWLIST} with at least one entry"

# The root's own filesystem only. A directory find cannot read may hold a
# binary, so an unread one fails the audit instead of passing it.
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
has_caps() { python3 -c 'import os, sys; os.getxattr(sys.argv[1], "security.capability", follow_symlinks=False)' "$1" 2>/dev/null; }

log "Auditing setuid/setgid binaries and file capabilities under ${TARGET}"
violations=0; kept=(); capkept=()
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
for f in "${capped[@]}"; do
    rel="${f#"${TARGET%/}"}"
    if [[ -n "${CAP_ALLOWED[$rel]:-}" ]]; then
        ok "capabilities allowed: ${rel}"
        capkept+=("$f")
    elif [[ "$STRIP" -eq 1 ]]; then
        python3 -c 'import os, sys; os.removexattr(sys.argv[1], "security.capability", follow_symlinks=False)' "$f"
        warn "file capabilities removed: ${rel}"
    else
        err "unjustified file capabilities: ${rel} ($(getcap "$f" 2>/dev/null | cut -d' ' -f2- || echo set))"
        violations=$((violations + 1))
    fi
done

# A stripped name that is a hard link to an allowed file took the bit or the
# capabilities off both; the image would ship that binary broken.
for bin in "${kept[@]}"; do
    [[ -u "$bin" || -g "$bin" ]] \
        || die "${bin#"${TARGET%/}"} lost its bit: a stripped file is another name for it"
done
for f in "${capkept[@]}"; do
    has_caps "$f" || die "${f#"${TARGET%/}"} lost its capabilities: a stripped file is another name for it"
done

echo
if [[ "$violations" -gt 0 ]]; then
    die "${violations} unjustified setuid/setgid binary(ies) or file capabilities.
Use a kryptikd-brokered service instead. If a binary genuinely needs the
privilege, add it to ${ALLOWLIST} or ${CAPLIST} with a justification."
fi
ok "no unjustified setuid/setgid binaries or file capabilities"
