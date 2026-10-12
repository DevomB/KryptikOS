#!/usr/bin/env bash
# Fail on an executable file the image carries that build/config/image-programs.txt does not name,
# and on an entry naming nothing: a file a recipe stopped installing stays in a cached sysroot.
#
#   tools/check-image-programs.sh ROOT [--list FILE] [--write FILE]
#
#   --list   the names, one path or glob per line; default build/config/image-programs.txt
#   --write  write the names ROOT holds to FILE instead, for a list to start from

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
# The verdict is python's exit status; the ERR trap would abort before it is read.
trap - ERR
set +e

ROOT=""
LIST="${KRYPTIK_ROOT}/build/config/image-programs.txt"
WRITE=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --list)  LIST="${2:?--list needs a file}"; shift 2 ;;
        --write) WRITE="${2:?--write needs a file}"; shift 2 ;;
        -*)      die "unknown option: $1" ;;
        *)       ROOT="$1"; shift ;;
    esac
done
[[ -n "$ROOT" ]] || die "usage: check-image-programs.sh ROOT [--list FILE] [--write FILE]"
ROOT="$(realpath -e -- "$ROOT")" || die "no such directory: ${ROOT}"
[[ -d "$ROOT" ]] || die "not a directory: ${ROOT}"
[[ -n "$WRITE" || -f "$LIST" ]] || die "no list at ${LIST}"

log "Executable files under ${ROOT} against ${LIST#"$KRYPTIK_ROOT"/}"
python3 - "$ROOT" "$LIST" "$WRITE" <<'EOF'
import fnmatch, os, stat, sys

root, listfile, write = sys.argv[1:4]

def programs():
    # Every regular file with an execute bit: what a manifest's modes can list as well.
    dev = os.lstat(root).st_dev
    found, bad = [], []
    for d, dirs, files in os.walk(root, onerror=bad.append):
        dirs[:] = [x for x in dirs if os.lstat(os.path.join(d, x)).st_dev == dev]
        for name in files:
            p = os.path.join(d, name)
            st = os.lstat(p)
            if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111:
                found.append(os.path.relpath(p, root))
    if bad:
        for e in bad:
            print(f"  could not read: {e}", file=sys.stderr)
        sys.exit(f"the walk of {root} was incomplete")
    return sorted(found)

found = programs()
if write:
    with open(write, "w") as fh:
        fh.write("".join(p + "\n" for p in found))
    print(f"  wrote {len(found)} names to {write}")
    sys.exit(0)

exact, globs = {}, []
for n, line in enumerate(open(listfile), 1):
    entry = line.split("#", 1)[0].strip()
    if not entry:
        continue
    if entry.startswith("/"):
        sys.exit(f"{listfile}:{n}: {entry}: paths are relative to the root, with no leading /")
    if any(c in entry for c in "*?["):
        globs.append([entry, n, 0])
    else:
        exact[entry] = [n, 0]

unnamed = []
for p in found:
    hit = exact.get(p)
    if hit:
        hit[1] += 1
        continue
    for g in globs:
        if fnmatch.fnmatchcase(p, g[0]):
            g[2] += 1
            break
    else:
        unnamed.append(p)

stale = [(n, e) for e, (n, c) in exact.items() if not c] + [(n, e) for e, n, c in globs if not c]
print(f"  {len(found)} executable files, {len(exact)} names and {len(globs)} patterns in the list")
for p in unnamed:
    print(f"  NOT NAMED  {p}", file=sys.stderr)
for n, e in sorted(stale):
    print(f"  NAMES NOTHING  line {n}: {e}", file=sys.stderr)
if unnamed or stale:
    sys.exit(f"{len(unnamed)} executable file(s) the list does not name, {len(stale)} entr{'y' if len(stale) == 1 else 'ies'} naming nothing: "
             "name a new program, remove an old one in its recipe, or drop the entry")
EOF
rc=$?
[[ "$rc" -eq 0 ]] || exit "$rc"
[[ -n "$WRITE" ]] || ok "every executable file is named, and every name has one"
