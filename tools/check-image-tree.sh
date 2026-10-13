#!/usr/bin/env bash
# Fail on what an image's recipes did to the root instead of adding to /usr: the upper directory of the
# overlay they ran on, against the sysroot under it (docs/design/software-delivery.md).
#
#   tools/check-image-tree.sh LOWER UPPER
#
# Refused: a whiteout or an opaque or redirected directory (a root path removed or hidden), a file the
# root already has, a directory of the root's under /usr with another mode or owner, a file outside
# /usr, a device node, a setuid or setgid bit, a file capability. The chroot's own scratch, mount points
# and marks are let be.
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
# The verdict is python's exit status; the ERR trap would abort before it is read.
trap - ERR
set +e
[[ "$#" -eq 2 ]] || die "usage: check-image-tree.sh LOWER UPPER"
[[ -d "$1" && -d "$2" ]] || die "not directories: $1 $2"
log "What the image's recipes left in $2, against $1"
python3 - "$1" "$2" <<'EOF'
import os, stat, sys
lower, upper = sys.argv[1:3]
# Written by the chroot itself (stage 03), or left by builds; none of it is the image's.
SCRATCH = ("tmp/", "var/tmp/", "root/", "run/", "dev/", "proc/", "sys/")
MOUNTS = {"kryptik", "kryptik-sources", "kryptik-work", "kryptik-kryptikd", "kryptik-wlproxy"}
# Stage 03 writes these on every run: its marker, and the two links it sets again.
MARKS = {"etc/kryptik/inside-chroot", "var/run", "var/lock"}

def xattr(path, name):
    try:
        return os.getxattr(path, name, follow_symlinks=False)
    except OSError:
        return None

bad, files, dirs = [], 0, 0
for d, subdirs, names in os.walk(upper):
    for entry in sorted(subdirs) + sorted(names):
        p = os.path.join(d, entry)
        rel = os.path.relpath(p, upper)
        top = rel.split("/", 1)[0]
        if (rel + "/").startswith(SCRATCH) or top in MOUNTS or rel in MARKS:
            continue
        st = os.lstat(p)
        lp = os.path.join(lower, rel)
        try:
            lst = os.lstat(lp)
        except FileNotFoundError:
            lst = None
        if stat.S_ISCHR(st.st_mode) and st.st_rdev == 0 or xattr(p, "trusted.overlay.whiteout") is not None:
            bad.append(f"removes the root's /{rel}")
            continue
        if xattr(p, "trusted.overlay.redirect") is not None:
            bad.append(f"moves /{rel} within the root")
            continue
        if stat.S_ISDIR(st.st_mode):
            if xattr(p, "trusted.overlay.opaque") == b"y":
                bad.append(f"hides what the root has under /{rel}")
            elif lst is not None and not stat.S_ISDIR(lst.st_mode):
                bad.append(f"replaces the root's /{rel} with a directory")
            elif lst is not None and top == "usr" and (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) != (stat.S_IMODE(lst.st_mode), lst.st_uid, lst.st_gid):
                bad.append(f"changes the root's directory /{rel} "
                           f"({oct(stat.S_IMODE(lst.st_mode))} {lst.st_uid}:{lst.st_gid} -> {oct(stat.S_IMODE(st.st_mode))} {st.st_uid}:{st.st_gid})")
            elif lst is None and top != "usr":
                bad.append(f"makes /{rel} outside /usr")
            elif top == "usr":
                dirs += 1
            continue
        if lst is not None:
            bad.append(f"replaces the root's /{rel}")
        elif top != "usr":
            bad.append(f"installs /{rel} outside /usr")
        elif not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
            bad.append(f"makes /{rel}, neither a file nor a link")
        elif stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            bad.append(f"/{rel} is setuid or setgid")
        elif xattr(p, "security.capability") is not None:
            bad.append(f"/{rel} carries a file capability")
        else:
            files += 1
for b in bad:
    print(f"  REFUSED  {b}", file=sys.stderr)
if bad:
    sys.exit(f"{len(bad)} change(s) to the root: an image may only add files under /usr")
if not os.path.isdir(os.path.join(upper, "usr")):
    sys.exit("the recipes installed nothing under /usr")
print(f"  {files} files and links, {dirs} directories under /usr; nothing of the root's replaced, removed or changed")
EOF
rc=$?
[[ "$rc" -eq 0 ]] || exit "$rc"
ok "the image only adds to /usr"
