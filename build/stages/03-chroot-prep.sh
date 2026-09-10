#!/usr/bin/env bash
# Stage 03 — Chroot preparation (Phase 3 of docs/roadmap.md)
#
# Turns the stage 02 sysroot into something that can be chrooted into: the full
# FHS directory layout, the essential device nodes, /etc/passwd and /etc/group,
# and the virtual filesystem mounts.
#
# REQUIRES ROOT. Creating device nodes and bind-mounting /dev needs real
# privilege; this is the one stage that does, and it escalates explicitly here
# rather than the whole build running as root.
#
#   sudo ./03-chroot-prep.sh mount     prepare layout and mount virtual fs
#   sudo ./03-chroot-prep.sh umount    unmount cleanly
#   sudo ./03-chroot-prep.sh enter     drop into the chroot interactively

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# common.sh refuses to run as root by default; this stage is the exception and
# says so rather than quietly working around the guard.
if [[ "${EUID}" -ne 0 ]]; then
    die "stage 03 must run as root.

Creating device nodes and bind-mounting /dev requires real privilege. This
is the only stage that does - stages 01, 02 and 04 build unprivileged.

  sudo $0 ${*:-mount}"
fi

export LFS="${KRYPTIK_WORK}/sysroot"
ACTION="${1:-mount}"

[[ -d "$LFS" ]] || die "no sysroot at ${LFS}. Run stages 01 and 02 first."
[[ -x "${LFS}/usr/bin/bash" ]] || die "sysroot has no bash. Stage 02 has not completed."

# --- directory layout -------------------------------------------------------

create_layout() {
    log "creating FHS layout"
    mkdir -pv "$LFS"/{boot,home,mnt,opt,srv}
    mkdir -pv "$LFS"/etc/{opt,sysconfig}
    mkdir -pv "$LFS"/lib/firmware
    mkdir -pv "$LFS"/media/{floppy,cdrom}
    mkdir -pv "$LFS"/usr/{,local/}{include,src}
    mkdir -pv "$LFS"/usr/lib/locale
    mkdir -pv "$LFS"/usr/local/{bin,lib,sbin}
    mkdir -pv "$LFS"/usr/{,local/}share/{color,dict,doc,info,locale,man}
    mkdir -pv "$LFS"/usr/{,local/}share/{misc,terminfo,zoneinfo}
    mkdir -pv "$LFS"/usr/{,local/}share/man/man{1..8}
    mkdir -pv "$LFS"/var/{cache,local,log,mail,opt,spool}
    mkdir -pv "$LFS"/var/lib/{color,misc,locate}

    # Mount points for the virtual filesystems. These must exist before
    # mount_virtual runs; without them the mounts fail with the distinctly
    # unhelpful "mount point does not exist".
    mkdir -pv "$LFS"/{dev,proc,sys,run}

    ln -sfv /run "$LFS/var/run"
    ln -sfv /run/lock "$LFS/var/lock"

    # 0750, not 0755: root's home should not be world-readable.
    install -dv -m 0750 "$LFS/root"
    # Sticky bits on the shared writable dirs, or any user can unlink another's
    # files - a trivially exploitable local issue that is easy to forget.
    install -dv -m 1777 "$LFS/tmp" "$LFS/var/tmp"

    # Kryptik-specific: zone definitions live here and kryptikd reads them.
    install -dv -m 0755 "$LFS/etc/kryptik"
    install -dv -m 0700 "$LFS/etc/kryptik/zones"

    # Mount point for the repository itself. Stage 04 runs INSIDE the chroot
    # and needs its own scripts, config and source tarballs; without this it
    # would have neither.
    install -dv -m 0755 "$LFS/kryptik"
}

# Stage 04 refuses to run outside the chroot, and this marker is how it tells.
# A file rather than an environment variable: env vars survive into a plain
# shell and would let stage 04 believe it is chrooted when it is not, which is
# precisely the mistake the check exists to prevent.
create_chroot_marker() {
    printf 'Created by stage 03 on %s\nsysroot: %s\n' "$(date -Iseconds)" "$LFS" \
        > "$LFS/etc/kryptik/inside-chroot"
    chmod 0644 "$LFS/etc/kryptik/inside-chroot"
}

# --- essential files --------------------------------------------------------

create_passwd_group() {
    log "creating /etc/passwd and /etc/group"

    # Deliberately minimal. Every account here is one that something in the
    # base system genuinely needs; extra accounts are extra attack surface,
    # and a distro that ships unused system users has already lost track of
    # what runs on it.
    cat > "$LFS/etc/passwd" <<'PASSWD'
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/dev/null:/usr/bin/false
daemon:x:6:6:Daemon User:/dev/null:/usr/bin/false
messagebus:x:18:18:D-Bus Message Daemon User:/run/dbus:/usr/bin/false
uuidd:x:80:80:UUID Generation Daemon User:/dev/null:/usr/bin/false
nobody:x:65534:65534:Unprivileged User:/dev/null:/usr/bin/false
PASSWD

    cat > "$LFS/etc/group" <<'GROUP'
root:x:0:
bin:x:1:daemon
sys:x:2:
kmem:x:3:
tape:x:4:
tty:x:5:
daemon:x:6:
floppy:x:7:
disk:x:8:
lp:x:9:
dialout:x:10:
audio:x:11:
video:x:12:
utmp:x:13:
cdrom:x:15:
adm:x:16:
messagebus:x:18:
input:x:24:
mail:x:34:
kvm:x:61:
uuidd:x:80:
wheel:x:97:
users:x:999:
nogroup:x:65534:
GROUP

    # Log files that must exist with the right ownership before anything runs.
    touch "$LFS/var/log/"{btmp,lastlog,faillog,wtmp}
    chgrp -v utmp "$LFS/var/log/lastlog" 2>/dev/null || true
    chmod -v 664 "$LFS/var/log/lastlog"
    # btmp records FAILED logins and can contain mistyped passwords. 600.
    chmod -v 600 "$LFS/var/log/btmp"
}

# --- device nodes -----------------------------------------------------------

create_devices() {
    log "creating essential device nodes"
    mkdir -pv "$LFS/dev"
    # Only these two are needed before devtmpfs takes over at boot.
    [[ -e "$LFS/dev/console" ]] || mknod -m 600 "$LFS/dev/console" c 5 1
    [[ -e "$LFS/dev/null" ]] || mknod -m 666 "$LFS/dev/null" c 1 3
}

# --- virtual filesystems ----------------------------------------------------

mount_virtual() {
    log "mounting virtual filesystems"

    # /dev is bind-mounted from the host: the chroot needs working device nodes
    # and creating a full set by hand is both tedious and error-prone.
    mountpoint -q "$LFS/dev" || mount -v --bind /dev "$LFS/dev"

    mkdir -pv "$LFS"/dev/{pts,shm}
    mountpoint -q "$LFS/dev/pts" || \
        mount -vt devpts devpts -o gid=5,mode=0620 "$LFS/dev/pts"
    mountpoint -q "$LFS/proc" || mount -vt proc proc "$LFS/proc"
    mountpoint -q "$LFS/sys" || mount -vt sysfs sysfs "$LFS/sys"
    mountpoint -q "$LFS/run" || mount -vt tmpfs tmpfs "$LFS/run"

    # The repository itself, so stage 04 can reach its scripts, its config and
    # the source tarballs. Bind rather than copy: 600MB of sources should not
    # be duplicated, and edits on the host take effect immediately.
    #
    # The second mount is not redundant. A bind mount SILENTLY IGNORES -o
    # nodev,nosuid on the initial call - it inherits the source's flags - so
    # passing them there produces a mount that looks hardened in the command
    # line and is not. They only take effect on a subsequent remount.
    if ! mountpoint -q "$LFS/kryptik"; then
        mount -v --bind "$KRYPTIK_ROOT" "$LFS/kryptik"
        mount -v -o remount,bind,nodev,nosuid "$LFS/kryptik"
    fi

    # nosuid,nodev on shm: nothing in a build chroot needs setuid binaries or
    # device nodes in shared memory, and both are escape primitives.
    if [[ -h "$LFS/dev/shm" ]]; then
        install -v -d -m 1777 "$LFS$(readlink "$LFS/dev/shm")"
    else
        mountpoint -q "$LFS/dev/shm" || \
            mount -vt tmpfs -o nosuid,nodev tmpfs "$LFS/dev/shm"
    fi
}

umount_virtual() {
    log "unmounting virtual filesystems"
    # Reverse order, and lazily where a stale process may hold a reference.
    for m in kryptik dev/pts dev/shm dev run sys proc; do
        if mountpoint -q "$LFS/$m" 2>/dev/null; then
            umount -v "$LFS/$m" 2>/dev/null || umount -lv "$LFS/$m"
        fi
    done
    ok "unmounted"
}

# --- chroot -----------------------------------------------------------------

CHROOT_ENV=(
    HOME=/root
    TERM="${TERM:-xterm}"
    PS1='(kryptik chroot) \u:\w\$ '
    # PATH deliberately excludes the host: if a build reaches a host binary the
    # chroot has failed and we want it to fail loudly, not silently succeed.
    PATH=/usr/bin:/usr/sbin
    KRYPTIK_ROOT=/kryptik
    "MAKEFLAGS=-j${KRYPTIK_JOBS:-$(nproc)}"
    "KRYPTIK_JOBS=${KRYPTIK_JOBS:-$(nproc)}"
)

enter_chroot() {
    log "entering chroot"
    dim "  PATH excludes the host deliberately - a build that reaches a host"
    dim "  binary means the chroot failed, and should fail loudly."
    chroot "$LFS" /usr/bin/env -i "${CHROOT_ENV[@]}" /bin/bash --login
}

# Verify the chroot is real before stage 04 trusts it.
verify_chroot() {
    log "verifying chroot"
    local out
    out="$(chroot "$LFS" /usr/bin/env -i \
        HOME=/root PATH=/usr/bin:/usr/sbin \
        /bin/bash -c 'echo "bash=$BASH_VERSION"; echo "uname=$(uname -m)"; \
                      ls /usr/bin | wc -l' 2>&1)" || {
        err "chroot failed:"
        echo "$out" >&2
        return 1
    }
    echo "$out" | sed 's/^/  /'

    # Stage 04 needs the repo and its sources visible from inside.
    if chroot "$LFS" /usr/bin/env -i PATH=/usr/bin:/usr/sbin         /bin/bash -c '[ -d /kryptik/sources ] && [ -x /kryptik/build/stages/04-base-system.sh ]' 2>/dev/null; then
        ok "repository and sources reachable at /kryptik inside the chroot"
    else
        err "the repository is NOT visible inside the chroot; stage 04 cannot run"
        return 1
    fi

    # The chroot's bash must be OURS, not the host's.
    #
    # $BASH_VERSION carries only the version ("5.2.32(1)-release") - the build
    # triple appears only in `bash --version`. Grepping the former for
    # "kryptik" always fails and warned on a perfectly good chroot.
    local ver
    ver="$(chroot "$LFS" /usr/bin/env -i PATH=/usr/bin:/usr/sbin \
           /bin/bash --version 2>/dev/null | head -1)"
    if [[ "$ver" == *"kryptik"* ]]; then
        ok "chroot is running Kryptik's own bash: ${ver}"
    else
        err "chroot bash is NOT Kryptik's: ${ver:-unknown}"
        err "The chroot may be reaching host binaries; stage 04 would build against them."
        return 1
    fi
}

case "$ACTION" in
    mount)
        create_layout
        create_passwd_group
        create_devices
        create_chroot_marker
        mount_virtual
        verify_chroot
        echo
        ok "chroot ready at ${LFS}"
        echo
        dim "Build the base system with:"
        dim "  sudo chroot ${LFS} /usr/bin/env -i HOME=/root TERM=\$TERM \\"
        dim "      PATH=/usr/bin:/usr/sbin KRYPTIK_ROOT=/kryptik \\"
        dim "      /bin/bash -c /kryptik/build/stages/04-base-system.sh"
        echo
        dim "Or interactively: sudo $0 enter"
        dim "Unmount with:     sudo $0 umount"
        ;;
    umount)
        umount_virtual
        ;;
    enter)
        mount_virtual
        enter_chroot
        ;;
    verify)
        verify_chroot
        ;;
    *)
        die "unknown action ${ACTION:?} (expected mount, umount, enter, verify)"
        ;;
esac
