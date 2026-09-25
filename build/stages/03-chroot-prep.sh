#!/usr/bin/env bash
# Stage 03: make the sysroot chrootable (FHS layout, device nodes, passwd and
# group, virtual filesystem mounts). The only stage that needs root on the host.
#   sudo 03-chroot-prep.sh mount            prepare the layout and mount
#   sudo 03-chroot-prep.sh umount           unmount
#   sudo 03-chroot-prep.sh enter            shell in the chroot
#   sudo 03-chroot-prep.sh verify           check the chroot
#   sudo 03-chroot-prep.sh run CMD [ARG..]  mount, run CMD inside, unmount
#   03-chroot-prep.sh status                list active mounts
#   03-chroot-prep.sh guard-unmounted       fail if anything is mounted

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

require_outside_chroot "stage 03"

export LFS="$KRYPTIK_SYSROOT"
ACTION="${1:-mount}"

# Where the repository, the sources and the work tree are bound in the chroot.
IN_ROOT="/kryptik"
IN_SOURCES="/kryptik-sources"
IN_WORK="/kryptik-work"
# Single files: the kryptikd and wlproxy binaries built outside.
IN_KRYPTIKD="/kryptik-kryptikd"
IN_WLPROXY="/kryptik-wlproxy"

# Bound one subdirectory at a time: $KRYPTIK_WORK contains sysroot/, and
# binding all of it would give the chroot a nested view of its own root to
# install into by mistake. verify_chroot checks there is none.
WORK_SUBDIRS=(.stamps logs build images keys/release)

need_root() {
    [[ "${EUID}" -eq 0 ]] || die "stage 03 '${ACTION}' must run as root.

Creating device nodes and bind-mounting /dev requires real privilege. This is
the only stage that does - stages 01 and 02 build unprivileged, and 04 and 05
run as root only INSIDE the chroot, where root owns nothing outside the
sysroot.

  sudo $0 ${ACTION}"
}

# Not required by status and guard-unmounted, which must work on a cleaned tree.
need_sysroot() {
    [[ -d "$LFS" ]] || die "no sysroot at ${LFS}. Run stages 01 and 02 first."
    [[ -x "${LFS}/usr/bin/bash" ]] || die \
        "sysroot has no bash at ${LFS}/usr/bin/bash. Stage 02 has not completed."
    [[ -d "$KRYPTIK_SOURCES" ]] || die \
        "no source tree at ${KRYPTIK_SOURCES}. Run: make sources"
}

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

    # Mount points for mount_virtual.
    mkdir -pv "$LFS"/{dev,proc,sys,run}

    ln -sfv /run "$LFS/var/run"
    ln -sfv /run/lock "$LFS/var/lock"

    # root's home is not world-readable.
    install -dv -m 0750 "$LFS/root"
    # Sticky, or any user can unlink another's files.
    install -dv -m 1777 "$LFS/tmp" "$LFS/var/tmp"

    # Stage 04 links the zones here from the verified /usr/lib/kryptik/zones.
    install -dv -m 0755 "$LFS/etc/kryptik"

    # Mount points for the repository, the sources and the work tree.
    install -dv -m 0755 "$LFS$IN_ROOT"
    install -dv -m 0755 "$LFS$IN_SOURCES"
    install -dv -m 0755 "$LFS$IN_WORK"
    local d
    for d in "${WORK_SUBDIRS[@]}"; do
        install -dv -m 0755 "${LFS}${IN_WORK}/${d}"
        install -dv -m 0755 "${KRYPTIK_WORK}/${d}"
    done
}

# How stages 04 and 05 know they are in the chroot. A file, not an env var,
# which would survive into a plain shell.
create_chroot_marker() {
    printf 'Created by stage 03 on %s\nsysroot: %s\n' "$(date -Iseconds)" "$LFS" \
        > "$LFS/etc/kryptik/inside-chroot"
    chmod 0644 "$LFS/etc/kryptik/inside-chroot"
}

# --- essential files --------------------------------------------------------

create_passwd_group() {
    # Written once: stage 04 then adds accounts with useradd and groupadd, and
    # later entries into the chroot must not overwrite them.
    if [[ -s "$LFS/etc/passwd" && -s "$LFS/etc/group" ]]; then
        log "keeping /etc/passwd and /etc/group (already present)"
        return 0
    fi
    log "creating /etc/passwd and /etc/group"

    # Only accounts the base system needs; each extra one is attack surface.
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
    # btmp logs failed logins, which can hold mistyped passwords.
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

# Every path this stage mounts, relative to $LFS. umount_virtual and
# mounts_active both read this list, so they cannot drift apart.
mount_list() {
    local d
    for d in "${WORK_SUBDIRS[@]}"; do printf '%s\n' "${IN_WORK}/${d}"; done
    printf '%s\n' \
        "$IN_ROOT" \
        "$IN_SOURCES" \
        "$IN_KRYPTIKD" \
        "$IN_WLPROXY" \
        "/dev" \
        "/dev/pts" \
        "/dev/shm" \
        "/proc" \
        "/sys" \
        "/run"
}

mounts_active() {
    local m
    while IFS= read -r m; do
        mountpoint -q "${LFS}${m}" 2>/dev/null && return 0
    done < <(mount_list)
    return 1
}

mount_status() {
    local m any=0
    while IFS= read -r m; do
        if mountpoint -q "${LFS}${m}" 2>/dev/null; then
            printf '  mounted  %s\n' "${LFS}${m}"; any=1
        fi
    done < <(mount_list)
    [[ "$any" -eq 1 ]] || printf '  nothing mounted under %s\n' "$LFS"
}

# A bind mount ignores nodev,nosuid,ro on the first call; they take effect
# only on a remount, hence two calls.
bind_hardened() {
    local src="$1" dst="$2" opts="$3"
    mountpoint -q "$dst" && return 0
    mount -v --bind "$src" "$dst"
    mount -v -o "remount,bind,${opts}" "$dst"
}

mount_virtual() {
    log "mounting virtual filesystems"

    # The host's /dev, rather than a hand-made set of nodes.
    mountpoint -q "$LFS/dev" || mount -v --bind /dev "$LFS/dev"

    mkdir -pv "$LFS"/dev/{pts,shm}
    mountpoint -q "$LFS/dev/pts" || \
        mount -vt devpts devpts -o gid=5,mode=0620 "$LFS/dev/pts"
    mountpoint -q "$LFS/proc" || mount -vt proc proc "$LFS/proc"
    mountpoint -q "$LFS/sys" || mount -vt sysfs sysfs "$LFS/sys"
    mountpoint -q "$LFS/run" || mount -vt tmpfs tmpfs "$LFS/run"

    # The repository, read-only: nothing in the build may write to the checkout.
    bind_hardened "$KRYPTIK_ROOT" "$LFS$IN_ROOT" "nodev,nosuid,ro"

    # Separate from the repository: KRYPTIK_SOURCES can be anywhere.
    bind_hardened "$KRYPTIK_SOURCES" "$LFS$IN_SOURCES" "nodev,nosuid,ro"

    # The work tree, writable, one subdirectory at a time (see WORK_SUBDIRS).
    local d
    for d in "${WORK_SUBDIRS[@]}"; do
        bind_hardened "${KRYPTIK_WORK}/${d}" "${LFS}${IN_WORK}/${d}" "nodev,nosuid"
    done

    # kryptikd is Rust, built outside because the sysroot has no Rust
    # toolchain; bound read-only for stage 04 to install (a copy goes stale).
    if [[ -n "${KRYPTIK_KRYPTIKD_BIN:-}" ]]; then
        if [[ -f "$KRYPTIK_KRYPTIKD_BIN" ]]; then
            : > "${LFS}${IN_KRYPTIKD}"
            bind_hardened "$KRYPTIK_KRYPTIKD_BIN" "${LFS}${IN_KRYPTIKD}" "nodev,nosuid,ro"
        else
            die "KRYPTIK_KRYPTIKD_BIN=${KRYPTIK_KRYPTIKD_BIN} does not exist"
        fi
    fi
    # The per-zone Wayland proxy, likewise.
    if [[ -n "${KRYPTIK_WLPROXY_BIN:-}" ]]; then
        if [[ -f "$KRYPTIK_WLPROXY_BIN" ]]; then
            : > "${LFS}${IN_WLPROXY}"
            bind_hardened "$KRYPTIK_WLPROXY_BIN" "${LFS}${IN_WLPROXY}" "nodev,nosuid,ro"
        else
            die "KRYPTIK_WLPROXY_BIN=${KRYPTIK_WLPROXY_BIN} does not exist"
        fi
    fi

    # nosuid,nodev: setuid files and device nodes in shm are escape primitives.
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
    local m p
    while IFS= read -r m; do
        p="${LFS}${m}"
        if mountpoint -q "$p" 2>/dev/null; then
            umount -v "$p" 2>/dev/null || umount -lv "$p"
        fi
    done < <(mount_list | tac)

    if mounts_active; then
        warn "some mounts are still active under ${LFS}:"
        mount_status >&2
        return 1
    fi
    # The files the two binaries were bound onto. Left behind, they end up in
    # the root image, and stage 01 takes a file there for a mount.
    rm -f "${LFS}${IN_KRYPTIKD}" "${LFS}${IN_WLPROXY}"
    ok "unmounted"
}

# --- chroot -----------------------------------------------------------------

# The whole environment inside the chroot; every path a stage needs is here.
chroot_env() {
    local jobs="${KRYPTIK_JOBS:-$(kryptik_default_jobs)}"
    printf '%s\n' \
        "HOME=/root" \
        "TERM=${TERM:-xterm}" \
        "PS1=(kryptik chroot) \\u:\\w\\\$ " \
        "PATH=/usr/bin:/usr/sbin" \
        "KRYPTIK_ROOT=${IN_ROOT}" \
        "KRYPTIK_SOURCES=${IN_SOURCES}" \
        "KRYPTIK_WORK=${IN_WORK}" \
        "KRYPTIK_JOBS=${jobs}" \
        "MAKEFLAGS=-j${jobs}" \
        "KRYPTIK_STALE=${KRYPTIK_STALE:-refuse}" \
        "KRYPTIK_BUILD_COMMIT=${KRYPTIK_BUILD_COMMIT:-unknown}" \
        "KRYPTIK_KRYPTIKD_BIN=${KRYPTIK_KRYPTIKD_BIN:+$IN_KRYPTIKD}" \
        "KRYPTIK_WLPROXY_BIN=${KRYPTIK_WLPROXY_BIN:+$IN_WLPROXY}" \
        "KRYPTIK_ALLOW_UNCHROOTED=0" \
        "NO_COLOR=${NO_COLOR:-}"
}

# PATH excludes the host, so reaching for a host binary fails loudly.
in_chroot() {
    local -a env_args=()
    mapfile -t env_args < <(chroot_env)
    chroot "$LFS" /usr/bin/env -i "${env_args[@]}" "$@"
}

enter_chroot() {
    log "entering chroot"
    dim "  PATH excludes the host deliberately - a build that reaches a host"
    dim "  binary means the chroot failed, and should fail loudly."
    in_chroot /bin/bash --login
}

# Verify the chroot is real before stages 04 and 05 trust it.
verify_chroot() {
    log "verifying chroot"
    local out
    out="$(in_chroot /bin/bash -c 'echo "bash=$BASH_VERSION"; echo "uname=$(uname -m)"; ls /usr/bin | wc -l' 2>&1)" || {
        err "chroot failed:"
        echo "$out" >&2
        return 1
    }
    echo "$out" | sed 's/^/  /'

    # The repository, sources and work tree must be visible inside.
    local probe
    probe="[ -x ${IN_ROOT}/build/stages/04-base-system.sh ]"
    probe="${probe} && [ -d ${IN_SOURCES} ]"
    probe="${probe} && [ -d ${IN_WORK}/.stamps ] && [ -d ${IN_WORK}/logs ]"
    probe="${probe} && [ -d ${IN_WORK}/build ]"
    if in_chroot /bin/bash -c "$probe" 2>/dev/null; then
        ok "repository, sources and work tree reachable inside the chroot"
    else
        err "the build contract is not satisfied inside the chroot:"
        err "  ${IN_ROOT}                        <- ${KRYPTIK_ROOT}"
        err "  ${IN_SOURCES}                <- ${KRYPTIK_SOURCES}"
        err "  ${IN_WORK}/{.stamps,logs,build,images,keys/release}  <- ${KRYPTIK_WORK}/"
        return 1
    fi

    # No nested view of the sysroot (see WORK_SUBDIRS).
    if in_chroot /bin/bash -c "[ -e ${IN_WORK}/sysroot ]" 2>/dev/null; then
        err "${IN_WORK}/sysroot exists inside the chroot."
        err "That is the chroot's own root seen a second time, and it is how a"
        err "stage ends up installing into a nested target tree. Refusing."
        return 1
    fi
    ok "no nested view of the sysroot inside the chroot"

    # The chroot's bash must be ours. Compare the pinned version, not the
    # triple, which becomes x86_64-pc-linux-gnu once stage 04 rebuilds bash.
    local ver
    ver="$(in_chroot /bin/bash --version 2>/dev/null || true)"
    ver="${ver%%$'\n'*}"
    if [[ "$ver" == *"version ${V_BASH}"* ]]; then
        ok "chroot bash is the one Kryptik built (${V_BASH}): ${ver}"
        if [[ "$ver" == *"kryptik"* ]]; then
            dim "  still carrying stage 02's cross-build triple"
        else
            dim "  native triple - stage 04 has rebuilt bash, which is expected"
        fi
    else
        err "chroot bash is not Kryptik's pinned ${V_BASH}: ${ver:-unknown}"
        err "The chroot may be reaching host binaries; stage 04 would build against them."
        return 1
    fi

    # Should be the native target gcc: a warning here, a refusal in stage 05.
    local triple
    triple="$(in_chroot /bin/bash -c 'gcc -dumpmachine' 2>/dev/null || true)"
    if [[ "$triple" == *"-kryptik-linux-gnu" ]]; then
        ok "chroot gcc targets ${triple}"
    else
        warn "chroot gcc -dumpmachine reports '${triple:-nothing}', not a kryptik triple"
        warn "Stage 04 will build against it anyway; stage 05 refuses to."
    fi
}

# Mount, run one command inside, always unmount (`make system`, `make kernel`).
run_in_chroot() {
    [[ "$#" -ge 1 ]] || die "run needs a command to execute inside the chroot"

    # Unmount on every exit, or a cancelled build leaves the host's /dev bound
    # in the sysroot for the next rm -rf to delete.
    trap 'umount_virtual || true' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    create_layout
    create_passwd_group
    create_devices
    create_chroot_marker
    mount_virtual
    verify_chroot

    log "running inside chroot: $*"
    echo
    # As in step(): the ERR trap fires even under set +e, and it exits.
    local rc=0
    set +e
    trap - ERR
    in_chroot /bin/bash -c 'exec "$@"' kryptik-chroot "$@"
    rc=$?
    trap _kryptik_trap ERR
    set -e
    echo

    if [[ "$rc" -eq 0 ]]; then
        ok "chroot command finished: $*"
    else
        err "chroot command failed (exit ${rc}): $*"
    fi
    return "$rc"
}

case "$ACTION" in
    mount)
        need_root; need_sysroot
        create_layout
        create_passwd_group
        create_devices
        create_chroot_marker
        mount_virtual
        verify_chroot
        echo
        ok "chroot ready at ${LFS}"
        echo
        dim "Build the base system with:  make system"
        dim "Build the kernel with:       make kernel"
        dim "Or interactively:            sudo $0 enter"
        dim "Unmount with:                sudo $0 umount"
        ;;
    umount)
        need_root
        umount_virtual
        ;;
    enter)
        need_root; need_sysroot
        mount_virtual
        enter_chroot
        ;;
    verify)
        need_root; need_sysroot
        verify_chroot
        ;;
    run)
        need_root; need_sysroot
        shift
        run_in_chroot "$@"
        ;;
    status)
        mount_status
        ;;
    guard-unmounted)
        # Unprivileged: `make clean` runs it before deleting the work tree.
        if mounts_active; then
            err "there are still active mounts under ${LFS}:"
            mount_status >&2
            die "unmount first:  sudo $0 umount"
        fi
        ;;
    *)
        die "unknown action ${ACTION:?}
expected: mount, umount, enter, verify, run, status, guard-unmounted"
        ;;
esac
