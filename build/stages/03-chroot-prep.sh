#!/usr/bin/env bash
# Stage 03 — Chroot preparation (docs/roadmap.md, Base system)
#
# Turns the stage 02 sysroot into something that can be chrooted into: the full
# FHS directory layout, the essential device nodes, /etc/passwd and /etc/group,
# and the virtual filesystem mounts.
#
# The privileged actions REQUIRE ROOT. Creating device nodes and bind-mounting
# /dev needs real privilege; this is the one stage that does, and it escalates
# explicitly here rather than the whole build running as root.
#
#   sudo ./03-chroot-prep.sh mount            prepare layout and mount virtual fs
#   sudo ./03-chroot-prep.sh umount           unmount cleanly
#   sudo ./03-chroot-prep.sh enter            drop into the chroot interactively
#   sudo ./03-chroot-prep.sh run CMD [ARG..]  mount, run CMD inside, unmount
#
# and two that do not need privilege, because `make clean` has to be able to
# ask them:
#
#   ./03-chroot-prep.sh status            report what is currently mounted
#   ./03-chroot-prep.sh guard-unmounted   exit non-zero if anything is mounted
#
# `run` is what `make system` and `make kernel` drive. It is the only place in
# the build where a privileged command executes a build stage, and it always
# unmounts again - on success, on failure, and on interrupt.

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

require_outside_chroot "stage 03"

export LFS="$KRYPTIK_SYSROOT"
ACTION="${1:-mount}"

# Inside the chroot these are the fixed paths the build contract uses. The
# repository, the source tarballs and the work tree all live outside the
# sysroot and are bind-mounted in at these names.
IN_ROOT="/kryptik"
IN_SOURCES="/kryptik-sources"
IN_WORK="/kryptik-work"
# A single file, not a directory: the kryptikd binary built outside.
IN_KRYPTIKD="/kryptik-kryptikd"
IN_WLPROXY="/kryptik-wlproxy"

# The work tree is bind-mounted SUBDIRECTORY BY SUBDIRECTORY, deliberately.
#
# $KRYPTIK_WORK contains sysroot/, and sysroot/ is the chroot's own root. Bind
# the whole of $KRYPTIK_WORK to /kryptik-work and the chroot gains a complete
# second view of itself at /kryptik-work/sysroot - so any stage that still
# computes "${KRYPTIK_WORK}/sysroot" as an install destination silently writes
# into a nested tree instead of failing. Exposing only the four directories
# the in-chroot stages actually need (stage 06 binds the kernels to their
# command lines under images/; stage 04 makes the release signing key under
# keys/release, which stage 06 signs payloads with) means that path does not exist, and the
# mistake stops being invisible. verify_chroot asserts it.
WORK_SUBDIRS=(.stamps logs build images keys/release)

# common.sh refuses to run as root by default; this stage is the exception for
# its privileged actions, and says so rather than quietly working around the
# guard.
need_root() {
    [[ "${EUID}" -eq 0 ]] || die "stage 03 '${ACTION}' must run as root.

Creating device nodes and bind-mounting /dev requires real privilege. This is
the only stage that does - stages 01 and 02 build unprivileged, and 04 and 05
run as root only INSIDE the chroot, where root owns nothing outside the
sysroot.

  sudo $0 ${ACTION}"
}

# Checked lazily: `status` and `guard-unmounted` must work on a half-built or
# already-cleaned tree, which is exactly when `make clean` asks.
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

    # Kryptik-specific. The zone definitions themselves go to the verified
    # /usr/lib/kryptik/zones (stage 04, s_kryptikd), which links this in.
    install -dv -m 0755 "$LFS/etc/kryptik"

    # Mount points for the three trees that live outside the sysroot: the
    # repository (scripts and config), the source tarballs, and the work tree
    # (stamps, logs, unpacked build trees).
    install -dv -m 0755 "$LFS$IN_ROOT"
    install -dv -m 0755 "$LFS$IN_SOURCES"
    install -dv -m 0755 "$LFS$IN_WORK"
    local d
    for d in "${WORK_SUBDIRS[@]}"; do
        install -dv -m 0755 "${LFS}${IN_WORK}/${d}"
        install -dv -m 0755 "${KRYPTIK_WORK}/${d}"
    done
}

# Stages 04 and 05 refuse to run outside the chroot, and this marker is how
# they tell. A file rather than an environment variable: env vars survive into
# a plain shell and would let a stage believe it is chrooted when it is not,
# which is precisely the mistake the check exists to prevent.
create_chroot_marker() {
    printf 'Created by stage 03 on %s\nsysroot: %s\n' "$(date -Iseconds)" "$LFS" \
        > "$LFS/etc/kryptik/inside-chroot"
    chmod 0644 "$LFS/etc/kryptik/inside-chroot"
}

# --- essential files --------------------------------------------------------

create_passwd_group() {
    # Once. These are the accounts the chroot needs before shadow exists;
    # after that, stage 04 adds the groups and users the running system needs
    # (seat, kryptik, dhcpcd, ...) with groupadd and useradd, and every later
    # entry into the chroot - the kernel stage, the media stage's kernel
    # bind, a test - must leave them alone. Rewriting the files on every
    # entry is how the first media shipped a system in which seatd and the
    # launch daemon could not find their groups.
    if [[ -s "$LFS/etc/passwd" && -s "$LFS/etc/group" ]]; then
        log "keeping /etc/passwd and /etc/group (already present)"
        return 0
    fi
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

# Every path this stage mounts, relative to $LFS, outermost first.
# umount_virtual walks it in reverse and mounts_active answers "is anything
# still mounted" from the same list, so the two cannot drift apart.
mount_list() {
    local d
    for d in "${WORK_SUBDIRS[@]}"; do printf '%s\n' "${IN_WORK}/${d}"; done
    printf '%s\n' \
        "$IN_ROOT" \
        "$IN_SOURCES" \
        "$IN_KRYPTIKD" \
        "$IN_WLPROXY" \
        "/dev/pts" \
        "/dev/shm" \
        "/dev" \
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

# A bind mount SILENTLY IGNORES -o nodev,nosuid,ro on the initial call - it
# inherits the source's flags - so passing them there produces a mount that
# looks hardened on the command line and is not. They only take effect on a
# subsequent remount, so every bind here is two calls, not one.
bind_hardened() {
    local src="$1" dst="$2" opts="$3"
    mountpoint -q "$dst" && return 0
    mount -v --bind "$src" "$dst"
    mount -v -o "remount,bind,${opts}" "$dst"
}

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

    # The repository itself, so stages 04 and 05 can reach their scripts and
    # their config. Bind rather than copy, and read-only: nothing in the build
    # writes to the checkout, and a build that tries to should fail.
    bind_hardened "$KRYPTIK_ROOT" "$LFS$IN_ROOT" "nodev,nosuid,ro"

    # The source tarballs, read-only. Separate from the repository because
    # KRYPTIK_SOURCES can point anywhere - 600MB of tarballs frequently live
    # on different storage from the checkout, and in this build they must,
    # because the checkout may be on a filesystem that does not preserve
    # POSIX ownership.
    bind_hardened "$KRYPTIK_SOURCES" "$LFS$IN_SOURCES" "nodev,nosuid,ro"

    # Stamps, logs and unpacked build trees. Writable; see WORK_SUBDIRS above
    # for why these are bound one at a time rather than as one tree.
    local d
    for d in "${WORK_SUBDIRS[@]}"; do
        bind_hardened "${KRYPTIK_WORK}/${d}" "${LFS}${IN_WORK}/${d}" "nodev,nosuid"
    done

    # kryptikd is Rust, built outside the chroot because the sysroot has no
    # Rust toolchain. Bind the binary in read-only so stage 04 can install
    # it; copying would put a host path in the build and leave a stale copy
    # behind on the next run.
    if [[ -n "${KRYPTIK_KRYPTIKD_BIN:-}" ]]; then
        if [[ -f "$KRYPTIK_KRYPTIKD_BIN" ]]; then
            : > "${LFS}${IN_KRYPTIKD}"
            bind_hardened "$KRYPTIK_KRYPTIKD_BIN" "${LFS}${IN_KRYPTIKD}" "nodev,nosuid,ro"
        else
            die "KRYPTIK_KRYPTIKD_BIN=${KRYPTIK_KRYPTIKD_BIN} does not exist"
        fi
    fi
    # The per-zone Wayland proxy, the same way and for the same reason.
    if [[ -n "${KRYPTIK_WLPROXY_BIN:-}" ]]; then
        if [[ -f "$KRYPTIK_WLPROXY_BIN" ]]; then
            : > "${LFS}${IN_WLPROXY}"
            bind_hardened "$KRYPTIK_WLPROXY_BIN" "${LFS}${IN_WLPROXY}" "nodev,nosuid,ro"
        else
            die "KRYPTIK_WLPROXY_BIN=${KRYPTIK_WLPROXY_BIN} does not exist"
        fi
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

# The environment inside the chroot IS the build contract. Every path a stage
# needs to locate is named here and nowhere else.
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

# PATH deliberately excludes the host: if a build reaches a host binary the
# chroot has failed and we want it to fail loudly, not silently succeed.
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

    # Stages 04 and 05 need the repository, the sources and the work tree
    # visible from inside, at the paths the contract names.
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

    # The work tree must NOT expose a nested sysroot. See WORK_SUBDIRS.
    if in_chroot /bin/bash -c "[ -e ${IN_WORK}/sysroot ]" 2>/dev/null; then
        err "${IN_WORK}/sysroot exists inside the chroot."
        err "That is the chroot's own root seen a second time, and it is how a"
        err "stage ends up installing into a nested target tree. Refusing."
        return 1
    fi
    ok "no nested view of the sysroot inside the chroot"

    # The chroot's bash must be OURS, not the host's.
    #
    # Two earlier versions of this check were wrong, in two different ways,
    # and the second way is worth keeping written down because it only
    # appeared once the build got far enough to trip it.
    #
    # First: $BASH_VERSION carries only "5.2.32(1)-release". The build triple
    # appears only in `bash --version`, so grepping the former for "kryptik"
    # always failed and warned on a perfectly good chroot.
    #
    # Then: grepping the latter for "kryptik" worked - right up until stage 04
    # rebuilt bash. Stage 02 cross-compiles it with
    # --host=x86_64-kryptik-linux-gnu, which stamps that triple into the
    # version string. Stage 04 rebuilds it natively, and config.guess then
    # reports x86_64-pc-linux-gnu, correctly, because that IS the build system
    # now. The triple was never evidence of whose bash this is; it only ever
    # recorded which stage built it last. The check failed on the correct
    # chroot it was meant to protect, and would have blocked stage 05 too.
    #
    # What actually discriminates is the VERSION. This host runs bash 5.2.21;
    # Kryptik pins 5.2.32. A chroot reaching a host binary reports the host's
    # version, and a sysroot that never got its own bash cannot report ours at
    # all.
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

    # And its compiler must be the NATIVE TARGET compiler - not a cross
    # compiler, not the host's. Checking here means a broken toolchain
    # surfaces before four hours of stage 04, not after. Stage 05 checks it
    # again and refuses, because the kernel is where it matters most.
    local triple
    triple="$(in_chroot /bin/bash -c 'gcc -dumpmachine' 2>/dev/null || true)"
    if [[ "$triple" == *"-kryptik-linux-gnu" ]]; then
        ok "chroot gcc targets ${triple}"
    else
        warn "chroot gcc -dumpmachine reports '${triple:-nothing}', not a kryptik triple"
        warn "Stage 04 will build against it anyway; stage 05 refuses to."
    fi
}

# mount, run one command inside, always unmount. This is what `make system`
# and `make kernel` drive: the privileged surface is exactly the mounts and
# this one chroot call, and the build stage itself is ordinary code running in
# a tree that root owns anyway.
run_in_chroot() {
    [[ "$#" -ge 1 ]] || die "run needs a command to execute inside the chroot"

    # Unmount on every exit path, including SIGINT and SIGTERM. Without this a
    # cancelled build leaves /dev bind-mounted inside the sysroot, and the next
    # thing to rm -rf that tree takes the host's /dev with it.
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
    # Same as step(): `set +e` does not stop the ERR trap, and the trap
    # exits. Without disarming it, "chroot command failed (exit N)" below was
    # never printed - the unmount still happened, via the EXIT trap, so the
    # damage was limited to losing the message.
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
        # Unprivileged on purpose: `make clean` calls this before removing the
        # work tree. Deleting a directory that still has /dev bind-mounted
        # into it is how a build system eats its host.
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
