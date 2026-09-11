#!/usr/bin/env bash
# Build a bootable initramfs for the Kryptik developer VM.
#
# WHAT THIS IS FOR
#
# The zone launcher can only be trusted once it has run somewhere other than
# the developer's WSL host: WSL2 runs a Microsoft kernel with its own patches,
# and "isolation works here" is not the same claim as "isolation works on the
# kernel Kryptik ships". This builds the smallest image that can answer the
# second question - a kernel, an init, a console, and kryptikd - so the real
# launcher suite can be run inside a VM rather than only beside one.
#
# WHY IT SWITCH_ROOTS ONTO A TMPFS
#
# This is not an optimisation and removing it breaks the whole point of the
# image. pivot_root(2) REFUSES to operate when the current root is the initial
# ramdisk - the kernel returns EINVAL for rootfs, by design. kryptikd's zone
# setup is built on pivot_root (rootfs.rs::pivot_into), so in an
# initramfs-only boot every single zone start fails with
# "could not build the zone root", and the launcher suite would report a
# uniform failure that says nothing about the launcher.
#
# So /init copies the image onto a tmpfs and switch_roots into it. After that
# / is an ordinary tmpfs mount, pivot_root works, and the suite is testing
# kryptikd rather than an initramfs restriction.
#
# WHAT IS IN THE IMAGE, AND WHERE IT CAME FROM
#
# Today the userspace is assembled from the HOST's binaries plus packages
# unpacked from the signed Ubuntu archive. That is deliberate and temporary:
# it makes the VM harness testable before stage 04 produces a Kryptik sysroot.
# It also means this image is NOT a Kryptik system and must never be described
# as one. When stage 04 lands, pass --sysroot DIR and the host userspace is
# replaced wholesale; see tools/vm/README.md.

set -euo pipefail

die() { printf 'mkinitramfs: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*" >&2; }

OUT=""
KRYPTIKD=""
SYSROOT=""
S6ROOT=""
ZONES=""

usage() {
    cat <<'EOF'
usage: mkinitramfs.sh --out FILE --kryptikd BIN --s6root DIR [--sysroot DIR] [--zones DIR]

  --out FILE      where to write the initramfs (cpio.gz)
  --kryptikd BIN  the kryptikd binary to install at /usr/bin/kryptikd.
                  Build it statically (--target x86_64-unknown-linux-musl) or
                  its dynamic dependencies must exist in the image.
  --s6root DIR    a tree containing the s6 stack and busybox, as unpacked
                  from distribution packages (usr/bin/s6-svscan, usr/bin/busybox)
  --sysroot DIR   OPTIONAL. A Kryptik sysroot to use as the image userspace
                  instead of the host's binaries. This is the flag that turns
                  the harness from "a VM" into "a Kryptik VM"; until stage 04
                  produces one, leaving it off is honest and leaving it on a
                  half-built tree is not.
  --zones DIR     zone definitions to install at /etc/kryptik/zones
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --kryptikd) KRYPTIKD="$2"; shift 2 ;;
        --s6root) S6ROOT="$2"; shift 2 ;;
        --sysroot) SYSROOT="$2"; shift 2 ;;
        --zones) ZONES="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$OUT" ]]      || { usage; die "--out is required"; }
[[ -n "$KRYPTIKD" ]] || { usage; die "--kryptikd is required"; }
[[ -n "$S6ROOT" ]]   || { usage; die "--s6root is required"; }
[[ -x "$KRYPTIKD" ]] || die "$KRYPTIKD is not executable"
[[ -x "$S6ROOT/usr/bin/s6-svscan" ]] || die "$S6ROOT/usr/bin/s6-svscan not found"
[[ -x "$S6ROOT/usr/bin/busybox" ]]   || die "$S6ROOT/usr/bin/busybox not found"

command -v cpio >/dev/null || die "cpio is required"
command -v gzip >/dev/null || die "gzip is required"

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

note "staging in $ROOT"

mkdir -p "$ROOT"/{bin,sbin,usr/bin,usr/sbin,lib,lib64,etc,proc,sys,dev,run,tmp,root,var/lib/kryptik/zones,newroot}
chmod 1777 "$ROOT/tmp"

# --- busybox, and a symlink for every applet it provides --------------------
install -m 0755 "$S6ROOT/usr/bin/busybox" "$ROOT/bin/busybox"
# Ask busybox itself rather than hardcoding a list: the applet set differs
# between builds, and a missing symlink shows up as a confusing "not found"
# in the middle of a boot rather than as an error here.
while read -r applet; do
    [[ -n "$applet" ]] || continue
    # `busybox --list` INCLUDES "busybox". Linking that name replaces the real
    # binary with a symlink to itself, and every applet - including /bin/sh -
    # then fails with ELOOP. The kernel reports this as
    #   "/init exists but couldn't execute it (error -40)"
    # followed by "No working init found", which names the init and says
    # nothing about the symlink that caused it. Cost an entire boot to find.
    [[ "$applet" == "busybox" ]] && continue
    ln -sf /bin/busybox "$ROOT/bin/$applet" 2>/dev/null || true
done < <("$S6ROOT/usr/bin/busybox" --list 2>/dev/null)

# Assert the thing that went wrong, rather than trusting the guard above.
[[ -f "$ROOT/bin/busybox" && ! -L "$ROOT/bin/busybox" ]] \
    || die "/bin/busybox is not a real file in the image; every applet would ELOOP"
[[ -L "$ROOT/bin/sh" ]] || die "/bin/sh applet symlink missing from the image"
note "busybox: $(find "$ROOT/bin" -type l | wc -l) applet symlinks"

# --- the s6 stack -----------------------------------------------------------
for d in usr/bin usr/lib; do
    [[ -d "$S6ROOT/$d" ]] || continue
    mkdir -p "$ROOT/$d"
    cp -a "$S6ROOT/$d/." "$ROOT/$d/"
done
[[ -x "$ROOT/usr/bin/s6-svscan" ]] || die "s6-svscan did not make it into the image"

# --- kryptikd ---------------------------------------------------------------
install -m 0755 "$KRYPTIKD" "$ROOT/usr/bin/kryptikd"
if ldd "$ROOT/usr/bin/kryptikd" 2>&1 | grep -q 'not a dynamic executable\|statically linked'; then
    note "kryptikd: static ($(stat -c %s "$ROOT/usr/bin/kryptikd") bytes)"
else
    note "kryptikd: DYNAMIC - its libraries must be in the image"
fi

# --- userspace: a Kryptik sysroot if we have one, the host's if we do not ---
HOST_BINS=(
    /bin/bash /bin/sh
    /usr/bin/env /usr/bin/id /usr/bin/tr /usr/bin/sed /usr/bin/awk
    /usr/bin/grep /usr/bin/cut /usr/bin/sort /usr/bin/head /usr/bin/tail
    /usr/bin/wc /usr/bin/cat /usr/bin/ls /usr/bin/mktemp /usr/bin/timeout
    /usr/bin/sleep /usr/bin/date /usr/bin/stat /usr/bin/readlink /usr/bin/dirname
    /usr/bin/basename /usr/bin/touch /usr/bin/chmod /usr/bin/cp /usr/bin/rm
    /usr/bin/mkdir /usr/bin/printf /usr/bin/echo /usr/bin/true /usr/bin/false
    /usr/bin/pgrep /usr/bin/kill /usr/bin/find /usr/bin/xargs /usr/bin/tee
    /usr/bin/mknod /usr/bin/unshare /usr/bin/mount /usr/sbin/chroot
)

copy_with_libs() { # src dest-root
    local src="$1" root="$2" dest
    [[ -e "$src" ]] || return 0
    dest="$root${src}"
    mkdir -p "$(dirname "$dest")"
    cp -aL "$src" "$dest" 2>/dev/null || return 0
    # Resolve the library closure. Without this a binary copies fine and then
    # fails at boot with "No such file or directory", which names the binary
    # rather than the missing library and sends you looking in the wrong place.
    local lib
    while read -r lib; do
        [[ -n "$lib" && -e "$lib" ]] || continue
        local ldest="$root${lib}"
        [[ -e "$ldest" ]] && continue
        mkdir -p "$(dirname "$ldest")"
        cp -aL "$lib" "$ldest" 2>/dev/null || true
    done < <(ldd "$src" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}')
}

if [[ -n "$SYSROOT" ]]; then
    [[ -d "$SYSROOT" ]] || die "--sysroot $SYSROOT is not a directory"
    note "userspace: Kryptik sysroot $SYSROOT"
    for d in bin sbin usr lib lib64 etc; do
        [[ -d "$SYSROOT/$d" ]] && cp -a "$SYSROOT/$d/." "$ROOT/$d/" 2>/dev/null || true
    done
    printf 'kryptik-sysroot\n' > "$ROOT/etc/kryptik-userspace-origin"
else
    note "userspace: HOST binaries (this image is NOT a Kryptik system)"
    for b in "${HOST_BINS[@]}"; do copy_with_libs "$b" "$ROOT"; done
    # s6 and the copied host binaries are dynamically linked against glibc.
    for lib in "$S6ROOT"/usr/lib/x86_64-linux-gnu/*; do
        [[ -e "$lib" ]] || continue
        mkdir -p "$ROOT/usr/lib/x86_64-linux-gnu"
        cp -aL "$lib" "$ROOT/usr/lib/x86_64-linux-gnu/" 2>/dev/null || true
    done
    for s6bin in "$ROOT"/usr/bin/s6-* "$ROOT"/usr/bin/execline* ; do
        [[ -x "$s6bin" ]] || continue
        while read -r lib; do
            [[ -n "$lib" && -e "$lib" ]] || continue
            [[ -e "$ROOT$lib" ]] && continue
            mkdir -p "$(dirname "$ROOT$lib")"
            cp -aL "$lib" "$ROOT$lib" 2>/dev/null || true
        done < <(ldd "$s6bin" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}')
    done
    printf 'host-binaries\n' > "$ROOT/etc/kryptik-userspace-origin"
fi

# The dynamic loader must exist at the exact path the ELF headers name.
for interp in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-x86-64.so.2; do
    if [[ -e "$interp" && ! -e "$ROOT$interp" ]]; then
        mkdir -p "$(dirname "$ROOT$interp")"
        cp -aL "$interp" "$ROOT$interp"
    fi
done

# --- zone definitions -------------------------------------------------------
mkdir -p "$ROOT/etc/kryptik/zones"
if [[ -n "$ZONES" && -d "$ZONES" ]]; then
    cp -a "$ZONES/." "$ROOT/etc/kryptik/zones/"
    note "zones: $(find "$ROOT/etc/kryptik/zones" -name '*.toml' | wc -l) definition(s)"
fi

# --- minimal /etc -----------------------------------------------------------
printf 'root:x:0:0:root:/root:/bin/bash\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\n'                       > "$ROOT/etc/group"
printf 'kryptik-vm\n'                      > "$ROOT/etc/hostname"
printf '127.0.0.1 localhost kryptik-vm\n'  > "$ROOT/etc/hosts"

# --- stage 1 init: the switch_root ------------------------------------------
cat > "$ROOT/init" <<'INIT'
#!/bin/busybox sh
# Stage 1. Runs as PID 1 on the initial rootfs.
#
# Its only real job is to get OFF the initial rootfs, because pivot_root(2)
# returns EINVAL when the current root is rootfs and kryptikd's zone setup is
# built on pivot_root. Staying here would make every zone start fail for a
# reason that has nothing to do with kryptikd.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

/bin/busybox mount -t proc     proc     /proc
/bin/busybox mount -t sysfs    sysfs    /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev

echo "KRYPTIK_VM_STAGE1_OK"

/bin/busybox mkdir -p /newroot
if ! /bin/busybox mount -t tmpfs -o size=1500m,mode=0755 tmpfs /newroot; then
    echo "KRYPTIK_VM_FAIL stage1: could not mount the tmpfs root"
    exec /bin/busybox sh
fi

for d in bin sbin usr lib lib64 etc root var init2; do
    [ -e "/$d" ] && /bin/busybox cp -a "/$d" /newroot/ 2>/dev/null
done
/bin/busybox mkdir -p /newroot/proc /newroot/sys /newroot/dev /newroot/run \
                      /newroot/tmp /newroot/mnt
/bin/busybox chmod 1777 /newroot/tmp

if [ ! -x /newroot/init2 ]; then
    echo "KRYPTIK_VM_FAIL stage1: /init2 missing from the new root"
    exec /bin/busybox sh
fi

echo "KRYPTIK_VM_SWITCHROOT"
exec /bin/busybox switch_root /newroot /init2
INIT
chmod 0755 "$ROOT/init"

# --- stage 2 init: mounts, then s6 ------------------------------------------
cat > "$ROOT/init2" <<'INIT2'
#!/bin/busybox sh
# Stage 2. PID 1 on the real (tmpfs) root.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

/bin/busybox mount -t proc     proc     /proc
/bin/busybox mount -t sysfs    sysfs    /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /dev/pts /dev/shm /run /sys/fs/cgroup
/bin/busybox mount -t devpts devpts /dev/pts
# securityfs, so /sys/kernel/security/lsm can be read. Without it the smoke
# payload reports the LSM list as "unknown", which looks like a missing
# feature rather than an unmounted filesystem.
/bin/busybox mkdir -p /sys/kernel/security
/bin/busybox mount -t securityfs securityfs /sys/kernel/security 2>/dev/null
/bin/busybox mount -t tmpfs  tmpfs  /dev/shm
/bin/busybox mount -t tmpfs  tmpfs  /run
# cgroup v2, which kryptikd check probes for and the (not yet written) zone
# resource limits will need. The failure is REPORTED rather than swallowed:
# a silent 2>/dev/null here meant the guest came up without cgroup2 and the
# only evidence was an "UNKNOWN" filesystem type several lines later.
if /bin/busybox mount -t cgroup2 cgroup2 /sys/fs/cgroup; then
    echo "KRYPTIK_VM_CGROUP_MOUNT=ok"
else
    echo "KRYPTIK_VM_CGROUP_MOUNT=failed"
fi

/bin/busybox hostname kryptik-vm 2>/dev/null
/bin/busybox ip link set lo up 2>/dev/null || /bin/busybox ifconfig lo up 2>/dev/null

echo "KRYPTIK_VM_STAGE2_OK root=$(/bin/busybox stat -f -c %T / 2>/dev/null)"

# Mode comes from the kernel command line so one image serves both the
# automated smoke run and an interactive console.
MODE=smoke
for a in $(/bin/busybox cat /proc/cmdline); do
    case "$a" in kryptik.mode=*) MODE="${a#kryptik.mode=}" ;; esac
done
echo "KRYPTIK_VM_MODE=$MODE"

# Build the s6 scan directory. /run is a fresh tmpfs, so this is rebuilt every
# boot rather than shipped.
SVC=/run/service
/bin/busybox mkdir -p "$SVC"

if [ "$MODE" = "console" ]; then
    /bin/busybox mkdir -p "$SVC/getty"
    /bin/busybox cat > "$SVC/getty/run" <<'RUN'
#!/bin/busybox sh
exec /bin/busybox setsid -c /bin/bash -l </dev/ttyS0 >/dev/ttyS0 2>&1
RUN
    /bin/busybox chmod 0755 "$SVC/getty/run"
else
    /bin/busybox mkdir -p "$SVC/smoke"
    /bin/busybox cat > "$SVC/smoke/run" <<'RUN'
#!/bin/busybox sh
exec /usr/bin/kryptik-vm-smoke >/dev/ttyS0 2>&1
RUN
    /bin/busybox chmod 0755 "$SVC/smoke/run"
fi

echo "KRYPTIK_VM_S6_START"
# s6-svscan becomes PID 1 for the rest of the boot: it supervises the service
# directory and reaps orphans. s6-linux-init, the full PID-1 package, is not
# used here and this is not pretending to be it - see tools/vm/README.md.
exec /usr/bin/s6-svscan "$SVC"
INIT2
chmod 0755 "$ROOT/init2"

# --- the smoke payload ------------------------------------------------------
cat > "$ROOT/usr/bin/kryptik-vm-smoke" <<'SMOKE'
#!/bin/bash
# Runs once, under s6 supervision, on a smoke-mode boot. Prints sentinels the
# host-side harness greps for, then powers the machine off.
#
# Every sentinel is printed exactly once and the final one is printed last, so
# a truncated serial log cannot be mistaken for a pass.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

echo "KRYPTIK_VM_SMOKE_BEGIN"
echo "KRYPTIK_VM_KERNEL=$(uname -r)"
echo "KRYPTIK_VM_ARCH=$(uname -m)"
echo "KRYPTIK_VM_USERSPACE=$(cat /etc/kryptik-userspace-origin 2>/dev/null)"
echo "KRYPTIK_VM_UID=$(id -u)"
echo "KRYPTIK_VM_PID1=$(cat /proc/1/comm 2>/dev/null)"
echo "KRYPTIK_VM_ROOTFS=$(stat -f -c %T / 2>/dev/null)"

# Security features the zone model depends on, reported from inside the VM
# rather than assumed from the host.
# cgroup v2 is detected by the presence of cgroup.controllers, not by
# `stat -f -c %T`. busybox's stat does not know the cgroup2 magic number and
# prints UNKNOWN for a correctly mounted cgroup2 - reporting a missing security
# feature when the feature was there all along.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "KRYPTIK_VM_CGROUP2=v2"
    echo "KRYPTIK_VM_CGROUP_CONTROLLERS=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null | tr ' ' ',')"
else
    echo "KRYPTIK_VM_CGROUP2=absent"
fi

# seccomp: /proc/config.gz is usually absent. The Seccomp line in
# /proc/self/status only exists when CONFIG_SECCOMP is on, which is the fact
# being established.
if grep -q '^Seccomp:' /proc/self/status 2>/dev/null; then
    echo "KRYPTIK_VM_SECCOMP=supported"
else
    echo "KRYPTIK_VM_SECCOMP=absent"
fi

# securityfs MOUNTED, not merely present as a directory.
if [ -r /sys/kernel/security/lsm ]; then
    echo "KRYPTIK_VM_SECURITYFS=mounted"
    echo "KRYPTIK_VM_LSM=$(cat /sys/kernel/security/lsm 2>/dev/null)"
else
    echo "KRYPTIK_VM_SECURITYFS=not-mounted"
    echo "KRYPTIK_VM_LSM=unknown"
fi
echo "KRYPTIK_VM_LANDLOCK_ABI=$(/usr/bin/kryptikd check --zones /etc/kryptik/zones 2>/dev/null | sed -n 's/.*landlock *yes (ABI v\([0-9]*\)).*/\1/p' | head -1)"
echo "KRYPTIK_VM_USERNS_MAX=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)"

echo "KRYPTIK_VM_CHECK_BEGIN"
if /usr/bin/kryptikd check --zones /etc/kryptik/zones; then
    echo "KRYPTIK_VM_CHECK=pass"
else
    echo "KRYPTIK_VM_CHECK=fail"
fi
echo "KRYPTIK_VM_CHECK_END"

# The real launcher suite, inside the VM. This is the reason the image exists.
if [ -x /usr/lib/kryptik/compartments/tests/launcher.sh ]; then
    echo "KRYPTIK_VM_LAUNCHER_BEGIN"
    KRYPTIKD=/usr/bin/kryptikd KRYPTIK_TEST_TIMEOUT=60 \
        /usr/lib/kryptik/compartments/tests/launcher.sh
    rc=$?
    echo "KRYPTIK_VM_LAUNCHER_RC=$rc"
    echo "KRYPTIK_VM_LAUNCHER_END"
else
    echo "KRYPTIK_VM_LAUNCHER_RC=missing"
fi

if [ -x /usr/lib/kryptik/compartments/tests/adversarial.sh ]; then
    echo "KRYPTIK_VM_ADVERSARIAL_BEGIN"
    /usr/lib/kryptik/compartments/tests/adversarial.sh
    echo "KRYPTIK_VM_ADVERSARIAL_RC=$?"
    echo "KRYPTIK_VM_ADVERSARIAL_END"
fi

echo "KRYPTIK_VM_SMOKE_END"
sync
echo "KRYPTIK_VM_POWEROFF"
# RB_POWER_OFF via busybox; the harness treats a clean poweroff as part of the
# pass, because a VM that only ever panics is not a booted system.
/bin/busybox poweroff -f
SMOKE
chmod 0755 "$ROOT/usr/bin/kryptik-vm-smoke"

# --- the test suites go into the image --------------------------------------
# THE LAYOUT MATTERS. Both suites locate the repository as "$HERE/../..", so
# they must sit at <prefix>/compartments/tests/ and not at <prefix>/tests/.
# Getting this wrong does not produce a path error: adversarial.sh simply
# reports "kryptikd binary not built" for every check that needs it and exits
# non-zero, which reads like a build failure rather than a layout mistake.
KTESTS="$ROOT/usr/lib/kryptik/compartments/tests"
mkdir -p "$KTESTS"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
for t in launcher.sh adversarial.sh; do
    if [[ -f "$REPO/compartments/tests/$t" ]]; then
        install -m 0755 "$REPO/compartments/tests/$t" "$KTESTS/$t"
    fi
done

mkdir -p "$ROOT/usr/lib/kryptik/compartments/kryptikd/target/debug"
ln -sf /usr/bin/kryptikd \
   "$ROOT/usr/lib/kryptik/compartments/kryptikd/target/debug/kryptikd" 2>/dev/null || true

# adversarial.sh cross-checks its namespace set against isolate.rs and skips
# that check when the source is absent. Shipping the one file turns a skipped
# consistency check into a real one.
mkdir -p "$ROOT/usr/lib/kryptik/compartments/kryptikd/src"
[[ -f "$REPO/compartments/kryptikd/src/isolate.rs" ]] && \
    install -m 0644 "$REPO/compartments/kryptikd/src/isolate.rs" \
        "$ROOT/usr/lib/kryptik/compartments/kryptikd/src/isolate.rs"

# The zone definitions the suites read from the repo layout.
mkdir -p "$ROOT/usr/lib/kryptik/compartments/zones"
[[ -n "$ZONES" && -d "$ZONES" ]] && cp -a "$ZONES/." "$ROOT/usr/lib/kryptik/compartments/zones/"

# --- pack -------------------------------------------------------------------
mkdir -p "$(dirname "$OUT")"
( cd "$ROOT" && find . -print0 | cpio --null -o --format=newc --quiet ) | gzip -9 > "$OUT"

note "wrote $OUT ($(stat -c %s "$OUT") bytes)"
note "sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
