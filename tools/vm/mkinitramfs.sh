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
AS_DISK=""
KRYPTIKD=""
SYSROOT=""
S6ROOT=""
ZONES=""

usage() {
    cat <<'EOF'
usage: mkinitramfs.sh --out FILE --kryptikd BIN --s6root DIR [--sysroot DIR] [--zones DIR]

  --out FILE      where to write the image
  --as-disk SIZE  write an ext4 ROOT FILESYSTEM of this size (e.g. 6G) instead
                  of a cpio.gz initramfs. Needed for a real Kryptik userspace:
                  an initramfs is unpacked into RAM, and the stage 04 sysroot is
                  3.6G, so it would need more memory than the machine has. The
                  staged tree is identical either way - only the packing and the
                  first three lines of /init differ.
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
        --as-disk) AS_DISK="$2"; shift 2 ;;
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

    # VERIFY, do not take the flag's word for it.
    #
    # This used to stamp the image "kryptik-sysroot" because --sysroot was
    # passed, full stop. An EMPTY directory therefore produced an image that
    # boot-smoke.sh reported as "a Kryptik userspace booted" - the exact false
    # claim this harness exists to prevent, made by the harness itself.
    #
    # WHAT COUNTS AS EVIDENCE, and why the first version of this was wrong.
    #
    # It looked for `x86_64-kryptik-linux-gnu` inside the sysroot's bash, on the
    # reasoning that a host bash says x86_64-pc-linux-gnu and a Kryptik one does
    # not. That held for a stage-02 sysroot, where bash is cross-compiled with
    # --host=x86_64-kryptik-linux-gnu, and it stopped holding the moment stage
    # 04 finished: the final bash is built natively INSIDE the sysroot, where
    # config.guess correctly reports x86_64-pc-linux-gnu, because that is the
    # build system now. So this check refused the first real, complete Kryptik
    # userspace the build tab produced.
    #
    # The build tab hit the identical bug in their own chroot check and wrote
    # the lesson down: "the triple was never evidence of whose bash this is. It
    # recorded which stage built it last."
    #
    # So: two kinds of evidence, and at least one MEASURED kind is required.
    #   - a binary from the sysroot, run, reporting a Kryptik target: the
    #     sysroot's own gcc -dumpmachine, or a cross-built shell's embedded
    #     triple. This cannot be faked by editing a file.
    #   - /etc/os-release saying ID=kryptik. Corroboration only, and never
    #     sufficient on its own: it is a text file, and anyone can write one.
    sysroot_shell=""
    for cand in usr/bin/bash bin/bash usr/bin/sh bin/sh; do
        if [[ -f "$SYSROOT/$cand" ]]; then sysroot_shell="$SYSROOT/$cand"; break; fi
    done
    [[ -n "$sysroot_shell" ]] || die \
        "--sysroot $SYSROOT has no shell at usr/bin/bash, bin/bash, usr/bin/sh or bin/sh.
 That is not a userspace this image can boot, and stamping it as one would make
 boot-smoke.sh report a Kryptik boot that did not happen."

    sysroot_evidence=()
    sysroot_measured=0

    # 1. The sysroot's own compiler, asked what it targets. A stage-04 sysroot
    #    contains the target gcc; running it is a behaviour, not a string.
    for gcc_cand in usr/bin/gcc bin/gcc; do
        [[ -x "$SYSROOT/$gcc_cand" ]] || continue
        gcc_triple="$("$SYSROOT/$gcc_cand" -dumpmachine 2>/dev/null || true)"
        if [[ "$gcc_triple" == *-kryptik-linux-* ]]; then
            sysroot_evidence+=("$gcc_cand -dumpmachine = $gcc_triple")
            sysroot_measured=1
        fi
        break
    done

    # 2. A cross-built shell still carries the triple it was configured with.
    #    NOT `|| echo unknown` on the pipeline: `grep -m1` exits non-zero when
    #    `strings` is killed by SIGPIPE after the match, so a fallback there
    #    fired even on success and printed "x86_64-pc-linux-gnu\nunknown".
    sysroot_triple="$(strings -a "$sysroot_shell" 2>/dev/null \
                      | grep -m1 -o '[a-z0-9_]*-kryptik-linux-[a-z]*' || true)"
    if [[ -n "$sysroot_triple" ]]; then
        sysroot_evidence+=("${sysroot_shell#"$SYSROOT"/} carries $sysroot_triple")
        sysroot_measured=1
    fi

    # 3. Corroboration.
    sysroot_id=""
    if [[ -f "$SYSROOT/etc/os-release" ]]; then
        sysroot_id="$(sed -n 's/^ID=//p' "$SYSROOT/etc/os-release" | tr -d '"')"
        sysroot_build="$(sed -n 's/^BUILD_ID=//p' "$SYSROOT/etc/os-release" | tr -d '"')"
        [[ "$sysroot_id" == "kryptik" ]] && \
            sysroot_evidence+=("etc/os-release ID=kryptik BUILD_ID=${sysroot_build:-none}")
    fi

    if (( sysroot_measured == 0 )); then
        host_triple="$(strings -a "$sysroot_shell" 2>/dev/null \
                       | grep -m1 -o '[a-z0-9_]*-[a-z]*-linux-[a-z]*' || true)"
        [[ -n "$host_triple" ]] || host_triple="none found"
        die "--sysroot $SYSROOT does not look like a Kryptik userspace.
 Nothing in it, when RUN, reports a Kryptik target: its shell ($sysroot_shell)
 carries '$host_triple', and there is no gcc there that targets
 *-kryptik-linux-*.${sysroot_id:+
 (etc/os-release says ID=$sysroot_id, but that is a text file and not evidence
 on its own.)}
 Refusing rather than producing an image that would be reported as a Kryptik
 boot. Pass a sysroot built by stage 04, or leave --sysroot off and the image
 will honestly say it uses host binaries."
    fi

    note "userspace: Kryptik sysroot $SYSROOT"
    for e in "${sysroot_evidence[@]}"; do note "  verified: $e"; done
    for d in bin sbin usr lib lib64 etc; do
        [[ -d "$SYSROOT/$d" ]] && cp -a "$SYSROOT/$d/." "$ROOT/$d/" 2>/dev/null || true
    done

    # AFTER the copy, not before it. The sysroot ships its own
    # /usr/bin/kryptikd - stage 04 installs one - and the loop above has just
    # written it over the binary this image exists to test. Placing this
    # reinstall before the copy, as the first attempt did, changes nothing at
    # all: the copy still wins, and the image still boots stage 04's kryptikd.
    #
    # It is not a theoretical objection. Two boots from a real sysroot failed
    # 105 checks each with
    #     kryptikd: unknown key "storage.size"
    # because stage 04's copy predates the ephemeral-storage work - a perfect
    # Kryptik userspace in which every single zone failed to start.
    #
    # Both hashes go in the stamp, so the substitution is visible to whoever
    # reads the image rather than being something they have to know.
    if [[ -f "$SYSROOT/usr/bin/kryptikd" ]]; then
        SYSROOT_KRYPTIKD="$(sha256sum "$SYSROOT/usr/bin/kryptikd" | cut -d" " -f1)"
        note "  the sysroot ships its own kryptikd (${SYSROOT_KRYPTIKD:0:12}...); the one under test overrides it"
    fi
    install -m 0755 "$KRYPTIKD" "$ROOT/usr/bin/kryptikd"
    # The stamp records what was MEASURED, not what was requested, so anything
    # reading it later is reading evidence. The shell's hash pins which build.
    {
        printf 'kryptik-sysroot\n'
        # Every line here is something that was measured, so a reader of this
        # stamp is reading evidence rather than a claim. The shell's hash pins
        # which build it was.
        for e in "${sysroot_evidence[@]}"; do printf 'evidence %s\n' "$e"; done
        printf 'shell %s\n' "$(sha256sum "$sysroot_shell" | cut -d" " -f1)"
        printf 'kryptikd-under-test %s\n' "$(sha256sum "$KRYPTIKD" | cut -d' ' -f1)"
        [[ -n "${SYSROOT_KRYPTIKD:-}" ]] && \
            printf 'kryptikd-in-sysroot-overridden %s\n' "$SYSROOT_KRYPTIKD"
        printf 'shell-version %s\n' \
            "$("$sysroot_shell" --version 2>/dev/null | head -1 || echo unknown)"
    } > "$ROOT/etc/kryptik-userspace-origin"
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
    # The CA bundle. kryptikd binds /etc/ssl/certs read-only into every zone so
    # that TLS works there; without it in the image, the launcher check for
    # that passthrough fails against an image gap rather than against kryptikd.
    for ca in /etc/ssl/certs /usr/share/ca-certificates; do
        if [[ -d "$ca" ]]; then
            mkdir -p "$ROOT$ca"
            cp -aL "$ca/." "$ROOT$ca/" 2>/dev/null || true
        fi
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

    # The command a person types. Shipped next to kryptikd because an image
    # where the only interface is the daemon's argument list is an image nobody
    # can use, and because the VM should exercise what users will actually run
    # rather than a developer path they never see.
    if [[ -f "$REPO/tools/kryptik" ]]; then
        install -m 0755 "$REPO/tools/kryptik" "$ROOT/usr/bin/kryptik"
        cat > "$ROOT/etc/kryptik/kryptik.conf" <<'KCONF'
# Where `kryptik` looks for zone definitions and zone data.
# Read as DATA - this file is never sourced, so a line here cannot run a command.
zones_dir = /etc/kryptik/zones
rootfs    = /var/lib/kryptik/zones
uid_base  = 100000
KCONF
        chmod 0644 "$ROOT/etc/kryptik/kryptik.conf"
        note "kryptik: the user-facing command, with /etc/kryptik/kryptik.conf"
    fi
fi

# --- minimal /etc -----------------------------------------------------------
printf 'root:x:0:0:root:/root:/bin/bash\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\n'                       > "$ROOT/etc/group"
printf 'kryptik-vm\n'                      > "$ROOT/etc/hostname"
printf '127.0.0.1 localhost kryptik-vm\n'  > "$ROOT/etc/hosts"

# --- stage 1 init -----------------------------------------------------------
#
# Two versions, because the problem stage 1 solves only exists for an
# initramfs. pivot_root(2) returns EINVAL when the current root is the initial
# ramfs, and kryptikd's zone setup is built on pivot_root - so an initramfs
# image has to get off rootfs before any zone can start. A disk image is
# already on a real ext4 root, where pivot_root works, and copying it onto a
# tmpfs would defeat the entire point of putting it on a disk.
if [[ -n "$AS_DISK" ]]; then
cat > "$ROOT/init" <<'INIT'
#!/bin/busybox sh
# Stage 1, disk image. PID 1 on a real ext4 root mounted by the kernel from
# /dev/vda. No switch_root: we are already where the initramfs version spends
# its whole life trying to get to.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

/bin/busybox mount -t proc     proc     /proc
/bin/busybox mount -t sysfs    sysfs    /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev

echo "KRYPTIK_VM_STAGE1_OK"
echo "KRYPTIK_VM_T_STAGE1=$(/bin/busybox cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "KRYPTIK_VM_ROOTFS=disk"

if [ ! -x /init2 ]; then
    echo "KRYPTIK_VM_FAIL stage1: /init2 missing from the root filesystem"
    exec /bin/busybox sh
fi
exec /init2
INIT
else
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
echo "KRYPTIK_VM_T_STAGE1=$(/bin/busybox cut -d' ' -f1 /proc/uptime 2>/dev/null)"

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
fi
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
# Bring up any NIC the VM was given. With --nic none there is none and this is
# a no-op; with --nic user there is one, and the launcher suite's H1 positive
# control needs it UP to be a control at all - a down interface still appears
# in /proc/net/dev, but a zone that cannot see it has been shown nothing.
for _if in /sys/class/net/*; do
    _n="$(/bin/busybox basename "$_if")"
    [ "$_n" = "lo" ] && continue
    /bin/busybox ip link set "$_n" up 2>/dev/null
    /bin/busybox udhcpc -i "$_n" -t 2 -T 2 -n -q 2>/dev/null &
done

echo "KRYPTIK_VM_T_STAGE2=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "KRYPTIK_VM_STAGE2_OK root=$(/bin/busybox stat -f -c %T / 2>/dev/null)"

# Mode comes from the kernel command line so one image serves both the
# automated smoke run and an interactive console.
MODE=smoke
for a in $(/bin/busybox cat /proc/cmdline); do
    case "$a" in kryptik.mode=*) MODE="${a#kryptik.mode=}" ;; esac
done
echo "KRYPTIK_VM_MODE=$MODE"

# Restart mode. The question is whether this system comes back by itself after a
# reboot, and the only way to ask it is to reboot and see.
#
# The boot counter lives on the ROOT FILESYSTEM, not in /run, and that is the
# point: /run is a tmpfs and would be empty on the second boot whether the
# reboot worked or not, so a counter there would prove nothing. On disk it
# survives the reset and is discarded when QEMU exits, because the image is
# attached with -snapshot - so the run is repeatable and the artifact whose
# hash is the evidence is never written to.
if [ "$MODE" = "restart" ]; then
    # GUARD, and it is not optional: the boot counter has to survive the
    # reboot, and on an initramfs it cannot - the root is rebuilt from the cpio
    # every time, so every boot reads 1, reboots, and the VM loops until the
    # harness timeout kills it. Restart mode needs a disk image, and saying so
    # is better than a runaway guest.
    if [ "$(awk '$2=="/" {print $3; exit}' /proc/mounts 2>/dev/null)" = "tmpfs" ]; then
        echo "KRYPTIK_VM_RESTART_SKIP=needs-a-disk-image"
        echo "KRYPTIK_VM_RESTART_SKIP_WHY=the root is a tmpfs, so a boot counter cannot survive a reboot"
        MODE=smoke
    fi
fi

if [ "$MODE" = "restart" ]; then
    BOOTC=/var/lib/kryptik/boot-count
    mkdir -p /var/lib/kryptik
    n=0
    [ -f "$BOOTC" ] && n=$(cat "$BOOTC" 2>/dev/null)
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    n=$((n+1))
    echo "$n" > "$BOOTC"
    sync
    echo "KRYPTIK_VM_BOOT_NUMBER=$n"
    if [ "$n" -gt 2 ]; then
        # Belt as well as braces: even on a disk, one bad condition must not
        # produce an endless reboot loop.
        echo "KRYPTIK_VM_FAIL restart: boot $n - refusing to reboot again"
    elif [ "$n" -eq 1 ]; then
        # Prove the zone machinery works BEFORE the reboot, so a second boot
        # that comes up broken is distinguishable from one that never ran.
        if /usr/bin/kryptikd list --running >/dev/null 2>&1; then
            echo "KRYPTIK_VM_RESTART_PRE=ok"
        else
            echo "KRYPTIK_VM_RESTART_PRE=failed"
        fi
        echo "KRYPTIK_VM_REBOOTING"
        sync
        /bin/busybox reboot -f
        sleep 30
        echo "KRYPTIK_VM_FAIL restart: reboot did not take effect"
    else
        echo "KRYPTIK_VM_RESTART_SECOND_BOOT=ok"
        if /usr/bin/kryptikd list --running >/dev/null 2>&1; then
            echo "KRYPTIK_VM_RESTART_POST=ok"
        else
            echo "KRYPTIK_VM_RESTART_POST=failed"
        fi
        # A zone that actually runs after the restart, not just a daemon that
        # answers. This is the difference between "it booted" and "it works".
        #
        # `untrusted`, because it is a SHIPPED zone: the first version of this
        # named `alpha`, which is a fixture the launcher suite creates in its
        # own scratch directory and which no real system has - so it reported
        # "failed" about a restart that was fine. Of the six shipped zones,
        # four declare encrypted storage and are refused by design; `net` holds
        # the NIC; `untrusted` is the one an ordinary user would start.
        zout="$(/usr/bin/kryptik run untrusted -- /bin/sh -c 'echo ZONE_RAN_AFTER_RESTART' 2>&1)"
        case "$zout" in
            *ZONE_RAN_AFTER_RESTART*) echo "KRYPTIK_VM_RESTART_ZONE=ran" ;;
            *) echo "KRYPTIK_VM_RESTART_ZONE=failed"
               echo "KRYPTIK_VM_RESTART_ZONE_WHY=$(printf '%s' "$zout" | tr '\n' '|' | cut -c1-200)" ;;
        esac
    fi
fi

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

echo "KRYPTIK_VM_T_S6=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
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

echo "KRYPTIK_VM_T_PAYLOAD=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "KRYPTIK_VM_SMOKE_BEGIN"
echo "KRYPTIK_VM_KERNEL=$(uname -r)"
echo "KRYPTIK_VM_ARCH=$(uname -m)"
echo "KRYPTIK_VM_USERSPACE=$(head -1 /etc/kryptik-userspace-origin 2>/dev/null)"
# The stamp now holds one `evidence` line per thing that was measured at build
# time, replacing the single `triple` line this had gone on grepping for -
# reporting an empty string about an image carrying three pieces of evidence.
sed -n 's/^evidence /KRYPTIK_VM_USERSPACE_EVIDENCE=/p' /etc/kryptik-userspace-origin 2>/dev/null
echo "KRYPTIK_VM_USERSPACE_KRYPTIKD=$(sed -n 's/^kryptikd-under-test //p' /etc/kryptik-userspace-origin 2>/dev/null)"
# And the same question asked of the RUNNING system rather than of a stamp: a
# Kryptik userspace carries the target gcc, and its own compiler naming the
# target is a fact about what actually booted.
echo "KRYPTIK_VM_GCC_TRIPLE=$(gcc -dumpmachine 2>/dev/null)"
echo "KRYPTIK_VM_OSRELEASE_ID=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '\"')"
# Measured in the guest, from the shell the guest is actually running - not
# copied from what the image builder recorded. If these two ever disagree, the
# image was assembled from one tree and stamped from another.
echo "KRYPTIK_VM_SHELL_TRIPLE=$(strings -a /bin/sh 2>/dev/null | grep -m1 -o '[a-z0-9_]*-[a-z]*-linux-[a-z]*' || echo unknown)"
echo "KRYPTIK_VM_UID=$(id -u)"
echo "KRYPTIK_VM_PID1=$(cat /proc/1/comm 2>/dev/null)"
# From /proc/mounts, not `stat -f -c %T`: ext4 shares a magic number with ext2
# and ext3, so stat calls a Kryptik ext4 root "ext2/ext3" and the log then reads
# as though the image were something it is not.
echo "KRYPTIK_VM_ROOTFS=$(awk '$2=="/" {print $3; exit}' /proc/mounts 2>/dev/null)"

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
    # Idle cost, measured BEFORE the suites run - afterwards the numbers describe
# the tests rather than the system. MemAvailable rather than MemFree: free
# memory excludes reclaimable page cache and makes any Linux system look full.
echo "KRYPTIK_VM_MEM_TOTAL_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"
echo "KRYPTIK_VM_MEM_AVAIL_KB=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
echo "KRYPTIK_VM_PROCS=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
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

# The privileged launch contract (security Design 01 P1/P2/P7). On this stock
# kernel the restriction on unprivileged user namespaces is EMULATED with the
# AppArmor sysctl; the probe reports which knob it used, and the distinction
# must survive into the morning report - an emulated result is not target-kernel
# evidence.
if [ -x /usr/lib/kryptik/security/probes/vm-privileged-contract.sh ]; then
    echo "KRYPTIK_VM_PRIVCONTRACT_BEGIN"
    # The probe's contract: ZONES_DIR must contain a zone named "probe"
    # (routed, ephemeral) and a nic zone. Build that set in its own directory
    # rather than adding a test zone to the shipped one - `kryptikd check`
    # reports the shipped set, and a fixture in it would show up there forever.
    mkdir -p /run/probe-zones
    cp /etc/kryptik/zones/*.toml /run/probe-zones/ 2>/dev/null
    cat > /run/probe-zones/probe.toml <<'PROBEZONE'
[zone]
name        = "probe"
description = "fixture for the privileged launch contract probe"
[network]
mode = "routed"
[storage]
mode = "ephemeral"
size = "64M"
[ui]
border_color = "#0f0f0f"
PROBEZONE
    mkdir -p /var/lib/kryptik/zones
    sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 >/dev/null 2>&1 \
        && echo "KRYPTIK_VM_USERNS_KNOB=apparmor-emulated" \
        || echo "KRYPTIK_VM_USERNS_KNOB=none"
    /usr/lib/kryptik/security/probes/vm-privileged-contract.sh \
        /usr/bin/kryptikd /run/probe-zones /var/lib/kryptik/zones
    echo "KRYPTIK_VM_PRIVCONTRACT_RC=$?"
    # Put it back: every later check in this payload assumes the default.
    sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1
    echo "KRYPTIK_VM_PRIVCONTRACT_END"
fi

# What block devices does the guest actually have? Printed unconditionally,
# because "the disk was attached" and "the kernel has a driver for it" are
# different facts and only the guest can tell you the second one. A stock
# distribution kernel keeps virtio_blk and ext4 as modules in its initrd, and
# this image carries no modules at all.
echo "KRYPTIK_VM_BLOCKDEV=$(awk 'NR>2 {printf "%s(%sK) ", $4, $3}' /proc/partitions 2>/dev/null)"
echo "KRYPTIK_VM_FILESYSTEMS=$(awk '{print $NF}' /proc/filesystems 2>/dev/null | tr '\n' ',')"
if [ -b /dev/vda ]; then
    mkdir -p /mnt/disk
    if mount -t ext4 /dev/vda /mnt/disk 2>/dev/null; then
        echo "KRYPTIK_VM_DISKMOUNT=ok"
        echo "KRYPTIK_VM_DISKMARK=$(cat /mnt/disk/kryptik-disk-marker 2>/dev/null)"
        umount /mnt/disk 2>/dev/null
    else
        echo "KRYPTIK_VM_DISKMOUNT=failed"
    fi
else
    echo "KRYPTIK_VM_DISKMOUNT=no-vda"
fi

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

# The same suite again, with the restriction on.
#
# This is the evidence R-7a asks for and the reason the P5 repair exists. The
# run above is on the stock default, where unprivileged user namespaces are
# allowed - which is NOT the kernel Kryptik intends to ship, so on its own it
# says nothing about the privileged path on the target. With the AppArmor knob
# set, a root kryptikd is the only thing that can create a user namespace at
# all, which is exactly the target's rule.
#
# The whole suite runs rather than group K alone: if the repair were wrong, the
# failure would not be confined to the checks that look privileged.
if [ -x /usr/lib/kryptik/compartments/tests/launcher.sh ]; then
    echo "KRYPTIK_VM_RESTRICTED_BEGIN"
    if sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 >/dev/null 2>&1; then
        echo "KRYPTIK_VM_RESTRICTED_KNOB=apparmor-emulated"
        KRYPTIKD=/usr/bin/kryptikd KRYPTIK_TEST_TIMEOUT=60 \
            /usr/lib/kryptik/compartments/tests/launcher.sh
        echo "KRYPTIK_VM_RESTRICTED_RC=$?"
        sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1
    else
        echo "KRYPTIK_VM_RESTRICTED_KNOB=none"
        echo "KRYPTIK_VM_RESTRICTED_RC=noknob"
    fi
    echo "KRYPTIK_VM_RESTRICTED_END"
fi

# The same suite again, with the restriction on.
#
# This is the evidence R-7a asks for and the reason the P5 repair exists. The
# run above is on the stock default, where unprivileged user namespaces are
# allowed - which is NOT the kernel Kryptik intends to ship, so on its own it
# says nothing about the privileged path on the target. With the AppArmor knob
# set, a root kryptikd is the only thing that can create a user namespace at
# all, which is exactly the target's rule.
#
# The whole suite runs rather than group K alone: if the repair were wrong, the
# failure would not be confined to the checks that look privileged.
if [ -x /usr/lib/kryptik/compartments/tests/launcher.sh ]; then
    echo "KRYPTIK_VM_RESTRICTED_BEGIN"
    if sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 >/dev/null 2>&1; then
        echo "KRYPTIK_VM_RESTRICTED_KNOB=apparmor-emulated"
        KRYPTIKD=/usr/bin/kryptikd KRYPTIK_TEST_TIMEOUT=60 \
            /usr/lib/kryptik/compartments/tests/launcher.sh
        echo "KRYPTIK_VM_RESTRICTED_RC=$?"
        sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1
    else
        echo "KRYPTIK_VM_RESTRICTED_KNOB=none"
        echo "KRYPTIK_VM_RESTRICTED_RC=noknob"
    fi
    echo "KRYPTIK_VM_RESTRICTED_END"
fi

# The same suite again, with the restriction on.
#
# This is the evidence R-7a asks for and the reason the P5 repair exists. The
# run above is on the stock default, where unprivileged user namespaces are
# allowed - which is NOT the kernel Kryptik intends to ship, so on its own it
# says nothing about the privileged path on the target. With the AppArmor knob
# set, a root kryptikd is the only thing that can create a user namespace at
# all, which is exactly the target's rule.
#
# The whole suite runs rather than group K alone: if the repair were wrong, the
# failure would not be confined to the checks that look privileged.
if [ -x /usr/lib/kryptik/compartments/tests/launcher.sh ]; then
    echo "KRYPTIK_VM_RESTRICTED_BEGIN"
    if sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 >/dev/null 2>&1; then
        echo "KRYPTIK_VM_RESTRICTED_KNOB=apparmor-emulated"
        KRYPTIKD=/usr/bin/kryptikd KRYPTIK_TEST_TIMEOUT=60 \
            /usr/lib/kryptik/compartments/tests/launcher.sh
        echo "KRYPTIK_VM_RESTRICTED_RC=$?"
        sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1
    else
        echo "KRYPTIK_VM_RESTRICTED_KNOB=none"
        echo "KRYPTIK_VM_RESTRICTED_RC=noknob"
    fi
    echo "KRYPTIK_VM_RESTRICTED_END"
fi

# The same suite again, with the restriction on.
#
# This is the evidence R-7a asks for and the reason the P5 repair exists. The
# run above is on the stock default, where unprivileged user namespaces are
# allowed - which is NOT the kernel Kryptik intends to ship, so on its own it
# says nothing about the privileged path on the target. With the AppArmor knob
# set, a root kryptikd is the only thing that can create a user namespace at
# all, which is exactly the target's rule.
#
# The whole suite runs rather than group K alone: if the repair were wrong, the
# failure would not be confined to the checks that look privileged.
if [ -x /usr/lib/kryptik/compartments/tests/launcher.sh ]; then
    echo "KRYPTIK_VM_RESTRICTED_BEGIN"
    if sysctl -w kernel.apparmor_restrict_unprivileged_userns=1 >/dev/null 2>&1; then
        echo "KRYPTIK_VM_RESTRICTED_KNOB=apparmor-emulated"
        KRYPTIKD=/usr/bin/kryptikd KRYPTIK_TEST_TIMEOUT=60 \
            /usr/lib/kryptik/compartments/tests/launcher.sh
        echo "KRYPTIK_VM_RESTRICTED_RC=$?"
        sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1
    else
        echo "KRYPTIK_VM_RESTRICTED_KNOB=none"
        echo "KRYPTIK_VM_RESTRICTED_RC=noknob"
    fi
    echo "KRYPTIK_VM_RESTRICTED_END"
fi

# The user-facing command, exercised where a user would meet it: as root, on
# the real zone set, in the VM. Its own suite builds fixtures in a scratch
# directory, so it does not disturb the shipped zones.
if [ -x /usr/lib/kryptik/compartments/tests/cli.sh ]; then
    echo "KRYPTIK_VM_CLI_BEGIN"
    KRYPTIKD=/usr/bin/kryptikd /usr/lib/kryptik/compartments/tests/cli.sh
    echo "KRYPTIK_VM_CLI_RC=$?"
    echo "KRYPTIK_VM_CLI_END"
fi

if [ -x /usr/lib/kryptik/compartments/tests/adversarial.sh ]; then
    echo "KRYPTIK_VM_ADVERSARIAL_BEGIN"
    /usr/lib/kryptik/compartments/tests/adversarial.sh
    echo "KRYPTIK_VM_ADVERSARIAL_RC=$?"
    echo "KRYPTIK_VM_ADVERSARIAL_END"
fi

echo "KRYPTIK_VM_T_END=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
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
# Every suite, by glob, not a list. A hardcoded pair is how cli.sh came to
# exist, be wired into the smoke payload, and then not be in the image - the
# payload would have found nothing and said nothing, because it tests for the
# file before running it.
for t in "$REPO"/compartments/tests/*.sh; do
    [[ -f "$t" ]] || continue
    install -m 0755 "$t" "$KTESTS/$(basename "$t")"
done
note "test suites: $(find "$KTESTS" -name '*.sh' | wc -l) installed"

mkdir -p "$ROOT/usr/lib/kryptik/compartments/kryptikd/target/debug"
ln -sf /usr/bin/kryptikd \
   "$ROOT/usr/lib/kryptik/compartments/kryptikd/target/debug/kryptikd" 2>/dev/null || true

# The security tab's own probes, when present. They are written to run in the
# VM as root and to print NOT RUN with a reason rather than passing when they
# cannot measure something - so shipping them costs nothing and closes the gap
# where a security-owned check existed but only ever ran on a developer host.
KPROBES="$ROOT/usr/lib/kryptik/security/probes"
SECPROBES="${KRYPTIK_SECURITY_PROBES:-$HOME/kryptik-overnight-2026-09-11/security/probes}"
if [[ -d "$SECPROBES" ]]; then
    mkdir -p "$KPROBES"
    for pb in "$SECPROBES"/*.sh; do
        [[ -f "$pb" ]] || continue
        install -m 0755 "$pb" "$KPROBES/$(basename "$pb")"
    done
    note "security probes: $(find "$KPROBES" -name '*.sh' | wc -l) installed"
fi

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
if [[ -n "$AS_DISK" ]]; then
    command -v mke2fs >/dev/null || die "--as-disk needs mke2fs (e2fsprogs)"
    # mke2fs -d populates the filesystem from a directory WITHOUT mounting it,
    # so this needs no root and no loop device - which matters, because the
    # developer host has neither.
    #
    # ONE LIMITATION, STATED RATHER THAN HIDDEN: -d preserves each file's
    # numeric owner, and the staging tree was assembled by an unprivileged
    # user, so the image's files are owned by that uid instead of by root.
    # Nothing this harness measures depends on it - the guest runs as root and
    # root ignores DAC ownership, and the checks that care about ownership
    # (group K) chown their own fixtures at runtime. But this is a development
    # image builder and not a release one: a real image must be built as root,
    # or under fakeroot, neither of which exists on this host. The stamp below
    # records it so nobody has to rediscover it.
    note "packing as an ext4 root filesystem ($AS_DISK)"
    note "  NOTE: files are owned by uid $(id -u), not root — development image only"
    rm -f "$OUT"
    # Not piped into sed: a pipeline reports the LAST command's status, so
    # `mke2fs ... | sed` would report sed's success and swallow a failed image.
    if ! mke2fs -q -t ext4 -F -L kryptik -d "$ROOT" "$OUT" "$AS_DISK" > "$ROOT.mke2fs.log" 2>&1; then
        sed 's/^/  mke2fs: /' "$ROOT.mke2fs.log" >&2 || true
        die "mke2fs failed writing $OUT"
    fi
    [[ -s "$ROOT.mke2fs.log" ]] && sed 's/^/  mke2fs: /' "$ROOT.mke2fs.log" >&2
    rm -f "$ROOT.mke2fs.log"
    [[ -s "$OUT" ]] || die "mke2fs produced no image at $OUT"
    note "wrote $OUT ($(stat -c %s "$OUT") bytes, ext4, label kryptik)"
    note "sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
    note "boot it with: run-qemu.sh --kernel K --disk $OUT --root-disk"
else
    ( cd "$ROOT" && find . -print0 | cpio --null -o --format=newc --quiet ) | gzip -9 > "$OUT"
    note "wrote $OUT ($(stat -c %s "$OUT") bytes)"
    note "sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
fi
