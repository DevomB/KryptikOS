#!/bin/sh -e
# Idempotent on purpose: s6-rc may run this again after a runlevel change.

[ -r /etc/hostname ] && hostname "$(cat /etc/hostname)" || true

# The kernel mounts devtmpfs itself (CONFIG_DEVTMPFS_MOUNT=y); these are the
# rest, each guarded because stage 2 init may already have done it.
mountpoint -q /proc    || mount -t proc  proc  /proc -o nosuid,noexec,nodev
mountpoint -q /sys     || mount -t sysfs sysfs /sys  -o nosuid,noexec,nodev
# securityfs and cgroup2. Both are guarded and neither may abort this script:
# it runs under `sh -e`, and the first attempt at this mounted securityfs
# unguarded on a kernel without CONFIG_SECURITYFS. The mount failed, -e killed
# sysinit, s6-rc started nothing, and a machine that was otherwise fine came up
# with no services at all. An observability filesystem is not worth a boot.
if ! mountpoint -q /sys/kernel/security 2>/dev/null; then
    if mount -t securityfs securityfs /sys/kernel/security \
             -o nosuid,noexec,nodev 2>/dev/null; then
        echo "sysinit: securityfs mounted"
    else
        echo "sysinit: securityfs unavailable - /sys/kernel/security/lsm will be" >&2
        echo "sysinit: unreadable and the active LSM list cannot be observed." >&2
        echo "sysinit: (kernel needs CONFIG_SECURITYFS=y)" >&2
    fi
fi

# cgroup v2 is NOT optional: kryptikd refuses to start zones without it, on the
# grounds that a zone missing one control is not a weaker zone but one that does
# not isolate. It is still guarded, because a machine that boots and says why
# zones are unavailable is more useful than one that does not boot.
mkdir -p /sys/fs/cgroup
if ! mountpoint -q /sys/fs/cgroup 2>/dev/null; then
    if mount -t cgroup2 cgroup2 /sys/fs/cgroup \
             -o nsdelegate,nosuid,noexec,nodev 2>/dev/null; then
        echo "sysinit: cgroup2 mounted"
    else
        echo "sysinit: FAILED to mount cgroup2 - kryptikd will refuse zones" >&2
    fi
fi

mkdir -p /dev/pts /dev/shm
mountpoint -q /dev/pts || mount -t devpts devpts /dev/pts -o gid=5,mode=620,nosuid,noexec
mountpoint -q /dev/shm || mount -t tmpfs  tmpfs  /dev/shm -o nosuid,nodev
# efivarfs: the A/B trial (boot-success, kryptik-update) reads and writes
# Boot#### and BootNext through it. Absent on a non-UEFI boot; that is reported
# by boot-success, not here.
if [ -d /sys/firmware/efi/efivars ] && ! mountpoint -q /sys/firmware/efi/efivars; then
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars -o nosuid,noexec,nodev 2>/dev/null \
        || echo "sysinit: efivarfs did not mount" >&2
fi

# --- persistent state (Design 08) -------------------------------------------
#
# The root filesystem is dm-verity and read-only. Everything that has to
# change after the build lives on the partition labelled kryptik-state, or,
# on install media without one, on a tmpfs that says so. The image's own /var
# is copied into a fresh state volume once, so packages find the directories
# they installed; after that the volume is authoritative.
#
# Then /etc becomes an overlay (lower: the verified /etc; upper: on state),
# /home and /root come from state, and /tmp is a tmpfs. Nothing writes to the
# verified root, and a write that tries fails with EROFS rather than quietly
# landing somewhere the next boot will not see.
state_mnt=/run/kryptik/state
mkdir -p /run/kryptik "$state_mnt"
chmod 0700 /run/kryptik
if ! mountpoint -q /var; then
    state_dev="$(blkid -t PARTLABEL=kryptik-state -o device 2>/dev/null | head -1)"
    if [ -n "$state_dev" ] && [ -b "$state_dev" ]; then
        if mount -t ext4 -o nosuid,nodev,noatime "$state_dev" "$state_mnt"; then
            echo "sysinit: state partition ${state_dev} mounted"
        else
            echo "sysinit: FAILED to mount state partition ${state_dev}; using tmpfs" >&2
            mount -t tmpfs -o nosuid,nodev,mode=0755 tmpfs "$state_mnt"
        fi
    else
        echo "sysinit: no kryptik-state partition (install medium?); state is a tmpfs and will not persist"
        mount -t tmpfs -o nosuid,nodev,mode=0755 tmpfs "$state_mnt"
    fi
    if [ ! -e "$state_mnt/.kryptik-state" ]; then
        echo "sysinit: initialising state from the image's /var"
        cp -a /var/. "$state_mnt/"
        mkdir -p "$state_mnt/lib/kryptik/etc/upper" "$state_mnt/lib/kryptik/etc/work" \
                 "$state_mnt/lib/kryptik/zones" "$state_mnt/lib/kryptik/volumes" \
                 "$state_mnt/lib/kryptik/boot" "$state_mnt/lib/kryptik/updates" \
                 "$state_mnt/home" "$state_mnt/roothome" "$state_mnt/log/kryptik"
        chmod 0700 "$state_mnt/lib/kryptik/volumes" "$state_mnt/roothome"
        chmod 0755 "$state_mnt/home"
        date -Iseconds > "$state_mnt/.kryptik-state" 2>/dev/null || : > "$state_mnt/.kryptik-state"
    fi
    mount --move "$state_mnt" /var
fi
rmdir "$state_mnt" 2>/dev/null || true

# /etc as an overlay. The lower layer is the verified root's /etc, which is
# what every later boot verifies; the upper layer holds the machine's own
# changes - passwords, hostname, the first-boot user - on state.
if ! mountpoint -q /etc; then
    mkdir -p /var/lib/kryptik/etc/upper /var/lib/kryptik/etc/work
    if mount -t overlay overlay \
             -o lowerdir=/etc,upperdir=/var/lib/kryptik/etc/upper,workdir=/var/lib/kryptik/etc/work,nosuid,nodev \
             /etc; then
        echo "sysinit: /etc overlay mounted"
    else
        echo "sysinit: FAILED to overlay /etc - the system is read-only and cannot keep local changes" >&2
    fi
fi
mkdir -p /var/home /var/roothome
mountpoint -q /home || mount --bind /var/home /home
mountpoint -q /root || mount --bind /var/roothome /root
mountpoint -q /tmp  || mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /tmp

# Kryptik's runtime state. 0700 on /run/kryptik: zone metadata is not
# world-readable.
mkdir -p /run/kryptik /run/lock /var/log/kryptik /var/lib/kryptik/boot
chmod 0700 /run/kryptik
chmod 0755 /run/lock /var/log/kryptik

# What booted, for everything that needs to know: the slot, and whether this
# is an install medium. Both come from the signed command line.
slot=""; media=""
for word in $(cat /proc/cmdline 2>/dev/null); do
    case "$word" in
        kryptik.slot=*)  slot="${word#kryptik.slot=}" ;;
        kryptik.media=*) media="${word#kryptik.media=}" ;;
    esac
done
printf 'slot=%s\nmedia=%s\n' "$slot" "$media" > /run/kryptik/boot-identity
echo "sysinit: booted slot='${slot}' media='${media}'"

# Kryptik's kernel tunables. A boot that silently skipped these would look
# exactly like one that applied them, so failures are reported.
if [ -d /etc/sysctl.d ]; then
    for f in /etc/sysctl.d/*.conf; do
        [ -r "$f" ] || continue
        sysctl -p "$f" >/dev/null || echo "sysinit: sysctl -p $f reported errors" >&2
    done
fi
echo "sysinit: complete"
