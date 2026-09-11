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
    if mount -t securityfs securityfs /sys/kernel/security              -o nosuid,noexec,nodev 2>/dev/null; then
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
    if mount -t cgroup2 cgroup2 /sys/fs/cgroup              -o nsdelegate,nosuid,noexec,nodev 2>/dev/null; then
        echo "sysinit: cgroup2 mounted"
    else
        echo "sysinit: FAILED to mount cgroup2 - kryptikd will refuse zones" >&2
    fi
fi

mkdir -p /dev/pts /dev/shm
mountpoint -q /dev/pts || mount -t devpts devpts /dev/pts -o gid=5,mode=620,nosuid,noexec
mountpoint -q /dev/shm || mount -t tmpfs  tmpfs  /dev/shm -o nosuid,nodev

# Kryptik's runtime state. 0700 on /run/kryptik: zone metadata is not
# world-readable.
mkdir -p /run/kryptik /run/lock /var/log/kryptik
chmod 0700 /run/kryptik
chmod 0755 /run/lock /var/log/kryptik

# Kryptik's kernel tunables. A boot that silently skipped these would look
# exactly like one that applied them, so failures are reported.
if [ -d /etc/sysctl.d ]; then
    for f in /etc/sysctl.d/*.conf; do
        [ -r "$f" ] || continue
        sysctl -p "$f" >/dev/null || echo "sysinit: sysctl -p $f reported errors" >&2
    done
fi
echo "sysinit: complete"
