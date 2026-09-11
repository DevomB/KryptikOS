#!/bin/sh -e
# Idempotent on purpose: s6-rc may run this again after a runlevel change.

[ -r /etc/hostname ] && hostname "$(cat /etc/hostname)" || true

# The kernel mounts devtmpfs itself (CONFIG_DEVTMPFS_MOUNT=y); these are the
# rest, each guarded because stage 2 init may already have done it.
mountpoint -q /proc    || mount -t proc  proc  /proc -o nosuid,noexec,nodev
mountpoint -q /sys     || mount -t sysfs sysfs /sys  -o nosuid,noexec,nodev
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
