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

# --- what booted: the slot or the medium, from the signed command line ------
#
# Both come from the kernel's compiled-in command line (Design 08): nothing
# a bootloader, a firmware variable or a person at a prompt could change.
slot=""; media=""
for word in $(cat /proc/cmdline 2>/dev/null); do
    case "$word" in
        kryptik.slot=*)  slot="${word#kryptik.slot=}" ;;
        kryptik.media=*) media="${word#kryptik.media=}" ;;
    esac
done

# --- persistent state (Design 08) -------------------------------------------
#
# The root filesystem is dm-verity and read-only. Everything that has to
# change after the build lives on the partition labelled kryptik-state ON THE
# DISK THE ROOT CAME FROM (devices.sh: a label is not an identity, and a
# second disk carrying the same layout must not be mistaken for this
# installation's). The image's own /var is copied into a fresh state volume
# once, so packages find the directories they installed; after that the
# volume is authoritative.
#
# Three outcomes, and they are told apart on purpose:
#   persistent  the installed system's state partition is mounted at /var
#   tmpfs       an install medium: nothing persists, by design
#   degraded    an INSTALLED system whose state partition is missing,
#               ambiguous or unmountable. /var is a tmpfs so the machine can
#               be logged into and repaired, and every later step that would
#               otherwise act as if the machine were fine - first-boot setup,
#               the desktop session, the update trial commit, the updater -
#               reads /run/kryptik/state-degraded and refuses. Silently
#               booting a fresh non-persistent user state on an installed
#               machine is exactly what this must not do.
. /usr/libexec/kryptik/devices.sh
state_mnt=/run/kryptik/state
STATE=""; STATE_REASON=""; state_dev=""; root_disk=""
mkdir -p /run/kryptik "$state_mnt"
chmod 0700 /run/kryptik
rm -f /run/kryptik/state-degraded
if ! mountpoint -q /var; then
    root_disk="$(kryptik_root_disk 2>/dev/null || true)"
    n="$(kryptik_part_count kryptik-state 2>/dev/null || echo 0)"
    others="$(kryptik_others kryptik-state 2>/dev/null | tr '\n' ' ')"
    [ -n "$others" ] && echo "sysinit: kryptik-state on other disks ignored: ${others}(not this root's disk ${root_disk:-?})"
    if [ -n "$media" ]; then
        STATE=tmpfs; STATE_REASON="install medium"
        echo "sysinit: install medium: state is a tmpfs and will not persist"
    elif [ -z "$root_disk" ]; then
        STATE=degraded; STATE_REASON="cannot tell which disk the root came from"
    elif [ "$n" -eq 0 ]; then
        STATE=degraded; STATE_REASON="no partition labelled kryptik-state on ${root_disk}"
    elif [ "$n" -gt 1 ]; then
        STATE=degraded; STATE_REASON="${n} partitions labelled kryptik-state on ${root_disk}; refusing to guess"
    else
        state_dev="$(kryptik_part kryptik-state)"
        if [ ! -b "$state_dev" ]; then
            STATE=degraded; STATE_REASON="${state_dev} is not a block device"
        elif mount -t ext4 -o nosuid,nodev,noatime "$state_dev" "$state_mnt" 2>/run/kryptik/state-mount.err; then
            STATE=persistent
            echo "sysinit: state partition ${state_dev} mounted (disk ${root_disk})"
        else
            STATE=degraded; STATE_REASON="mount of ${state_dev} failed: $(tr '\n' ' ' < /run/kryptik/state-mount.err)"
        fi
    fi
    if [ "$STATE" != persistent ]; then
        mount -t tmpfs -o nosuid,nodev,mode=0755 tmpfs "$state_mnt"
    fi
    if [ "$STATE" = degraded ]; then
        printf '%s\n' "$STATE_REASON" > /run/kryptik/state-degraded
        {
            echo
            echo "sysinit: ******************************************************************"
            echo "sysinit: *  STATE DEGRADED: ${STATE_REASON}"
            echo "sysinit: *  This is an installed system (slot ${slot}) and its persistent"
            echo "sysinit: *  state could not be used. /var is a TEMPORARY filesystem now:"
            echo "sysinit: *  nothing changed in this session will survive a reboot."
            echo "sysinit: *  The desktop will not start; log in on the console to repair,"
            echo "sysinit: *  or boot the install medium and run kryptik-recover --status."
            echo "sysinit: ******************************************************************"
            echo
        } > /dev/console 2>&1 || true
        echo "sysinit: STATE DEGRADED: ${STATE_REASON}" >&2
    fi
    if [ ! -e "$state_mnt/.kryptik-state" ]; then
        echo "sysinit: initialising state from the image's /var (${STATE})"
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
else
    STATE="$(awk '$2=="/var"{print ($3=="tmpfs")?"tmpfs":"persistent"; exit}' /proc/mounts)"
fi
rmdir "$state_mnt" 2>/dev/null || true

# /etc as an overlay. The lower layer is the verified root's /etc, which is
# what every later boot verifies; the upper layer holds the machine's own
# changes - passwords, hostname, the first-boot user - on state.
#
# THE TRUST BOUNDARY, stated once: the upper layer is mutable and is not
# authenticated. Anyone who can write the state partition offline can put any
# file under /etc. So nothing that decides what runs with privilege, or what
# the system trusts, is read from /etc:
#   the init scripts and the service database   /usr/lib/s6-linux-init, /usr/lib/kryptik/s6-rc
#   the kernel tunables applied below           /usr/lib/kryptik/sysctl.d
#   the zone definitions the services use       /usr/lib/kryptik/zones
#   the release trust anchor (kryptik-update)   /usr/share/kryptik/trust
# all of which sit on the verified root. What remains under /etc is what
# must be mutable: accounts and passwords, hostname, the local user's
# session hooks. Their protection is the state partition's, and that
# partition is not encrypted in this developer tier - a stated limitation,
# not tamper protection.
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
# The transfer-consent channel (kryptikd consent.rs): questions from the
# broker, answers from the desktop session (group kryptik). Beside
# /run/kryptik-launch, not under /run/kryptik, which the zone registry keeps
# 0700. No zone has a path here. Group-writable and setgid so the session's
# answers belong to the group.
mkdir -p /run/kryptik-consent
chown root:kryptik /run/kryptik-consent 2>/dev/null || true
chmod 2770 /run/kryptik-consent

# What booted, for everything that needs to know.
printf 'slot=%s\nmedia=%s\nstate=%s\nstate_dev=%s\nroot_disk=%s\n' \
    "$slot" "$media" "$STATE" "$state_dev" "$root_disk" > /run/kryptik/boot-identity
echo "sysinit: booted slot='${slot}' media='${media}' state=${STATE}${state_dev:+ (${state_dev})}"

# Kryptik's kernel tunables, from the verified root only (see above). A boot
# that silently skipped these would look exactly like one that applied them,
# so failures are reported.
if [ -d /usr/lib/kryptik/sysctl.d ]; then
    for f in /usr/lib/kryptik/sysctl.d/*.conf; do
        [ -r "$f" ] || continue
        sysctl -p "$f" >/dev/null || echo "sysinit: sysctl -p $f reported errors" >&2
    done
fi
echo "sysinit: complete"
