#!/bin/sh -e
# Early boot: filesystems, the state partition, the /etc overlay, sysctls.
# Idempotent, since s6-rc may run it again after a runlevel change.

# kryptik-console holds the getty back until this finishes: it may ask for the
# state passphrase, and two readers on one terminal lose keystrokes.
echo running > /run/kryptik-sysinit
trap 'echo finished > /run/kryptik-sysinit' EXIT

[ -r /etc/hostname ] && hostname "$(cat /etc/hostname)" || true

# The only names the /etc overlay's upper layer may carry: accounts (with the
# shadow tools' backups and lock), identity, clock and zone 0's resolver.
ETC_MUTABLE="passwd shadow group gshadow subuid subgid passwd- shadow- group- gshadow- subuid- subgid- .pwd.lock hostname machine-id localtime adjtime resolv.conf"
prune_etc_upper() {   # prune_etc_upper UPPER QUARANTINE
    up="$1"; q="$2"; moved=0
    # State is untrusted: none of these paths may pass through a symlink.
    for path in "$up" "${up%/*}/work" "$q"; do
        [ "$(realpath -m -- "$path")" = "$path" ] || return 1
    done
    [ ! -e "$up" ] || [ -d "$up" ] || return 1
    [ -d "$up" ] || return 0
    for e in "$up"/* "$up"/.[!.]* "$up"/..?*; do
        [ -e "$e" ] || [ -L "$e" ] || continue
        name="${e##*/}"
        keep=0
        for k in $ETC_MUTABLE; do [ "$name" = "$k" ] && keep=1; done
        # Accounts must be regular files, not FIFOs or links into mutable
        # state. localtime may point only into the verified zoneinfo tree.
        if [ "$keep" = 1 ] && [ -f "$e" ] && [ ! -L "$e" ]; then continue; fi
        if [ "$name" = localtime ] && [ -L "$e" ] && [ -f "$e" ]; then
            case "$(realpath -e -- "$e")" in /usr/share/zoneinfo/*) continue ;; esac
        fi
        mkdir -p "$q" || return 1
        saved="$(mktemp -d "$q/$name.XXXXXX")" || return 1
        mv -T -- "$e" "$saved/entry" || return 1
        moved=$((moved + 1))
        echo "sysinit: /etc overlay: quarantined '$name' from the state partition (not something the system may change under /etc)" >&2
    done
    [ "$moved" -gt 0 ] && echo "sysinit: /etc overlay: $moved entr(y/ies) moved to lib/kryptik/etc/quarantine on the state partition" >&2
    return 0
}

# Up to three passphrase prompts on the console. Echo goes off before the
# prompt and stty never discards input, so an early answer is not lost.
# printf is a builtin: the passphrase never appears as an argument.
unlock_state() {   # unlock_state DEVICE -> /dev/mapper/kryptik-state
    try=1
    while [ "$try" -le 3 ] && [ ! -b /dev/mapper/kryptik-state ]; do
        stty -echo < /dev/console 2>/dev/null || true
        printf 'sysinit: passphrase for the state partition (try %s of 3): ' "$try" > /dev/console
        IFS= read -r pass < /dev/console || pass=""
        stty echo < /dev/console 2>/dev/null || true
        echo > /dev/console
        printf '%s' "$pass" | cryptsetup open --type luks2 --key-file=- "$1" kryptik-state 2>/dev/null || true
        try=$((try + 1))
    done
    pass=""
    [ -b /dev/mapper/kryptik-state ]
}

# The kernel mounts devtmpfs (CONFIG_DEVTMPFS_MOUNT=y); stage 2 init may
# already have mounted the rest.
mountpoint -q /proc    || mount -t proc  proc  /proc -o nosuid,noexec,nodev
mountpoint -q /sys     || mount -t sysfs sysfs /sys  -o nosuid,noexec,nodev
# Neither securityfs nor cgroup2 may abort this `sh -e` script: s6-rc would
# then start no services at all.
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

# kryptikd refuses zones without cgroup2; the machine still boots and says why.
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
# efivarfs: the A/B trial (boot-success, kryptik-update) uses Boot#### and
# BootNext. boot-success reports a non-UEFI boot.
if [ -d /sys/firmware/efi/efivars ] && ! mountpoint -q /sys/firmware/efi/efivars; then
    mount -t efivarfs efivarfs /sys/firmware/efi/efivars -o nosuid,noexec,nodev 2>/dev/null \
        || echo "sysinit: efivarfs did not mount" >&2
fi

# --- what booted: the slot or the medium, from the signed command line ------
slot=""; media=""
for word in $(cat /proc/cmdline 2>/dev/null); do
    case "$word" in
        kryptik.slot=*)  slot="${word#kryptik.slot=}" ;;
        kryptik.media=*) media="${word#kryptik.media=}" ;;
    esac
done

# --- persistent state --------------------------------------------------------
# The root is read-only; what changes lives on the kryptik-state partition of
# the root's own disk (devices.sh), seeded once from the image's /var.
#   persistent  the state partition is mounted at /var
#   tmpfs       install medium: nothing persists
#   degraded    installed, but the state partition cannot be used: /var is a
#               tmpfs for repair, and first boot, the session, the update
#               commit and the updater refuse (/run/kryptik/state-degraded)
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
        elif ! cryptsetup isLuks --type luks2 "$state_dev" 2>/dev/null; then
            # A plain filesystem in the encrypted one's place is never mounted.
            STATE=degraded; STATE_REASON="${state_dev} carries no LUKS2 header"
        elif ! unlock_state "$state_dev"; then
            STATE=degraded; STATE_REASON="${state_dev} was not unlocked in three tries; reboot to try again"
        elif mount -t ext4 -o nosuid,nodev,noatime /dev/mapper/kryptik-state "$state_mnt" 2>/run/kryptik/state-mount.err; then
            STATE=persistent
            echo "sysinit: state partition ${state_dev} unlocked and mounted (disk ${root_disk})"
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
            echo "sysinit: *  There are no accounts and no desktop in this state: boot the"
            echo "sysinit: *  install medium and run kryptik-recover --status to repair it."
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
    # State is not authenticated, and root honours files under /etc unasked
    # (ld.so.preload, nsswitch.conf, udev rules, login configuration), so the
    # upper layer is pruned to ETC_MUTABLE before the overlay is mounted.
    prune_etc_upper "$state_mnt/lib/kryptik/etc/upper" "$state_mnt/lib/kryptik/etc/quarantine" || {
        echo "sysinit: refusing to boot with an unsafe /etc upper layer; recover from the install medium" >&2
        exit 1
    }
    mount --move "$state_mnt" /var
else
    STATE="$(awk '$2=="/var"{print ($3=="tmpfs")?"tmpfs":"persistent"; exit}' /proc/mounts)"
fi
rmdir "$state_mnt" 2>/dev/null || true

# /etc as an overlay: the verified root's /etc under the machine's changes on
# state. The upper layer is not authenticated, so nothing deciding privilege or
# trust is read from /etc; those come from the verified root:
#   init, services   /usr/lib/s6-linux-init, /usr/lib/kryptik/s6-rc
#   sysctls          /usr/lib/kryptik/sysctl.d
#   zones            /usr/lib/kryptik/zones
#   release anchor   /usr/share/kryptik/trust
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

# /run/kryptik is 0700: zone metadata is not world-readable.
mkdir -p /run/kryptik /run/lock /var/log/kryptik /var/lib/kryptik/boot
chmod 0700 /run/kryptik
chmod 0755 /run/lock /var/log/kryptik
# Transfer consent (kryptikd consent.rs): broker questions, answers from the
# desktop session (group kryptik). Not under the 0700 /run/kryptik; no zone has
# a path here. Setgid so the session's answers belong to the group.
mkdir -p /run/kryptik-consent
chown root:kryptik /run/kryptik-consent 2>/dev/null || true
chmod 2770 /run/kryptik-consent

# What booted, for everything that needs to know.
printf 'slot=%s\nmedia=%s\nstate=%s\nstate_dev=%s\nroot_disk=%s\n' \
    "$slot" "$media" "$STATE" "$state_dev" "$root_disk" > /run/kryptik/boot-identity
echo "sysinit: booted slot='${slot}' media='${media}' state=${STATE}${state_dev:+ (${state_dev})}"

# Kernel tunables, from the verified root only. Failures are reported.
if [ -d /usr/lib/kryptik/sysctl.d ]; then
    for f in /usr/lib/kryptik/sysctl.d/*.conf; do
        [ -r "$f" ] || continue
        sysctl -p "$f" >/dev/null || echo "sysinit: sysctl -p $f reported errors" >&2
    done
fi
echo "sysinit: complete"
