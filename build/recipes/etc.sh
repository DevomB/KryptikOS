#!/usr/bin/env bash
# etc: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# /etc/os-release and friends. BUILD_ID, the commit that built the image, is
# added after the steps (at the end of this file): as this step's input it
# would re-fingerprint this step, and every step after it, on each commit.
s_etc() {
    cat > /etc/os-release <<'EOF'
NAME="Kryptik"
PRETTY_NAME="Kryptik (pre-alpha)"
ID=kryptik
ANSI_COLOR="0;36"
EOF

    echo "kryptik" > /etc/hostname

    # No root line: root comes from the kernel, and a wrong device name is
    # worse than none.
    cat > /etc/fstab <<'EOF'
# file system  mount point  type     options              dump  fsck
proc           /proc        proc     nosuid,noexec,nodev  0     0
sysfs          /sys         sysfs    nosuid,noexec,nodev  0     0
devpts         /dev/pts     devpts   gid=5,mode=620       0     0
tmpfs          /run         tmpfs    defaults             0     0
devtmpfs       /dev         devtmpfs mode=0755,nosuid     0     0
tmpfs          /dev/shm     tmpfs    nosuid,nodev         0     0
EOF

    cat > /etc/hosts <<'EOF'
127.0.0.1  localhost kryptik
::1        localhost ip6-localhost ip6-loopback
EOF

    # seat may talk to seatd (the compositor's user); kryptik may launch zones
    # through the trusted UI; the net zone's DHCP client drops to dhcpcd.
    # udev's rules give the DRM cards to video and the render nodes to render.
    local g
    for g in seat kryptik wheel video render; do
        getent group "$g" >/dev/null 2>&1 || groupadd -r "$g"
    done
    getent passwd dhcpcd >/dev/null 2>&1 || \
        useradd -r -g nogroup -d /var/lib/dhcpcd -s /usr/bin/false -c "dhcpcd privsep" dhcpcd 2>/dev/null || \
        useradd -r -d /var/lib/dhcpcd -s /usr/bin/false -c "dhcpcd privsep" dhcpcd
    install -d -m 0755 -o dhcpcd /var/lib/dhcpcd 2>/dev/null || install -d -m 0755 /var/lib/dhcpcd

    # root ships with no password ("*" matches nothing) until kryptik-firstboot
    # sets one, and the empty /etc/securetty keeps root off every terminal:
    # administration is su from wheel.
    [[ -f /etc/shadow ]] || pwconv
    usermod -p '*' root
    grep -q '^root:\*:' /etc/shadow && echo "root: no password" || { echo "FAIL: root has a password in the image"; return 1; }
    : > /etc/securetty
    # Both set here, not left to shadow's login.defs, which a release may
    # change: login reads the terminals root may use from CONSOLE's file.
    local def
    for def in "CONSOLE /etc/securetty" "SU_WHEEL_ONLY yes"; do
        if grep -q "^${def%% *}[[:space:]]" /etc/login.defs; then
            sed -i "s|^${def%% *}[[:space:]].*|${def}|" /etc/login.defs
        else
            printf '%s\n' "$def" >> /etc/login.defs
        fi
    done
    grep -qx 'CONSOLE /etc/securetty' /etc/login.defs && [[ ! -s /etc/securetty ]] \
        || { echo "FAIL: root is not kept off the terminals"; return 1; }

    # Kernel interface names (eth0, wlan0), the same on every machine: eudev's
    # slot-naming rule is masked.
    install -d -m 0755 /etc/udev/rules.d
    ln -sf /dev/null /etc/udev/rules.d/80-net-name-slot.rules

    cat > /etc/kryptik/kryptik.conf <<'EOF'
# The kryptik command's defaults on an installed system.
zones_dir = /usr/lib/kryptik/zones
rootfs    = /var/lib/kryptik/zones
uid_base  = 100000
EOF

    # A tty1 login becomes the compositor session; any other tty stays a shell.
    install -d -m 0755 /etc/profile.d /etc/skel
    cat > /etc/profile.d/kryptik-session.sh <<'EOF'
# Start the zoned desktop from a tty1 login; every other login is a shell.
if [ -z "${WAYLAND_DISPLAY:-}" ] && [ "$(tty 2>/dev/null)" = /dev/tty1 ] \
   && [ -x /usr/bin/kryptik-session ] && [ "$(id -u)" -ne 0 ]; then
    exec /usr/bin/kryptik-session
fi
EOF
    cat > /etc/skel/.bash_profile <<'EOF'
[ -r /etc/profile ] && . /etc/profile
[ -r ~/.bashrc ] && . ~/.bashrc
EOF
    [[ -f /etc/profile ]] || cat > /etc/profile <<'EOF'
# Kryptik /etc/profile
export PATH=/usr/bin:/usr/sbin
umask 022
for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done
EOF
    grep -q 'profile.d' /etc/profile || printf '%s\n' 'for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done' >> /etc/profile
    printf '/bin/sh\n/bin/bash\n/usr/bin/bash\n' > /etc/shells

    echo "--- identity ---"
    cat /etc/os-release
    echo "--- groups ---"
    grep -E '^(seat|kryptik|wheel|dhcpcd):' /etc/group
}
