#!/usr/bin/env bash
# init: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# s6-linux-init: /usr/lib/s6-linux-init/current and the /sbin entry points,
# under /usr/lib because the stage 2 scripts run as root first and must come
# from the verified root, not the /etc overlay. Upstream's skeleton scripts are
# all commented out, so ours replace them before the maker copies the skeldir.
s_init() {
    have() { command -v "$1" >/dev/null 2>&1; }
    have s6-linux-init-maker || { echo "s6-linux-init-maker not installed; s6 stack step failed?"; return 1; }
    have s6-svscan || { echo "s6-svscan not installed"; return 1; }

    local skel=/etc/s6-linux-init/skel
    mkdir -p "$skel"

    # Stage 2: runs once s6-svscan is pid 1.
    cat > "$skel/rc.init" <<'EOF'
#!/bin/sh -e
# Kryptik stage 2 init.

rl="$1"
shift

# s6-linux-init has already set up /run and, with -1, our console output.
# These are the mounts the rest of the system assumes exist. Each is guarded,
# because the kernel may have mounted some of them already (devtmpfs is
# automounted: CONFIG_DEVTMPFS_MOUNT=y).
mountpoint -q /proc     || mount -t proc     proc     /proc  -o nosuid,noexec,nodev
mountpoint -q /sys      || mount -t sysfs    sysfs    /sys   -o nosuid,noexec,nodev
mountpoint -q /dev      || mount -t devtmpfs devtmpfs /dev   -o mode=0755,nosuid
mkdir -p /dev/pts /dev/shm
mountpoint -q /dev/pts  || mount -t devpts devpts /dev/pts -o gid=5,mode=620,nosuid,noexec
mountpoint -q /dev/shm  || mount -t tmpfs  tmpfs  /dev/shm -o nosuid,nodev

[ -r /etc/hostname ] && hostname "$(cat /etc/hostname)" 2>/dev/null || true

# Kryptik's own state directories.
mkdir -p /run/kryptik /run/lock
chmod 0755 /run/kryptik

# The service manager, IF a compiled database exists.
#
# It deliberately does not exist yet: building an s6-rc source tree and
# compiling it belongs to the compositor and GUI isolation work. Saying so on the console is the point - a
# system that silently boots with no services and no explanation is
# indistinguishable from one whose service manager crashed.
if [ -d /usr/lib/kryptik/s6-rc/compiled ]; then
    s6-rc-init -c /usr/lib/kryptik/s6-rc/compiled /run/service
    s6-rc -v1 -up change "$rl"
else
    echo "kryptik: no compiled s6-rc database at /usr/lib/kryptik/s6-rc/compiled."
    echo "kryptik: booting with the early console only; no services will start."
    echo "kryptik: this is expected in a pre-alpha image - see docs/roadmap.md, compositor and GUI isolation."
fi
EOF

    # Shutdown: stop services and return; shutdownd unmounts and powers off.
    cat > "$skel/rc.shutdown" <<'EOF'
#!/bin/sh -e
# Kryptik shutdown. Bring services down and return; s6-linux-init-shutdownd
# performs the unmount and the hardware poweroff after this exits.

exec >/dev/console 2>&1

# Say so on the console at every step. Three boots could not distinguish
# "shutdownd never spawned this script" from "this script ran and hung", and
# the difference is the whole diagnosis: shutdownd waits for stage 3 to exit
# before it touches the hardware, so anything that blocks here looks exactly
# like a shutdown daemon that ignored the request.
echo "kryptik: rc.shutdown starting"

if [ -d /run/service ] && command -v s6-rc >/dev/null 2>&1; then
    echo "kryptik: bringing services down"
    # -t: a service that will not stop must not wedge the shutdown forever.
    # Without a timeout the only way out is the hardware, which is the outcome
    # this script exists to avoid.
    s6-rc -v2 -t 20000 -bDa change || echo "kryptik: s6-rc change exited $?"
    echo "kryptik: s6-rc returned"
else
    echo "kryptik: no service database to bring down"
fi
echo "kryptik: services stopped, handing back to shutdownd"
EOF

    cat > "$skel/rc.shutdown.final" <<'EOF'
#!/bin/sh -e
# Runs after every filesystem is unmounted. Kryptik needs nothing here, and
# upstream is emphatic that if you are unsure, the answer is nothing.
EOF

    cat > "$skel/runlevel" <<'EOF'
#!/bin/sh -e
test "$#" -gt 0 || { echo 'runlevel: fatal: too few arguments' 1>&2 ; exit 100 ; }
if [ -d /run/service ] && command -v s6-rc >/dev/null 2>&1; then
    exec s6-rc -v1 -up change "$1"
fi
echo "kryptik: no service database; runlevel '$1' has nothing to change" 1>&2
EOF

    chmod 0755 "$skel"/rc.init "$skel"/rc.shutdown "$skel"/rc.shutdown.final "$skel"/runlevel
    local s
    for s in rc.init rc.shutdown rc.shutdown.final runlevel; do
        sh -n "$skel/$s" || { echo "skeleton script $s has a syntax error"; return 1; }
    done

    # The maker will not write into an existing directory; build, then move.
    local tmp=/tmp/s6-linux-init-build.$$
    rm -rf "$tmp"

    #  -1  stage 2 output on /dev/console too, so a failed boot can be read
    #  -G  the early getty: our console wrapper
    #  -s  the envdir for the kernel command line's key=value pairs; under /run,
    #      since it is rewritten every boot and the root is read-only dm-verity
    #  -f  our skeleton
    # No -d /dev: the kernel mounts devtmpfs itself (CONFIG_DEVTMPFS_MOUNT=y).
    s6-linux-init-maker \
        -1 \
        -G "/usr/libexec/kryptik-console" \
        -p /usr/bin:/usr/sbin \
        -m 0022 \
        -c /usr/lib/s6-linux-init/current \
        -s /run/s6-linux-init/env \
        -f "$skel" \
        -D default \
        "$tmp"

    install -d -m 0755 /usr/lib/s6-linux-init
    rm -rf /usr/lib/s6-linux-init/current
    mv "$tmp" /usr/lib/s6-linux-init/current

    # /sbin/init and the rest; /sbin links to usr/sbin, and /sbin/init is where
    # the kernel looks.
    cp -a /usr/lib/s6-linux-init/current/bin/. /sbin/

    echo "--- /sbin entry points ---"
    ls -la /sbin/init /sbin/telinit /sbin/shutdown /sbin/halt /sbin/poweroff /sbin/reboot
}
