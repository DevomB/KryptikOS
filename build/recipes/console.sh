#!/usr/bin/env bash
# console: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# The console: a root shell on install media (agetty -n -l skips login), a
# login prompt otherwise. The device is the kernel's active console, not a
# guess: a serial port when there is one; a virtual terminal is left to
# getty-tty1.
s_console() {
    mkdir -p /usr/libexec
    cat > /usr/libexec/kryptik-console <<'EOF'
#!/bin/sh
# Start an interactive shell on the active kernel console.
#
# Called by the s6-linux-init early getty service. Takes an optional device
# name; otherwise asks the kernel which console it is using.

dev="$1"

# sysinit and then firstboot may be asking on this console (ask.sh: the state
# passphrase, the first account). Each gets 30 s to start (a broken service
# database must still end in a console); once one has, the console is its own
# until it ends.
for held in sysinit firstboot; do
    n=0
    until [ -e "/run/kryptik-$held" ] || [ "$n" -ge 150 ]; do sleep 0.2; n=$((n + 1)); done
    while [ "$(cat "/run/kryptik-$held" 2>/dev/null)" = running ]; do sleep 0.2; done
done

if [ -z "$dev" ]; then
    # /sys/class/tty/console/active lists the kernel-preferred console last.
    # With both video and serial consoles that is "tty0 ttyS0", so taking the
    # first field races rc.init's /sys mount and strands a headless login on tty0.
    if [ -r /sys/class/tty/console/active ]; then
        dev=$(awk '{print $NF}' < /sys/class/tty/console/active)
    fi
fi
[ -n "$dev" ] || dev=console

[ -e "/dev/$dev" ] || dev=console

# A virtual terminal is getty-tty1's. With no serial port the kernel's console
# is tty0, the terminal tty1 is shown on, and a second getty there would split
# its keystrokes.
case "$dev" in
    tty[0-9]*) exec s6-pause ;;
esac

if [ -x /usr/sbin/agetty ]; then
    # On an install medium (kryptik.media= is on the signed command line) the
    # serial console is the installer's root shell: -n -l skips login(1).
    # On an installed system it is an ordinary login prompt; root is locked,
    # so it admits the first-boot user, not root.
    if grep -qE '(^| )kryptik\.media=[a-z]+( |$)' /proc/cmdline 2>/dev/null; then
        exec /usr/sbin/agetty -n -l /usr/bin/bash --keep-baud \
             115200,57600,38400,9600 "$dev" vt220
    fi
    exec /usr/sbin/agetty --keep-baud 115200,57600,38400,9600 "$dev" vt220
fi

# No agetty: put a shell directly on the device. Less capable - no baud
# handling, no controlling-terminal setup beyond setsid - but a system whose
# console is unreachable cannot be debugged at all.
exec setsid -c /usr/bin/bash -l < "/dev/$dev" > "/dev/$dev" 2>&1
EOF
    chmod 0755 /usr/libexec/kryptik-console
    sh -n /usr/libexec/kryptik-console || { echo "console wrapper has a syntax error"; return 1; }
    echo "installed /usr/libexec/kryptik-console"
}
