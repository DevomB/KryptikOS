#!/usr/bin/env bash

# A root shell on install media, a login prompt otherwise, on the kernel's active console.
s_console() {
    mkdir -p /usr/libexec
    cat > /usr/libexec/kryptik-console <<'EOF'
#!/bin/sh
# A shell on the active kernel console for the early getty service; takes an optional device name.

dev="$1"

# Wait out sysinit and firstboot asking here (ask.sh); 30 s each to start, so a console always comes.
for held in sysinit firstboot; do
    n=0
    until [ -e "/run/kryptik-$held" ] || [ "$n" -ge 150 ]; do sleep 0.2; n=$((n + 1)); done
    while [ "$(cat "/run/kryptik-$held" 2>/dev/null)" = running ]; do sleep 0.2; done
done

if [ -z "$dev" ]; then
    # The preferred console comes last ("tty0 ttyS0"); taking the first strands a headless login.
    if [ -r /sys/class/tty/console/active ]; then
        dev=$(awk '{print $NF}' < /sys/class/tty/console/active)
    fi
fi
[ -n "$dev" ] || dev=console

[ -e "/dev/$dev" ] || dev=console

# A virtual terminal is getty-tty1's: a second getty on tty0, where tty1 shows, would split its keys.
case "$dev" in
    tty[0-9]*) exec s6-pause ;;
esac

if [ -x /usr/sbin/agetty ]; then
    # Install media (kryptik.media= on the signed command line) get a root shell, others a login.
    if grep -qw 'kryptik\.media=[a-z]' /proc/cmdline 2>/dev/null; then
        exec /usr/sbin/agetty -n -l /usr/bin/bash --keep-baud \
             115200,57600,38400,9600 "$dev" vt220
    fi
    exec /usr/sbin/agetty --keep-baud 115200,57600,38400,9600 "$dev" vt220
fi

# No agetty: a bare shell on the device, as an unreachable console cannot be debugged at all.
exec setsid -c /usr/bin/bash -l < "/dev/$dev" > "/dev/$dev" 2>&1
EOF
    chmod 0755 /usr/libexec/kryptik-console
    sh -n /usr/libexec/kryptik-console || { echo "console wrapper has a syntax error"; return 1; }
    echo "installed /usr/libexec/kryptik-console"
}
