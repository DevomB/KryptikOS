#!/usr/bin/env bash

# Everything a boot needs, checked from the target's point of view.
s_boot_check() {
    local n=0
    chk() {  # chk <description> <path> [x]
        if [[ -e "$2" ]] && { [[ "${3:-}" != x ]] || [[ -x "$2" ]]; }; then
            printf '  ok      %s (%s)\n' "$1" "$2"
        else
            printf '  MISSING %s (%s)\n' "$1" "$2"; n=$((n + 1))
        fi
    }

    chk "init"              /sbin/init x
    chk "poweroff"          /sbin/poweroff x
    chk "reboot"            /sbin/reboot x
    chk "shutdown"          /sbin/shutdown x
    chk "s6-svscan"         /usr/bin/s6-svscan x
    chk "console wrapper"   /usr/libexec/kryptik-console x
    chk "stage 2 script"    /usr/lib/s6-linux-init/current/scripts/rc.init x
    chk "shutdown script"   /usr/lib/s6-linux-init/current/scripts/rc.shutdown x
    chk "shell"             /bin/sh x
    chk "bash"              /usr/bin/bash x
    chk "os-release"        /etc/os-release
    chk "fstab"             /etc/fstab
    chk "C library"         /usr/lib/libc.so.6
    chk "dynamic loader"    /usr/lib/ld-linux-x86-64.so.2
    # The desktop.
    chk "compositor"        /usr/bin/dwl x
    chk "terminal"          /usr/bin/havoc x
    chk "seatd"             /usr/bin/seatd x
    chk "kryptik-launch"    /usr/bin/kryptik-launch x
    chk "kryptik-session"   /usr/bin/kryptik-session x
    chk "kryptik-chrome"    /usr/bin/kryptik-chrome x
    chk "havoc font"        /usr/share/fonts/TTF/DejaVuSansMono.ttf
    chk "kryptik-wlproxy"   /usr/bin/kryptik-wlproxy x
    chk "kryptikd"          /usr/bin/kryptikd x
    # The net zone's Wi-Fi, and the regulatory database a radio needs before it may transmit.
    chk "wpa_supplicant"    /usr/sbin/wpa_supplicant x
    chk "wpa_cli"           /usr/sbin/wpa_cli x
    chk "iw"                /usr/sbin/iw x
    chk "CA bundle"         /etc/ssl/certs/ca-certificates.crt
    chk "regulatory.db"     /lib/firmware/regulatory.db.zst
    chk "regulatory.db.p7s" /lib/firmware/regulatory.db.p7s.zst

    # /sbin/init must be reachable by the exact path the kernel uses.
    if [[ -x /sbin/init ]]; then
        printf '  ok      /sbin/init resolves to %s\n' "$(readlink -f /sbin/init)"
    fi

    # Without the early getty the machine boots to silence.
    local svcdir=/usr/lib/s6-linux-init/current/run-image/service
    if [[ -d "$svcdir" ]]; then
        echo "  services in the boot image:"
        local s
        for s in "$svcdir"/*; do
            [[ -e "$s" ]] || continue
            printf '    %s\n' "$(basename "$s")"
        done
        if compgen -G "${svcdir}/*getty*" > /dev/null; then
            echo "  ok      an early getty service exists"
        else
            echo "  MISSING early getty service"; n=$((n + 1))
        fi
    else
        echo "  MISSING ${svcdir}"; n=$((n + 1))
    fi

    # Without the service database the machine boots to a bare console.
    if [[ -d /usr/lib/kryptik/s6-rc/compiled ]]; then
        local nsvc
        nsvc="$(s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled list all 2>/dev/null | grep -c . || echo 0)"
        printf '  ok      s6-rc database (%s services)\n' "$nsvc"
        if s6-rc-db -c /usr/lib/kryptik/s6-rc/compiled list all 2>/dev/null | grep -qx default; then
            echo "  ok      a 'default' bundle exists for rc.init to bring up"
        else
            echo "  MISSING a 'default' bundle"; n=$((n + 1))
        fi
    else
        echo "  MISSING /usr/lib/kryptik/s6-rc/compiled - the image will boot to a bare console"
        n=$((n + 1))
    fi

    chk "sysctl fragments"  /usr/lib/kryptik/sysctl.d
    chk "zone definitions"  /usr/lib/kryptik/zones/work.toml
    chk "zone policies"     /usr/lib/kryptik/zones/policy/work.seccomp
    chk "device helper"     /usr/libexec/kryptik/devices.sh x
    chk "boot scripts"      /usr/libexec/kryptik/sysinit.sh x
    chk "test control helper" /usr/libexec/kryptik/testctl.sh
    chk "boot-success"      /usr/libexec/kryptik/boot-success.sh x
    chk "watchdog feeder"   /usr/libexec/kryptik/watchdog.sh x
    chk "first-boot setup"  /usr/libexec/kryptik/firstboot.sh x
    chk "login"             /usr/bin/login x
    chk "efiboot"           /usr/sbin/kryptik-efiboot x
    chk "updater"           /usr/sbin/kryptik-update x
    chk "recover"           /usr/sbin/kryptik-recover x
    chk "ssh-keygen"        /usr/bin/ssh-keygen x
    chk "cryptsetup"        /usr/sbin/cryptsetup x
    chk "seatd"             /usr/bin/seatd x

    if [[ -e /etc/kryptik/kryptikd-absent ]]; then
        echo "  NOTE    kryptikd is not installed in this image (see the kryptikd step)"
    fi

    [[ "$n" -eq 0 ]] || { echo "${n} boot prerequisite(s) missing"; return 1; }
    echo "the sysroot has what a boot needs"
}
