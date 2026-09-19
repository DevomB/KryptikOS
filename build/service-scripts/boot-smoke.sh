#!/bin/sh
# Report what this machine actually is. Every boot, on the console.
#
# The report used to be armed by kryptik.smoke=1 on the kernel command line.
# The command line is now part of the signed kernel and cannot be
# changed per boot, so the REPORT runs unconditionally - it is harmless and
# useful - and only the POWEROFF at the end is armed: on install media by the
# kryptik-testctl control disk (see testctl.sh), and on an installed system
# not by this script at all; a test driver logs in over the serial console
# and asks for it, which exercises the login path the product ships.
. /usr/libexec/kryptik/testctl.sh

say() { echo "KRYPTIK_SMOKE: $*"; }

echo
say "BEGIN"

# --- identity: what is actually running, measured here rather than assumed --
say "pid1=$(cat /proc/1/comm 2>/dev/null)"
say "kernel=$(uname -r)"
say "kernel_version_full=$(cat /proc/version 2>/dev/null | head -c 200)"
say "arch=$(uname -m)"
if [ -r /etc/os-release ]; then
    . /etc/os-release 2>/dev/null
    say "os_id=${ID:-?} build_id=${BUILD_ID:-?} version_id=${VERSION_ID:-?}"
fi
if [ -r /etc/kryptik-image.json ]; then
    say "image_json_present=yes"
    sed 's/^/KRYPTIK_SMOKE: image: /' /etc/kryptik-image.json
fi
say "compiler=$(gcc -dumpmachine 2>/dev/null || echo none)"
say "cmdline=$(cat /proc/cmdline 2>/dev/null | sed 's/dm-mod.create="[^"]*"/dm-mod.create=<verity table>/')"
if [ -r /run/kryptik/boot-identity ]; then
    say "boot_identity=$(tr '\n' ' ' < /run/kryptik/boot-identity)"
fi
say "efi=$([ -d /sys/firmware/efi ] && echo yes || echo no)"
say "secureboot=$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ' || echo unreadable)"

# --- the filesystem we booted from ----------------------------------------
# A root the kernel mounted itself appears in /proc/mounts as "/dev/root",
# whatever device it is. Name the device: mountinfo carries its
# major:minor, and sysfs names the block device behind that.
root_line="$(awk '$2=="/"{print $1, $3, $4; exit}' /proc/mounts)"
case "$root_line" in
    /dev/root*)
        mm="$(awk '$5=="/"{print $3; exit}' /proc/self/mountinfo 2>/dev/null)"
        if [ -n "$mm" ] && [ -e "/sys/dev/block/$mm" ]; then
            root_line="/dev/$(basename "$(readlink -f "/sys/dev/block/$mm")") ${root_line#/dev/root }"
        fi ;;
esac
say "root_source=$root_line"
if [ -r /sys/block/dm-0/dm/name ]; then
    say "dm0_name=$(cat /sys/block/dm-0/dm/name)"
    say "dm0_table=$(dmsetup table 2>/dev/null | head -3 | tr '\n' ';' | sed 's/ [0-9a-f]\{64\} / <hash> /g')"
fi
say "verity_root=$(dmsetup status kroot 2>/dev/null || echo none)"
for m in /proc /sys /dev/pts /dev/shm /run /var /etc /home /tmp; do
    if mountpoint -q "$m" 2>/dev/null; then say "mount_ok=$m"; else say "mount_MISSING=$m"; fi
done
say "var_source=$(awk '$2=="/var"{print $1, $3; exit}' /proc/mounts)"
say "etc_source=$(awk '$2=="/etc"{print $3; exit}' /proc/mounts)"
say "root_writable=$(touch /.kryptik-write-probe 2>/dev/null && { rm -f /.kryptik-write-probe; echo YES; } || echo no)"
say "state_marker=$(cat /var/.kryptik-state 2>/dev/null || echo none)"

# --- did the service manager actually bring things up? ---------------------
if [ -d /run/service ]; then
    say "scandir=/run/service"
    for svc in eudev getty-tty1 seatd watchdog; do
        if s6-svstat "/run/service/$svc" >/dev/null 2>&1; then
            up=$(s6-svstat -o up "/run/service/$svc" 2>/dev/null)
            [ "$up" = "true" ] && say "svc_$svc=up" || say "svc_$svc=down"
        else
            say "svc_$svc=not-supervised"
        fi
    done
fi
# A watchdog nobody feeds resets a healthy machine, and one that is not
# there protects nothing; both are worth a line. nowayout=1 is the kernel
# saying that closing the device will not stop it.
wd_n=0
for wd in /sys/class/watchdog/watchdog[0-9]*; do
    [ -d "$wd" ] || continue
    wd_n=$((wd_n + 1))
    say "watchdog ${wd##*/}: $(cat "$wd/identity" 2>/dev/null || echo unknown) state=$(cat "$wd/state" 2>/dev/null || echo ?) timeout=$(cat "$wd/timeout" 2>/dev/null || echo ?)s nowayout=$(cat "$wd/nowayout" 2>/dev/null || echo ?)"
done
say "watchdog_devices=${wd_n}"
if [ -x /usr/bin/s6-rc ]; then
    say "s6rc_up_begin"
    s6-rc -a list 2>/dev/null | sed 's/^/KRYPTIK_SMOKE: up: /'
    say "s6rc_up_end"
fi

# --- the hardening tunables that used never to ship ------------------------
for k in kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope \
         kernel.unprivileged_bpf_disabled kernel.kexec_load_disabled \
         fs.protected_symlinks kernel.randomize_va_space; do
    v=$(sysctl -n "$k" 2>/dev/null || echo "unreadable")
    say "sysctl $k=$v"
done

# --- the zone model, on this kernel ---------------------------------------
say "kryptikd_check_begin"
/usr/bin/kryptikd check --zones /usr/lib/kryptik/zones 2>&1 | sed 's/^/KRYPTIK_SMOKE: kd: /'
say "kryptikd_check_rc=$?"
say "kryptikd_check_end"
say "lsm=$(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"
# The CPU's microcode revision, and what the kernel's early loader said about
# the copy built into it. Under a hypervisor the loader is off and there is no
# message; on a real machine this line is the evidence that the update the
# signed kernel carries was applied.
say "microcode=$(awk -F': ' '/^microcode/ {print $2; exit}' /proc/cpuinfo 2>/dev/null) loader=$(dmesg 2>/dev/null | grep -m1 -o 'microcode: .*' || echo none)"
say "cgroup2=$(awk '$3=="cgroup2"{print $2; exit}' /proc/mounts 2>/dev/null || echo none)"

# --- users and the login path -------------------------------------------
say "users=$(awk -F: '$3>=1000 && $3<65534 {printf "%s ", $1}' /etc/passwd 2>/dev/null)"
say "root_password=$(awk -F: '$1=="root"{print ($2 ~ /^[!*]/ || $2=="") ? "none" : "set"}' /etc/shadow 2>/dev/null)"
say "securetty=$([ -e /etc/securetty ] && echo "present ($(wc -l < /etc/securetty) lines)" || echo absent)"
say "login_binary=$([ -x /usr/bin/login ] && echo present || echo MISSING)"
# The serial console's getty, which a test driver logs in at. A boot whose
# getty is down, restarting or blocked looks identical to a healthy one from
# the host (this report ends, then silence), and the getty's own stderr goes
# to the catch-all log, so this is the only record of its state at the moment
# the driver starts knocking.
for svc in /run/service/*early-getty*; do
    [ -d "$svc" ] || continue
    say "early_getty=$(s6-svstat "$svc" 2>&1 | head -c 160)"
    pid="$(s6-svstat -p "$svc" 2>/dev/null)"
    if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
        say "early_getty_pid=${pid} comm=$(cat "/proc/$pid/comm" 2>/dev/null) state=$(awk '/^State:/{print $2}' "/proc/$pid/status" 2>/dev/null) wchan=$(cat "/proc/$pid/wchan" 2>/dev/null) stdin=$(readlink "/proc/$pid/fd/0" 2>/dev/null)"
    fi
done
say "boot_success=$(cat /var/lib/kryptik/boot/last-result 2>/dev/null || echo none)"

# --- the catch-all log ------------------------------------------------------
if [ -d /run/uncaught-logs ]; then
    say "uncaught_logs=present"
    if [ -r /run/uncaught-logs/current ]; then
        tail -n 25 /run/uncaught-logs/current 2>/dev/null | sed 's/^/KRYPTIK_SMOKE: log: /'
    fi
else
    say "uncaught_logs=MISSING - no catch-all logger, daemon output is lost"
fi
say "END"
echo

# --- power off only when a test asked, and only on install media -----------
if testctl_load && [ "$(testctl_get smoke_poweroff)" = "1" ]; then
    # If an install was requested too, it runs from its own service; give it
    # its own say before shutting down (installer-run waits for us otherwise).
    wait_s="$(testctl_get install_wait)"
    [ -n "$wait_s" ] && sleep "$wait_s"
    say "POWEROFF"
    say "shutdownd_fifo=$( [ -p /run/service/s6-linux-init-shutdownd/fifo ] && echo present || echo absent )"
    # Detached watchdog: if the clean path does not take effect, say so loudly
    # (the host asserts this line is absent) and force it.
    setsid sh -c 'sleep 90
        echo "KRYPTIK_SMOKE: POWEROFF_DID_NOT_TAKE_EFFECT after 90s" > /dev/console 2>/dev/null
        sync
        [ -w /proc/sysrq-trigger ] && echo o > /proc/sysrq-trigger' </dev/null >/dev/null 2>&1 &
    /sbin/poweroff || say "poweroff_rc=$?"
    say "poweroff_requested_now_exiting"
fi
exit 0
