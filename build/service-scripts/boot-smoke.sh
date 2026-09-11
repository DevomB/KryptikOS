#!/bin/sh
# Report what this machine actually is, then power it off.
#
# Runs ONLY when the kernel command line contains kryptik.smoke=1. It is in
# the default bundle, so without that guard every ordinary boot would shut
# itself down - and the guard is the kernel command line rather than a file in
# the image, because the image is the thing under test and a test must not be
# able to arm itself.
grep -qw 'kryptik.smoke=1' /proc/cmdline 2>/dev/null || {
    echo "boot-smoke: not requested on the kernel command line; nothing to do"
    exit 0
}

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
    say "os_id=${ID:-?} build_id=${BUILD_ID:-?}"
fi
if [ -r /etc/kryptik-image.json ]; then
    say "image_json_present=yes"
    sed 's/^/KRYPTIK_SMOKE: image: /' /etc/kryptik-image.json
fi
say "compiler=$(gcc -dumpmachine 2>/dev/null || echo none)"

# --- the filesystem we booted from ----------------------------------------
say "root_source=$(awk '$2=="/"{print $1, $3; exit}' /proc/mounts)"
for m in /proc /sys /dev/pts /dev/shm /run; do
    if mountpoint -q "$m" 2>/dev/null; then say "mount_ok=$m"; else say "mount_MISSING=$m"; fi
done

# --- did the service manager actually bring things up? ---------------------
if [ -d /run/service ]; then
    say "scandir=/run/service"
    for svc in eudev getty-tty1; do
        if s6-svstat "/run/service/$svc" >/dev/null 2>&1; then
            say "svc_$svc=$(s6-svstat -o up,pid "/run/service/$svc" 2>/dev/null | tr '\n' ' ')"
        else
            say "svc_$svc=not-supervised"
        fi
    done
fi
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
/usr/bin/kryptikd check --zones /etc/kryptik/zones 2>&1 | sed 's/^/KRYPTIK_SMOKE: kd: /'
say "kryptikd_check_rc=$?"
say "kryptikd_check_end"
say "lsm=$(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"
say "cgroup2=$(awk '$3=="cgroup2"{print $2; exit}' /proc/mounts 2>/dev/null || echo none)"

say "END"
echo

# --- and shut down, which is itself under test ----------------------------
say "POWEROFF"
/sbin/poweroff
