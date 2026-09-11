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
            up=$(s6-svstat -o up "/run/service/$svc" 2>/dev/null)
            # -o up,pid prints "true <pid>"; report the state plainly so the
            # host side is not matching an s6 output format.
            [ "$up" = "true" ] && say "svc_$svc=up" || say "svc_$svc=down"
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
# --- the catch-all log ------------------------------------------------------
# s6-svscan-log catches the output of every supervised daemon that does not
# have its own logger. It is the only place a daemon's complaint can be read
# after the fact, and nothing had ever looked at it.
if [ -d /run/uncaught-logs ]; then
    say "uncaught_logs=present"
    say "uncaught_files=$(ls -A /run/uncaught-logs 2>/dev/null | tr '
' ' ')"
    if [ -r /run/uncaught-logs/current ]; then
        tail -n 25 /run/uncaught-logs/current 2>/dev/null | sed 's/^/KRYPTIK_SMOKE: log: /'
    fi
else
    say "uncaught_logs=MISSING - no catch-all logger, daemon output is lost"
fi

# --- is shutdownd actually reading its fifo? -------------------------------
# Everything else about the shutdown path checks out - the fifo exists at the
# path s6-linux-init-hpr opens, shutdownd is supervised and up, rc.shutdown is
# executable - and yet a poweroff request produces no action and no diagnostic.
#
# So ask the daemon directly. s6-linux-init-shutdownd.c logs
# "unknown command: X" for any byte it does not recognise. If that line appears
# below, shutdownd is reading this fifo and the problem is in what happens
# after; if it does not, shutdownd is not reading this fifo at all and every
# other observation about it is beside the point.
say "fifo_probe=sending an invalid byte"
printf 'X' > /run/service/s6-linux-init-shutdownd/fifo 2>/dev/null     && say "fifo_probe_write=ok" || say "fifo_probe_write=failed"
sleep 2
if [ -r /run/uncaught-logs/current ]; then
    tail -n 5 /run/uncaught-logs/current 2>/dev/null       | grep -a "unknown command" | sed 's/^/KRYPTIK_SMOKE: probe: /'       || say "fifo_probe_result=no 'unknown command' line - shutdownd is not reading it"
fi
say "shutdownd_pid_before=$(s6-svstat -o pid /run/service/s6-linux-init-shutdownd 2>/dev/null)"

# --- the shutdown path, before we depend on it -----------------------------
# /sbin/poweroff is s6-linux-init-hpr, which writes to shutdownd's fifo under
# /run/s6-linux-init. Stage 1 warned it could not write /run/s6-linux-init/env,
# so report what is actually there rather than inferring it from the hang.
say "run_entries=$(ls -A /run 2>/dev/null | tr '
' ' ')"
# The fifo s6-linux-init-hpr actually opens. The first version of this check
# looked under /run/s6-linux-init and reported "absent" about a path nothing
# uses - the fifo lives in shutdownd's own service directory, which `strings`
# on the hpr binary says plainly.
say "shutdownd_dir=$(ls -A /run/service/s6-linux-init-shutdownd 2>/dev/null | tr '
' ' ')"
if s6-svstat /run/service/s6-linux-init-shutdownd >/dev/null 2>&1; then
    say "svc_shutdownd=$(s6-svstat -o up /run/service/s6-linux-init-shutdownd 2>/dev/null)"
else
    say "svc_shutdownd=not-supervised"
fi

# Try the request three ways, narrowing as we go. shutdownd demonstrably reads
# this fifo (the invalid-byte probe above proves it), so the question is which
# part of what hpr does between opening the fifo and sending the command is
# getting in the way. hpr writes wtmp and broadcasts a wall message in between;
# -d skips the first and -W the second.
#
# Whichever variant works, the machine powers off here and the rest of this
# script never runs - which is the point. The transcript then says which one
# did it.
say "POWEROFF"
say "shutdownd_fifo=$( [ -p /run/service/s6-linux-init-shutdownd/fifo ] && echo present || echo absent )"

# Request the shutdown and then GET OUT OF THE WAY.
#
# This script runs as an s6-rc oneshot. rc.shutdown brings every service down
# with `s6-rc -bDa change`, and "every service" includes this one. Waiting here
# for the machine to stop means s6-rc waits for this oneshot to exit while this
# oneshot waits for s6-rc to finish shutting down - a deadlock.
#
# That deadlock is what three boots read as "shutdownd received the command and
# ignored it". It never ignored anything: it ran rc.shutdown exactly as it
# should, and rc.shutdown blocked in s6-rc before reaching its first echo, so
# there was nothing in the log either. The test was breaking the thing it was
# measuring.
#
# The watchdog is detached with setsid so the service teardown cannot take it
# with it, and it announces itself loudly - tools/image/boot-smoke.sh asserts
# that line is absent, so a stuck shutdown can never read as a clean one.
setsid sh -c 'sleep 90
    echo "KRYPTIK_SMOKE: POWEROFF_DID_NOT_TAKE_EFFECT after 90s" > /dev/console 2>/dev/null
    sync
    [ -w /proc/sysrq-trigger ] && echo o > /proc/sysrq-trigger'     </dev/null >/dev/null 2>&1 &

/sbin/poweroff || say "poweroff_rc=$?"
say "poweroff_requested_now_exiting"
exit 0
