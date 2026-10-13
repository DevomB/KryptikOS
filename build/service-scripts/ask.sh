#!/bin/sh
# Boot-time questions on every console: /dev/console may be a serial port the person is not at.
# POSIX sh, sourced by sysinit and firstboot.
#   consoles           the console devices, one per line
#   tell LINE...       each LINE on every console
#   ask [-s] SECS Q    Q on every console; the first line typed on any goes to stdout.
#                      -s keeps echo off; SECS 0 waits forever; fails if nothing comes in time.

ask_dir=/run/kryptik

consoles() {
    _c_active=$(cat /sys/class/tty/console/active 2>/dev/null) || _c_active=''
    for _c in ${_c_active:-console}; do
        [ -c "/dev/$_c" ] && echo "/dev/$_c"
    done
    return 0
}

tell() {
    for _t_dev in $(consoles); do
        { printf '%s\n' "$@" > "$_t_dev"; } 2>/dev/null || true
    done
}

# One reader per console, first line wins; stty never discards input, so an early answer is kept.
ask() {
    _a_quiet=''
    [ "$1" = -s ] && { _a_quiet=1; shift; }
    _a_secs=$1 _a_q=$2
    _a_devs=$(consoles)
    rm -f "$ask_dir/ask"
    mkfifo -m 0600 "$ask_dir/ask" || return 1
    exec 3<> "$ask_dir/ask"
    rm -f "$ask_dir/ask"
    _a_pids='' _a_n=0
    for _a_dev in $_a_devs; do
        (
            [ -z "$_a_quiet" ] || stty -echo < "$_a_dev" 2>/dev/null || true
            printf '%s' "$_a_q" > "$_a_dev" 2>/dev/null || true
            if IFS= read -r _a_line < "$_a_dev"; then
                printf 'A%s %s\n' "$_a_dev" "$_a_line"
            else
                echo E
            fi >&3
        ) < /dev/null > /dev/null 2>&1 &
        _a_pids="$_a_pids $!"
        _a_n=$((_a_n + 1))
    done
    if [ "$_a_secs" -gt 0 ]; then
        (
            trap 'kill "$!" 2>/dev/null; exit 0' TERM
            sleep "$_a_secs" & wait "$!"
            echo T >&3
        ) < /dev/null > /dev/null 2>&1 &
        _a_pids="$_a_pids $!"
    fi
    _a_ans='' _a_from='' _a_ended=0
    while [ "$_a_ended" -lt "$_a_n" ] && IFS= read -r _a_msg <&3; do
        case "$_a_msg" in
            A*) _a_msg=${_a_msg#A}; _a_from=${_a_msg%% *}; _a_ans=${_a_msg#* }; break ;;
            T) break ;;
            *) _a_ended=$((_a_ended + 1)) ;;
        esac
    done
    kill $_a_pids 2>/dev/null || true
    exec 3<&-
    for _a_dev in $_a_devs; do
        [ -z "$_a_quiet" ] || { stty echo < "$_a_dev"; } 2>/dev/null || true
        # The answering terminal echoed its own newline, unless echo was off.
        [ "$_a_dev" = "$_a_from" ] && [ -z "$_a_quiet" ] && continue
        { echo > "$_a_dev"; } 2>/dev/null || true
    done
    [ -n "$_a_from" ] || return 1
    # printf is a builtin, so the answer never appears as an argument.
    printf '%s' "$_a_ans"
}
