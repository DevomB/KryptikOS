#!/bin/bash
# First-boot setup, before the tty1 login prompt. An installed system ships no
# usable account (root has no password, /etc/securetty is empty), so this
# creates the desktop user and sets root's password (for `su` from wheel), from
# the installer's preseed if there is one, else by asking on the console.
# Does nothing on an install medium.
set -u
say() { echo "kryptik-firstboot: $*"; }
media="$(sed -n 's/^media=//p' /run/kryptik/boot-identity 2>/dev/null)"
[ -n "$media" ] && { say "install medium; no setup"; exit 0; }
# A degraded state is a tmpfs (sysinit.sh); an account made now would not last.
if [ -r /run/kryptik/state-degraded ]; then
    say "state is DEGRADED ($(cat /run/kryptik/state-degraded)); not creating accounts that would not persist"
    exit 0
fi

PRESEED=/var/lib/kryptik/firstboot.preseed
regular_user() { awk -F: '$3>=1000 && $3<65534 {print $1; exit}' /etc/passwd; }
has_password() { awk -F: -v u="$1" '$1==u && $2 ~ /^\$/ {ok=1} END {exit !ok}' /etc/shadow; }
# Done when a regular user and root can both authenticate, judged from the
# account database rather than a marker, so the next boot finishes a setup
# that was cut short.
complete() { u="$(regular_user)"; [ -n "$u" ] && has_password "$u" && has_password root; }

create_user() {   # create_user NAME
    case "$1" in
        ''|*[!a-z0-9_-]*|-*) say "refusing user name '$1'"; return 1 ;;
    esac
    getent group seat >/dev/null 2>&1 || groupadd -r seat
    getent group kryptik >/dev/null 2>&1 || groupadd -r kryptik
    useradd -m -k /etc/skel -s /usr/bin/bash -G seat,kryptik,wheel "$1" || return 1
    say "created user '$1' (groups: seat kryptik wheel)"
}

if complete; then
    rm -f "$PRESEED"
    say "a user account exists; nothing to do"
    exit 0
fi

if [ -r "$PRESEED" ]; then
    name="$(sed -n 's/^user=//p' "$PRESEED" | head -1)"
    hash="$(sed -n 's/^password_hash=//p' "$PRESEED" | head -1)"
    rhash="$(sed -n 's/^root_password_hash=//p' "$PRESEED" | head -1)"
    if [ -n "$name" ] && [ -n "$hash" ]; then
        id "$name" >/dev/null 2>&1 || create_user "$name" || say "preseed FAILED"
        # The hashes go through stdin, never argv.
        printf '%s:%s\n' "$name" "$hash" | chpasswd -e || say "preseed FAILED: the user's password was not set"
    else
        say "preseed file is incomplete; ignoring it"
    fi
    if [ -n "$rhash" ]; then
        printf 'root:%s\n' "$rhash" | chpasswd -e && say "root password set from the preseed"
    fi
    # Kept until it has done its work: a boot cut short above reads it again.
    if complete; then rm -f "$PRESEED"; exit 0; fi
fi

# Ask on tty1 for whatever is missing. Every question has a time limit, so a
# headless machine still reaches a login prompt and boot-success still runs.
PROMPT_SECS=600
tty=/dev/tty1
[ -c "$tty" ] || tty=/dev/console
# Not passwd: without PAM it reads /dev/tty, which a boot service does not have.
set_password() {   # set_password USER: two matching answers on $tty, through chpasswd
    local p1 p2
    for _ in 1 2 3; do
        printf 'New password for %s: ' "$1" > "$tty"
        read -r -s -t "$PROMPT_SECS" p1 < "$tty" || return 1
        printf '\nAgain: ' > "$tty"
        read -r -s -t "$PROMPT_SECS" p2 < "$tty" || return 1
        echo > "$tty"
        if [ -n "$p1" ] && [ "$p1" = "$p2" ]; then
            printf '%s:%s\n' "$1" "$p1" | chpasswd
            return
        fi
        echo "The two answers differ, or are empty." > "$tty"
    done
    return 1
}
name="$(regular_user)"
if [ -z "$name" ]; then
    {
        echo
        echo "===== Kryptik first-boot setup ====="
        echo "No user account exists yet. Create the desktop user now."
        printf 'User name: '
    } > "$tty" 2>&1
    if ! read -r -t "$PROMPT_SECS" name < "$tty"; then
        say "no answer within 10 minutes; the next boot asks again"
        exit 0
    fi
    name="$(printf '%s' "$name" | tr -d '[:space:]')"
    create_user "$name" > "$tty" 2>&1 || exit 0
fi
if ! has_password "$name"; then
    echo "Set a password for $name:" > "$tty"
    set_password "$name" 2> "$tty" || say "no password set for $name; the next boot asks again"
fi
if ! has_password root; then
    echo "Set the administrator (root) password, used by su:" > "$tty"
    set_password root 2> "$tty" || say "no root password set; the next boot asks again"
fi
exit 0
