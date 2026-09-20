#!/bin/bash
# First-boot setup: the one deliberate step between "installed" and "usable".
#
# An installed Kryptik ships no usable account: root has no password and
# cannot log in at a terminal (/etc/securetty is empty), and the desktop is
# an ordinary authenticated user session. This runs before the login prompt
# on tty1. If an installer preseed exists on the state partition it is
# consumed (once): the user is created and root's password set from it;
# otherwise, when no regular user exists yet, it asks on the console for
# both. Administration afterwards is `su` from the wheel group with root's
# password - explicit, and protected by a password that only exists on the
# installed machine. On an install medium this does nothing.
set -u
say() { echo "kryptik-firstboot: $*"; }
media="$(sed -n 's/^media=//p' /run/kryptik/boot-identity 2>/dev/null)"
[ -n "$media" ] && { say "install medium; no setup"; exit 0; }
# A degraded state (sysinit.sh) is a tmpfs: an account created now would be
# gone at the next boot, and asking for a password for it would be a lie.
if [ -r /run/kryptik/state-degraded ]; then
    say "state is DEGRADED ($(cat /run/kryptik/state-degraded)); not creating accounts that would not persist"
    exit 0
fi

PRESEED=/var/lib/kryptik/firstboot.preseed
regular_user() { awk -F: '$3>=1000 && $3<65534 {print $1; exit}' /etc/passwd; }
has_password() { awk -F: -v u="$1" '$1==u && $2 ~ /^\$/ {ok=1} END {exit !ok}' /etc/shadow; }
# Done means a regular user and root can both authenticate, read from the
# account database and not from a marker: a setup cut short anywhere (the
# power, a failed passwd) is finished by the next boot instead of skipped.
# It used to stop at the first uid of 1000 or more, and root cannot log in,
# so a user made a moment before the power went was a machine nobody could use.
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

# Interactive: ask on tty1 for whatever is still missing. Bounded by a timeout
# so a headless machine still reaches a login prompt.
tty=/dev/tty1
[ -c "$tty" ] || tty=/dev/console
name="$(regular_user)"
if [ -z "$name" ]; then
    {
        echo
        echo "===== Kryptik first-boot setup ====="
        echo "No user account exists yet. Create the desktop user now."
        printf 'User name: '
    } > "$tty" 2>&1
    if ! read -r -t 600 name < "$tty"; then
        say "no answer within 10 minutes; the next boot asks again"
        exit 0
    fi
    name="$(printf '%s' "$name" | tr -d '[:space:]')"
    create_user "$name" > "$tty" 2>&1 || exit 0
fi
if ! has_password "$name"; then
    echo "Set a password for $name:" > "$tty"
    passwd "$name" < "$tty" > "$tty" 2>&1 || say "passwd failed; the next boot asks again"
fi
if ! has_password root; then
    echo "Set the administrator (root) password, used by su:" > "$tty"
    passwd root < "$tty" > "$tty" 2>&1 || say "root passwd failed; the next boot asks again"
fi
exit 0
