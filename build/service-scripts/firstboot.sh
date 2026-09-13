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

PRESEED=/var/lib/kryptik/firstboot.preseed
has_user() { awk -F: '$3>=1000 && $3<65534 {found=1} END {exit !found}' /etc/passwd; }

create_user() {   # create_user NAME [HASH]
    name="$1"; hash="${2:-}"
    case "$name" in
        ''|*[!a-z0-9_-]*|-*) say "refusing user name '$name'"; return 1 ;;
    esac
    getent group seat >/dev/null 2>&1 || groupadd -r seat
    getent group kryptik >/dev/null 2>&1 || groupadd -r kryptik
    useradd -m -k /etc/skel -s /usr/bin/bash -G seat,kryptik,wheel "$name" || return 1
    if [ -n "$hash" ]; then
        # The hash goes through stdin, never argv.
        printf '%s:%s\n' "$name" "$hash" | chpasswd -e || return 1
    fi
    say "created user '$name' (groups: seat kryptik wheel)"
}

if [ -r "$PRESEED" ]; then
    name="$(sed -n 's/^user=//p' "$PRESEED" | head -1)"
    hash="$(sed -n 's/^password_hash=//p' "$PRESEED" | head -1)"
    rhash="$(sed -n 's/^root_password_hash=//p' "$PRESEED" | head -1)"
    if [ -n "$name" ] && [ -n "$hash" ]; then
        if id "$name" >/dev/null 2>&1; then
            say "preseed user '$name' already exists"
        else
            create_user "$name" "$hash" || say "preseed FAILED"
        fi
    else
        say "preseed file is incomplete; ignoring it"
    fi
    if [ -n "$rhash" ]; then
        printf 'root:%s\n' "$rhash" | chpasswd -e && say "root password set from the preseed"
    fi
    rm -f "$PRESEED"
fi

if has_user; then
    say "a user account exists; nothing to do"
    exit 0
fi

# Interactive: ask on tty1. Bounded by a timeout so a headless machine still
# reaches a login prompt (root is locked, so that prompt is only useful once a
# user exists - the setup can be repeated by running kryptik-firstboot as
# root from the recovery console).
tty=/dev/tty1
[ -c "$tty" ] || tty=/dev/console
{
    echo
    echo "===== Kryptik first-boot setup ====="
    echo "No user account exists yet. Create the desktop user now."
    printf 'User name: '
} > "$tty" 2>&1
name=""
if read -r -t 600 name < "$tty"; then
    name="$(printf '%s' "$name" | tr -d '[:space:]')"
    if create_user "$name" >"$tty" 2>&1; then
        echo "Set a password for $name:" > "$tty"
        passwd "$name" < "$tty" > "$tty" 2>&1 || say "passwd failed; run kryptik-firstboot again"
        echo "Set the administrator (root) password, used by su:" > "$tty"
        passwd root < "$tty" > "$tty" 2>&1 || say "root passwd failed; run kryptik-firstboot again"
    fi
else
    say "no answer within 10 minutes; a user can be created later with kryptik-firstboot"
fi
exit 0
