#!/bin/bash
# First-boot setup, before the tty1 login prompt. An installed system ships no
# usable account (root has no password, /etc/securetty is empty), so this
# creates the desktop user and sets root's password (for `su` from wheel), from
# the installer's preseed if there is one, else by asking on the console.
# Does nothing on an install medium.
set -u
say() { echo "kryptik-firstboot: $*"; }
# kryptik-console holds the serial console's getty back until this finishes,
# as it does for sysinit: both may be asking there.
echo running > /run/kryptik-firstboot
trap 'echo finished > /run/kryptik-firstboot' EXIT
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

# Ask on every console for whatever is missing (ask.sh). Every question has a
# time limit, so a headless machine still reaches a login prompt and
# boot-success still runs.
. /usr/libexec/kryptik/ask.sh
PROMPT_SECS=600
# Not passwd: without PAM it reads /dev/tty, which a boot service does not have.
set_password() {   # set_password USER: two matching answers, through chpasswd
    local p1 p2 err
    for _ in 1 2 3; do
        p1=$(ask -s "$PROMPT_SECS" "New password for $1: ") || return 1
        p2=$(ask -s "$PROMPT_SECS" "Again: ") || return 1
        if [ -n "$p1" ] && [ "$p1" = "$p2" ]; then
            err=$(printf '%s:%s\n' "$1" "$p1" | chpasswd 2>&1) && return 0
            tell "$err"
            return 1
        fi
        tell "The two answers differ, or are empty."
    done
    return 1
}
name="$(regular_user)"
if [ -z "$name" ]; then
    tell "" "===== Kryptik first-boot setup =====" \
         "No user account exists yet. Create the desktop user now."
    if ! name=$(ask "$PROMPT_SECS" "User name: "); then
        say "no answer within 10 minutes; the next boot asks again"
        exit 0
    fi
    name="$(printf '%s' "$name" | tr -d '[:space:]')"
    made=$(create_user "$name" 2>&1) && ok=1 || ok=
    tell "$made"
    [ -n "$ok" ] || exit 0
fi
if ! has_password "$name"; then
    tell "Set a password for $name:"
    set_password "$name" || say "no password set for $name; the next boot asks again"
fi
if ! has_password root; then
    tell "Set the administrator (root) password, used by su:"
    set_password root || say "no root password set; the next boot asks again"
fi
exit 0
