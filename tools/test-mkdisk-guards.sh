#!/usr/bin/env bash
#
# mkdisk.sh runs as root and does `rm -f "$OUT"` before writing gigabytes.
# These checks prove it refuses to aim that at anything but a regular file.
#
# The point that makes them worth having is the last one: a guard that refuses
# EVERYTHING would pass every denial below and be useless. So one case must get
# past the guard and fail for a different reason.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MKDISK="${ROOT}/tools/image/mkdisk.sh"
pass=0; fail=0
work=""
cleanup() { [[ -n "$work" && -d "$work" ]] && rm -rf "$work"; }
trap cleanup EXIT INT TERM

green() { printf '  PASS  %s\n' "$*"; pass=$((pass + 1)); }
red()   { printf '  FAIL  %s\n' "$*"; fail=$((fail + 1)); }
note()  { printf '        %s\n' "$*"; }

[[ -x "$MKDISK" ]] || { printf 'missing: %s\n' "$MKDISK"; exit 1; }
work="$(mktemp -d)" || exit 1
mkdir -p "${work}/sysroot"

# Runs mkdisk and reports what it said, without ever letting it get far enough
# to write anything: every case here dies during argument validation.
run() { "$MKDISK" --sysroot "${work}/sysroot" --out "$1" --size 1G 2>&1 || true; }

refuses_as_device() {
    local what="$1" target="$2" out
    out="$(run "$target")"
    case "$out" in
        *"refusing to write an image to"*|*"refusing to write an image through"*)
            green "${what}: refused" ;;
        *)  red "${what}: NOT refused by the path guard"
            printf '%s\n' "$out" | head -3 | sed 's/^/        /' ;;
    esac
}

echo "-- paths that must be refused outright"
refuses_as_device "a block device path (/dev/sda)"      "/dev/sda"
refuses_as_device "a character device (/dev/null)"      "/dev/null"
refuses_as_device "somewhere under /boot"               "/boot/kryptik.img"
refuses_as_device "somewhere under /etc"                "/etc/kryptik.img"
refuses_as_device "somewhere under /proc"               "/proc/kryptik.img"

mkfifo "${work}/afifo"
refuses_as_device "an existing fifo"                    "${work}/afifo"

mkdir -p "${work}/adir"
refuses_as_device "an existing directory"               "${work}/adir"

ln -sfn /dev/sda "${work}/sneaky.img"
refuses_as_device "a symlink pointing at a device"      "${work}/sneaky.img"

echo
echo "-- a path that does not exist at all is a clear error, not a write"
out="$(run "${work}/nosuchdir/x.img")"
case "$out" in
    *"directory for --out does not exist"*) green "a missing parent directory: refused" ;;
    *) red "a missing parent directory was not caught"
       printf '%s\n' "$out" | head -3 | sed 's/^/        /' ;;
esac

echo
echo "-- the control: an ordinary path must get PAST the guard"
# It still fails, because the sysroot is empty - but it must fail for THAT
# reason. If this case were also refused by the path guard, every refusal above
# would be satisfied by a script that simply never runs.
out="$(run "${work}/fine.img")"
case "$out" in
    *"refusing to write an image to"*|*"refusing to write an image through"*)
        red "an ordinary file path was refused by the path guard"
        note "the guard refuses everything, so the checks above prove nothing"
        printf '%s\n' "$out" | head -3 | sed 's/^/        /' ;;
    *)  green "an ordinary file path gets past the path guard"
        note "it then fails on its own merits, which is the point"
        printf '%s\n' "$out" | grep -m1 . | sed 's/^/        /' || true ;;
esac

# And nothing above should have created anything.
if [[ -e "${work}/fine.img" ]]; then
    red "mkdisk created ${work}/fine.img despite failing validation"
else
    green "no image file was created by any refused run"
fi

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]] || exit 1
