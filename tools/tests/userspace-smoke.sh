#!/usr/bin/env bash
# Run the built sysroot's programs in a chroot: they must work, not merely
# exist. Needs root.
set -uo pipefail
# This checkout, and the variables make passes to every stage.
WT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${KRYPTIK_WORK:-$WT/build/work}"
SOURCES="${KRYPTIK_SOURCES:-$WT/sources}"
# 77 (skipped), not a failure, without root or a built sysroot, as in CI.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "SKIP (77): needs root - this suite chroots into the built sysroot"
    exit 77
fi
if [[ ! -x "$WORK/sysroot/usr/bin/bash" ]]; then
    echo "SKIP (77): no built sysroot at $WORK/sysroot (make system)"
    exit 77
fi

mkdir -p "$WORK/logs"
LOG="$WORK/logs/userspace-smoke.$(date +%Y%m%dT%H%M%S).log"
ln -sfn "$LOG" "$WORK/logs/userspace-smoke.latest.log"

# Expected versions come from build/config/versions.env, written into the head
# of the inner script, which runs in the chroot and cannot read the repository.
# shellcheck source=/dev/null
. "$WT/build/config/versions.env"
{
    echo '#!/bin/bash'
    for v in GLIBC BASH COREUTILS SED GREP GAWK TAR FINDUTILS DIFFUTILS XZ ZSTD OPENSSL PERL PYTHON PKGCONF KMOD; do
        n="V_$v"; printf '%s=%q\n' "$n" "${!n:?versions.env does not define $n}"
    done
} > /tmp/kryptik-smoke-inner.sh
cat >> /tmp/kryptik-smoke-inner.sh <<'INNER'
# Runs INSIDE the chroot. Deliberately writes nothing outside /run.
fail=0
ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
t() {  # t <description> <expected> <command...>
    local d="$1" want="$2"; shift 2
    local got; got="$("$@" 2>&1)"
    if [[ "$got" == *"$want"* ]]; then ok "$d"; else bad "$d (got: ${got:0:70})"; fi
}

echo "== identity =="
t "os-release names Kryptik"        "ID=kryptik"        cat /etc/os-release
# BUILD_ID is the commit the system was built from: a hex id, never
# "unknown", and not any one commit this file could name.
if grep -qE '^BUILD_ID=[0-9a-f]{7,}$' /etc/os-release; then
    ok "os-release carries a build id ($(sed -n 's/^BUILD_ID=//p' /etc/os-release))"
else
    bad "os-release carries a build id (got: $(grep '^BUILD_ID=' /etc/os-release))"
fi
t "uname is x86_64"                 "x86_64"            uname -m

echo
echo "== the C library and loader =="
t "glibc reports its version"       "$V_GLIBC"              /usr/lib/libc.so.6 --version
t "ldd works"                       "libc.so.6"         ldd /usr/bin/bash

echo
echo "== core userland actually executes =="
t "bash"        "$V_BASH"        bash --version
t "coreutils"   "$V_COREUTILS"           ls --version
t "sed"         "$V_SED"           sed --version
t "grep"        "$V_GREP"          grep --version
t "gawk"        "$V_GAWK"         gawk --version
t "tar"         "$V_TAR"          tar --version
t "findutils"   "$V_FINDUTILS"        find --version
t "diffutils"   "$V_DIFFUTILS"          diff --version
t "xz"          "$V_XZ"         xz --version
t "zstd"        "$V_ZSTD"         zstd --version
t "openssl"     "$V_OPENSSL"         openssl version
t "perl"        "v$V_PERL"       perl --version
t "python3"     "$V_PYTHON"        python3 --version
t "pkg-config"  "$V_PKGCONF"         pkg-config --version
t "kmod"        "$V_KMOD"            kmod --version
t "procps top"    "procps-ng"     top -V
t "iproute2"    "ip utility"    ip -V
t "shadow"      "Usage: useradd" useradd --help
t "agetty"      "agetty"        agetty --help

echo
echo "== the pieces a boot needs =="
t "s6-svscan runs"      "s6-svscan"     s6-svscan -h
t "kryptikd runs"       "compartment"   kryptikd --help
t "kryptikd reads zones" "vault"        kryptikd list --zones /usr/lib/kryptik/zones
[ -x /sbin/init ] && ok "/sbin/init is executable" || bad "/sbin/init is executable"
[ -x /usr/libexec/kryptik-console ] && ok "console wrapper is executable" \
                                    || bad "console wrapper is executable"

echo
echo "== a compiler that targets Kryptik =="
t "gcc triple"  "x86_64-kryptik-linux-gnu"  gcc -dumpmachine
printf 'int main(void){return 0;}\n' > /run/smoke.c
if gcc -o /run/smoke /run/smoke.c 2>/run/smoke.err && /run/smoke; then
    ok "gcc compiles, links and the result runs"
else
    bad "gcc compiles, links and the result runs"; sed 's/^/        /' /run/smoke.err
fi

echo
echo "== hardened_malloc can actually be loaded =="
if out=$(LD_PRELOAD=/usr/lib/libhardened_malloc.so /usr/bin/bash -c 'echo alive' 2>&1) \
   && [ "$out" = alive ]; then
    ok "bash runs under LD_PRELOAD=libhardened_malloc.so"
else
    bad "bash runs under LD_PRELOAD=libhardened_malloc.so (got: ${out:0:80})"
fi

echo
if [ "$fail" -gt 0 ]; then echo "$fail check(s) failed"; exit 1; fi
echo "userspace smoke: all checks passed"
INNER
chmod 0755 /tmp/kryptik-smoke-inner.sh
cp /tmp/kryptik-smoke-inner.sh "$WORK/sysroot/run-smoke.sh" 2>/dev/null || true

# The status leaves the block through a file: $? after `{ ... } >> log` would
# be the block's last command, an echo.
RCFILE="$(mktemp)"
{
    date -Iseconds
    env KRYPTIK_ROOT="$WT" KRYPTIK_WORK="$WORK" KRYPTIK_SOURCES="$SOURCES" \
        NO_COLOR=1 TERM=xterm \
        "$WT/build/stages/03-chroot-prep.sh" run /run-smoke.sh
    echo "$?" > "$RCFILE"
    echo "smoke rc=$(cat "$RCFILE")"
} >> "$LOG" 2>&1
rc="$(cat "$RCFILE")"; rm -f "$RCFILE"

# The sysroot's manifest must not include the test script.
rm -f "$WORK/sysroot/run-smoke.sh"

sed -n '/== identity ==/,$p' "$LOG"
echo
echo "log: $LOG"
exit "$rc"
