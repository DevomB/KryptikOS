#!/usr/bin/env bash
# Does the built userspace actually run? Run as root.
#
# boot-check asserted that files exist. This runs them. "Present" and "works"
# are different claims, and the gap between them is where a sysroot that looks
# finished panics on first boot.
set -uo pipefail
C=/home/devomb/kryptik-overnight-2026-09-11
WT=$C/worktrees/build
[[ "$(id -u)" -eq 0 ]] || { echo "must run as root"; exit 1; }

LOG="$C/logs/userspace-smoke.$(date +%Y%m%dT%H%M%S).log"
ln -sfn "$LOG" "$C/logs/userspace-smoke.latest.log"

cat > /tmp/kryptik-smoke-inner.sh <<'INNER'
#!/bin/bash
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
t "os-release carries a build id"   "BUILD_ID=2501ecf"  cat /etc/os-release
t "uname is x86_64"                 "x86_64"            uname -m

echo
echo "== the C library and loader =="
t "glibc reports its version"       "2.40"              /usr/lib/libc.so.6 --version
t "ldd works"                       "libc.so.6"         ldd /usr/bin/bash

echo
echo "== core userland actually executes =="
t "bash"        "5.2.32"        bash --version
t "coreutils"   "9.5"           ls --version
t "sed"         "4.9"           sed --version
t "grep"        "3.11"          grep --version
t "gawk"        "5.3.0"         gawk --version
t "tar"         "1.35"          tar --version
t "findutils"   "4.10.0"        find --version
t "diffutils"   "3.10"          diff --version
t "xz"          "5.8.4"         xz --version
t "zstd"        "1.5.6"         zstd --version
t "openssl"     "3.3.1"         openssl version
t "perl"        "v5.40.0"       perl --version
t "python3"     "3.12.5"        python3 --version
t "pkg-config"  "2.3.0"         pkg-config --version
t "kmod"        "33"            kmod --version
t "procps top"    "procps-ng"     top -V
t "iproute2"    "ip utility"    ip -V
t "shadow"      "Usage: useradd" useradd --help
t "agetty"      "agetty"        agetty --help

echo
echo "== the pieces a boot needs =="
t "s6-svscan runs"      "s6-svscan"     s6-svscan -h
t "kryptikd runs"       "compartment"   kryptikd --help
t "kryptikd reads zones" "vault"        kryptikd list --zones /etc/kryptik/zones
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
cp /tmp/kryptik-smoke-inner.sh "$C/work/sysroot/run-smoke.sh" 2>/dev/null || true

{
    date -Iseconds
    env KRYPTIK_ROOT="$WT" KRYPTIK_WORK="$C/work" KRYPTIK_SOURCES="$C/sources" \
        NO_COLOR=1 TERM=xterm \
        "$WT/build/stages/03-chroot-prep.sh" run /run-smoke.sh
    echo "smoke rc=$?"
} >> "$LOG" 2>&1
rc=$?

# Put the tree back exactly as it was: the copied script is the only thing
# this added, and the manifest must describe the sysroot, not the test.
rm -f "$C/work/sysroot/run-smoke.sh"

sed -n '/== identity ==/,$p' "$LOG"
echo
echo "log: $LOG"
exit "$rc"
