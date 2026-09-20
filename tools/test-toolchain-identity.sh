#!/usr/bin/env bash
# Tests for the rule at the top of build/stages/01-toolchain.sh that clears a
# sysroot another toolchain built. The block is lifted out of the stage and run
# under the stage's own shell options and an ERR trap: run without them, an
# earlier version of this test passed a block that aborted on its first line.
# The only substitution is the path of the mounts file.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
MOUNTS="$W/mounts"; : > "$MOUNTS"
BLOCK="$(awk '/^# --- a cross toolchain is never rebuilt/ {on=1} /^step layout/ {on=0} on' "${ROOT}/build/stages/01-toolchain.sh" | sed "s#/proc/mounts#${MOUNTS}#g")"
[[ -n "$BLOCK" ]] || { echo "the block was not found in stage 01"; exit 1; }
PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  PASS  $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; [[ -f "$W/out" ]] && sed 's/^/        /' "$W/out"; }

# run GCC_VERSION: the block, in a shell set up as common.sh sets the stage's.
run() {
    ( set -Eeuo pipefail; trap 'echo "ERR trap at line $LINENO"; exit 8' ERR
      warn() { echo "warn: $*"; }; die() { echo "die: $*"; exit 9; }
      sha256_of_stdin() { sha256sum | cut -d' ' -f1; }
      # shellcheck disable=SC2034  # read by the block, through eval
      KRYPTIK_ROOT="$ROOT" V_BINUTILS=1 V_GCC="$1" V_GLIBC=2.40 V_LINUX=1 V_MPFR=1 V_GMP=1 V_MPC=1
      eval "$BLOCK" ) > "$W/out" 2>&1
}
populate() { mkdir -p "$LFS/usr/include" "$LFS/usr/lib" "$LFS/kryptik" "$STAMPS"; : > "$LFS/usr/include/pthread.h"; : > "$LFS/usr/lib/old.so"; : > "$STAMPS/01-gcc-pass1"; }
# expect NAME WANT_RC cleared|kept
expect() {
    local state=kept; [[ -e "$LFS/usr/lib/old.so" ]] || state=cleared
    if [[ "$RC" -eq "$2" && "$state" == "$3" ]]; then ok "$1"; else bad "$1 (exit $RC, sysroot $state)"; fi
}

LFS="$W/a/sysroot"; STAMPS="$W/a/stamps"; mkdir -p "$STAMPS"
run 14; RC=$?; [[ "$RC" -eq 0 && -s "$STAMPS/toolchain-id" ]] && ok "an empty tree gets this toolchain's record" || bad "an empty tree (exit $RC)"
populate
run 14; RC=$?; expect "the same toolchain leaves the tree alone" 0 kept
run 15; RC=$?; expect "another toolchain clears it" 0 cleared
[[ -n "$(find "$STAMPS/legacy" -name 01-gcc-pass1 2>/dev/null)" ]] && ok "and archives the stamps" || bad "the stamps were not archived"
[[ ! -e "$LFS/.kryptik-toolchain" ]] && ok "nothing is written into the sysroot, which becomes the root image" || bad "a record was written into the sysroot"

LFS="$W/b/sysroot"; STAMPS="$W/b/stamps"; populate
run 14; RC=$?; expect "a tree with no record is cleared" 0 cleared
LFS="$W/c/sysroot"; STAMPS="$W/c/stamps"; populate; : > "$LFS/kryptik/Makefile"
run 14; RC=$?; expect "a tree with the repository visible inside it is refused" 9 kept
[[ -e "$LFS/kryptik/Makefile" ]] && ok "and what stood in for the repository survives" || bad "THE STAND-IN FOR THE REPOSITORY WAS DELETED"
LFS="$W/d/sysroot"; STAMPS="$W/d/stamps"; populate
printf 'proc %s/proc proc rw 0 0\n' "$LFS" > "$MOUNTS"
run 14; RC=$?; expect "a tree with something mounted under it is refused" 9 kept

# The mount test alone: /proc/mounts writes a space as \040 and names the
# resolved path, and the path is not a pattern.
mkdir -p "$W/m/with space/sysroot" "$W/m/br[ack]et/sysroot" "$W/m/real/sysroot" "$W/m/sysroot-other"; ln -s "$W/m/real" "$W/m/link"
for p in "$W/m/with space/sysroot/kryptik" "$W/m/br[ack]et/sysroot/kryptik" "$W/m/real/sysroot/kryptik" "$W/m/sysroot-other/x"; do
    printf '/dev/sda1 %s ext4 rw 0 0\n' "${p// /\\040}"
done > "$MOUNTS"
eval "$(printf '%s\n' "$BLOCK" | awk '/^mounted_under\(\) \{/ {on=1} on {print} on && /^}/ {exit}')"
t() { local got=clear; mounted_under "$2" && got=mounted; [[ "$got" == "$3" ]] && ok "mount test: $1" || bad "mount test: $1 (got $got)"; }
t "a space in the path"                  "$W/m/with space/sysroot" mounted
t "brackets in the path"                 "$W/m/br[ack]et/sysroot"  mounted
t "a path reached through a symlink"     "$W/m/link/sysroot"       mounted
t "a sibling whose name starts the same" "$W/m/sysroot"            clear
rm -f "$MOUNTS"
t "an unreadable mounts file means mounted" "$W/a" mounted

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
