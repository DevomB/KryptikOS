#!/usr/bin/env bash
# Tests for stage 01's rule that clears a sysroot another toolchain built, and for its --toolchain-id.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
MOUNTS="$W/mounts"; : > "$MOUNTS"
BLOCK="$(awk '/^# --- a cross toolchain is never rebuilt/ {on=1} /^for row in / {on=0} on' "${ROOT}/build/stages/01-toolchain.sh" | sed "s#/proc/mounts#${MOUNTS}#g")"
[[ -n "$BLOCK" ]] || { echo "the block was not found in stage 01"; exit 1; }
PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  PASS  $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; [[ -f "$W/out" ]] && sed 's/^/        /' "$W/out"; }

# run ID: the block, under errexit and an ERR trap as in the stage, for toolchain identity ID.
run() {
    ( set -Eeuo pipefail; trap 'echo "ERR trap at line $LINENO"; exit 8' ERR
      warn() { echo "warn: $*"; }; die() { echo "die: $*"; exit 9; }
      # shellcheck disable=SC2034  # read by the block, through eval
      KRYPTIK_ROOT="$ROOT" toolchain_id="id-$1"
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

# The mount test alone: /proc/mounts holds resolved paths, a space written \040; none is a glob.
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

# --- the identity, from stage 01's own --toolchain-id on a copy of the tree ---
# copy DIR: the parts of the repository stage 01 reads.
copy() { rm -rf "$1"; mkdir -p "$1/build/stages"; cp -r "$ROOT/build/lib" "$ROOT/build/config" "$ROOT/build/patches" "$1/build/"; cp "$ROOT/build/stages/01-toolchain.sh" "$1/build/stages/"; }
# tid TREE WORK [PATH]: the identity the stage in TREE gives for WORK.
tid() { env -u KRYPTIK_ROOT KRYPTIK_WORK="$2" KRYPTIK_SOURCES="$W/src" NO_COLOR=1 PATH="${3:-$PATH}" bash "$1/build/stages/01-toolchain.sh" --toolchain-id 2> "$W/out"; }
# edit TREE RECIPE LINE: LINE added at the top of RECIPE's body.
edit() { sed -i "/^$2() {/a\\    $3" "$1/build/stages/01-toolchain.sh"; }

copy "$W/r0"; base="$(tid "$W/r0" "$W/w-empty")"
[[ "$base" =~ ^[0-9a-f]{64}$ ]] && ok "the stage gives an identity without building anything" || { bad "no identity: '$base'"; base=none; }
mkdir -p "$W/w-built/sysroot/usr/include" "$W/w-built/sysroot/tools/bin" "$W/w-built/.stamps"
: > "$W/w-built/sysroot/usr/include/stdio.h"; : > "$W/w-built/.stamps/binutils-pass1"; echo stale > "$W/w-built/.stamps/toolchain-id"
v="$(tid "$W/r0" "$W/w-built")"; [[ "$v" == "$base" ]] && ok "it is the same over an empty sysroot and a built one: no step's arguments read one" || bad "the identity depends on the sysroot"
copy "$W/r1"; edit "$W/r1" s_binutils_pass1 ': an edit'
v="$(tid "$W/r1" "$W/w-empty")"; [[ "$v" =~ ^[0-9a-f]{64}$ && "$v" != "$base" ]] && ok "a recipe edit changes it" || bad "a recipe edit left the identity alone"
copy "$W/r2"; edit "$W/r2" s_binutils_pass1 '# a comment'
v="$(tid "$W/r2" "$W/w-empty")"; [[ "$v" == "$base" ]] && ok "a comment does not" || bad "a comment changed the identity"
copy "$W/r3"; edit "$W/r3" s_sanity_check ': an edit'
v="$(tid "$W/r3" "$W/w-empty")"; [[ "$v" == "$base" ]] && ok "nor does an edit of the sanity check, which is a check" || bad "the check is in the identity"
mkdir -p "$W/cc"
printf '#!/bin/sh\ncase "$1" in --version) echo "gcc (another build) 99.1";; -dumpmachine) echo x86_64-linux-gnu;; esac\n' > "$W/cc/gcc"; chmod +x "$W/cc/gcc"
v="$(tid "$W/r0" "$W/w-empty" "$W/cc:$PATH")"; [[ "$v" =~ ^[0-9a-f]{64}$ && "$v" != "$base" ]] && ok "another host compiler changes it" || bad "the host compiler is not in the identity"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
