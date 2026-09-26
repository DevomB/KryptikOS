#!/usr/bin/env bash
# Tests for tools/check-artifact-hardening.sh, on objects compiled here (not
# checked in) so they match the real toolchain.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="${ROOT}/tools/check-artifact-hardening.sh"
CC="${CC:-gcc}"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == ok ]]; then green "$1"; else red "$1"; fi; }

command -v "$CC" >/dev/null || { echo "no compiler ($CC)"; exit 1; }
[[ -x "$CHECK" ]] || { echo "missing or non-executable: $CHECK"; exit 1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

src="$W/probe.c"
cat > "$src" <<'C'
#include <string.h>
#include <stdio.h>
int work(const char *s) { char b[64]; strncpy(b, s, sizeof b - 1); b[63] = 0; return (int) strlen(b); }
int main(void) { printf("%d\n", work("kryptik")); return 0; }
C

libsrc="$W/lib.c"
echo 'int twice(int x) { return x * 2; }' > "$libsrc"

HARD="-O2 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fcf-protection=full"
HLD="-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"

# One root per case, so findings cannot bleed between cases.
mkroot() { local d="$W/$1/usr/bin"; mkdir -p "$d"; printf '%s' "$W/$1"; }

run_check() {  # run_check <root> [extra args...] -> prints output, returns rc
    local r="$1"; shift
    KRYPTIK_WORK="$W/work" "$CHECK" "$r" "$@" 2>&1
}

# Control: a well-built executable and library pass.
clean_root="$(mkroot clean)"
# shellcheck disable=SC2086
$CC $HARD $HLD -o "$clean_root/usr/bin/good" "$src" 2>/dev/null
# shellcheck disable=SC2086
$CC $HARD $HLD -fPIC -shared -o "$clean_root/usr/bin/libgood.so" "$libsrc" 2>/dev/null

out="$(run_check "$clean_root")"; rc=$?
check "clean tree: checker exits 0" "$([[ $rc -eq 0 ]] && echo ok)"
check "clean tree: counted both objects" \
      "$(grep -qE 'objects +2' <<<"$out" && echo ok)"
check "clean tree: no hard finding" \
      "$(grep -q 'no object failed a hard check' <<<"$out" && echo ok)"
check "clean tree: saw the stack protector in the ELF" \
      "$(grep -qE 'with SSP +[1-9]' <<<"$out" && echo ok)"

es_root="$(mkroot execstack)"
# shellcheck disable=SC2086
$CC $HARD -Wl,-z,execstack -o "$es_root/usr/bin/bad" "$src" 2>/dev/null
out="$(run_check "$es_root")"; rc=$?
check "executable stack: detected" "$(grep -q 'EXEC-STACK' <<<"$out" && echo ok)"
check "executable stack: exits non-zero" "$([[ $rc -ne 0 ]] && echo ok)"

# An RPATH into the build tree: fine where built, the wrong library elsewhere.
rp_root="$(mkroot rpath)"
mkdir -p "$W/work/build/fake-lib"
# shellcheck disable=SC2086
$CC $HARD $HLD -Wl,-rpath,"$W/work/build/fake-lib" \
    -o "$rp_root/usr/bin/leaky" "$src" 2>/dev/null
out="$(run_check "$rp_root")"; rc=$?
check "build-tree RPATH: detected" "$(grep -q 'BUILD-RPATH' <<<"$out" && echo ok)"
check "build-tree RPATH: exits non-zero" "$([[ $rc -ne 0 ]] && echo ok)"

# A system RPATH is reported, not failed: packages set them legitimately.
sysrp_root="$(mkroot sysrpath)"
# shellcheck disable=SC2086
$CC $HARD $HLD -Wl,-rpath,/usr/lib/kryptik -o "$sysrp_root/usr/bin/ok" "$src" 2>/dev/null
out="$(run_check "$sysrp_root")"; rc=$?
check "system RPATH: reported, not failed" \
      "$({ [[ $rc -eq 0 ]] && grep -q 'RPATH' <<<"$out"; } && echo ok)"

# Soft findings: reported, fatal only under --strict.
np_root="$(mkroot nopie)"
# shellcheck disable=SC2086
$CC $HARD $HLD -no-pie -o "$np_root/usr/bin/notpie" "$src" 2>/dev/null
out="$(run_check "$np_root")"; rc=$?
check "non-PIE executable: reported" "$(grep -q 'NO-PIE' <<<"$out" && echo ok)"
check "non-PIE executable: does not fail by default" "$([[ $rc -eq 0 ]] && echo ok)"
out="$(run_check "$np_root" --strict)"; rc=$?
check "non-PIE executable: --strict fails" "$([[ $rc -ne 0 ]] && echo ok)"

norelro_root="$(mkroot norelro)"
# shellcheck disable=SC2086
$CC $HARD -Wl,-z,norelro -o "$norelro_root/usr/bin/nr" "$src" 2>/dev/null
out="$(run_check "$norelro_root")"
check "missing RELRO: reported" "$(grep -q 'NO-RELRO' <<<"$out" && echo ok)"

# /tools, the cross toolchain built without hardening, is excluded.
ex_root="$(mkroot excluded)"
mkdir -p "$ex_root/tools/bin"
# shellcheck disable=SC2086
$CC $HARD -Wl,-z,execstack -o "$ex_root/tools/bin/crossthing" "$src" 2>/dev/null
# shellcheck disable=SC2086
$CC $HARD $HLD -o "$ex_root/usr/bin/shipped" "$src" 2>/dev/null
out="$(run_check "$ex_root")"; rc=$?
check "/tools is excluded from the audit" \
      "$({ [[ $rc -eq 0 ]] && ! grep -q 'EXEC-STACK' <<<"$out"; } && echo ok)"
check "/tools exclusion does not hide the shipped tree" \
      "$(grep -qE 'objects +1' <<<"$out" && echo ok)"

empty_root="$(mkroot empty)"
out="$(run_check "$empty_root")"; rc=$?
check "empty tree: refuses to report success" "$([[ $rc -ne 0 ]] && echo ok)"
check "empty tree: says why" "$(grep -q 'no ELF objects found' <<<"$out" && echo ok)"

mix_root="$(mkroot mixed)"
# shellcheck disable=SC2086
$CC $HARD $HLD -o "$mix_root/usr/bin/real" "$src" 2>/dev/null
printf '#!/bin/sh\necho hi\n' > "$mix_root/usr/bin/script"
head -c 512 /dev/urandom > "$mix_root/usr/bin/noise"
out="$(run_check "$mix_root")"; rc=$?
check "non-ELF files skipped cleanly" \
      "$({ [[ $rc -eq 0 ]] && grep -qE 'objects +1' <<<"$out"; } && echo ok)"

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed."
    exit 1
fi
echo "All ${PASS} checks passed."
