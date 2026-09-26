#!/usr/bin/env bash
# Check that the hardening flags build an executable, a shared library, and a
# program linking the two.
#
#   tools/test-hardening-flags.sh          test with $CC (default gcc)
#   CC=x86_64-kryptik-linux-gnu-gcc ...    test the cross compiler
#
# -pie must stay out of the flags: it links Scrt1.o, whose _start needs main(),
# so every shared library fails with "undefined reference to `main'". GCC is
# --enable-default-pie, so executables are PIE anyway. Run inside the chroot to
# test the flags as stage 04 applies them.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

# Probes fail by design; the ERR trap would abort on the first one.
trap - ERR
set +e

load_hardening
validate_hardening_exceptions

CC="${CC:-gcc}"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
note()  { printf '\033[2m  note\033[0m  %s\n' "$1"; }

have "$CC" || die "compiler not found: ${CC}
Set CC to the compiler whose flags you want to verify."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

HCFLAGS="${KRYPTIK_OPT} ${KRYPTIK_CFLAGS_HARDENING}"
HLDFLAGS="${KRYPTIK_LDFLAGS_HARDENING}"

echo "Hardening flag verification"
echo "  compiler : ${CC} ($("$CC" -dumpmachine 2>/dev/null))"
echo "  version  : $("$CC" --version 2>/dev/null | head -1)"
echo "  CFLAGS   : ${HCFLAGS}"
echo "  LDFLAGS  : ${HLDFLAGS}"
echo

echo "-- the flag set itself"
if [[ " ${HCFLAGS} ${HLDFLAGS} " == *" -pie "* ]]; then
    red "no globally forced -pie (it breaks every shared library; see header)"
else
    green "no globally forced -pie"
fi
if [[ " ${HCFLAGS} ${HLDFLAGS} " == *" -fPIE "* ]]; then
    red "no globally forced -fPIE (redundant with --enable-default-pie)"
else
    green "no globally forced -fPIE"
fi

# -Werror: for most flags it does not understand, GCC only warns.
for f in $HCFLAGS; do
    if echo 'int main(void){return 0;}' | \
       "$CC" -Werror -x c - "$f" -o "$WORK/flagprobe" >/dev/null 2>&1; then
        green "accepted: ${f}"
    else
        red "rejected by ${CC}: ${f}"
    fi
done
rm -f "$WORK/flagprobe"
echo

echo "-- executable"
cat > "$WORK/exe.c" <<'C'
#include <stdio.h>
#include <string.h>
int copy(const char *src) {
    char buf[64];
    strncpy(buf, src, sizeof buf - 1);
    buf[sizeof buf - 1] = 0;
    return (int) strlen(buf);
}
int main(void) { printf("exe-ok %d\n", copy("kryptik")); return 0; }
C

# shellcheck disable=SC2086  # flags are deliberately word-split
"$CC" $HCFLAGS $HLDFLAGS -o "$WORK/exe" "$WORK/exe.c" 2> "$WORK/exe.err"
if [[ $? -eq 0 ]]; then
    green "executable links under the full flag set"
else
    red "executable does NOT link under the full flag set"
    sed 's/^/         /' "$WORK/exe.err"
fi

if [[ -x "$WORK/exe" ]] && [[ "$("$WORK/exe" 2>/dev/null)" == "exe-ok 7" ]]; then
    green "executable runs and produces the expected output"
else
    red "executable does not run correctly"
fi
echo

# The case -pie breaks.
echo "-- shared library"
cat > "$WORK/lib.c" <<'C'
#include <string.h>
int lib_len(const char *s) { char b[32]; strncpy(b, s, sizeof b - 1); b[sizeof b - 1] = 0; return (int) strlen(b); }
C

# shellcheck disable=SC2086
"$CC" $HCFLAGS $HLDFLAGS -fPIC -shared -o "$WORK/libprobe.so" "$WORK/lib.c" 2> "$WORK/lib.err"
if [[ $? -eq 0 ]]; then
    green "shared library links under the full flag set"
else
    red "shared library does NOT link under the full flag set"
    sed 's/^/         /' "$WORK/lib.err"
    if grep -q "undefined reference to .main" "$WORK/lib.err"; then
        red "  ^ this is the Scrt1.o failure: -pie has come back into the flag set"
    fi
fi

cat > "$WORK/user.c" <<'C'
#include <stdio.h>
int lib_len(const char *);
int main(void) { printf("lib-ok %d\n", lib_len("kryptik")); return 0; }
C
# shellcheck disable=SC2086
"$CC" $HCFLAGS $HLDFLAGS -o "$WORK/user" "$WORK/user.c" -L"$WORK" -lprobe \
     -Wl,-rpath,"$WORK" 2> "$WORK/user.err"
if [[ $? -eq 0 ]] && [[ "$("$WORK/user" 2>/dev/null)" == "lib-ok 7" ]]; then
    green "executable links against that library and runs"
else
    red "executable does not link against the hardened library"
    sed 's/^/         /' "$WORK/user.err"
fi
echo

# An accepted flag can still produce nothing, so check the ELF.
echo "-- what landed in the binaries"

if ! have readelf; then
    note "readelf not available; skipping ELF property checks"
else
    elf_has() { readelf -Wd "$1" 2>/dev/null | grep -q "$2"; }

    for target in "$WORK/exe" "$WORK/libprobe.so"; do
        [[ -e "$target" ]] || continue
        name="$(basename "$target")"

        if readelf -Wl "$target" 2>/dev/null | grep -q "GNU_RELRO"; then
            green "${name}: RELRO segment present (-Wl,-z,relro)"
        else
            red "${name}: no RELRO segment"
        fi

        if elf_has "$target" "BIND_NOW" || elf_has "$target" "FLAGS_1.*NOW"; then
            green "${name}: BIND_NOW (-Wl,-z,now) - full RELRO"
        else
            red "${name}: not BIND_NOW; RELRO is only partial"
        fi

        if readelf -Wl "$target" 2>/dev/null | grep -q "GNU_STACK.*RWE"; then
            red "${name}: stack is executable"
        else
            green "${name}: non-executable stack (-Wl,-z,noexecstack)"
        fi

        if readelf -n "$target" 2>/dev/null | grep -qE "IBT|SHSTK"; then
            green "${name}: CET property note (-fcf-protection=full)"
        else
            note "${name}: no CET note - check -fcf-protection on this target"
        fi
    done

    # PIE comes from the compiler's configuration, not from these flags.
    if [[ -e "$WORK/exe" ]]; then
        if "$CC" -v 2>&1 | grep -q -- "--enable-default-pie"; then
            if readelf -h "$WORK/exe" 2>/dev/null | grep -q "DYN (Position-Independent"; then
                green "exe: position-independent WITHOUT -pie (--enable-default-pie works)"
            else
                red "exe: compiler claims --enable-default-pie but produced a non-PIE binary"
            fi
        else
            note "exe: ${CC} is not built --enable-default-pie, so this binary is"
            note "      not PIE. Kryptik's own GCC is (stages 01 and 02); run this"
            note "      test inside the chroot for the authoritative answer."
        fi
    fi

    # Fortify and SSP leave symbols behind; none means the flag did not take.
    if have nm; then
        if nm -u "$WORK/exe" 2>/dev/null | grep -q "__strncpy_chk\|__memcpy_chk\|_chk@"; then
            green "exe: _FORTIFY_SOURCE is active (checked libc call emitted)"
        else
            note "exe: no *_chk symbol - this probe may be optimised out; check a"
            note "      real package before concluding _FORTIFY_SOURCE is inert"
        fi
        if nm -u "$WORK/exe" 2>/dev/null | grep -q "__stack_chk_fail"; then
            green "exe: stack protector is active (__stack_chk_fail referenced)"
        else
            red "exe: no __stack_chk_fail - -fstack-protector-strong did not take"
        fi
    fi
fi
echo

# Each exception must drop one flag that is really in the set.
echo "-- hardening exceptions"
EXC="${KRYPTIK_ROOT}/build/config/hardening-exceptions.txt"
if [[ ! -f "$EXC" ]]; then
    note "no exception file at ${EXC}"
else
    while read -r pkg flag rest; do
        [[ -z "${pkg:-}" || "$pkg" == \#* ]] && continue
        [[ -n "${rest:-}" ]] || { red "exception '${pkg} ${flag}' has no justification"; continue; }

        dropped="${HCFLAGS//${flag}/}"
        if [[ "$dropped" == "$HCFLAGS" ]]; then
            red "exception ${pkg}: '${flag}' is not in the flag set, so dropping it does nothing"
        else
            green "exception ${pkg}: '${flag}' is present and would be dropped"
            # And the package must still build without it.
            # shellcheck disable=SC2086
            if "$CC" $dropped $HLDFLAGS -fPIC -shared -o "$WORK/exc.so" "$WORK/lib.c" 2>/dev/null; then
                green "exception ${pkg}: the reduced flag set still builds"
            else
                red "exception ${pkg}: the reduced flag set does not build"
            fi
        fi
    done < "$EXC"
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed."
    echo "Do not work around this by deleting flags from hardening.env. Find"
    echo "which flag broke what, and add a justified per-package exception."
    exit 1
fi
echo "All ${PASS} checks passed."
