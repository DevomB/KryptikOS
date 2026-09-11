#!/usr/bin/env bash
# Regression test: stage 04's s6-linux-init configuration actually produces a
# boot image.
#
# WHY THIS IS NOT JUST PART OF STAGE 04
#
# The init configuration is the last step of a four-hour stage. Getting a flag
# wrong there means finding out at hour four, and the failure modes are quiet:
# a boot image with no stage 2 scripts, or an early getty that names a program
# that does not exist, both produce a maker that exits 0 and a machine that
# boots to silence.
#
# The s6 stack is small and builds in about a minute, so all of it can be
# checked up front.
#
# This is a HOST build. It proves nothing about the target toolchain - that is
# stage 05's compiler-check. What it proves is that the maker's interface, the
# option set and the skeleton scripts fit together, and that part is identical
# wherever it runs.
#
# ANTI-DRIFT
#
# The maker options and the skeleton scripts are extracted from
# build/stages/04-base-system.sh rather than duplicated here, so this test
# cannot quietly stop describing the code it is testing. That is the same
# mistake tools/test-step-errexit.sh used to make.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${ROOT}/build/stages/04-base-system.sh"
PASS=0
FAIL=0

green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == ok ]]; then green "$1"; else red "$1"; fi; }

# shellcheck source=/dev/null
source "${ROOT}/build/config/versions.env"
SRC="${KRYPTIK_SOURCES:-${ROOT}/sources}"

PKGS=("skalibs-${V_SKALIBS}" "execline-${V_EXECLINE}" "s6-${V_S6}"
      "s6-rc-${V_S6_RC}" "s6-linux-init-${V_S6_LINUX_INIT}")

missing=""
for p in "${PKGS[@]}"; do
    [[ -f "${SRC}/${p}.tar.gz" ]] || missing="${missing} ${p}.tar.gz"
done
if [[ -n "$missing" ]]; then
    echo
    echo "  ############################################################"
    echo "  #  SKIPPED - this is NOT a pass.                           #"
    echo "  ############################################################"
    echo
    echo "  The s6 source tarballs are not present, so the init"
    echo "  configuration was not exercised at all:"
    printf '    %s\n' $missing
    echo
    echo "  Fetch them and re-run:  make sources && make test-s6-init"
    echo
    exit 0
fi

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
PREFIX="$W/root"
mkdir -p "$W/build" "$PREFIX"

echo "Stage 04 init configuration"
echo

# ---------------------------------------------------------------------------
# 1. Build the stack the way stage 04 does, including the --skeldir argument
#    whose absence is the whole reason that argument exists.
# ---------------------------------------------------------------------------
for p in "${PKGS[@]}"; do
    tar -xf "${SRC}/${p}.tar.gz" -C "$W/build" || { red "unpack ${p}"; continue; }
    ( cd "$W/build/$p" || exit 1

      extra=()
      case "$p" in
          s6-linux-init-*) extra=(--skeldir=/etc/s6-linux-init/skel) ;;
      esac

      # --with-sysdeps is needed HERE and not in stage 04: skalibs installs its
      # sysdeps to PREFIX/lib/skalibs/sysdeps and later packages look there by
      # absolute path. Inside the chroot that is where they are; this builds
      # under a DESTDIR, so the absolute default points at the host's copy.
      ./configure --prefix=/usr --libdir=/usr/lib \
          --with-sysdeps="$PREFIX/usr/lib/skalibs/sysdeps" \
          --with-include="$PREFIX/usr/include" \
          --with-dynlib="$PREFIX/usr/lib" \
          --with-lib="$PREFIX/usr/lib" \
          "${extra[@]}" > "$W/$p.configure.log" 2>&1 || exit 1
      make -j"$(nproc)" > "$W/$p.make.log" 2>&1 || exit 1
      make DESTDIR="$PREFIX" install > "$W/$p.install.log" 2>&1 || exit 1
    ) && green "built ${p}" || { red "built ${p}"; tail -12 "$W/$p".*.log 2>/dev/null; }
done

[[ "$FAIL" -eq 0 ]] || { echo; echo "the s6 stack did not build; nothing further can be checked"; exit 1; }

# ---------------------------------------------------------------------------
# 2. --skeldir. Without it, s6-linux-init's --prefix=/usr puts the skeleton in
#    /usr/etc/s6-linux-init/skel and the maker never finds it.
# ---------------------------------------------------------------------------
check "skeleton installed to /etc/s6-linux-init/skel" \
      "$([[ -d "$PREFIX/etc/s6-linux-init/skel" ]] && echo ok)"
check "nothing landed in /usr/etc" \
      "$([[ ! -d "$PREFIX/usr/etc" ]] && echo ok)"

# ---------------------------------------------------------------------------
# 3. Kryptik's own skeleton scripts, taken from the stage file.
# ---------------------------------------------------------------------------
python3 - "$STAGE" "$PREFIX/etc/s6-linux-init/skel" <<'PY'
import re, sys, pathlib, os
src = pathlib.Path(sys.argv[1]).read_text()
dest = pathlib.Path(sys.argv[2]); dest.mkdir(parents=True, exist_ok=True)
n = 0
for m in re.finditer(r'cat > "\$skel/([a-z.]+)" <<\'EOF\'\n(.*?)\nEOF\n', src, re.S):
    p = dest / m.group(1)
    p.write_text(m.group(2) + "\n")
    os.chmod(p, 0o755)
    n += 1
sys.exit(0 if n == 4 else "expected 4 skeleton scripts in the stage file, found %d" % n)
PY
check "stage 04's four skeleton scripts extracted" "$([[ $? -eq 0 ]] && echo ok)"

for f in rc.init rc.shutdown rc.shutdown.final runlevel; do
    check "${f} is valid sh" \
          "$(sh -n "$PREFIX/etc/s6-linux-init/skel/$f" 2>/dev/null && echo ok)"
done

# ---------------------------------------------------------------------------
# 4. The maker, with stage 04's exact options.
#
# Extracted from the stage file so the two cannot drift apart. Only -f and the
# output directory are overridden, because those are the only ones that name a
# path belonging to a real installation.
# ---------------------------------------------------------------------------
mapfile -t OPTS < <(python3 - "$STAGE" <<'PY'
import re, sys, shlex
src = open(sys.argv[1]).read()
m = re.search(r'\n    s6-linux-init-maker \\\n(.*?)\n        "\$tmp"\n', src, re.S)
if not m:
    sys.exit("s6-linux-init-maker invocation not found in the stage file")
body = m.group(1).replace("\\\n", " ")
body = re.sub(r'#[^\n]*', '', body)
# The last option line still ends in the continuation that joined it to
# "$tmp", and shlex refuses a trailing backslash with nothing after it.
body = body.rstrip().rstrip("\\").rstrip()
skip = False
for tok in shlex.split(body):
    if skip:
        skip = False
        continue
    if tok == "-f":            # overridden below
        skip = True
        continue
    print(tok)
PY
) || { red "could not extract the maker options from the stage file"; exit 1; }

echo "  maker options from the stage file: ${OPTS[*]}"

# An extraction that silently produced nothing would run the maker with no
# options at all, and most of the checks below would still pass - the maker
# happily builds a default image. So assert the extraction worked before
# trusting anything that follows.
check "extracted a non-empty option set" "$([[ "${#OPTS[@]}" -ge 8 ]] && echo ok)"
check "extracted the early-getty option (-G)" \
      "$(printf '%s\n' "${OPTS[@]}" | grep -qx -- '-G' && echo ok)"
check "extracted the console-output option (-1)" \
      "$(printf '%s\n' "${OPTS[@]}" | grep -qx -- '-1' && echo ok)"
if [[ "${#OPTS[@]}" -lt 8 ]]; then
    echo
    echo "  The maker options could not be read out of ${STAGE##*/}."
    echo "  Everything below this point would be testing a default image, not"
    echo "  Kryptik's, so stopping here rather than reporting a green run."
    exit 1
fi

export PATH="$PREFIX/usr/bin:$PATH"
export LD_LIBRARY_PATH="$PREFIX/usr/lib"
OUT="$W/out"
makerlog="$W/maker.log"
s6-linux-init-maker "${OPTS[@]}" -f "$PREFIX/etc/s6-linux-init/skel" "$OUT" \
    > "$makerlog" 2>&1
rc=$?

check "s6-linux-init-maker succeeds" "$([[ $rc -eq 0 ]] && echo ok)"
[[ $rc -eq 0 ]] || { sed 's/^/    /' "$makerlog"; echo; echo "${FAIL} failed"; exit 1; }

# A warning here is not cosmetic. The one this caught - an env store outside
# /run - means init writing to the root filesystem at every boot, on a system
# whose kernel fragment enables dm-verity.
if grep -q 'warning' "$makerlog"; then
    red "s6-linux-init-maker emitted a warning:"
    sed 's/^/        /' "$makerlog"
else
    green "s6-linux-init-maker emitted no warnings"
fi

# ---------------------------------------------------------------------------
# 5. What it produced has to be bootable-shaped.
# ---------------------------------------------------------------------------
for b in init telinit shutdown halt poweroff reboot; do
    check "produced bin/${b}" "$([[ -e "$OUT/bin/$b" ]] && echo ok)"
done

check "produced an early getty service" \
      "$([[ -d "$OUT/run-image/service/s6-linux-init-early-getty" ]] && echo ok)"
check "the early getty runs Kryptik's console wrapper" \
      "$(grep -q 'kryptik-console' "$OUT/run-image/service/s6-linux-init-early-getty/run" 2>/dev/null && echo ok)"
check "produced the shutdown daemon" \
      "$([[ -d "$OUT/run-image/service/s6-linux-init-shutdownd" ]] && echo ok)"
check "stage 2 script is Kryptik's, not upstream's template" \
      "$(grep -q 'Kryptik stage 2 init' "$OUT/scripts/rc.init" 2>/dev/null && echo ok)"
check "shutdown script is Kryptik's" \
      "$(grep -q 'handing back to shutdownd' "$OUT/scripts/rc.shutdown" 2>/dev/null && echo ok)"

# The console wrapper is written by a different step; check it the same way.
python3 - "$STAGE" "$W/kryptik-console" <<'PY'
import re, sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r"cat > /usr/libexec/kryptik-console <<'EOF'\n(.*?)\nEOF\n", src, re.S)
sys.exit("console wrapper not found in the stage file") if not m else None
pathlib.Path(sys.argv[2]).write_text(m.group(1) + "\n")
PY
check "console wrapper extracted from the stage file" "$([[ -s "$W/kryptik-console" ]] && echo ok)"
check "console wrapper is valid sh" "$(sh -n "$W/kryptik-console" 2>/dev/null && echo ok)"
check "console wrapper does not hardcode a tty" \
      "$(grep -q 'console/active' "$W/kryptik-console" && echo ok)"
check "console wrapper avoids login(1), which Kryptik does not ship" \
      "$(grep -q 'agetty -n -l' "$W/kryptik-console" && echo ok)"

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} check(s) failed, ${PASS} passed."
    exit 1
fi
echo "All ${PASS} checks passed."
