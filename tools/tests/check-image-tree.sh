#!/usr/bin/env bash
# Tests for tools/check-image-tree.sh on a fixture sysroot and the upper directory an overlay left.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/tools/check-image-tree.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
L="$T/lower"; U="$T/upper"
mkdir -p "$L/usr/bin" "$L/usr/share/info" "$L/etc/kryptik" "$L/tmp"
printf 'root\n' > "$L/usr/bin/bash"; chmod 755 "$L/usr/bin/bash"
printf 'index\n' > "$L/usr/share/info/dir"
check() { NO_COLOR=1 bash "$CHECK" "$L" "$U" 2>&1; }
# The upper directory a clean build leaves: new files under /usr, copied-up directories, the chroot's own marks.
fresh() {
    rm -rf "$U"; mkdir -p "$U/usr/bin" "$U/usr/share/probe" "$U/etc/kryptik" "$U/tmp/build" "$U/kryptik-work"
    printf 'probe\n' > "$U/usr/bin/kryptik-probe"; chmod 755 "$U/usr/bin/kryptik-probe"
    printf 'data\n' > "$U/usr/share/probe/README"
    ln -s kryptik-probe "$U/usr/bin/probe"
    printf 'marker\n' > "$U/etc/kryptik/inside-chroot"
    printf 'scratch\n' > "$U/tmp/build/object.o"
    chmod --reference="$L/usr/bin" "$U/usr/bin"; chmod --reference="$L/etc/kryptik" "$U/etc/kryptik"
    chmod --reference="$L/tmp" "$U/tmp"
}

fresh
out="$(check)"; rc=$?
[[ "$rc" -eq 0 && "$out" == *"3 files and links"* ]] \
    && ok "new files under /usr pass; the chroot's marker and scratch are let be" || bad "clean tree: rc=$rc: $out"

fresh; mkdir -p "$U/usr/share/info"; printf 'changed\n' > "$U/usr/share/info/dir"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"replaces the root's /usr/share/info/dir"* ]] \
    && ok "a file of the root's, rewritten, fails" || bad "replaced file: rc=$rc: $out"

fresh; mkdir -p "$U/etc/probe"; printf 'conf\n' > "$U/etc/probe/probe.conf"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"makes /etc/probe outside /usr"* && "$out" == *"installs /etc/probe/probe.conf outside /usr"* ]] \
    && ok "a file outside /usr fails, with its directory" || bad "outside /usr: rc=$rc: $out"

fresh; chmod 4755 "$U/usr/bin/kryptik-probe"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/kryptik-probe is setuid or setgid"* ]] \
    && ok "a setuid bit fails" || bad "setuid: rc=$rc: $out"

fresh; chmod 0777 "$U/usr/bin"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"changes the root's directory /usr/bin"* ]] \
    && ok "a root directory with another mode fails" || bad "directory mode: rc=$rc: $out"

fresh; ln -s /etc/passwd "$U/usr/bin/passwd-link"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/passwd-link links to /etc/passwd, outside /usr"* ]] \
    && ok "a link to a path outside /usr fails" || bad "absolute link out: rc=$rc: $out"

fresh; ln -s ../../tmp/probe "$U/usr/bin/climb"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"/usr/bin/climb links to ../../tmp/probe, outside /usr"* ]] \
    && ok "a relative link that climbs out of /usr fails" || bad "relative link out: rc=$rc: $out"

fresh; ln -s /usr/share/probe/README "$U/usr/bin/probe-readme"
out="$(check)"; rc=$?
[[ "$rc" -eq 0 ]] && ok "an absolute link that stays in /usr passes" || bad "absolute link in: rc=$rc: $out"

fresh; rm -rf "${U:?}/usr"
out="$(check)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"installed nothing under /usr"* ]] \
    && ok "an image with nothing under /usr fails" || bad "empty image: rc=$rc: $out"

# A whiteout is a character device 0/0, which only root can make.
fresh
if mknod "$U/usr/bin/bash" c 0 0 2>/dev/null; then
    out="$(check)"; rc=$?
    [[ "$rc" -ne 0 && "$out" == *"removes the root's /usr/bin/bash"* ]] \
        && ok "a whiteout fails" || bad "whiteout: rc=$rc: $out"
else
    printf '  SKIP  a whiteout fails (making one needs root)\n'
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
