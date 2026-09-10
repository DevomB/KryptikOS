#!/usr/bin/env bash
# Stage 00 — verify the host can build Kryptik.
# Based on the LFS host system requirements, plus Kryptik's own needs.

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

FAIL=0
WARN=0

# version_ge A B -> true if A >= B
version_ge() {
    [[ "$1" == "$2" ]] && return 0
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

check_version() {
    local name="$1" min="$2" got="$3"
    if [[ -z "$got" ]]; then
        err "${name}: not found (need >= ${min})"; FAIL=$((FAIL + 1)); return
    fi
    if version_ge "$got" "$min"; then
        ok "${name} ${got}"
    else
        err "${name} ${got} is too old (need >= ${min})"; FAIL=$((FAIL + 1))
    fi
}

# Extract the first dotted version number from a tool's version output.
ver_of() { "$@" 2>&1 | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true; }

log "Host system check"
require_linux
refuse_root

log "Required toolchain"
check_version "bash"      3.2    "$(ver_of bash --version)"
check_version "binutils"  2.13.1 "$(ver_of ld --version)"
check_version "bison"     2.7    "$(ver_of bison --version)"
check_version "coreutils" 8.1    "$(ver_of ls --version)"
check_version "diffutils" 2.8.1  "$(ver_of diff --version)"
check_version "findutils" 4.2.31 "$(ver_of find --version)"
check_version "gawk"      4.0.1  "$(ver_of gawk --version)"
check_version "gcc"       5.2    "$(ver_of gcc --version)"
check_version "g++"       5.2    "$(ver_of g++ --version)"
check_version "grep"      2.5.1  "$(ver_of grep --version)"
check_version "gzip"      1.3.12 "$(ver_of gzip --version)"
check_version "m4"        1.4.10 "$(ver_of m4 --version)"
check_version "make"      4.0    "$(ver_of make --version)"
check_version "patch"     2.5.4  "$(ver_of patch --version)"
check_version "perl"      5.8.8  "$(ver_of perl -V:version)"
check_version "python3"   3.4    "$(ver_of python3 --version)"
check_version "sed"       4.1.5  "$(ver_of sed --version)"
check_version "tar"       1.22   "$(ver_of tar --version)"
check_version "texinfo"   5.0    "$(ver_of makeinfo --version)"
check_version "xz"        5.0.0  "$(ver_of xz --version)"
check_version "linux"     5.4    "$(uname -r | grep -oE '^[0-9]+(\.[0-9]+)+')"

log "Kryptik-specific requirements"
for t in git curl sha256sum cpio rsync flex bc openssl; do
    if have "$t"; then ok "$t"
    else err "$t: not found"; FAIL=$((FAIL + 1)); fi
done

for t in qemu-system-x86_64 cryptsetup veritysetup sbsign; do
    if have "$t"; then ok "$t"
    else warn "$t: not found (needed from Phase 4 on, not now)"; WARN=$((WARN + 1)); fi
done

log "Environment sanity"

# /bin/sh must be bash for the LFS build; dash breaks bashisms in build scripts.
sh_target="$(readlink -f /bin/sh 2>/dev/null || echo unknown)"
if [[ "$sh_target" == *bash ]]; then
    ok "/bin/sh -> bash"
else
    err "/bin/sh -> ${sh_target} (must be bash)
       Debian/Ubuntu:  sudo dpkg-reconfigure dash   # answer No"
    FAIL=$((FAIL + 1))
fi

if have awk && [[ "$(readlink -f "$(command -v awk)")" == *gawk ]]; then
    ok "awk -> gawk"
else
    err "awk must be a symlink to gawk"; FAIL=$((FAIL + 1))
fi

# yacc must be bison
if have yacc && yacc --version 2>&1 | grep -qi bison; then
    ok "yacc -> bison"
else
    warn "yacc is not bison — some packages will fail to build"; WARN=$((WARN + 1))
fi

# The build is disk- and memory-hungry.
avail_gb=$(df -BG --output=avail "$KRYPTIK_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)
if [[ "${avail_gb:-0}" -ge 60 ]]; then
    ok "disk space: ${avail_gb}G available"
elif [[ "${avail_gb:-0}" -ge 30 ]]; then
    warn "disk space: ${avail_gb}G — tight; 60G+ recommended"; WARN=$((WARN + 1))
else
    err "disk space: ${avail_gb}G — need at least 30G"; FAIL=$((FAIL + 1))
fi

mem_gb=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1024 / 1024 ))
if [[ "$mem_gb" -ge 8 ]]; then ok "memory: ${mem_gb}G"
else warn "memory: ${mem_gb}G — GCC bootstrap wants 8G+"; WARN=$((WARN + 1)); fi

ok "parallelism: will use -j$(nproc)"

# A C++ toolchain that cannot link is a classic silent failure.
log "Compiler link test"
tmpd="$(mktemp -d)"; trap 'rm -rf "$tmpd"' EXIT
cat > "$tmpd/t.cpp" <<'CPP'
#include <iostream>
int main() { std::cout << "ok"; return 0; }
CPP
if g++ -o "$tmpd/t" "$tmpd/t.cpp" 2>/dev/null && [[ "$("$tmpd/t")" == "ok" ]]; then
    ok "g++ compiles and links C++"
else
    err "g++ cannot compile/link a C++ program (missing libstdc++ headers?)"
    FAIL=$((FAIL + 1))
fi

log "Config validation"
load_config && ok "versions.env parses"
validate_hardening_exceptions && ok "hardening exceptions documented"

echo
if [[ "$FAIL" -gt 0 ]]; then
    die "${FAIL} blocking problem(s), ${WARN} warning(s). Fix the failures above."
fi
[[ "$WARN" -gt 0 ]] && warn "${WARN} warning(s) — not blocking for the current phase."
ok "Host is ready. Next: make sources"
