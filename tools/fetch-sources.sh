#!/usr/bin/env bash
# Fetch and verify upstream source tarballs.
#
#   ./tools/fetch-sources.sh            download and verify against sources.lock
#   ./tools/fetch-sources.sh --lock     download and WRITE sources.lock
#   ./tools/fetch-sources.sh --list     print the resolved URL list, download nothing
#
# On checksums: this script never invents them. `--lock` records what it
# actually downloaded; verification mode refuses anything that does not match a
# recorded hash. A generated lock is trust-on-first-use and is NOT a substitute
# for checking upstream signatures — audit it before committing. See
# docs/supply-chain.md.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

MODE="verify"
case "${1:-}" in
    --lock) MODE="lock" ;;
    --list) MODE="list" ;;
    "")     ;;
    *)      die "unknown argument: $1 (expected --lock, --list, or nothing)" ;;
esac

# name|version|url
manifest() {
    local gnu="$MIRROR_GNU"
    cat <<MANIFEST
binutils|${V_BINUTILS}|${gnu}/binutils/binutils-${V_BINUTILS}.tar.xz
gcc|${V_GCC}|${gnu}/gcc/gcc-${V_GCC}/gcc-${V_GCC}.tar.xz
glibc|${V_GLIBC}|${gnu}/glibc/glibc-${V_GLIBC}.tar.xz
linux|${V_LINUX}|${MIRROR_KERNEL}/v${V_LINUX%%.*}.x/linux-${V_LINUX}.tar.xz
gmp|${V_GMP}|${gnu}/gmp/gmp-${V_GMP}.tar.xz
mpfr|${V_MPFR}|${gnu}/mpfr/mpfr-${V_MPFR}.tar.xz
mpc|${V_MPC}|${gnu}/mpc/mpc-${V_MPC}.tar.gz
bash|${V_BASH}|${gnu}/bash/bash-${V_BASH}.tar.gz
coreutils|${V_COREUTILS}|${gnu}/coreutils/coreutils-${V_COREUTILS}.tar.xz
sed|${V_SED}|${gnu}/sed/sed-${V_SED}.tar.xz
grep|${V_GREP}|${gnu}/grep/grep-${V_GREP}.tar.xz
gawk|${V_GAWK}|${gnu}/gawk/gawk-${V_GAWK}.tar.xz
findutils|${V_FINDUTILS}|${gnu}/findutils/findutils-${V_FINDUTILS}.tar.xz
diffutils|${V_DIFFUTILS}|${gnu}/diffutils/diffutils-${V_DIFFUTILS}.tar.xz
tar|${V_TAR}|${gnu}/tar/tar-${V_TAR}.tar.xz
gzip|${V_GZIP}|${gnu}/gzip/gzip-${V_GZIP}.tar.xz
make|${V_MAKE}|${gnu}/make/make-${V_MAKE}.tar.gz
patch|${V_PATCH}|${gnu}/patch/patch-${V_PATCH}.tar.xz
m4|${V_M4}|${gnu}/m4/m4-${V_M4}.tar.xz
ncurses|${V_NCURSES}|${gnu}/ncurses/ncurses-${V_NCURSES}.tar.gz
readline|${V_READLINE}|${gnu}/readline/readline-${V_READLINE}.tar.gz
glibc-fhs-patch|${V_GLIBC}|${MIRROR_LFS_PATCHES}/glibc-${V_GLIBC}-fhs-1.patch
MANIFEST
}

if [[ "$MODE" == "list" ]]; then
    manifest | while IFS='|' read -r name ver url; do
        printf '%-12s %-10s %s\n' "$name" "$ver" "$url"
    done
    exit 0
fi

mkdir -p "$KRYPTIK_SOURCES"

lookup_hash() {
    [[ -f "$KRYPTIK_LOCK" ]] || return 1
    awk -v f="$1" '$2 == f { print $1; found=1 } END { exit !found }' "$KRYPTIK_LOCK"
}

if [[ "$MODE" == "lock" ]]; then
    warn "Lock mode: recording checksums of whatever downloads."
    warn "Audit sources.lock against upstream signatures before committing it."
    : > "${KRYPTIK_LOCK}.new"
fi

total=0; fetched=0; cached=0
while IFS='|' read -r name ver url; do
    [[ -z "$name" ]] && continue
    total=$((total + 1))
    file="$(basename "$url")"
    dest="${KRYPTIK_SOURCES}/${file}"

    if [[ -f "$dest" ]]; then
        cached=$((cached + 1))
    else
        log "fetching ${name} ${ver}"
        if ! curl -fSL --retry 3 --retry-delay 2 -o "${dest}.part" "$url"; then
            rm -f "${dest}.part"
            die "download failed: ${url}"
        fi
        mv "${dest}.part" "$dest"
        fetched=$((fetched + 1))
    fi

    actual="$(sha256_of "$dest")"

    if [[ "$MODE" == "lock" ]]; then
        printf '%s  %s\n' "$actual" "$file" >> "${KRYPTIK_LOCK}.new"
        ok "${name} ${ver}  ${actual:0:16}…"
    else
        if ! expected="$(lookup_hash "$file")"; then
            die "no entry for ${file} in sources.lock.
Run './tools/fetch-sources.sh --lock' to generate one, then audit it."
        fi
        if [[ "$actual" != "$expected" ]]; then
            err "CHECKSUM MISMATCH for ${file}"
            err "  expected ${expected}"
            err "  actual   ${actual}"
            die "Refusing to continue. Delete ${dest} and retry, or investigate."
        fi
        ok "${name} ${ver}  verified"
    fi
done < <(manifest)

if [[ "$MODE" == "lock" ]]; then
    sort -k2 "${KRYPTIK_LOCK}.new" > "$KRYPTIK_LOCK"
    rm -f "${KRYPTIK_LOCK}.new"
    ok "wrote $(wc -l < "$KRYPTIK_LOCK") entries to sources.lock"
    warn "NOT YET AUDITED. Verify against upstream signatures before trusting."
else
    ok "${total} package(s) verified (${fetched} downloaded, ${cached} cached)"
fi
