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
xz|${V_XZ}|${MIRROR_XZ}/v${V_XZ}/xz-${V_XZ}.tar.xz
file|${V_FILE}|${MIRROR_FILE}/file-${V_FILE}.tar.gz
zlib|${V_ZLIB}|${MIRROR_GITHUB}/madler/zlib/releases/download/v${V_ZLIB}/zlib-${V_ZLIB}.tar.gz
bzip2|${V_BZIP2}|${MIRROR_SOURCEWARE}/bzip2/bzip2-${V_BZIP2}.tar.gz
zstd|${V_ZSTD}|${MIRROR_GITHUB}/facebook/zstd/releases/download/v${V_ZSTD}/zstd-${V_ZSTD}.tar.gz
expat|${V_EXPAT}|${MIRROR_GITHUB}/libexpat/libexpat/releases/download/R_${V_EXPAT//./_}/expat-${V_EXPAT}.tar.xz
libffi|${V_LIBFFI}|${MIRROR_GITHUB}/libffi/libffi/releases/download/v${V_LIBFFI}/libffi-${V_LIBFFI}.tar.gz
libxcrypt|${V_LIBXCRYPT}|${MIRROR_GITHUB}/besser82/libxcrypt/releases/download/v${V_LIBXCRYPT}/libxcrypt-${V_LIBXCRYPT}.tar.xz
openssl|${V_OPENSSL}|https://www.openssl.org/source/openssl-${V_OPENSSL}.tar.gz
bison|${V_BISON}|${gnu}/bison/bison-${V_BISON}.tar.xz
flex|${V_FLEX}|${MIRROR_GITHUB}/westes/flex/releases/download/v${V_FLEX}/flex-${V_FLEX}.tar.gz
gettext|${V_GETTEXT}|${gnu}/gettext/gettext-${V_GETTEXT}.tar.xz
texinfo|${V_TEXINFO}|${gnu}/texinfo/texinfo-${V_TEXINFO}.tar.xz
autoconf|${V_AUTOCONF}|${gnu}/autoconf/autoconf-${V_AUTOCONF}.tar.xz
automake|${V_AUTOMAKE}|${gnu}/automake/automake-${V_AUTOMAKE}.tar.xz
libtool|${V_LIBTOOL}|${gnu}/libtool/libtool-${V_LIBTOOL}.tar.xz
gperf|${V_GPERF}|${gnu}/gperf/gperf-${V_GPERF}.tar.gz
attr|${V_ATTR}|${MIRROR_SAVANNAH}/attr/attr-${V_ATTR}.tar.gz
acl|${V_ACL}|${MIRROR_SAVANNAH}/acl/acl-${V_ACL}.tar.xz
libcap|${V_LIBCAP}|${MIRROR_LIBCAP}/libcap-${V_LIBCAP}.tar.xz
shadow|${V_SHADOW}|${MIRROR_GITHUB}/shadow-maint/shadow/releases/download/${V_SHADOW}/shadow-${V_SHADOW}.tar.xz
pkgconf|${V_PKGCONF}|https://distfiles.ariadne.space/pkgconf/pkgconf-${V_PKGCONF}.tar.xz
iana-etc|${V_IANA_ETC}|${MIRROR_GITHUB}/Mic92/iana-etc/releases/download/${V_IANA_ETC}/iana-etc-${V_IANA_ETC}.tar.gz
less|${V_LESS}|https://www.greenwoodsoftware.com/less/less-${V_LESS}.tar.gz
groff|${V_GROFF}|${gnu}/groff/groff-${V_GROFF}.tar.gz
util-linux|${V_UTIL_LINUX}|${MIRROR_KERNEL_UTILS}/util-linux/v${V_UTIL_LINUX%.*}/util-linux-${V_UTIL_LINUX}.tar.xz
e2fsprogs|${V_E2FSPROGS}|${MIRROR_E2FSPROGS}/v${V_E2FSPROGS}/e2fsprogs-${V_E2FSPROGS}.tar.gz
procps-ng|${V_PROCPS}|${MIRROR_SOURCEFORGE}/procps-ng/procps-ng-${V_PROCPS}.tar.xz
psmisc|${V_PSMISC}|${MIRROR_SOURCEFORGE}/psmisc/psmisc-${V_PSMISC}.tar.xz
inetutils|${V_INETUTILS}|${gnu}/inetutils/inetutils-${V_INETUTILS}.tar.xz
iproute2|${V_IPROUTE2}|${MIRROR_KERNEL_UTILS}/net/iproute2/iproute2-${V_IPROUTE2}.tar.xz
kbd|${V_KBD}|${MIRROR_KERNEL_UTILS}/kbd/kbd-${V_KBD}.tar.xz
kmod|${V_KMOD}|${MIRROR_KERNEL_UTILS}/kernel/kmod/kmod-${V_KMOD}.tar.xz
libpipeline|${V_LIBPIPELINE}|${MIRROR_SAVANNAH}/libpipeline/libpipeline-${V_LIBPIPELINE}.tar.gz
man-db|${V_MANDB}|${MIRROR_SAVANNAH}/man-db/man-db-${V_MANDB}.tar.xz
elfutils|${V_ELFUTILS}|${MIRROR_SOURCEWARE}/elfutils/${V_ELFUTILS}/elfutils-${V_ELFUTILS}.tar.bz2
eudev|${V_EUDEV}|${MIRROR_GITHUB}/eudev-project/eudev/releases/download/v${V_EUDEV}/eudev-${V_EUDEV}.tar.gz
grub|${V_GRUB}|${gnu}/grub/grub-${V_GRUB}.tar.xz
perl|${V_PERL}|https://www.cpan.org/src/5.0/perl-${V_PERL}.tar.xz
python|${V_PYTHON}|https://www.python.org/ftp/python/${V_PYTHON}/Python-${V_PYTHON}.tar.xz
skalibs|${V_SKALIBS}|${MIRROR_SKARNET}/skalibs/skalibs-${V_SKALIBS}.tar.gz
execline|${V_EXECLINE}|${MIRROR_SKARNET}/execline/execline-${V_EXECLINE}.tar.gz
s6|${V_S6}|${MIRROR_SKARNET}/s6/s6-${V_S6}.tar.gz
s6-rc|${V_S6_RC}|${MIRROR_SKARNET}/s6-rc/s6-rc-${V_S6_RC}.tar.gz
s6-linux-init|${V_S6_LINUX_INIT}|${MIRROR_SKARNET}/s6-linux-init/s6-linux-init-${V_S6_LINUX_INIT}.tar.gz
hardened-malloc|${V_HARDENED_MALLOC}|${MIRROR_GITHUB}/GrapheneOS/hardened_malloc/archive/refs/tags/${V_HARDENED_MALLOC}.tar.gz
glibc-fhs-patch|${V_GLIBC}|${MIRROR_LFS_PATCHES}/glibc-${V_GLIBC}-fhs-1.patch
linux-hardened|${V_LINUX_HARDENED}|${MIRROR_HARDENED}/v${V_LINUX_HARDENED}/linux-hardened-v${V_LINUX_HARDENED}.patch
MANIFEST
}

if [[ "$MODE" == "list" ]]; then
    manifest | while IFS='|' read -r name ver url; do
        printf '%-12s %-10s %s\n' "$name" "$ver" "$url"
    done
    exit 0
fi

mkdir -p "$KRYPTIK_SOURCES"

# Download one file, trying mirrors in order.
#
# Three things learned the hard way from ftp.gnu.org:
#   --no-progress-meter   the progress bar renders as thousands of lines when
#                         stdout is not a terminal, burying real errors
#   --speed-limit/-time   a transfer that stalls at 54% otherwise hangs for
#                         minutes before curl gives up; fail fast and retry
#   -C -                  resume a partial file rather than restarting a 140MB
#                         kernel tarball from zero
fetch_one() {
    local url="$1" dest="$2"
    local -a urls=("$url")

    # GNU tarballs get a second mirror.
    if [[ -n "${MIRROR_GNU_FALLBACK:-}" && "$url" == "${MIRROR_GNU}/"* ]]; then
        urls+=("${MIRROR_GNU_FALLBACK}/${url#"${MIRROR_GNU}/"}")
    fi

    local u attempt=0
    for u in "${urls[@]}"; do
        attempt=$((attempt + 1))
        [[ "$attempt" -gt 1 ]] && warn "trying fallback mirror: ${u}"
        if curl -fL \
                --no-progress-meter \
                --connect-timeout 20 \
                --speed-limit 2048 --speed-time 30 \
                --retry 3 --retry-delay 2 --retry-connrefused \
                -C - -o "${dest}.part" "$u"; then
            mv "${dest}.part" "$dest"
            return 0
        fi
        warn "failed from ${u}"
    done

    # Keep the .part file: the next run resumes instead of restarting.
    return 1
}

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
        if ! fetch_one "$url" "$dest"; then
            die "download failed: ${name} ${ver}
Tried every mirror. Re-run to resume — partial downloads are kept."
        fi
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
