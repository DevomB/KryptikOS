#!/usr/bin/env bash
# Fetch and verify upstream source tarballs.
#
#   ./tools/fetch-sources.sh            download and verify against sources.lock
#   ./tools/fetch-sources.sh --lock     download and WRITE sources.lock
#   ./tools/fetch-sources.sh --list     print the resolved manifest, download nothing
#
# --lock records whatever downloads (trust on first use): audit it before
# committing. See docs/supply-chain.md.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

MODE="verify"
case "${1:-}" in
    --lock) MODE="lock" ;;
    --list) MODE="list" ;;
    "")     ;;
    *)      die "unknown argument: $1 (expected --lock, --list, or nothing)" ;;
esac

# Test hook: tools/tests/fetch-sources.sh substitutes a manifest of file:// URLs.
if [[ -n "${KRYPTIK_FETCH_MANIFEST:-}" ]]; then
    [[ "${KRYPTIK_FETCH_SELFTEST:-0}" == "1" ]] || die \
"KRYPTIK_FETCH_MANIFEST is set but KRYPTIK_FETCH_SELFTEST is not.
Refusing to fetch or lock against a substituted manifest."
    warn "SELF-TEST MODE: the manifest is substituted, not the real one"
fi

# name|version|url|sig|new
#
# sig says how upstream vouches for the file (tools/verify-signatures.sh):
#   gnu      a .sig on the canonical GNU host
#   kernel   kernel.org's .tar.sign over the uncompressed tar
#   sig asc  a detached signature beside the file, with that suffix
#   stem.sig a .sig beside it, named without the .tar.* suffix (less-710.sig)
#   sums:NAME  the signature NAME beside it, over a checksum list named NAME
#            without its suffix, which must give the file's digest
#   probe    whichever of .sig, .asc and .sign is published; an uploaded file
#            with none keeps probe, so a later release's signature is found
#   sha256   the publisher's .sha256 beside it (tools/verify-provenance.sh)
#   sha256.txt  the same, named .sha256.txt
#   tag      a signed tag the archive must reproduce (tools/verify-provenance.sh)
#   none     nothing: a generated archive (GitHub /archive/, GitLab
#            /-/archive/, sr.ht /archive/) can have nothing beside it
# new says where its newest release is found (tools/check-source-currency.sh):
#   gnu      the canonical GNU host's listing
#   vdir     the listing in the newest vN/ directory beside the file's own
#   github   the project's designated latest release
#   listing  the listing of the directory the file is in
#   rule     its row in tools/currency-rules.tsv
#   eol      nowhere: the kernel's support status is tools/check-kernel-eol.sh's
#   follows:NAME  nowhere: it moves only when NAME's pin does
manifest() {
    if [[ -n "${KRYPTIK_FETCH_MANIFEST:-}" ]]; then
        cat "$KRYPTIK_FETCH_MANIFEST"
        return
    fi
    local gnu="$MIRROR_GNU"
    cat <<MANIFEST
binutils|${V_BINUTILS}|${gnu}/binutils/binutils-${V_BINUTILS}.tar.xz|gnu|gnu
gcc|${V_GCC}|${gnu}/gcc/gcc-${V_GCC}/gcc-${V_GCC}.tar.xz|gnu|rule
glibc|${V_GLIBC}|${gnu}/glibc/glibc-${V_GLIBC}.tar.xz|gnu|gnu
linux|${V_LINUX}|${MIRROR_KERNEL}/v${V_LINUX%%.*}.x/linux-${V_LINUX}.tar.xz|kernel|eol
gmp|${V_GMP}|${gnu}/gmp/gmp-${V_GMP}.tar.xz|gnu|gnu
mpfr|${V_MPFR}|${gnu}/mpfr/mpfr-${V_MPFR}.tar.xz|gnu|gnu
mpc|${V_MPC}|${gnu}/mpc/mpc-${V_MPC}.tar.gz|gnu|gnu
bash|${V_BASH}|${gnu}/bash/bash-${V_BASH}.tar.gz|gnu|gnu
coreutils|${V_COREUTILS}|${gnu}/coreutils/coreutils-${V_COREUTILS}.tar.xz|gnu|gnu
sed|${V_SED}|${gnu}/sed/sed-${V_SED}.tar.xz|gnu|gnu
grep|${V_GREP}|${gnu}/grep/grep-${V_GREP}.tar.xz|gnu|gnu
gawk|${V_GAWK}|${gnu}/gawk/gawk-${V_GAWK}.tar.xz|gnu|gnu
findutils|${V_FINDUTILS}|${gnu}/findutils/findutils-${V_FINDUTILS}.tar.xz|gnu|gnu
diffutils|${V_DIFFUTILS}|${gnu}/diffutils/diffutils-${V_DIFFUTILS}.tar.xz|gnu|gnu
tar|${V_TAR}|${gnu}/tar/tar-${V_TAR}.tar.xz|gnu|gnu
gzip|${V_GZIP}|${gnu}/gzip/gzip-${V_GZIP}.tar.xz|gnu|gnu
make|${V_MAKE}|${gnu}/make/make-${V_MAKE}.tar.gz|gnu|gnu
patch|${V_PATCH}|${gnu}/patch/patch-${V_PATCH}.tar.xz|gnu|gnu
m4|${V_M4}|${gnu}/m4/m4-${V_M4}.tar.xz|gnu|gnu
ncurses|${V_NCURSES}|${gnu}/ncurses/ncurses-${V_NCURSES}.tar.gz|gnu|gnu
readline|${V_READLINE}|${gnu}/readline/readline-${V_READLINE}.tar.gz|gnu|gnu
xz|${V_XZ}|${MIRROR_XZ}/v${V_XZ}/xz-${V_XZ}.tar.xz|sig|github
file|${V_FILE}|${MIRROR_FILE}/file-${V_FILE}.tar.gz|asc|listing
zlib|${V_ZLIB}|${MIRROR_GITHUB}/madler/zlib/releases/download/v${V_ZLIB}/zlib-${V_ZLIB}.tar.gz|asc|github
bzip2|${V_BZIP2}|${MIRROR_SOURCEWARE}/bzip2/bzip2-${V_BZIP2}.tar.gz|sig|listing
zstd|${V_ZSTD}|${MIRROR_GITHUB}/facebook/zstd/releases/download/v${V_ZSTD}/zstd-${V_ZSTD}.tar.gz|sig|github
expat|${V_EXPAT}|${MIRROR_GITHUB}/libexpat/libexpat/releases/download/R_${V_EXPAT//./_}/expat-${V_EXPAT}.tar.xz|asc|github
libffi|${V_LIBFFI}|${MIRROR_GITHUB}/libffi/libffi/releases/download/v${V_LIBFFI}/libffi-${V_LIBFFI}.tar.gz|probe|github
libxcrypt|${V_LIBXCRYPT}|${MIRROR_GITHUB}/besser82/libxcrypt/releases/download/v${V_LIBXCRYPT}/libxcrypt-${V_LIBXCRYPT}.tar.xz|asc|github
openssl|${V_OPENSSL}|https://www.openssl.org/source/openssl-${V_OPENSSL}.tar.gz|asc|rule
bc|${V_BC}|${gnu}/bc/bc-${V_BC}.tar.gz|gnu|gnu
bison|${V_BISON}|${gnu}/bison/bison-${V_BISON}.tar.xz|gnu|gnu
flex|${V_FLEX}|${MIRROR_GITHUB}/westes/flex/releases/download/v${V_FLEX}/flex-${V_FLEX}.tar.gz|sig|github
gdbm|${V_GDBM}|${gnu}/gdbm/gdbm-${V_GDBM}.tar.gz|gnu|gnu
gettext|${V_GETTEXT}|${gnu}/gettext/gettext-${V_GETTEXT}.tar.xz|gnu|gnu
texinfo|${V_TEXINFO}|${gnu}/texinfo/texinfo-${V_TEXINFO}.tar.xz|gnu|gnu
libtool|${V_LIBTOOL}|${gnu}/libtool/libtool-${V_LIBTOOL}.tar.xz|gnu|gnu
gperf|${V_GPERF}|${gnu}/gperf/gperf-${V_GPERF}.tar.gz|gnu|gnu
attr|${V_ATTR}|${MIRROR_SAVANNAH}/attr/attr-${V_ATTR}.tar.gz|sig|listing
acl|${V_ACL}|${MIRROR_SAVANNAH}/acl/acl-${V_ACL}.tar.xz|sig|listing
libcap|${V_LIBCAP}|${MIRROR_LIBCAP}/libcap-${V_LIBCAP}.tar.xz|kernel|listing
shadow|${V_SHADOW}|${MIRROR_GITHUB}/shadow-maint/shadow/releases/download/${V_SHADOW}/shadow-${V_SHADOW}.tar.xz|asc|github
pkgconf|${V_PKGCONF}|https://distfiles.ariadne.space/pkgconf/pkgconf-${V_PKGCONF}.tar.xz|probe|listing
iana-etc|${V_IANA_ETC}|${MIRROR_GITHUB}/Mic92/iana-etc/releases/download/${V_IANA_ETC}/iana-etc-${V_IANA_ETC}.tar.gz|sha256|github
less|${V_LESS}|https://www.greenwoodsoftware.com/less/less-${V_LESS}.tar.gz|stem.sig|rule
groff|${V_GROFF}|${gnu}/groff/groff-${V_GROFF}.tar.gz|gnu|gnu
util-linux|${V_UTIL_LINUX}|${MIRROR_KERNEL_UTILS}/util-linux/v${V_UTIL_LINUX%.*}/util-linux-${V_UTIL_LINUX}.tar.xz|kernel|vdir
e2fsprogs|${V_E2FSPROGS}|${MIRROR_E2FSPROGS}/v${V_E2FSPROGS}/e2fsprogs-${V_E2FSPROGS}.tar.gz|kernel|vdir
procps-ng|${V_PROCPS}|${MIRROR_SOURCEFORGE}/procps-ng/procps-ng-${V_PROCPS}.tar.xz|asc|rule
psmisc|${V_PSMISC}|${MIRROR_SOURCEFORGE}/psmisc/psmisc-${V_PSMISC}.tar.xz|asc|rule
inetutils|${V_INETUTILS}|${gnu}/inetutils/inetutils-${V_INETUTILS}.tar.gz|gnu|gnu
iproute2|${V_IPROUTE2}|${MIRROR_KERNEL_UTILS}/net/iproute2/iproute2-${V_IPROUTE2}.tar.xz|kernel|listing
iputils|${V_IPUTILS}|${MIRROR_GITHUB}/iputils/iputils/releases/download/${V_IPUTILS}/iputils-${V_IPUTILS}.tar.xz|asc|github
kbd|${V_KBD}|${MIRROR_KERNEL_UTILS}/kbd/kbd-${V_KBD}.tar.xz|kernel|listing
kmod|${V_KMOD}|${MIRROR_KERNEL_UTILS}/kernel/kmod/kmod-${V_KMOD}.tar.xz|kernel|listing
libpipeline|${V_LIBPIPELINE}|${MIRROR_SAVANNAH}/libpipeline/libpipeline-${V_LIBPIPELINE}.tar.gz|asc|listing
man-db|${V_MANDB}|${MIRROR_SAVANNAH}/man-db/man-db-${V_MANDB}.tar.xz|asc|listing
elfutils|${V_ELFUTILS}|${MIRROR_SOURCEWARE}/elfutils/${V_ELFUTILS}/elfutils-${V_ELFUTILS}.tar.bz2|sig|rule
eudev|${V_EUDEV}|${MIRROR_GITHUB}/eudev-project/eudev/releases/download/v${V_EUDEV}/eudev-${V_EUDEV}.tar.gz|asc|github
perl|${V_PERL}|https://www.cpan.org/src/5.0/perl-${V_PERL}.tar.xz|sha256.txt|rule
python|${V_PYTHON}|https://www.python.org/ftp/python/${V_PYTHON}/Python-${V_PYTHON}.tar.xz|asc|rule
skalibs|${V_SKALIBS}|${MIRROR_SKARNET}/skalibs/skalibs-${V_SKALIBS}.tar.gz|sha256|listing
execline|${V_EXECLINE}|${MIRROR_SKARNET}/execline/execline-${V_EXECLINE}.tar.gz|sha256|listing
s6|${V_S6}|${MIRROR_SKARNET}/s6/s6-${V_S6}.tar.gz|sha256|listing
s6-rc|${V_S6_RC}|${MIRROR_SKARNET}/s6-rc/s6-rc-${V_S6_RC}.tar.gz|sha256|listing
s6-linux-init|${V_S6_LINUX_INIT}|${MIRROR_SKARNET}/s6-linux-init/s6-linux-init-${V_S6_LINUX_INIT}.tar.gz|sha256|listing
hardened-malloc|${V_HARDENED_MALLOC}|${MIRROR_GITHUB}/GrapheneOS/hardened_malloc/archive/refs/tags/${V_HARDENED_MALLOC}.tar.gz|tag|github
kernel-hardening-checker|${V_KERNEL_HARDENING_CHECKER}|${MIRROR_GITHUB}/a13xp0p0v/kernel-hardening-checker/archive/refs/tags/v${V_KERNEL_HARDENING_CHECKER}.tar.gz|none|rule
cmake|${V_CMAKE}|${MIRROR_CMAKE}/v${V_CMAKE%.*}/cmake-${V_CMAKE}.tar.gz|sums:cmake-${V_CMAKE}-SHA-256.txt.asc|vdir
cmake-bin|${V_CMAKE}|${MIRROR_CMAKE}/v${V_CMAKE%.*}/cmake-${V_CMAKE}-linux-x86_64.tar.gz|sums:cmake-${V_CMAKE}-SHA-256.txt.asc|vdir
json-c|${V_JSON_C}|${MIRROR_GITHUB}/json-c/json-c/archive/json-c-${V_JSON_C}/json-c-${V_JSON_C}.tar.gz|none|github
popt|${V_POPT}|${MIRROR_OSUOSL_RPM}/popt/releases/popt-1.x/popt-${V_POPT}.tar.gz|probe|listing
libaio|${V_LIBAIO}|${MIRROR_PAGURE}/libaio/libaio-${V_LIBAIO}.tar.gz|probe|listing
lvm2|${V_LVM2}|${MIRROR_SOURCEWARE}/lvm2/LVM2.${V_LVM2}.tgz|asc|rule
cryptsetup|${V_CRYPTSETUP}|${MIRROR_KERNEL_UTILS}/cryptsetup/v${V_CRYPTSETUP%.*}/cryptsetup-${V_CRYPTSETUP}.tar.xz|kernel|vdir
openssh|${V_OPENSSH}|${MIRROR_OPENBSD}/OpenSSH/portable/openssh-${V_OPENSSH}.tar.gz|asc|rule
libmnl|${V_LIBMNL}|${MIRROR_NETFILTER}/libmnl/libmnl-${V_LIBMNL}.tar.bz2|sig|listing
libnftnl|${V_LIBNFTNL}|${MIRROR_NETFILTER}/libnftnl/libnftnl-${V_LIBNFTNL}.tar.xz|sig|listing
nftables|${V_NFTABLES}|${MIRROR_NETFILTER}/nftables/nftables-${V_NFTABLES}.tar.xz|sig|listing
dnsmasq|${V_DNSMASQ}|${MIRROR_KELLEYS}/dnsmasq-${V_DNSMASQ}.tar.xz|asc|listing
dhcpcd|${V_DHCPCD}|${MIRROR_GITHUB}/NetworkConfiguration/dhcpcd/releases/download/v${V_DHCPCD}/dhcpcd-${V_DHCPCD}.tar.xz|asc|github
libnl|${V_LIBNL}|${MIRROR_GITHUB}/thom311/libnl/releases/download/libnl${V_LIBNL//./_}/libnl-${V_LIBNL}.tar.gz|sig|github
wpa-supplicant|${V_WPA_SUPPLICANT}|${MIRROR_W1FI}/wpa_supplicant-${V_WPA_SUPPLICANT}.tar.gz|asc|listing
iw|${V_IW}|${MIRROR_KERNEL_SOFTWARE}/network/iw/iw-${V_IW}.tar.xz|kernel|listing
ca-bundle|${V_CA_BUNDLE}|${MIRROR_CURL_CA}/cacert-${V_CA_BUNDLE}.pem|sha256|rule
linux-firmware|${V_LINUX_FIRMWARE}|${MIRROR_KERNEL}/firmware/linux-firmware-${V_LINUX_FIRMWARE}.tar.xz|kernel|listing
wireless-regdb|${V_WIRELESS_REGDB}|${MIRROR_KERNEL_SOFTWARE}/network/wireless-regdb/wireless-regdb-${V_WIRELESS_REGDB}.tar.xz|kernel|listing
intel-microcode|${V_INTEL_MICROCODE}|${MIRROR_GITHUB}/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/refs/tags/microcode-${V_INTEL_MICROCODE}.tar.gz|none|github
meson|${V_MESON}|${MIRROR_GITHUB}/mesonbuild/meson/releases/download/${V_MESON}/meson-${V_MESON}.tar.gz|asc|github
ninja|${V_NINJA}|${MIRROR_GITHUB}/ninja-build/ninja/archive/v${V_NINJA}/ninja-${V_NINJA}.tar.gz|none|github
wayland|${V_WAYLAND}|${MIRROR_FDO_GITLAB}/wayland/wayland/-/releases/${V_WAYLAND}/downloads/wayland-${V_WAYLAND}.tar.xz|sig|rule
wayland-protocols|${V_WAYLAND_PROTOCOLS}|${MIRROR_FDO_GITLAB}/wayland/wayland-protocols/-/releases/${V_WAYLAND_PROTOCOLS}/downloads/wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz|sig|rule
libxkbcommon|${V_LIBXKBCOMMON}|${MIRROR_GITHUB}/xkbcommon/libxkbcommon/archive/xkbcommon-${V_LIBXKBCOMMON}/libxkbcommon-${V_LIBXKBCOMMON}.tar.gz|none|github
xkeyboard-config|${V_XKEYBOARD_CONFIG}|${MIRROR_XORG}/data/xkeyboard-config/xkeyboard-config-${V_XKEYBOARD_CONFIG}.tar.xz|sig|listing
pixman|${V_PIXMAN}|${MIRROR_CAIRO}/pixman-${V_PIXMAN}.tar.gz|sums:pixman-${V_PIXMAN}.tar.gz.sha512.asc|listing
libdrm|${V_LIBDRM}|${MIRROR_DRI}/libdrm-${V_LIBDRM}.tar.xz|sig|listing
libevdev|${V_LIBEVDEV}|${MIRROR_FDO_SW}/libevdev/libevdev-${V_LIBEVDEV}.tar.xz|sig|listing
mtdev|${V_MTDEV}|${MIRROR_BITMATH}/mtdev-${V_MTDEV}.tar.bz2|probe|listing
libinput|${V_LIBINPUT}|${MIRROR_FDO_GITLAB}/libinput/libinput/-/archive/${V_LIBINPUT}/libinput-${V_LIBINPUT}.tar.gz|none|rule
seatd|${V_SEATD}|${MIRROR_SRHT}/~kennylevinsen/seatd/archive/${V_SEATD}.tar.gz|none|rule
hwdata|${V_HWDATA}|${MIRROR_GITHUB}/vcrhonek/hwdata/archive/v${V_HWDATA}/hwdata-${V_HWDATA}.tar.gz|none|github
libdisplay-info|${V_LIBDISPLAY_INFO}|${MIRROR_FDO_GITLAB}/emersion/libdisplay-info/-/releases/${V_LIBDISPLAY_INFO}/downloads/libdisplay-info-${V_LIBDISPLAY_INFO}.tar.xz|sig|rule
wlroots|${V_WLROOTS}|${MIRROR_FDO_GITLAB}/wlroots/wlroots/-/releases/${V_WLROOTS}/downloads/wlroots-${V_WLROOTS}.tar.gz|sig|rule
dwl|${V_DWL}|${MIRROR_CODEBERG}/dwl/dwl/releases/download/v${V_DWL}/dwl-v${V_DWL}.tar.gz|probe|rule
havoc|${V_HAVOC}|${MIRROR_GITHUB}/ii8/havoc/archive/${V_HAVOC}/havoc-${V_HAVOC}.tar.gz|none|github
dejavu-fonts|${V_DEJAVU_FONTS}|${MIRROR_GITHUB}/dejavu-fonts/dejavu-fonts/releases/download/version_${V_DEJAVU_FONTS//./_}/dejavu-fonts-ttf-${V_DEJAVU_FONTS}.tar.bz2|probe|github
lynx|${V_LYNX}|${MIRROR_DICKEY}/lynx/tarballs/lynx${V_LYNX}.tar.bz2|asc|rule
nano|${V_NANO}|${MIRROR_NANO}/v${V_NANO%%.*}/nano-${V_NANO}.tar.xz|asc|vdir
glibc-fhs-patch|${V_GLIBC}|${MIRROR_LFS_PATCHES}/glibc-${V_GLIBC}-fhs-1.patch|none|follows:glibc
linux-hardened|${V_LINUX_HARDENED}|${MIRROR_HARDENED}/v${V_LINUX_HARDENED}/linux-hardened-v${V_LINUX_HARDENED}.patch|sig|eol
MANIFEST
}

if [[ "$MODE" == "list" ]]; then
    manifest | while IFS='|' read -r name ver url sig new; do
        printf '%-12s %-10s %s %s %s\n' "$name" "$ver" "$url" "$sig" "$new"
    done
    exit 0
fi

mkdir -p "$KRYPTIK_SOURCES"

# fetch_one <url> <dest>: try each mirror in order.
fetch_one() {
    local url="$1" dest="$2"
    local -a urls=("$url")

    # GNU tarballs get a second mirror.
    if [[ -n "${MIRROR_GNU_FALLBACK:-}" && "$url" == "${MIRROR_GNU}/"* ]]; then
        urls+=("${MIRROR_GNU_FALLBACK}/${url#"${MIRROR_GNU}/"}")
    fi

    # Per mirror: resume, then, if a partial existed, once more from zero. A
    # .part longer than the upstream file makes every resume fail (curl 36 for
    # file://, 33 or HTTP 416) and would otherwise fail every mirror on every run.
    local u attempt=0
    for u in "${urls[@]}"; do
        attempt=$((attempt + 1))
        [[ "$attempt" -gt 1 ]] && warn "trying fallback mirror: ${u}"

        if fetch_attempt "$u" "$dest" resume; then return 0; fi

        if [[ -s "${dest}.part" ]]; then
            warn "resume failed; discarding the partial file and starting over"
            rm -f "${dest}.part"
            if fetch_attempt "$u" "$dest" fresh; then return 0; fi
        fi
        warn "failed from ${u}"
    done

    # A .part is kept for the next run unless resuming from it failed.
    return 1
}

# fetch_attempt <url> <dest> resume|fresh
# --no-progress-meter: the bar floods logs that are not a terminal.
# --speed-limit/--speed-time: fail a stalled transfer fast, then retry.
fetch_attempt() {
    local u="$1" dest="$2" mode="$3"
    local -a resume=()
    [[ "$mode" == resume ]] && resume=(-C -)
    if curl -fL \
            --no-progress-meter \
            --connect-timeout 20 \
            --speed-limit 2048 --speed-time 30 \
            --retry 3 --retry-delay 2 --retry-connrefused \
            "${resume[@]}" -o "${dest}.part" "$u"; then
        mv "${dest}.part" "$dest"
        return 0
    fi
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
while IFS='|' read -r name ver url _; do
    [[ -z "$name" ]] && continue
    total=$((total + 1))
    file="$(basename "$url")"
    dest="${KRYPTIK_SOURCES}/${file}"

    was_fetched=no
    if [[ -f "$dest" ]]; then
        cached=$((cached + 1))
    else
        log "fetching ${name} ${ver}"
        if ! fetch_one "$url" "$dest"; then
            die "download failed: ${name} ${ver}
Tried every mirror. Re-run to resume — a partial download is kept unless
resuming from it is what failed, in which case it has been discarded."
        fi
        fetched=$((fetched + 1))
        was_fetched=yes
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
            # Nothing is deleted: a mismatching file is evidence.
            if [[ "$was_fetched" == yes ]]; then
                die "This file was downloaded just now, so the DOWNLOAD is
wrong rather than the disk: a bad mirror, or a stale partial file that
poisoned a resume. Remove ${dest} and any ${dest}.part, then retry."
            fi
            die "This file was already on disk and does not match the hash
sources.lock recorded for it, so it CHANGED after it was locked. Do not
delete it yet - work out why first. See docs/supply-chain.md."
        fi
        ok "${name} ${ver}  verified"
    fi
done < <(manifest)

# The GNU keyring, kept with the sources so a cache of them carries it: the
# signature gate checks GNU signatures against it, and ftp.gnu.org does not
# answer every runner every time.
keyring="${KRYPTIK_SOURCES}/.keys/gnu-keyring.gpg"
if [[ ! -s "$keyring" ]]; then
    mkdir -p "${KRYPTIK_SOURCES}/.keys"
    log "fetching the GNU keyring"
    fetch_attempt "https://ftp.gnu.org/gnu/gnu-keyring.gpg" "$keyring" fresh \
        || { rm -f "${keyring}.part"; warn "could not fetch the GNU keyring; tools/verify-signatures.sh fetches it again"; }
fi

if [[ "$MODE" == "lock" ]]; then
    sort -k2 "${KRYPTIK_LOCK}.new" > "$KRYPTIK_LOCK"
    rm -f "${KRYPTIK_LOCK}.new"
    ok "wrote $(wc -l < "$KRYPTIK_LOCK") entries to sources.lock"
    warn "NOT YET AUDITED. Verify against upstream signatures before trusting."
else
    ok "${total} package(s) verified (${fetched} downloaded, ${cached} cached)"
fi
