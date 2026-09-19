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

# Self-test hook. tools/test-fetch-sources.sh substitutes a small manifest of
# file:// URLs so the checksum logic below - which is the part that enforces
# sources.lock - can be driven offline. Only the manifest is substituted; the
# download, the hashing and the refusal all run as they do in production.
#
# Gated, because a substituted manifest is a substituted definition of what
# Kryptik is built from.
if [[ -n "${KRYPTIK_FETCH_MANIFEST:-}" ]]; then
    [[ "${KRYPTIK_FETCH_SELFTEST:-0}" == "1" ]] || die \
"KRYPTIK_FETCH_MANIFEST is set but KRYPTIK_FETCH_SELFTEST is not.
Refusing to fetch or lock against a substituted manifest."
    warn "SELF-TEST MODE: the manifest is substituted, not the real one"
fi

# WHY bc CARRIES A DEFAULT VERSION AND NOTHING ELSE DOES.
#
# bc is a build-time requirement of the KERNEL, not a shipped convenience:
# linux/Kbuild generates include/generated/timeconst.h with `bc -q`, and
# arch/x86 asm-offsets depends on that header, so stage 05 dies at "bc:
# command not found" after its config step has already succeeded.
#
# `${V_BC:-1.08.2}` exists so that this row and the `V_BC` pin in
# build/config/versions.env can land in either order without breaking a build
# in flight - versions.env is the build's, this file is provenance's.
# The default cannot smuggle in an unaudited source: sources.lock pins the
# BYTES by filename, so any other value for V_BC produces a filename with no
# lock entry and fetch-sources.sh refuses it by name. Remove the default once
# versions.env carries the pin; it is redundancy for a handover, not policy.

# name|version|url
manifest() {
    if [[ -n "${KRYPTIK_FETCH_MANIFEST:-}" ]]; then
        cat "$KRYPTIK_FETCH_MANIFEST"
        return
    fi
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
bc|${V_BC}|${gnu}/bc/bc-${V_BC}.tar.gz
bison|${V_BISON}|${gnu}/bison/bison-${V_BISON}.tar.xz
flex|${V_FLEX}|${MIRROR_GITHUB}/westes/flex/releases/download/v${V_FLEX}/flex-${V_FLEX}.tar.gz
gdbm|${V_GDBM:-1.26}|${gnu}/gdbm/gdbm-${V_GDBM:-1.26}.tar.gz
gettext|${V_GETTEXT}|${gnu}/gettext/gettext-${V_GETTEXT}.tar.xz
texinfo|${V_TEXINFO}|${gnu}/texinfo/texinfo-${V_TEXINFO}.tar.xz
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
perl|${V_PERL}|https://www.cpan.org/src/5.0/perl-${V_PERL}.tar.xz
python|${V_PYTHON}|https://www.python.org/ftp/python/${V_PYTHON}/Python-${V_PYTHON}.tar.xz
skalibs|${V_SKALIBS}|${MIRROR_SKARNET}/skalibs/skalibs-${V_SKALIBS}.tar.gz
execline|${V_EXECLINE}|${MIRROR_SKARNET}/execline/execline-${V_EXECLINE}.tar.gz
s6|${V_S6}|${MIRROR_SKARNET}/s6/s6-${V_S6}.tar.gz
s6-rc|${V_S6_RC}|${MIRROR_SKARNET}/s6-rc/s6-rc-${V_S6_RC}.tar.gz
s6-linux-init|${V_S6_LINUX_INIT}|${MIRROR_SKARNET}/s6-linux-init/s6-linux-init-${V_S6_LINUX_INIT}.tar.gz
hardened-malloc|${V_HARDENED_MALLOC}|${MIRROR_GITHUB}/GrapheneOS/hardened_malloc/archive/refs/tags/${V_HARDENED_MALLOC}.tar.gz
kernel-hardening-checker|${V_KERNEL_HARDENING_CHECKER}|${MIRROR_GITHUB}/a13xp0p0v/kernel-hardening-checker/archive/refs/tags/v${V_KERNEL_HARDENING_CHECKER}.tar.gz
cmake|${V_CMAKE}|${MIRROR_CMAKE}/v${V_CMAKE%.*}/cmake-${V_CMAKE}.tar.gz
cmake-bin|${V_CMAKE}|${MIRROR_CMAKE}/v${V_CMAKE%.*}/cmake-${V_CMAKE}-linux-x86_64.tar.gz
json-c|${V_JSON_C}|${MIRROR_GITHUB}/json-c/json-c/archive/json-c-${V_JSON_C}/json-c-${V_JSON_C}.tar.gz
popt|${V_POPT}|${MIRROR_OSUOSL_RPM}/popt/releases/popt-1.x/popt-${V_POPT}.tar.gz
libaio|${V_LIBAIO}|${MIRROR_PAGURE}/libaio/libaio-${V_LIBAIO}.tar.gz
lvm2|${V_LVM2}|${MIRROR_SOURCEWARE}/lvm2/LVM2.${V_LVM2}.tgz
cryptsetup|${V_CRYPTSETUP}|${MIRROR_KERNEL_UTILS}/cryptsetup/v${V_CRYPTSETUP%.*}/cryptsetup-${V_CRYPTSETUP}.tar.xz
openssh|${V_OPENSSH}|${MIRROR_OPENBSD}/OpenSSH/portable/openssh-${V_OPENSSH}.tar.gz
libmnl|${V_LIBMNL}|${MIRROR_NETFILTER}/libmnl/libmnl-${V_LIBMNL}.tar.bz2
libnftnl|${V_LIBNFTNL}|${MIRROR_NETFILTER}/libnftnl/libnftnl-${V_LIBNFTNL}.tar.xz
nftables|${V_NFTABLES}|${MIRROR_NETFILTER}/nftables/nftables-${V_NFTABLES}.tar.xz
dnsmasq|${V_DNSMASQ}|${MIRROR_KELLEYS}/dnsmasq-${V_DNSMASQ}.tar.xz
dhcpcd|${V_DHCPCD}|${MIRROR_GITHUB}/NetworkConfiguration/dhcpcd/releases/download/v${V_DHCPCD}/dhcpcd-${V_DHCPCD}.tar.xz
libnl|${V_LIBNL}|${MIRROR_GITHUB}/thom311/libnl/releases/download/libnl${V_LIBNL//./_}/libnl-${V_LIBNL}.tar.gz
wpa-supplicant|${V_WPA_SUPPLICANT}|${MIRROR_W1FI}/wpa_supplicant-${V_WPA_SUPPLICANT}.tar.gz
iw|${V_IW}|${MIRROR_KERNEL_SOFTWARE}/network/iw/iw-${V_IW}.tar.xz
chrony|${V_CHRONY}|${MIRROR_CHRONY}/chrony-${V_CHRONY}.tar.gz
ca-bundle|${V_CA_BUNDLE}|${MIRROR_CURL_CA}/cacert-${V_CA_BUNDLE}.pem
linux-firmware|${V_LINUX_FIRMWARE}|${MIRROR_KERNEL}/firmware/linux-firmware-${V_LINUX_FIRMWARE}.tar.xz
wireless-regdb|${V_WIRELESS_REGDB}|${MIRROR_KERNEL_SOFTWARE}/network/wireless-regdb/wireless-regdb-${V_WIRELESS_REGDB}.tar.xz
intel-microcode|${V_INTEL_MICROCODE}|${MIRROR_GITHUB}/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/refs/tags/microcode-${V_INTEL_MICROCODE}.tar.gz
meson|${V_MESON}|${MIRROR_GITHUB}/mesonbuild/meson/releases/download/${V_MESON}/meson-${V_MESON}.tar.gz
ninja|${V_NINJA}|${MIRROR_GITHUB}/ninja-build/ninja/archive/v${V_NINJA}/ninja-${V_NINJA}.tar.gz
wayland|${V_WAYLAND}|${MIRROR_FDO_GITLAB}/wayland/wayland/-/releases/${V_WAYLAND}/downloads/wayland-${V_WAYLAND}.tar.xz
wayland-protocols|${V_WAYLAND_PROTOCOLS}|${MIRROR_FDO_GITLAB}/wayland/wayland-protocols/-/releases/${V_WAYLAND_PROTOCOLS}/downloads/wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz
libxkbcommon|${V_LIBXKBCOMMON}|${MIRROR_GITHUB}/xkbcommon/libxkbcommon/archive/xkbcommon-${V_LIBXKBCOMMON}/libxkbcommon-${V_LIBXKBCOMMON}.tar.gz
xkeyboard-config|${V_XKEYBOARD_CONFIG}|${MIRROR_XORG}/data/xkeyboard-config/xkeyboard-config-${V_XKEYBOARD_CONFIG}.tar.xz
pixman|${V_PIXMAN}|${MIRROR_CAIRO}/pixman-${V_PIXMAN}.tar.gz
libdrm|${V_LIBDRM}|${MIRROR_DRI}/libdrm-${V_LIBDRM}.tar.xz
libevdev|${V_LIBEVDEV}|${MIRROR_FDO_SW}/libevdev/libevdev-${V_LIBEVDEV}.tar.xz
mtdev|${V_MTDEV}|${MIRROR_BITMATH}/mtdev-${V_MTDEV}.tar.bz2
libinput|${V_LIBINPUT}|${MIRROR_FDO_GITLAB}/libinput/libinput/-/archive/${V_LIBINPUT}/libinput-${V_LIBINPUT}.tar.gz
seatd|${V_SEATD}|${MIRROR_SRHT}/~kennylevinsen/seatd/archive/${V_SEATD}.tar.gz
hwdata|${V_HWDATA}|${MIRROR_GITHUB}/vcrhonek/hwdata/archive/v${V_HWDATA}/hwdata-${V_HWDATA}.tar.gz
libdisplay-info|${V_LIBDISPLAY_INFO}|${MIRROR_FDO_GITLAB}/emersion/libdisplay-info/-/releases/${V_LIBDISPLAY_INFO}/downloads/libdisplay-info-${V_LIBDISPLAY_INFO}.tar.xz
wlroots|${V_WLROOTS}|${MIRROR_FDO_GITLAB}/wlroots/wlroots/-/releases/${V_WLROOTS}/downloads/wlroots-${V_WLROOTS}.tar.gz
dwl|${V_DWL}|${MIRROR_CODEBERG}/dwl/dwl/releases/download/v${V_DWL}/dwl-v${V_DWL}.tar.gz
havoc|${V_HAVOC}|${MIRROR_GITHUB}/ii8/havoc/archive/${V_HAVOC}/havoc-${V_HAVOC}.tar.gz
dejavu-fonts|${V_DEJAVU_FONTS}|${MIRROR_GITHUB}/dejavu-fonts/dejavu-fonts/releases/download/version_${V_DEJAVU_FONTS//./_}/dejavu-fonts-ttf-${V_DEJAVU_FONTS}.tar.bz2
lynx|${V_LYNX}|${MIRROR_DICKEY}/lynx/tarballs/lynx${V_LYNX}.tar.bz2
nano|${V_NANO}|${MIRROR_NANO}/v${V_NANO%%.*}/nano-${V_NANO}.tar.xz
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

    # One place, two attempts per mirror: resume, then - if resuming is what
    # failed - from the start.
    #
    # A STALE PARTIAL USED TO WEDGE A SOURCE FOREVER. `-C -` asks the server to
    # continue from the size of the local .part. If that partial is LONGER than
    # the upstream file, the range is unsatisfiable: curl exits 36 ("failed to
    # resume") for file:// and 33/416 over HTTP. The old loop treated that as a
    # dead mirror, tried the fallback, failed the same way, and died with
    # "Tried every mirror. Re-run to resume - partial downloads are kept."
    #
    # Every subsequent run then did exactly the same thing, because the thing
    # keeping it broken was the file the message promised to keep. Measured: a
    # 90000-byte .part against a 65536-byte upstream file failed identically on
    # every attempt, blaming the mirrors for a problem on local disk.
    #
    # So a failed attempt that had a partial to resume from discards it and
    # retries the SAME url once from zero before moving on. A genuinely dead
    # mirror still falls through to the next one; a poisoned partial no longer
    # survives to poison the retry.
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

    # Keep any .part: the next run resumes instead of restarting. It is only
    # kept when it was not itself the reason for the failure.
    return 1
}

# fetch_attempt <url> <dest> resume|fresh
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
while IFS='|' read -r name ver url; do
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
            # The same mismatch means two very different things, and the
            # operator needs to know which one they are looking at. Neither
            # case deletes anything: a hash that does not match is evidence,
            # and evidence is not something a tool should destroy on its own.
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

if [[ "$MODE" == "lock" ]]; then
    sort -k2 "${KRYPTIK_LOCK}.new" > "$KRYPTIK_LOCK"
    rm -f "${KRYPTIK_LOCK}.new"
    ok "wrote $(wc -l < "$KRYPTIK_LOCK") entries to sources.lock"
    warn "NOT YET AUDITED. Verify against upstream signatures before trusting."
else
    ok "${total} package(s) verified (${fetched} downloaded, ${cached} cached)"
fi
