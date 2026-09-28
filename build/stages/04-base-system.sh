#!/usr/bin/env bash
# Stage 04: the hardened base system, built in the chroot with the full flag
# set from build/config/hardening.env. The recipes are one file per step under
# build/recipes; this file holds the flags, the helpers, the order and the runner.
# usage: make system   (or, in the chroot, 04-base-system.sh [--redo <step>])
#        04-base-system.sh --list   print the build order and stop

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

# --- hardening --------------------------------------------------------------
# The first stage with hardening flags: these packages ship (docs/hardening.md).
load_hardening
validate_hardening_exceptions

# Built with the native target gcc, in the chroot.
stage_contract "${BASH_SOURCE[0]}" "bs-" gcc
# shellcheck disable=SC2034  # consumed by step() in common.sh
KRYPTIK_FAIL_TAIL=40

STAMPS="${KRYPTIK_WORK}/.stamps"
LOGS="${KRYPTIK_WORK}/logs"
BUILDDIR="${KRYPTIK_WORK}/build"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(kryptik_default_jobs)}"

# The chroot builds as root, with no other user to drop to, and gnulib's
# configure (coreutils, tar) refuses to run as root. FORCE_UNSAFE_CONFIGURE=1
# is upstream's own switch for that check and affects nothing else.
export FORCE_UNSAFE_CONFIGURE=1

export MAKEFLAGS="-j${KRYPTIK_JOBS}"
umask 022

MODE="build"
REDO=""
# shellcheck disable=SC2034  # REDO is consumed by step() in common.sh
case "${1:-}" in
    --list) MODE="list" ;;
    --redo) REDO="${2:?--redo needs a package name}" ;;
esac

mkdir -p "$STAMPS" "$LOGS" "$BUILDDIR"

# tree_digest PATH...: one digest over each file's content and its path under
# the tree, so a renamed file changes it as an edited one does; a directory
# stands for every file below it, and a path that is neither is left out. For
# a step argument that stands for files the step reads by path.
tree_digest() {
    local f
    # if, not &&: a last path that is not there must not fail the loop, and
    # with it the stage's PACKAGES assignment.
    for f in "$@"; do
        if [[ -d "$f" ]]; then find "$f" -type f -print0
        elif [[ -f "$f" ]]; then printf '%s\0' "$f"
        fi
    done | LC_ALL=C sort -z | xargs -0r sha256sum | sed "s|  ${KRYPTIK_ROOT}/|  |" | sha256_of_stdin
}

# --- hardening exceptions ---------------------------------------------------

# The flags to drop for a package, from hardening-exceptions.txt.
exception_flags_for() {
    local pkg="$1" f="${KRYPTIK_ROOT}/build/config/hardening-exceptions.txt"
    [[ -f "$f" ]] || return 0
    awk -v p="$pkg" '!/^[[:space:]]*#/ && $1 == p { print $2 }' "$f"
}

# Hardening minus the package's exceptions; a -final row takes its package's.
set_flags_for() {
    local pkg="$1" drop
    export CFLAGS="${KRYPTIK_OPT} ${KRYPTIK_CFLAGS_HARDENING}"
    export CXXFLAGS="${KRYPTIK_OPT} ${KRYPTIK_CFLAGS_HARDENING}"
    export LDFLAGS="${KRYPTIK_LDFLAGS_HARDENING}"

    while read -r drop; do
        [[ -z "$drop" ]] && continue
        warn "${pkg}: dropping ${drop} (justified exception)"
        CFLAGS="${CFLAGS//${drop}/}"
        CXXFLAGS="${CXXFLAGS//${drop}/}"
        LDFLAGS="${LDFLAGS//${drop}/}"
    done < <(exception_flags_for "${pkg%-final}")

    export CFLAGS CXXFLAGS LDFLAGS
}

# --- step machinery ---------------------------------------------------------

# The shared step() calls this after printing the tail of a failed log.
step_failure_hint() {
    # Two locals: one `local` expands all its words before assigning any.
    local name="$1"
    local logfile="${LOGS}/${STAMP_PREFIX}${name}.log"

    # The error can be thousands of lines above the tail; show likely causes.
    if [[ -f "$logfile" ]]; then
        local hits
        hits="$(grep -nE '^(make(\[[0-9]+\])?: \*\*\*|.*: \*\*\* )|\[ERROR\]|undefined (symbol|reference)|No such file or directory|Permission denied|command not found|configure: error|fatal error|cannot find -l|ModuleNotFoundError|ImportError|^[A-Za-z_.]*Error:|Could not build' \
                "$logfile" 2>/dev/null | tail -15)"
        if [[ -n "$hits" ]]; then
            err ""
            err "Lines in ${logfile} that look like the actual cause:"
            printf '%s\n' "$hits" | sed 's/^/    /' >&2
        fi
    fi

    err ""
    err "Check the actual error before assuming it is the hardening flags."
    err "The first stage 04 failure looked like one and was not - it was a"
    err "missing native glibc and no generated locales."
    err ""
    err "If it IS a hardening incompatibility, add an entry to"
    err "build/config/hardening-exceptions.txt WITH a justification, so"
    err "only that flag is dropped and only for that package."
}

# Native build: no --host, as this runs on the target.
native_build() {
    local tarball="$1" dirname="$2"; shift 2
    local src; src="$(unpack "$tarball" "$dirname")"
    cd "$src"
    ./configure --prefix=/usr "$@"
    make
    make install
}

# meson packages; the Wayland stack is meson-only. --buildtype=plain leaves the
# flags to the hardening CFLAGS (release adds -O3 and -DNDEBUG), and
# --wrap-mode=nodownload keeps a subproject from fetching unlocked sources.
meson_build() {
    local tarball="$1" dirname="$2"; shift 2
    local src; src="$(unpack "$tarball" "$dirname")"
    cd "$src"
    meson setup build --prefix=/usr --buildtype=plain --wrap-mode=nodownload "$@"
    ninja -C build
    ninja -C build install
}

# cmake only generates json-c's build files (cryptsetup needs json-c for LUKS2
# headers) and stays out of the image. The chroot runs Kitware's binary, pinned
# in sources.lock and never installed, instead of a long source build; where it
# cannot run, s_cmake builds from source with its bundled libraries. Unpacked
# on demand: the build tree is cleared between runs, and a resumed json-c step
# must not rely on a skipped cmake step.
prebuilt_cmake() {
    local dir="${BUILDDIR}/cmake-${V_CMAKE}-linux-x86_64"
    if [[ ! -x "${dir}/bin/cmake" ]]; then
        rm -rf "$dir"
        tar -xf "${KRYPTIK_SOURCES}/cmake-${V_CMAKE}-linux-x86_64.tar.gz" -C "$BUILDDIR"
    fi
    [[ -x "${dir}/bin/cmake" ]] || return 1
    "${dir}/bin/cmake" --version > /dev/null 2>&1 || return 1
    printf '%s' "${dir}/bin/cmake"
}

# --- recipes ----------------------------------------------------------------
# One file per step under build/recipes, sourced here. The build order is the
# list below; a step's fingerprint is its function's text, wherever it lives.
for recipe in "$(dirname "${BASH_SOURCE[0]}")/../recipes/"*.sh; do
    # shellcheck source=/dev/null
    source "$recipe"
done

# --- build order: by dependency, not alphabetical ----------------------------
PACKAGES=(
    "compiler-check" "--check s_compiler_check"
    "locales"     "s_locales"
    "gettext"     "native_build gettext-${V_GETTEXT}.tar.xz gettext-${V_GETTEXT} --disable-shared"
    "bison"       "native_build bison-${V_BISON}.tar.xz bison-${V_BISON} --docdir=/usr/share/doc/bison-${V_BISON}"
    "perl"        "s_perl"
    # After perl, which generates part of its source; before python, whose
    # _crypt module needs crypt(), gone from glibc since 2.39.
    "libxcrypt"   "native_build libxcrypt-${V_LIBXCRYPT}.tar.xz libxcrypt-${V_LIBXCRYPT} --enable-hashes=strong,glibc --enable-obsolete-api=no --disable-static --disable-failure-tokens"
    # Before python, whose install (ensurepip) unzips a bundled wheel.
    "zlib"        "s_zlib"
    "python"      "s_python"
    # No XS modules: texinfo links them without the hardening, and texi2any
    # runs as plain Perl without them.
    "texinfo"     "native_build texinfo-${V_TEXINFO}.tar.xz texinfo-${V_TEXINFO} --disable-perl-xs"
    # --disable-makeinstall-chown: wall's setgid tty is under that hook, not the setuid one.
    "util-linux"  "native_build util-linux-${V_UTIL_LINUX}.tar.xz util-linux-${V_UTIL_LINUX} --libdir=/usr/lib --runstatedir=/run --disable-chfn-chsh --disable-login --disable-nologin --disable-su --disable-setpriv --disable-runuser --disable-pylibmount --disable-liblastlog2 --disable-makeinstall-setuid --disable-makeinstall-chown --disable-static --without-python"
    "glibc"       "s_glibc"
    "bzip2"       "s_bzip2"
    "xz"          "s_xz_native"
    "zstd"        "s_zstd"
    "file"        "native_build file-${V_FILE}.tar.gz file-${V_FILE}"
    "readline"    "s_readline"
    "m4"          "native_build m4-${V_M4}.tar.xz m4-${V_M4}"
    "flex"        "native_build flex-${V_FLEX}.tar.gz flex-${V_FLEX} --disable-static"
    # Before everything that asks pkg-config for its dependencies (e2fsprogs,
    # iproute2, kmod, eudev).
    "pkgconf"     "s_pkgconf"
    "binutils"    "s_binutils_native"
    "gmp"         "native_build gmp-${V_GMP}.tar.xz gmp-${V_GMP} --enable-cxx --disable-static"
    "mpfr"        "native_build mpfr-${V_MPFR}.tar.xz mpfr-${V_MPFR} --disable-static --enable-thread-safe"
    "mpc"         "native_build mpc-${V_MPC}.tar.gz mpc-${V_MPC} --disable-static"
    # After its libraries; everything below is built by it.
    "gcc"         "s_gcc_native"
    "attr"        "native_build attr-${V_ATTR}.tar.gz attr-${V_ATTR} --disable-static --sysconfdir=/etc"
    "acl"         "native_build acl-${V_ACL}.tar.xz acl-${V_ACL} --disable-static"
    "libcap"      "s_libcap"
    "shadow"      "s_shadow"
    # --enable-pc-files needs --with-pkg-config-libdir, or no .pc files are
    # installed and pkg-config finds no ncursesw.
    "ncurses"     "native_build ncurses-${V_NCURSES}.tar.gz ncurses-${V_NCURSES} --mandir=/usr/share/man --with-shared --without-debug --without-normal --with-cxx-shared --enable-pc-files --with-pkg-config-libdir=/usr/lib/pkgconfig"
    "sed"         "native_build sed-${V_SED}.tar.xz sed-${V_SED}"
    "psmisc"      "native_build psmisc-${V_PSMISC}.tar.xz psmisc-${V_PSMISC}"
    "bash"        "native_build bash-${V_BASH}.tar.gz bash-${V_BASH} --without-bash-malloc --with-installed-readline"
    "libtool"     "native_build libtool-${V_LIBTOOL}.tar.xz libtool-${V_LIBTOOL}"
    "gperf"       "native_build gperf-${V_GPERF}.tar.gz gperf-${V_GPERF} --docdir=/usr/share/doc/gperf-${V_GPERF}"
    "expat"       "native_build expat-${V_EXPAT}.tar.xz expat-${V_EXPAT} --disable-static --docdir=/usr/share/doc/expat-${V_EXPAT}"
    "inetutils"   "s_inetutils"
    "less"        "native_build less-${V_LESS}.tar.gz less-${V_LESS} --sysconfdir=/etc"
    "openssl"     "s_openssl"
    # --with-gcc-arch=x86-64, not LFS's "native": inert while CFLAGS are set,
    # but the image must never be tuned to the build machine's CPU.
    "libffi"      "native_build libffi-${V_LIBFFI}.tar.gz libffi-${V_LIBFFI} --disable-static --with-gcc-arch=x86-64"
    "python-final" "s_python_final"
    "coreutils"   "s_coreutils"
    "diffutils"   "native_build diffutils-${V_DIFFUTILS}.tar.xz diffutils-${V_DIFFUTILS}"
    # No persistent-memory allocator: it needs a fixed-address, non-PIE gawk.
    "gawk"        "s_gawk"
    "findutils"   "native_build findutils-${V_FINDUTILS}.tar.xz findutils-${V_FINDUTILS} --localstatedir=/var/lib/locate"
    "grep"        "native_build grep-${V_GREP}.tar.xz grep-${V_GREP}"
    "gzip"        "native_build gzip-${V_GZIP}.tar.xz gzip-${V_GZIP}"
    "make"        "native_build make-${V_MAKE}.tar.gz make-${V_MAKE}"
    "patch"       "native_build patch-${V_PATCH}.tar.xz patch-${V_PATCH}"
    "tar"         "s_tar"
    "groff"       "native_build groff-${V_GROFF}.tar.gz groff-${V_GROFF}"
    # For the kernel build, which generates timeconst.h with `bc -q`. After flex
    # and bison, which bc needs.
    "bc"          "s_bc"
    # --disable-manpages: kmod's man pages need scdoc, which is not pinned.
    "kmod"        "native_build kmod-${V_KMOD}.tar.xz kmod-${V_KMOD} --sysconfdir=/etc --with-openssl --with-xz --with-zstd --with-zlib --disable-manpages"
    "libpipeline" "native_build libpipeline-${V_LIBPIPELINE}.tar.gz libpipeline-${V_LIBPIPELINE}"
    # gdbm before man-db, whose configure otherwise picks another database
    # interface silently.
    "gdbm"        "s_gdbm"
    "man-db"      "s_man_db"
    "procps-ng"   "native_build procps-ng-${V_PROCPS}.tar.xz procps-ng-${V_PROCPS} --docdir=/usr/share/doc/procps-ng-${V_PROCPS} --disable-static --disable-kill"
    "e2fsprogs"   "s_e2fsprogs"
    "elfutils"    "s_elfutils"
    "iproute2"    "s_iproute2"
    "kbd"         "s_kbd"
    "eudev"       "s_eudev"
    "iana-etc"    "s_iana_etc"
    "hardened-malloc" "s_hardened_malloc"
    "s6"          "s_s6_stack"

    # --- encrypted volumes: cryptsetup, with libdevmapper (LVM2, which needs
    #     libaio), json-c (built with cmake) and popt.
    "cmake"       "s_cmake"
    "json-c"      "s_json_c"
    "popt"        "native_build popt-${V_POPT}.tar.gz popt-${V_POPT} --disable-static"
    "libaio"      "s_libaio"
    "lvm2"        "s_lvm2"
    "cryptsetup"  "s_cryptsetup"
    # --- updates: the installed system verifies update manifests itself.
    "openssh"     "s_openssh"
    # --- the net zone: NAT, a resolver and a DHCP client.
    "libmnl"      "native_build libmnl-${V_LIBMNL}.tar.bz2 libmnl-${V_LIBMNL} --disable-static"
    "libnftnl"    "native_build libnftnl-${V_LIBNFTNL}.tar.xz libnftnl-${V_LIBNFTNL} --disable-static"
    "nftables"    "native_build nftables-${V_NFTABLES}.tar.xz nftables-${V_NFTABLES} --without-cli --disable-man-doc --disable-python --with-json=no --disable-static"
    "dnsmasq"     "s_dnsmasq"
    "dhcpcd"      "s_dhcpcd"
    # --- the net zone's Wi-Fi (docs/design/net-zone.md).
    "libnl"       "native_build libnl-${V_LIBNL}.tar.gz libnl-${V_LIBNL} --sysconfdir=/etc --disable-static"
    "wpa-supplicant" "s_wpa_supplicant"
    "iw"          "s_iw"
    # --- what the net zone verifies a release server by.
    "ca-bundle"   "s_ca_bundle"
    # --- device firmware (ADR-012): what build/config/firmware.list names.
    "linux-firmware" "s_firmware $(sha256_of "${KRYPTIK_ROOT}/build/config/firmware.list" 2>/dev/null || echo none)"
    # --- the desktop: build tools, the Wayland stack, compositor, applications.
    "meson"       "s_meson"
    "ninja"       "s_ninja"
    # ping, which builds with meson; inetutils ships none.
    "iputils"     "s_iputils"
    "wayland"     "s_wayland"
    "wayland-protocols" "meson_build wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz wayland-protocols-${V_WAYLAND_PROTOCOLS} -Dtests=false"
    "xkeyboard-config"  "meson_build xkeyboard-config-${V_XKEYBOARD_CONFIG}.tar.xz xkeyboard-config-${V_XKEYBOARD_CONFIG}"
    "libxkbcommon" "s_libxkbcommon"
    "pixman"      "meson_build pixman-${V_PIXMAN}.tar.gz pixman-${V_PIXMAN} -Dtests=disabled -Ddemos=disabled -Dgtk=disabled -Dopenmp=disabled"
    "libdrm"      "s_libdrm"
    "libevdev"    "meson_build libevdev-${V_LIBEVDEV}.tar.xz libevdev-${V_LIBEVDEV} -Dtests=disabled -Ddocumentation=disabled"
    "mtdev"       "native_build mtdev-${V_MTDEV}.tar.bz2 mtdev-${V_MTDEV} --disable-static"
    "libinput"    "s_libinput"
    "seatd"       "s_seatd"
    "hwdata"      "s_hwdata"
    "libdisplay-info" "meson_build libdisplay-info-${V_LIBDISPLAY_INFO}.tar.xz libdisplay-info-${V_LIBDISPLAY_INFO}"
    "wlroots"     "s_wlroots"
    # dwl's three inputs are digests, so editing any of them rebuilds it.
    "dwl"         "s_dwl $(sha256_of "${KRYPTIK_ROOT}/build/desktop/dwl-config.h" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/build/desktop/zone-colours.h" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/dwl-zone-borders.py" 2>/dev/null || echo none)"
    "havoc"       "s_havoc"
    "fonts"       "s_fonts"
    "lynx"        "s_lynx"
    "nano"        "native_build nano-${V_NANO}.tar.xz nano-${V_NANO} --sysconfdir=/etc --enable-utf8"
    # The desktop's own pieces; the proxy's path and hash are arguments, as for
    # kryptikd.
    "desktop"     "s_desktop ${KRYPTIK_WLPROXY_BIN:-none} $([[ -f "${KRYPTIK_WLPROXY_BIN:-}" ]] && sha256_of "${KRYPTIK_WLPROXY_BIN}" || echo absent) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-launch.c" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-session" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/kryptik-chrome" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/desktop/wlprobe.c" 2>/dev/null || echo none)"

    # From here the steps configure the system rather than build packages.
    "etc"         "s_etc"
    "console"     "s_console"
    "init"        "s_init"
    # After init, whose stage 2 scripts look for the database; before the
    # updater and efiboot, whose checks source the devices.sh it installs. The
    # digest covers the files the recipe reads by path, which declare -f cannot.
    "services" "s_services $(tree_digest "${KRYPTIK_ROOT}"/build/services/*/* "${KRYPTIK_ROOT}"/build/service-scripts/*.sh "${KRYPTIK_ROOT}"/build/config/sysctl.d/*.conf)"
    # Before the updater, whose check runs kryptik-update, which needs efiboot.
    "efiboot"     "s_efiboot $(sha256_of "${KRYPTIK_ROOT}/tools/efi/kryptik-efiboot.c" 2>/dev/null || echo none)"
    "updater"     "s_updater $(sha256_of "${KRYPTIK_ROOT}/tools/update/kryptik-update" 2>/dev/null || echo none) $(sha256_of "${KRYPTIK_ROOT}/tools/update/kryptik-recover" 2>/dev/null || echo none)"
    "netzone"     "s_netzone $(sha256_of "${KRYPTIK_ROOT}/tools/net/netzone-init.sh" 2>/dev/null || echo none)-$(sha256_of "${KRYPTIK_ROOT}/tools/net/sntp-offset.py" 2>/dev/null || echo none)-$(sha256_of "${KRYPTIK_ROOT}/tools/net/update-fetch.py" 2>/dev/null || echo none)"
    "installer"   "s_installer $(sha256_of "${KRYPTIK_ROOT}/tools/install/kryptik-install.sh" 2>/dev/null || echo none)"
    # The binary's path and hash, and a digest of the zone files: kryptikd
    # validates them at install time, so the two must move together.
    "kryptikd"    "s_kryptikd ${KRYPTIK_KRYPTIKD_BIN:-none} $([[ -f "${KRYPTIK_KRYPTIKD_BIN:-}" ]] && sha256_of "${KRYPTIK_KRYPTIKD_BIN}" || echo absent) $(tree_digest "${KRYPTIK_ROOT}"/compartments/zones/*.toml "${KRYPTIK_ROOT}"/compartments/zones/policy/*) $(sha256_of "${KRYPTIK_ROOT}/tools/kryptik" 2>/dev/null || echo none)"
    # The suites and guest checks the VM drivers run; every file is an input.
    "tests"       "s_tests $(tree_digest "${KRYPTIK_ROOT}"/compartments/tests/*.sh "${KRYPTIK_ROOT}"/compartments/kryptikd/probes/*.sh "${KRYPTIK_ROOT}"/compartments/kryptikd/src/isolate.rs "${KRYPTIK_ROOT}"/compartments/kryptikd/src/rootfs.rs "${KRYPTIK_ROOT}"/build/guest-tests/*.sh "${KRYPTIK_ROOT}"/build/guest-tests/*.py)"
    # The tarballs it reads are pinned by sources.lock and named by fetch-sources.
    "licences"    "s_licences $(sha256_of "${KRYPTIK_ROOT}/sources.lock") $(sha256_of "${KRYPTIK_ROOT}/tools/fetch-sources.sh") $(sha256_of "${KRYPTIK_ROOT}/LICENSE") $(tree_digest "${KRYPTIK_ROOT}/build/licences")"
    "boot-check"  "--check s_boot_check"
)

# Rows before glibc link stage 01's crt files, which carry no CET property, and
# ld marks a binary only when every input is marked. So each is built again by
# the same recipe right after glibc, unless it has its own -final row further
# down (python, which waits for its libraries).
rows=()
for ((i = 0; i < ${#PACKAGES[@]}; i += 2)); do
    rows+=("${PACKAGES[i]}" "${PACKAGES[i+1]}")
    [[ "${PACKAGES[i]}" == glibc ]] || continue
    for ((j = 0; j < i; j += 2)); do
        for ((k = i; k < ${#PACKAGES[@]}; k += 2)); do
            if [[ "${PACKAGES[k]}" == "${PACKAGES[j]}-final" ]]; then continue 2; fi
        done
        rows+=("${PACKAGES[j]}-final" "${PACKAGES[j+1]}")
    done
done
PACKAGES=("${rows[@]}")

# --- run --------------------------------------------------------------------

if [[ "$MODE" == "list" ]]; then
    printf 'Kryptik stage 04 build order (%d entries):\n\n' "$(( ${#PACKAGES[@]} / 2 ))"
    for ((i = 0; i < ${#PACKAGES[@]}; i += 2)); do
        if [[ "${PACKAGES[i+1]}" == --check* ]]; then
            printf '  %2d. %-16s  (check)\n' "$(( i / 2 + 1 ))" "${PACKAGES[i]}"
        else
            printf '  %2d. %s\n' "$(( i / 2 + 1 ))" "${PACKAGES[i]}"
        fi
    done
    exit 0
fi

# The commit that built this image, for /etc/os-release, passed in from outside
# (the chroot has no git): no commit is better than a wrong one.
KRYPTIK_BUILD_COMMIT="${KRYPTIK_BUILD_COMMIT:-unknown}"
export KRYPTIK_BUILD_COMMIT

log "Kryptik stage 04 — hardened base system"
dim "  CFLAGS : ${CFLAGS}"
dim "  LDFLAGS: ${LDFLAGS}"
dim "  jobs   : ${KRYPTIK_JOBS}"
echo

# Outside the chroot the packages would link against host libraries.
require_inside_chroot "stage 04" "system"

# Built by stage 02's toolchain: rebuilding it invalidates every stamp here.
# gcc2 is its last build step; verify after it is a check.
stage_depends_on "tt-" gcc2

for ((i = 0; i < ${#PACKAGES[@]}; i += 2)); do
    name="${PACKAGES[i]}"
    recipe="${PACKAGES[i+1]}"
    [[ -n "$recipe" ]] || die "${name}: a row with no recipe"
    # shellcheck disable=SC2086  # recipe is a deliberately word-split command
    step "$name" $recipe
done

# Written on every run and by no step (see s_etc).
sed -i '/^BUILD_ID=/d' /etc/os-release
printf 'BUILD_ID=%s\n' "$KRYPTIK_BUILD_COMMIT" >> /etc/os-release

echo
ok "Stage 04 finished."
dim "Next: make kernel  (stage 05)"
