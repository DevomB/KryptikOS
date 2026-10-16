#!/usr/bin/env bash
# The hardening flags each step builds with, the helpers its recipe calls, and the recipes themselves:
# sourced by stage 04 and the image stage, which build recipes the same way.

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
    export CXXFLAGS="${KRYPTIK_OPT} ${KRYPTIK_CFLAGS_HARDENING} ${KRYPTIK_CXXFLAGS_HARDENING}"
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
# One file per step under build/recipes, sourced here; each stage lists the order it builds
# them in. A step's fingerprint is its function's text, wherever it lives.
for recipe in "$(dirname "${BASH_SOURCE[0]}")/../recipes/"*.sh; do
    # shellcheck source=/dev/null
    source "$recipe"
done
