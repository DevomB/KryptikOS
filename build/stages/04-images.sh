#!/usr/bin/env bash
# Software images (docs/design/software-delivery.md): each image's recipes built in the chroot over the
# finished base system, through an overlay whose upper directory keeps what they install. Stage 06
# packs each tree as it packs the root.
# usage: make images   (as root, for the overlay; or 04-images.sh NAME... for some of build/images)
#        04-images.sh --inside NAME   in the chroot: one image's rows, as stage 04 runs its own
#
# A definition sets image_version and image_rows, and may set image_over, the images it is built over:
# their trees lie under it, above the sysroot, while its rows run. image_ships=no makes a layer that
# only images built over it use, a toolchain, which stage 06 never packs.

source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
load_config

DEFS="${KRYPTIK_ROOT}/build/images"
SYSROOT="${KRYPTIK_WORK}/sysroot"
CHROOTD="${KRYPTIK_ROOT}/build/stages/03-chroot-prep.sh"

# --- on the host: an overlay per image, its rows run inside it ---------------

# image_setting NAME VAR: VAR in NAME's definition, an array's words joined by spaces.
image_setting() {
    # shellcheck source=/dev/null
    ( source "${DEFS}/${1}.sh"; declare -n v="$2"; printf '%s' "${v[*]:-}" )
}

# What an image is built from: its definition and files, the recipes and flags, the pins, the base
# system, and the images it is built over.
image_inputs() {   # image_inputs NAME
    local f dep
    for f in "${DEFS}/${1}.sh" "${DEFS}/${1}"/* "${KRYPTIK_ROOT}/build/lib/recipes.sh" "${KRYPTIK_ROOT}"/build/recipes/*.sh \
             "${BASH_SOURCE[0]}" "${KRYPTIK_ROOT}/tools/check-image-tree.sh" "${KRYPTIK_ROOT}/build/config/hardening.env" \
             "${KRYPTIK_ROOT}/build/config/hardening-exceptions.txt" "${KRYPTIK_ROOT}/build/config/versions.env" \
             "${KRYPTIK_ROOT}/sources.lock" "${DEFS}/versions.env" "${DEFS}/sources.lock"; do
        if [[ -f "$f" ]]; then printf '%s %s\n' "${f#"${KRYPTIK_ROOT}/"}" "$(sha256_of "$f")"; fi
    done
    printf 'base %s\n' "$(_stamp_read "${KRYPTIK_WORK}/.stamps/bs-licences")"
    for dep in $(image_setting "$1" image_over); do
        printf 'over %s %s\n' "$dep" "$(sed -n 's/^fingerprint: //p' "${KRYPTIK_WORK}/image-build/${dep}/record")"
    done
}

# The image that is being built, so an exit takes its mounts down with it.
MOUNTED=""
unmount_image() {   # unmount_image TOP
    env KRYPTIK_WORK="$1" "$CHROOTD" umount > /dev/null 2>&1 || true
    if mountpoint -q "$1/sysroot"; then umount "$1/sysroot" || umount -l "$1/sysroot"; fi
    # Not grep -q: under pipefail its early exit could fail findmnt and hide a mount.
    if findmnt -rn -o TARGET | grep -F "$1/" >&2; then die "still mounted under $1 (above): nothing there is removed"; fi
}

# The images being built, innermost last, so one built over itself is refused.
BUILDING=""
build_image() {   # build_image NAME
    local name="$1" top="${KRYPTIK_WORK}/image-build/${1}" version want d ships dep lowers=""
    local -a over
    [[ "$name" =~ ^[a-z0-9-]{1,32}$ ]] || die "image name ${name}: a-z, 0-9 and -, at most 32"
    [[ -f "${DEFS}/${name}.sh" ]] || die "no image ${name}: nothing at ${DEFS}/${name}.sh"
    [[ " ${BUILDING} " != *" ${name} "* ]] || die "image ${name} is built over itself:${BUILDING} ${name}"
    version="$(image_setting "$name" image_version)"
    [[ "$version" =~ ^[!-~]{1,64}$ ]] || die "image ${name}: version '${version}' is not 1-64 printable characters without a space"
    ships="$(image_setting "$name" image_ships)"; ships="${ships:-yes}"
    [[ "$ships" == yes || "$ships" == no ]] || die "image ${name}: image_ships is yes or no, not '${ships}'"
    read -ra over <<< "$(image_setting "$name" image_over)"
    # What it is built over comes first; the nearest layer is named first, as overlayfs takes it.
    BUILDING="${BUILDING} ${name}"
    for dep in "${over[@]}"; do
        build_image "$dep"
        lowers+="${KRYPTIK_WORK}/image-build/${dep}/tree:"
    done
    BUILDING="${BUILDING% "${name}"}"
    want="$(image_inputs "$name" | sha256_of_stdin)"
    if [[ -d "${top}/tree/usr" ]] && grep -qx "fingerprint: ${want}" "${top}/record" 2>/dev/null; then
        dim "  skip ${name} ${version} (already built, inputs unchanged)"
        return 0
    fi
    log "image ${name} ${version}"
    unmount_image "$top"
    rm -rf "$top"
    # A fresh upper directory: no row may skip on a stamp from the last one.
    rm -f "${KRYPTIK_WORK}/.stamps/image-${name}-"*
    mkdir -p "${top}/upper" "${top}/overlay-work" "${top}/sysroot"
    # Stage 03 takes the chroot's root from KRYPTIK_WORK, so the overlay is that work tree's sysroot,
    # and the real work tree's stamps, logs, build and images are bound into it as usual.
    for d in .stamps logs build images; do ln -s "${KRYPTIK_WORK}/${d}" "${top}/${d}"; done
    MOUNTED="$top"
    mount -t overlay overlay -o "lowerdir=${lowers}${SYSROOT},upperdir=${top}/upper,workdir=${top}/overlay-work" "${top}/sysroot"
    env KRYPTIK_WORK="$top" KRYPTIK_KRYPTIKD_BIN= KRYPTIK_WLPROXY_BIN= \
        "$CHROOTD" run /kryptik/build/stages/04-images.sh --inside "$name"
    unmount_image "$top"
    MOUNTED=""
    "${KRYPTIK_ROOT}/tools/check-image-tree.sh" "${lowers}${SYSROOT}" "${top}/upper"
    # Without extended attributes: overlayfs keeps its own on the upper directory.
    mkdir -p "${top}/tree"
    rsync -aH --numeric-ids "${top}/upper/usr" "${top}/tree/"
    rm -rf "${top}/upper" "${top}/overlay-work"
    printf 'name: %s\nversion: %s\nships: %s\nover: %s\nfingerprint: %s\n' \
        "$name" "$version" "$ships" "${over[*]}" "$want" > "${top}/record"
    ok "image ${name} ${version}: $(find "${top}/tree" ! -type d | wc -l) files and links"
}

build_images() {   # build_images [NAME...]
    [[ "$EUID" -eq 0 ]] || die "the image stage mounts an overlay over the sysroot: run it as root (make images)"
    require_outside_chroot "the image stage"
    [[ -f "${KRYPTIK_WORK}/.stamps/bs-licences" ]] || die "stage 04 has not finished: make system first"
    trap '[[ -z "$MOUNTED" ]] || unmount_image "$MOUNTED"' EXIT
    local names=("$@") d n
    if [[ "${#names[@]}" -eq 0 ]]; then
        for d in "${DEFS}"/*.sh; do names+=("$(basename "$d" .sh)"); done
    fi
    log "Kryptik software images: ${names[*]}"
    for n in "${names[@]}"; do
        build_image "$n"
    done
    ok "software images built: ${names[*]}"
    dim "Next: make media packs each one beside the root (stage 06)"
}

if [[ "${1:-}" != --inside ]]; then
    build_images "$@"
    exit 0
fi

# --- in the chroot: one image's rows, as stage 04 runs its own ---------------

name="${2:?--inside needs an image name}"
require_inside_chroot "the image stage"
load_hardening
validate_hardening_exceptions
stage_contract "${BASH_SOURCE[0]}" "image-${name}-" gcc
# shellcheck disable=SC2034  # consumed by step() and the recipes
STAMPS="${KRYPTIK_WORK}/.stamps" LOGS="${KRYPTIK_WORK}/logs" BUILDDIR="${KRYPTIK_WORK}/build"
KRYPTIK_JOBS="${KRYPTIK_JOBS:-$(kryptik_default_jobs)}"
# As stage 04 builds: gnulib refuses root without this, and every make runs in parallel.
export FORCE_UNSAFE_CONFIGURE=1 MAKEFLAGS="-j${KRYPTIK_JOBS}"
# The root's index of info manuals is the root's; automake leaves it alone. And a Python tool the
# build runs leaves no bytecode for the root's modules in the image.
export AM_UPDATE_INFO_DIR=no PYTHONDONTWRITEBYTECODE=1
umask 022
source "${KRYPTIK_ROOT}/build/lib/recipes.sh"
# shellcheck source=/dev/null
source "${DEFS}/${name}.sh"
# Stage 04's last build step: a rebuilt base system rebuilds every image.
stage_depends_on "bs-" licences
# shellcheck disable=SC2154  # image_rows comes from the image's definition
for ((i = 0; i < ${#image_rows[@]}; i += 2)); do
    # shellcheck disable=SC2086  # a recipe is a word-split command, as in stage 04
    step "${image_rows[i]}" ${image_rows[i+1]}
done
