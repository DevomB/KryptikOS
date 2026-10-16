#!/usr/bin/env bash
# dwl, patched and configured as stage 04 builds it (build/recipes/dwl.sh), compiles against the
# pinned wlroots' headers, so a C error in Kryptik's edits shows here and not hours into a Distro
# build. A negative control proves the check can fail. Needs curl, gcc, python3, patch, b2sum,
# pkg-config, wayland-scanner and the headers of libwayland, xkbcommon, libinput, pixman, libdrm and
# libudev, which CI installs; without them it exits 77. KRYPTIK_TEST_SOURCES names a directory that
# keeps the fetched tarballs between runs (CI caches it); one there is used only with the lock's hash.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
for t in curl gcc python3 patch b2sum pkg-config wayland-scanner; do
    command -v "$t" >/dev/null 2>&1 || { echo "dwl-compile.sh: no $t here (77)"; exit 77; }
done
PKGS=(wayland-server xkbcommon libinput pixman-1 libdrm libudev)
for p in "${PKGS[@]}"; do
    pkg-config --exists "$p" || { echo "dwl-compile.sh: no $p headers here (77)"; exit 77; }
done
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
# shellcheck source=/dev/null
. "$REPO/build/config/versions.env"

# fetch NAME FILE VERSION: the pinned file, from the URL fetch-sources.sh resolves, then the source's
# mirrors, then Gentoo's distfiles, as fetch-sources.sh tries them; kept only with the lock's hash.
fetch() {
    local name="$1" file="$2" url want u
    url="$("$REPO/tools/fetch-sources.sh" --list-root 2>/dev/null | awk -v n="$name" '$1 == n { print $3; exit }')"
    want="$(awk -v f="$file" '$2 == f { print $1 }' "$REPO/sources.lock")"
    [[ -n "$url" && -n "$want" ]] || { echo "FAIL: no URL or no lock row for ${name} (${file})"; exit 1; }
    local keep="${KRYPTIK_TEST_SOURCES:-}"
    if [[ -n "$keep" && -f "$keep/$file" && "$(sha256sum "$keep/$file" | cut -c1-64)" == "$want" ]]; then
        tar -xf "$keep/$file" -C "$W" || { echo "FAIL: cannot unpack ${file}"; exit 1; }
        return 0
    fi
    local -a urls=("$url")
    while read -r u; do urls+=("${u//"{VER}"/"$3"}"); done < <(awk -v n="$name" '$1 == n { print $2 }' "$REPO/tools/source-mirrors.tsv")
    urls+=("https://distfiles.gentoo.org/distfiles/$(printf '%s' "$file" | b2sum | cut -c1-2)/${file}")
    for u in "${urls[@]}"; do
        if curl -fsSL --retry 2 --max-time 120 -o "$W/$file" "$u" \
           && [[ "$(sha256sum "$W/$file" | cut -c1-64)" == "$want" ]]; then
            tar -xf "$W/$file" -C "$W" || { echo "FAIL: cannot unpack ${file}"; exit 1; }
            [[ -z "$keep" ]] || { mkdir -p "$keep" && cp "$W/$file" "$keep/$file"; }
            return 0
        fi
        echo "note: ${file} not from ${u}"
    done
    echo "FAIL: no source of ${file} has the locked hash ${want}"
    exit 1
}
fetch wlroots "wlroots-${V_WLROOTS}.tar.gz" "$V_WLROOTS"
fetch wayland-protocols "wayland-protocols-${V_WAYLAND_PROTOCOLS}.tar.xz" "$V_WAYLAND_PROTOCOLS"
fetch dwl "dwl-v${V_DWL}.tar.gz" "$V_DWL"
# The pinned libwayland's own headers, not the host's: Kryptik's edits call 1.23's
# wl_client_{get,set}_user_data, which an older host's lack.
fetch wayland "wayland-${V_WAYLAND}.tar.xz" "$V_WAYLAND"
WLR="$W/wlroots-${V_WLROOTS}"
DWL="$W/dwl-v${V_DWL}"
WL="$W/wayland-${V_WAYLAND}"

# The two headers meson writes for wlroots: the backends stage 04 builds (DRM, libinput, the
# session), no Xwayland, GLES2 or Vulkan.
GEN="$W/gen"
mkdir -p "$GEN/wlr"
sed -e 's/^#mesondefine \(WLR_HAS_[A-Z0-9_]*\)$/#define \1 0/' "$WLR/include/wlr/config.h.in" \
    | sed -e 's/^#define \(WLR_HAS_DRM_BACKEND\|WLR_HAS_LIBINPUT_BACKEND\|WLR_HAS_SESSION\) 0$/#define \1 1/' \
    > "$GEN/wlr/config.h"
IFS=. read -r major minor micro <<<"$V_WLROOTS"
sed -e "s/^#mesondefine WLR_VERSION_STR$/#define WLR_VERSION_STR \"${V_WLROOTS}\"/" \
    -e "s/^#mesondefine WLR_VERSION_MAJOR$/#define WLR_VERSION_MAJOR ${major}/" \
    -e "s/^#mesondefine WLR_VERSION_MINOR$/#define WLR_VERSION_MINOR ${minor}/" \
    -e "s/^#mesondefine WLR_VERSION_MICRO$/#define WLR_VERSION_MICRO ${micro}/" \
    "$WLR/include/wlr/version.h.in" > "$GEN/wlr/version.h"
IFS=. read -r wmajor wminor wmicro <<<"$V_WAYLAND"
sed -e "s/@WAYLAND_VERSION_MAJOR@/${wmajor}/; s/@WAYLAND_VERSION_MINOR@/${wminor}/; s/@WAYLAND_VERSION_MICRO@/${wmicro}/; s/@WAYLAND_VERSION@/${V_WAYLAND}/" \
    -e "s/^#mesondefine WAYLAND_VERSION_MAJOR$/#define WAYLAND_VERSION_MAJOR ${wmajor}/" \
    -e "s/^#mesondefine WAYLAND_VERSION_MINOR$/#define WAYLAND_VERSION_MINOR ${wminor}/" \
    -e "s/^#mesondefine WAYLAND_VERSION_MICRO$/#define WAYLAND_VERSION_MICRO ${wmicro}/" \
    -e "s/^#mesondefine WAYLAND_VERSION$/#define WAYLAND_VERSION \"${V_WAYLAND}\"/" \
    "$WL/src/wayland-version.h.in" > "$GEN/wayland-version.h"
wayland-scanner server-header "$WL/protocol/wayland.xml" "$GEN/wayland-server-protocol.h" \
    || { echo "FAIL: wayland-scanner refused wayland ${V_WAYLAND}'s own protocol"; exit 1; }
if grep -q '@\|#mesondefine' "$GEN/wlr/config.h" "$GEN/wlr/version.h" "$GEN/wayland-version.h"; then
    echo "FAIL: a header template of wlroots ${V_WLROOTS} or wayland ${V_WAYLAND} has a placeholder this check does not fill:"
    grep -n '@\|#mesondefine' "$GEN/wlr/config.h" "$GEN/wlr/version.h" "$GEN/wayland-version.h"
    exit 1
fi
# Every protocol's server header, by the name dwl's Makefile and wlroots' headers include. One this
# scanner refuses is noted: a header dwl needs and lacks fails the compile below by its name.
while IFS= read -r x; do
    wayland-scanner server-header "$x" "$GEN/$(basename "$x" .xml)-protocol.h" 2>/dev/null \
        || echo "note: wayland-scanner refused ${x#"$W"/}"
done < <(find "$W/wayland-protocols-${V_WAYLAND_PROTOCOLS}" "$WLR/protocol" "$DWL/protocols" -name '*.xml')

# The patches and edits stage 04 applies, in its order, and its config.
(
    cd "$DWL" || exit 1
    pdir="$REPO/build/patches/dwl-${V_DWL}"
    ( cd "$pdir" && sha256sum --check --quiet --strict SHA256SUMS ) || { echo "FAIL: ${pdir}: a patch does not match SHA256SUMS"; exit 1; }
    for p in "$pdir"/*.patch; do
        patch -Np1 -F0 --no-backup-if-mismatch -s -i "$p" || { echo "FAIL: ${p##*/} did not apply"; exit 1; }
    done
    python3 "$REPO/tools/desktop/dwl-zone-borders.py" . || { echo "FAIL: dwl-zone-borders.py did not apply"; exit 1; }
    cp "$REPO/build/desktop/zone-colours.h" zone-colours.h
    cp "$REPO/build/desktop/dwl-config.h" config.h
) || exit 1

# dwl 0.8's own flags (config.mk), its warnings as errors where config.mk makes them so.
# shellcheck disable=SC2046
compile() {   # compile FILE...: gcc -fsyntax-only, as stage 04 would build them
    gcc -fsyntax-only -std=c11 -pedantic -Wall -Wextra -Wdeclaration-after-statement -Wno-unused-parameter \
        -Wshadow -Wunused-macros -Werror=strict-prototypes -Werror=implicit -Werror=return-type \
        -Werror=incompatible-pointer-types -Wfloat-conversion \
        -DWLR_USE_UNSTABLE -D_POSIX_C_SOURCE=200809L -DVERSION='"'"${V_DWL}"'"' \
        -I"$DWL" -I"$GEN" -I"$WL/src" -I"$WLR/include" $(pkg-config --cflags "${PKGS[@]}") "$@"
}
fail=0
if compile "$DWL/dwl.c" "$DWL/util.c" 2> "$W/errors"; then
    echo "PASS: dwl ${V_DWL} with Kryptik's patches and edits compiles against wlroots ${V_WLROOTS} ($(grep -c 'warning:' "$W/errors") warnings)"
else
    echo "FAIL: dwl ${V_DWL} with Kryptik's patches and edits does not compile:"
    grep -E 'error:' "$W/errors" | head -20
    fail=1
fi
# The control: a member that does not exist must fail, or the check proves nothing.
{ cat "$DWL/dwl.c"; printf 'static void kryptik_control(Client *c) { c->no_such_member = 1; }\n'; } > "$DWL/control.c"
if compile "$DWL/control.c" 2>/dev/null; then
    echo "FAIL: the negative control compiled: the check cannot fail"
    fail=1
else
    echo "PASS: the negative control (a member that does not exist) fails to compile"
fi
exit "$fail"
