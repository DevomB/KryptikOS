#!/usr/bin/env bash
# dwl: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# dwl with Kryptik's config.h: the keybindings are the trusted launcher, and
# border colours are the compositor-controlled zone identity. Its three inputs
# are digests in this step's arguments:
#   build/desktop/dwl-config.h        the configuration; includes the next
#   build/desktop/zone-colours.h      the zone -> border colour table
#   tools/desktop/dwl-zone-borders.py the change to dwl.c that draws them
# config.h uses `ZoneColor`, which only the patch adds: the three go together.
# Upstream fixes come first, from build/patches/dwl-0.8 (see its README).
s_dwl() {
    local cfg_sha="${1:-none}" colours_sha="${2:-none}" patch_sha="${3:-none}"
    local desk="${KRYPTIK_ROOT}/build/desktop"
    local cfg="${desk}/dwl-config.h" colours="${desk}/zone-colours.h"
    local patch="${KRYPTIK_ROOT}/tools/desktop/dwl-zone-borders.py"
    local f
    for f in "$cfg" "$colours" "$patch"; do
        [[ -f "$f" ]] || { echo "desktop input missing: ${f}"; return 1; }
    done
    # A digest mismatch means the inputs changed under the build.
    local got
    for f in "$cfg:$cfg_sha" "$colours:$colours_sha" "$patch:$patch_sha"; do
        got="$(sha256_of "${f%%:*}")"
        if [[ "${f##*:}" != "none" && "$got" != "${f##*:}" ]]; then
            echo "${f%%:*} changed during the build (fingerprinted ${f##*:}, now ${got})"
            return 1
        fi
    done
    echo "inputs: dwl-config.h ${cfg_sha}"
    echo "        zone-colours.h ${colours_sha}"
    echo "        dwl-zone-borders.py ${patch_sha}"

    local src; src="$(unpack "dwl-v${V_DWL}.tar.gz" "dwl-v${V_DWL}")"
    cd "$src"
    apply_repo_patches "dwl-${V_DWL}"
    # The patch makes exact-string edits and refuses any other dwl version.
    python3 "$patch" .
    grep -q 'zonecolors(Client \*c)' dwl.c || { echo "FAIL: the zone border change is not in dwl.c"; return 1; }
    cp "$colours" zone-colours.h
    cp "$cfg" config.h
    make PREFIX=/usr XWAYLAND= XLIBS=
    make PREFIX=/usr install
    # The installed binary must carry the change: the chooser's app_id prefix
    # is a literal in it.
    grep -aq 'kryptik\.' /usr/bin/dwl || { echo "FAIL: /usr/bin/dwl does not contain the zone chooser"; return 1; }
    echo "installed dwl with per-zone borders"
    dwl -v 2>&1 | head -1 || true
}
