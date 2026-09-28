#!/usr/bin/env bash
# licences: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# Every source's licence files, from its own tarball, under
# /usr/share/licenses/<source>/, and Kryptik's own under kryptik/. Beside the
# top-level files: the kernel's LICENSES/preferred and exceptions, which its
# COPYING points to, firmware's WHENCE, which says which licence covers which
# file, and a lowercase licence file (the microcode's). Acceptance checks that
# no shipped source is left without one (tools/check-image-licences.sh).
s_licences() {
    local more_re='^[^/]+/(license|WHENCE|LICENSES/(preferred|exceptions)/[^/]+)$'
    local name url f m dir tmp n=0 members
    while read -r name _ url _; do
        [[ -n "$name" ]] || continue
        f="${KRYPTIK_SOURCES}/${url##*/}"
        [[ -f "$f" ]] || continue
        mapfile -t members < <(licence_members "$f" "$more_re")
        [[ "${#members[@]}" -gt 0 ]] || continue
        # One extraction for all of them: every tar run reads the whole
        # compressed stream, and linux-firmware has over a hundred.
        tmp="$(mktemp -d)"
        tar -xf "$f" -C "$tmp" -- "${members[@]}"
        dir="/usr/share/licenses/${name}"
        install -d -m 0755 "$dir"
        for m in "${members[@]}"; do
            # A link to a file not extracted would dangle: there is nothing to copy.
            # By its path below the top directory, so doc/COPYING and COPYING
            # cannot overwrite each other.
            if [[ -f "${tmp}/${m}" ]]; then
                install -D -m 0644 "${tmp}/${m}" "${dir}/${m#*/}"
                n=$((n + 1))
            fi
        done
        rm -rf "$tmp"
    done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)

    # Licence texts that no source tarball here carries, kept in
    # build/licences/: the MPL 2.0 of Mozilla's CA bundle, and what kryptikd
    # and kryptik-wlproxy link statically, which is Rust's standard library,
    # the libc crate and musl. libdrm ships no licence file either; its MIT
    # notice heads each file of its core library, the only part built.
    for f in "${KRYPTIK_ROOT}"/build/licences/*/*; do
        install -D -m 0644 "$f" "/usr/share/licenses/$(basename "$(dirname "$f")")/$(basename "$f")"
        n=$((n + 1))
    done
    f="${KRYPTIK_SOURCES}/libdrm-${V_LIBDRM}.tar.xz"
    mapfile -t members < <(tar -tf "$f" | grep -E '^[^/]+/[^/]+\.c$' || true)
    [[ "${#members[@]}" -gt 0 ]] || { echo "FAIL: no C files at the top of ${f##*/}"; return 1; }
    install -d -m 0755 /usr/share/licenses/libdrm
    header_notices "$f" "${members[@]}" > /usr/share/licenses/libdrm/COPYING
    n=$((n + 1))

    install -Dm644 "${KRYPTIK_ROOT}/LICENSE" /usr/share/licenses/kryptik/LICENSE
    echo "${n} licence files in $(find /usr/share/licenses -mindepth 1 -maxdepth 1 -type d | wc -l) directories"
}
