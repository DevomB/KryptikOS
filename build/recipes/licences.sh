#!/usr/bin/env bash

# Every source's licence files, from its own tarball, under /usr/share/licenses/<source>/.
s_licences() {
    # Also the microcode's lowercase license, firmware's WHENCE and the kernel's LICENSES/.
    local more_re='^[^/]+/(license|WHENCE|LICENSES/(preferred|exceptions)/[^/]+)$'
    local name url f m dir tmp n=0 members
    while read -r name _ url _; do
        [[ -n "$name" ]] || continue
        f="${KRYPTIK_SOURCES}/${url##*/}"
        [[ -f "$f" ]] || continue
        mapfile -t members < <(licence_members "$f" "$more_re")
        [[ "${#members[@]}" -gt 0 ]] || continue
        # One extraction: every tar run reads the whole stream, and firmware has over a hundred.
        tmp="$(mktemp -d)"
        tar -xf "$f" -C "$tmp" -- "${members[@]}"
        dir="/usr/share/licenses/${name}"
        install -d -m 0755 "$dir"
        for m in "${members[@]}"; do
            # Skip a dangling link; keep the path so doc/COPYING and COPYING do not collide.
            if [[ -f "${tmp}/${m}" ]]; then
                install -D -m 0644 "${tmp}/${m}" "${dir}/${m#*/}"
                n=$((n + 1))
            fi
        done
        rm -rf "$tmp"
    done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)

    # Texts no tarball carries: the CA bundle's MPL, and Rust std, libc and musl in static binaries.
    for f in "${KRYPTIK_ROOT}"/build/licences/*/*; do
        install -D -m 0644 "$f" "/usr/share/licenses/$(basename "$(dirname "$f")")/$(basename "$f")"
        n=$((n + 1))
    done
    # libdrm ships no licence file; its MIT notice heads each file of the core library.
    f="${KRYPTIK_SOURCES}/libdrm-${V_LIBDRM}.tar.xz"
    mapfile -t members < <(tar -tf "$f" | grep -E '^[^/]+/[^/]+\.c$' || true)
    [[ "${#members[@]}" -gt 0 ]] || { echo "FAIL: no C files at the top of ${f##*/}"; return 1; }
    install -d -m 0755 /usr/share/licenses/libdrm
    header_notices "$f" "${members[@]}" > /usr/share/licenses/libdrm/COPYING
    n=$((n + 1))

    install -Dm644 "${KRYPTIK_ROOT}/LICENSE" /usr/share/licenses/kryptik/LICENSE
    echo "${n} licence files in $(find /usr/share/licenses -mindepth 1 -maxdepth 1 -type d | wc -l) directories"
}
