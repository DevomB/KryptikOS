#!/usr/bin/env bash
# firmware: a stage 04 recipe, sourced by build/stages/04-base-system.sh,
# which runs it in the order its list gives.

# copy-firmware.sh lays the pinned linux-firmware release out as the kernel
# names the files; build/config/firmware.list (format in its header) picks what
# ships, beside wireless-regdb. Files are zstd-compressed, as the kernel looks
# for name.zst (CONFIG_FW_LOADER_COMPRESS_ZSTD), and links are repointed.
s_firmware() {
    echo "list digest: ${1:-none}"
    local list="${KRYPTIK_ROOT}/build/config/firmware.list"
    [[ -f "$list" ]] || { echo "FAIL: ${list} is missing"; return 1; }
    local src; src="$(unpack "linux-firmware-${V_LINUX_FIRMWARE}.tar.xz" "linux-firmware-${V_LINUX_FIRMWARE}")"
    cd "$src"
    [[ -x ./copy-firmware.sh ]] || chmod +x ./copy-firmware.sh
    local tree="${src}/.installed"
    rm -rf "$tree"; mkdir -p "$tree"
    ./copy-firmware.sh -j"${KRYPTIK_JOBS:-$(nproc)}" "$tree" > /dev/null

    local dest="${KRYPTIK_DESTDIR}/lib/firmware"
    rm -rf "$dest"; mkdir -p "$dest"
    local line keep pattern matches n total=0 missing=0
    local selected="${src}/.selected"
    : > "$selected"
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        keep=0; pattern="$line"
        if [[ "$line" =~ ^newest[[:space:]]+([0-9]+)[[:space:]]+(.+)$ ]]; then
            keep="${BASH_REMATCH[1]}"; pattern="${BASH_REMATCH[2]}"
        fi
        matches="$(find "$tree" -path "${tree}/${pattern}" \( -type f -o -type l \) -print | sort)"
        if [[ "$keep" -gt 0 && -n "$matches" ]]; then
            # Group by the name with its trailing -NUMBER removed, keep the
            # highest NUMBERs of each group; a name without one is kept as is.
            matches="$(printf '%s\n' "$matches" | while IFS= read -r f; do
                b="${f##*/}"; stem="${b%.*}"; ext="${b##*.}"; ver="${stem##*-}"
                if [[ "$ver" =~ ^[0-9]+$ ]]; then
                    printf '%s\t%s\t%s\n' "${stem%-*}.${ext}" "$ver" "$f"
                else
                    printf '%s\t%s\t%s\n' "$b" 0 "$f"
                fi
            done | sort -t "$(printf '\t')" -k1,1 -k2,2nr | awk -F '\t' -v k="$keep" '{ if (++c[$1] <= k) print $3 }')"
        fi
        n="$(printf '%s\n' "$matches" | grep -c .)"
        if [[ "$n" -eq 0 ]]; then
            echo "  MISSING  ${pattern}: matches nothing in linux-firmware-${V_LINUX_FIRMWARE}"
            missing=$((missing + 1))
        else
            printf '%s\n' "$matches" >> "$selected"
            printf '  %5d  %s\n' "$n" "$line"
        fi
        total=$((total + n))
    done < "$list"
    if [[ "$missing" -gt 0 ]]; then
        echo "FAIL: ${missing} pattern(s) in firmware.list match nothing; the list must name what this release has"
        return 1
    fi
    # A symlink's target comes too, wherever it points inside the tree.
    local f t
    while IFS= read -r f; do
        [[ -L "$f" ]] || continue
        t="$(readlink -f "$f")"
        [[ "$t" == "${tree}/"* && -f "$t" ]] || { echo "FAIL: ${f#"${tree}/"} points outside the tree or at nothing (${t})"; return 1; }
        printf '%s\n' "$t"
    done < "$selected" >> "${selected}.targets"
    cat "${selected}.targets" >> "$selected"
    sort -u "$selected" | sed "s#^${tree}/##" > "${selected}.rel"
    echo "  $(wc -l < "${selected}.rel") files and links selected by ${total} matches"
    ( cd "$tree" && tr '\n' '\0' < "${selected}.rel" | xargs -0 cp -a --parents -t "$dest" )

    # regulatory.db and the signature cfg80211 checks with the kernel's key.
    local regdb; regdb="$(unpack "wireless-regdb-${V_WIRELESS_REGDB}.tar.xz" "wireless-regdb-${V_WIRELESS_REGDB}")"
    install -m 0644 "${regdb}/regulatory.db" "${regdb}/regulatory.db.p7s" "$dest/"

    # Compress the regular files, then repoint every symlink at the .zst. zstd
    # takes its files one at a time, so several run at once.
    find "$dest" -type f ! -name '*.zst' -print0 \
        | xargs -0 -r -P"${KRYPTIK_JOBS:-$(nproc)}" -n 32 zstd -19 -q --rm
    while IFS= read -r -d '' f; do
        t="$(readlink "$f")"
        ln -sfn "${t}.zst" "${f}.zst"
        rm -f "$f"
    done < <(find "$dest" -type l -print0)
    if find "$dest" -type l ! -exec test -e {} \; -print | grep .; then
        echo "FAIL: dangling links under /lib/firmware (above)"; return 1
    fi
    chmod -R u=rwX,go=rX "$dest"
    echo "  /lib/firmware: $(find "$dest" -type f | wc -l) files, $(find "$dest" -type l | wc -l) links, $(du -sh "$dest" | cut -f1)"
    [[ -f "$dest/regulatory.db.zst" && -f "$dest/regulatory.db.p7s.zst" ]] || { echo "FAIL: the regulatory database did not land"; return 1; }
}
