# Sourced by the suites in tools/tests that build pinned sources. The caller sets REPO (the
# checkout) and W (its scratch directory). KRYPTIK_TEST_SOURCES names a directory that keeps fetched
# tarballs between runs (CI caches it); one kept there is used only with the lock's hash.

# fetch_pinned NAME FILE VERSION: FILE unpacked in W, and the directory it unpacked to on stdout.
# It comes from the URL fetch-sources.sh resolves, then the source's mirrors, then Gentoo's
# distfiles, as fetch-sources.sh tries them, and is kept only with sources.lock's hash.
fetch_pinned() {
    local name="$1" file="$2" ver="$3" url want u keep="${KRYPTIK_TEST_SOURCES:-}" got=""
    url="$("$REPO/tools/fetch-sources.sh" --list-root 2>/dev/null | awk -v n="$name" '$1 == n { print $3; exit }')"
    want="$(awk -v f="$file" '$2 == f { print $1 }' "$REPO/sources.lock")"
    [[ -n "$url" && -n "$want" ]] || { echo "FAIL: no URL or no lock row for ${name} (${file})" >&2; return 1; }
    if [[ -n "$keep" && -f "$keep/$file" && "$(sha256sum "$keep/$file" | cut -c1-64)" == "$want" ]]; then
        got="$keep/$file"
    else
        local -a urls=("$url")
        while read -r u; do urls+=("${u//"{VER}"/"$ver"}"); done \
            < <(awk -v n="$name" '$1 == n { print $2 }' "$REPO/tools/source-mirrors.tsv")
        urls+=("https://distfiles.gentoo.org/distfiles/$(printf '%s' "$file" | b2sum | cut -c1-2)/${file}")
        for u in "${urls[@]}"; do
            if curl -fsSL --retry 2 --max-time 120 -o "$W/$file" "$u" \
               && [[ "$(sha256sum "$W/$file" | cut -c1-64)" == "$want" ]]; then
                got="$W/$file"
                [[ -z "$keep" ]] || { mkdir -p "$keep" && cp "$W/$file" "$keep/$file"; }
                break
            fi
            echo "note: ${file} not from ${u}" >&2
        done
        [[ -n "$got" ]] || { echo "FAIL: no source of ${file} has the locked hash ${want}" >&2; return 1; }
    fi
    tar -xf "$got" -C "$W" || { echo "FAIL: cannot unpack ${file}" >&2; return 1; }
    printf '%s/%s\n' "$W" "$(tar -tf "$got" | head -1 | cut -d/ -f1)"
}
