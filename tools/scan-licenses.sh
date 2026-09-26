#!/usr/bin/env bash
# Record the licence evidence each source tarball actually carries.
#
#   ./tools/scan-licenses.sh                  scan, using the cache
#   ./tools/scan-licenses.sh --refresh        ignore the cache
#   ./tools/scan-licenses.sh --only=NAME      one source
#   ./tools/scan-licenses.sh --tsv            machine-readable (the default shape)
#
# Only top-level licence files are read, never per-file headers. An SPDX id is
# given only where the text is unambiguous; anything else is `unknown`.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

ONLY=""
REFRESH=0
for a in "$@"; do
    case "$a" in
        --refresh) REFRESH=1 ;;
        --tsv) ;;                      # the only output shape; accepted for symmetry
        --only=*) ONLY="${a#--only=}" ;;
        -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done

# Keyed by tarball sha256: listing the kernel tarball decompresses all of it.
CACHE="${KRYPTIK_WORK}/licences.cache"
mkdir -p "$(dirname "$CACHE")"
[[ "$REFRESH" -eq 1 ]] && rm -f "$CACHE"
[[ -f "$CACHE" ]] || : > "$CACHE"

# The first row for a digest wins.
declare -A CACHE_ROW=()
while IFS= read -r c_line; do
    [[ -n "$c_line" ]] || continue
    c_key="${c_line#*$'\t'}"; c_key="${c_key%%$'\t'*}"
    [[ -n "${CACHE_ROW[$c_key]:-}" ]] || CACHE_ROW["$c_key"]="$c_line"
done < "$CACHE"

remember() {  # remember ROW DIGEST
    printf '%s\n' "$1"
    printf '%s\n' "$1" >> "$CACHE"
    CACHE_ROW["$2"]="$1"
}

# Licence files come from common.sh's licence_members, the reader
# stage 04 installs from too.

# classify <path-to-text> -> comma-separated SPDX ids, or "unknown"
# Every marker found is reported: libcap's one file is BSD-3-Clause or GPL-2.0.
# Matching is case-insensitive over the first 8KB, whitespace collapsed. A GNU
# licence with no version stated stays unknown.
classify() {
    local f="$1" head ids=""
    head="$(head -c 8000 "$f" 2>/dev/null)" 2>/dev/null
    head="${head//[[:space:]]/ }"
    while [[ "$head" == *"  "* ]]; do head="${head//  / }"; done
    head="${head,,}"
    add() { ids="${ids}${ids:+,}$1"; }
    has() { case "$head" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

    has "gnu lesser general public license" && {
        has "version 3"   && add LGPL-3.0
        has "version 2.1" && add LGPL-2.1
    }
    has "gnu library general public license" && has "version 2" && add LGPL-2.0
    has "gnu affero general public license"  && has "version 3" && add AGPL-3.0
    # LGPL texts cite the GPL. In one, the GPL is added unless the GPL's closing
    # sentence is present, and the dedupe below drops the same-version GPL.
    if has "gnu general public license"; then
        case "$head" in
            *"gnu lesser general public license"*|*"gnu library general public license"*)
                has "the gnu general public license does not permit incorporating" || {
                    has "version 3" && add GPL-3.0
                    has "version 2" && add GPL-2.0
                } ;;
            *)  has "version 3" && add GPL-3.0
                has "version 2" && add GPL-2.0 ;;
        esac
    fi
    has "apache license" && has "version 2.0" && add Apache-2.0

    # MIT grants sublicensing; the same grant without it is only MIT-like.
    if has "permission is hereby granted, free of charge"; then
        if has "sublicense"; then add MIT; else add MIT-or-similar; fi
    elif has "permission to use, copy, modify, and" && has "distribute this software"; then
        add ISC
    fi

    has "altered source versions must be plainly marked as such" && add Zlib

    # BSD family, distinguished by whether a non-endorsement clause is present.
    if has "redistribution and use in source and binary forms"; then
        if has "neither the name" || has "endorse or promote"; then
            add BSD-3-Clause
        else
            add BSD-2-Clause-or-similar
        fi
    fi

    if [[ -z "$ids" ]]; then printf 'unknown'; return; fi

    # An LGPL text cites its GPL version; that alone is not a dual licence.
    local out
    out="$(printf '%s' "$ids" | tr ',' '\n' | sort -u)"
    case "$out" in
        *LGPL-3.0*) out="$(printf '%s\n' "$out" | grep -vx 'GPL-3.0' || true)" ;;
    esac
    case "$out" in
        *LGPL-2.1*) out="$(printf '%s\n' "$out" | grep -vx 'GPL-2.0' || true)" ;;
    esac
    printf '%s' "$out" | paste -sd, -
}

emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6"; }

# One row per source:
#   name  tarball_sha256  spdx  multi  files  method
while read -r name _ver url; do
    [[ -n "$name" ]] || continue
    [[ -n "$ONLY" && "$name" != "$ONLY" ]] && continue

    file="$(basename "$url")"
    path="${KRYPTIK_SOURCES}/${file}"

    if [[ ! -f "$path" ]]; then
        emit "$name" "-" "unknown" "no" "-" "not-downloaded"
        continue
    fi

    digest="$(sha256_of "$path")"

    cached="${CACHE_ROW[$digest]:-}"
    if [[ -n "$cached" ]]; then
        printf '%s\n' "$cached"
        continue
    fi

    case "$file" in
        *.patch|*.diff)
            row="$(emit "$name" "$digest" "unknown" "no" "-" "not-an-archive")"
            remember "$row" "$digest"; continue ;;
    esac

    names="$(licence_members "$path" | head -6 || true)"
    if [[ -z "$names" ]]; then
        row="$(emit "$name" "$digest" "unknown" "no" "-" "no-top-level-licence-file")"
        remember "$row" "$digest"; continue
    fi

    tmp="$(mktemp -d)"
    ids=""; listed=""
    while IFS= read -r n; do
        [[ -n "$n" ]] || continue
        base="${n##*/}"
        if tar xf "$path" -O "$n" > "${tmp}/x" 2>/dev/null; then
            id="$(classify "${tmp}/x")"
            fsha="$(sha256_of "${tmp}/x")"
            ids="${ids}${ids:+,}${id}"
            listed="${listed}${listed:+;}${base}:${id}:${fsha:0:16}"
        fi
    done <<< "$names"
    rm -rf "$tmp"

    # Distinct ids across files; an `unknown` beside a recognised licence is
    # not a second licence.
    uniq_ids="$(printf '%s' "$ids" | tr ',' '\n' | grep -v '^$' | sort -u | paste -sd, -)"
    if [[ "$uniq_ids" == *,* ]]; then
        stripped="$(printf '%s' "$uniq_ids" | tr ',' '\n' | grep -v '^unknown$' \
                    | sort -u | paste -sd, -)"
        [[ -n "$stripped" ]] && uniq_ids="$stripped"
    fi
    n_ids="$(printf '%s' "$uniq_ids" | tr ',' '\n' | grep -c . || true)"
    multi=no
    [[ "${n_ids:-0}" -gt 1 ]] && multi=yes

    row="$(emit "$name" "$digest" "${uniq_ids:-unknown}" "$multi" "${listed:--}" \
                "tarball-top-level-licence-file")"
    remember "$row" "$digest"
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)
