#!/usr/bin/env bash
# Record the licence evidence each source tarball actually carries.
#
#   ./tools/scan-licenses.sh                  scan, using the cache
#   ./tools/scan-licenses.sh --refresh        ignore the cache
#   ./tools/scan-licenses.sh --only NAME      one source
#   ./tools/scan-licenses.sh --tsv            machine-readable (the default shape)
#
# WHAT THIS IS AND IS NOT.
#
# It reports, per source, the top-level licence files present in the tarball,
# their sha256, and an SPDX identifier ONLY where the text says so
# unambiguously. Everything else is `unknown` with the evidence recorded, so a
# human can finish the job without repeating the extraction.
#
# It is deliberately not a licence scanner in the compliance-tool sense. It
# does not read per-file headers, it does not detect a GPL file inside an MIT
# project, and it will not tell you whether linking is permitted. Calling this
# "the licences" would be the same overclaim as calling a lockfile hash an
# authenticity check, and the output labels itself accordingly:
#
#     method = tarball-top-level-licence-file
#
# A package carrying both COPYING and COPYING.LIB - bc does - is reported with
# both files and `multi` set, because picking one of them would be a decision
# this tool has no basis to make.
#
# CACHING. Listing a 154MB xz kernel tarball means decompressing all of it, so
# results are cached under build/work and keyed by the tarball's sha256. A
# changed tarball gets a new key and is rescanned; the cache cannot go stale
# without the bytes changing.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

ONLY=""
REFRESH=0
for a in "$@"; do
    case "$a" in
        --refresh) REFRESH=1 ;;
        --tsv) ;;                      # the only output shape; accepted for symmetry
        --only=*) ONLY="${a#--only=}" ;;
        -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done

CACHE="${KRYPTIK_WORK}/licences.cache"
mkdir -p "$(dirname "$CACHE")"
[[ "$REFRESH" -eq 1 ]] && rm -f "$CACHE"
[[ -f "$CACHE" ]] || : > "$CACHE"

# The cache, read once and indexed by tarball digest. It was read in full,
# by an awk process, once per source; it grows with every source scanned.
# First row for a digest wins, as awk's `exit` on first match did.
declare -A CACHE_ROW=()
while IFS= read -r c_line; do
    [[ -n "$c_line" ]] || continue
    c_key="${c_line#*$'\t'}"; c_key="${c_key%%$'\t'*}"
    [[ -n "${CACHE_ROW[$c_key]:-}" ]] || CACHE_ROW["$c_key"]="$c_line"
done < "$CACHE"

# Print a row and record it, in the file and in the index.
remember() {  # remember ROW DIGEST
    printf '%s\n' "$1"
    printf '%s\n' "$1" >> "$CACHE"
    CACHE_ROW["$2"]="$1"
}

# Top-level licence-ish filenames, as a POSIX ERE anchored to depth 1.
LICENCE_RE='^[^/]+/(COPYING[^/]*|COPYRIGHT[^/]*|LICEN[CS]E[^/]*|License)$'

# classify <path-to-text> -> comma-separated SPDX ids, or "unknown"
#
# EVERY marker present is reported, not the first one matched. libcap's single
# `License` file offers the work under BSD-3-Clause *or* GPL-2.0, and a scanner
# that returned on the first hit would report one of them and hide a real dual
# licence - which is the same failure as picking one of two licence files.
#
# Matching is case-insensitive on a whitespace-collapsed copy of the first 8KB.
# Case mattered: zlib's condition reads "2. Altered source versions must be
# plainly marked as such", and a case-sensitive pattern for that sentence
# reported zlib's own licence as unknown.
#
# The GNU licences state their version on a line of their own, so the version
# is read rather than assumed - "GNU General Public License" with no version is
# a different fact from GPL-3.0 and stays unknown.
classify() {
    local f="$1" head ids=""
    # Whitespace folded to single spaces and case folded, in the shell: the
    # two tr processes this used to spawn per licence file did the same.
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
    # "lesser"/"library" contain the plain phrase too, so only count the plain
    # GPL when a copy of it is actually present as its own heading.
    if has "gnu general public license"; then
        case "$head" in
            *"gnu lesser general public license"*|*"gnu library general public license"*)
                # A LGPL file references the GPL; only claim GPL if the text
                # also carries the GPL's own preamble sentence.
                has "the gnu general public license does not permit incorporating" || {
                    has "version 3" && add GPL-3.0
                    has "version 2" && add GPL-2.0
                } ;;
            *)  has "version 3" && add GPL-3.0
                has "version 2" && add GPL-2.0 ;;
        esac
    fi
    has "apache license" && has "version 2.0" && add Apache-2.0

    # MIT and ISC share an opening clause. MIT grants "merge, publish,
    # distribute, sublicense"; ISC does not mention sublicensing.
    if has "permission is hereby granted, free of charge"; then
        if has "sublicense"; then add MIT; else add MIT-or-similar; fi
    elif has "permission to use, copy, modify, and" && has "distribute this software"; then
        add ISC
    fi

    # The zlib licence forbids misrepresenting the origin and requires altered
    # versions to be marked.
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

    # LGPL-3.0's text says it "incorporates the terms and conditions of version
    # 3 of the GNU General Public License", and LGPL-2.1's preamble discusses
    # the GPL at length. Reporting both from ONE file would read as a dual
    # licence when the file is simply the LGPL. Suppress the plain GPL of the
    # matching version when its LGPL is present in the same text.
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

    # Cache hit: the bytes are unchanged, so the answer is unchanged.
    cached="${CACHE_ROW[$digest]:-}"
    if [[ -n "$cached" ]]; then
        printf '%s\n' "$cached"
        continue
    fi

    # A .patch is not an archive and carries no licence of its own.
    case "$file" in
        *.patch|*.diff)
            row="$(emit "$name" "$digest" "unknown" "no" "-" "not-an-archive")"
            remember "$row" "$digest"; continue ;;
    esac

    names="$(tar tf "$path" 2>/dev/null | grep -E "$LICENCE_RE" | head -6 || true)"
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

    # Distinct identifiers across all files, so COPYING+COPYING.LIB reads as
    # two and two copies of GPL-3.0 reads as one. `unknown` alongside a real
    # identifier is dropped: one unrecognised COPYRIGHT notice next to a
    # recognised licence is not a second licence.
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
