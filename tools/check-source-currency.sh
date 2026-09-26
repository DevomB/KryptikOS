#!/usr/bin/env bash
# Compare every pinned version against what upstream currently publishes.
# Informational: exits 0 unless --fail-on-behind or --strict is given.
#
#   ./tools/check-source-currency.sh                 report everything
#   ./tools/check-source-currency.sh --only=NAME     one package
#   ./tools/check-source-currency.sh --fail-on-behind
#   ./tools/check-source-currency.sh --strict        also fail on UNKNOWN
#   ./tools/check-source-currency.sh --tsv           machine-readable

# Every "newest" comes from the project's own host: a listing or its designated
# latest release. Anything that does not parse is UNKNOWN, never "current".

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

ONLY=""
FAIL_BEHIND=0
STRICT=0
TSV=0
for a in "$@"; do
    case "$a" in
        --fail-on-behind) FAIL_BEHIND=1 ;;
        --strict) STRICT=1; FAIL_BEHIND=1 ;;
        --tsv) TSV=1 ;;
        --only=*) ONLY="${a#--only=}" ;;
        -h|--help) sed -n '2,9p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done

have curl    || die "curl required"
have python3 || die "python3 required"

WORK="${KRYPTIK_WORK}/currency"
rm -rf "$WORK"; mkdir -p "$WORK"

# Test hook: tools/test-check-source-currency.sh serves listings on 127.0.0.1.
if [[ -n "${KRYPTIK_CURRENCY_BASE:-}" ]]; then
    [[ "${KRYPTIK_CURRENCY_SELFTEST:-0}" == "1" ]] || die \
"KRYPTIK_CURRENCY_BASE is set but KRYPTIK_CURRENCY_SELFTEST is not.
Refusing to compare pinned versions against a substituted upstream."
    warn "SELF-TEST MODE: upstream listings come from ${KRYPTIK_CURRENCY_BASE}"
fi

# Under the test hook, move an upstream URL onto the fixture server, path kept.
resolve() {
    local url="$1"
    if [[ -n "${KRYPTIK_CURRENCY_BASE:-}" ]]; then
        printf '%s' "${KRYPTIK_CURRENCY_BASE}/$(printf '%s' "$url" | sed -E 's#^https?://##')"
    else
        printf '%s' "$url"
    fi
}

# `|| true`: a failed fetch must give an empty answer (UNKNOWN), not trip
# common.sh's ERR trap and abort the run.
fetch() { curl -fsSL --max-time 25 "$(resolve "$1")" 2>/dev/null || true; }

# versions_in_listing <listing-url> <ERE with one capture group>
# Every version offered, pre-releases dropped, in version order. The ERE goes
# into sed with "@" as the delimiter (patterns match a trailing "/"), so no "@".
versions_in_listing() {
    fetch "$1" \
      | grep -oE "$2" \
      | sed -E "s@$2@\1@" \
      | grep -vE '(rc|alpha|beta|pre|dev)[0-9]*$' \
      | sort -V -u || true
}

# Separate from versions_in_listing so Perl's filter can run before the maximum.
newest_in_listing() { versions_in_listing "$@" | tail -1; }

# The project's designated latest release, not the highest tag (expat has a
# CVS-era "V20000512"). No releases.atom fallback: without Releases it lists
# tags, newest first, which gave shadow a "3.3.1" that is not shadow's.
# Unauthenticated, the API allows 60 requests an hour; set GH_TOKEN.
newest_github_release() {
    local auth=()
    [[ -n "${GH_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer ${GH_TOKEN}")
    curl -fsSL --max-time 25 "${auth[@]}" \
        "$(resolve "https://api.github.com/repos/$1/releases/latest")" \
        2>/dev/null \
      | python3 -c "
import json, re, sys
try:
    d = json.load(sys.stdin)
except Exception:
    raise SystemExit
if not isinstance(d, dict) or d.get('prerelease') or 'tag_name' not in d:
    raise SystemExit
tag = d.get('tag_name') or ''
# R_2_8_4 -> 2.8.4 ; v1.3.2 -> 1.3.2 ; openssl-3.5.8 -> 3.5.8
m = re.search(r'(\d+[\d._]*\d)', tag.replace('_', '.'))
print(m.group(1) if m else '')" || true
}

# Newest version with an even minor: odd minors are Perl development series.
drop_odd_minor() {
    python3 -c "
import sys
out = []
for line in sys.stdin:
    v = line.strip()
    if not v:
        continue
    parts = v.split('.')
    if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) % 2 == 1:
        continue
    out.append(v)
print(out[-1] if out else '')"
}

# Every value of one string key in a JSON response, leading "v" dropped. The key
# is matched with its opening quote ("name" is not "author_name") and, for
# "name", the object's opening brace, so a nested "name" is skipped.
api_values() {  # api_values URL KEY
    local open='"'
    [[ "$2" == name ]] && open='\{"'
    fetch "$1" | grep -oE "${open}$2\":\"[^\"]*\"" \
        | sed -E "s/.*\"$2\":\"v?([^\"]*)\"/\1/" || true
}

# The highest all-numeric version (0.8-dev and 4.0.7rc1 are dropped). Sorted,
# since GitLab lists releases by date, not version.
numeric_newest() { grep -E '^[0-9]+(\.[0-9]+)+$' | sort -V -u | tail -1 || true; }

# freedesktop projects number a release candidate X.Y.9N or X.Y.90N.
drop_ninety() { grep -vE '\.9[0-9]+$' || true; }

# --- per-source strategy ----------------------------------------------------

# upstream_for <name> <url> prints "<newest>|<consulted>"; either may be empty.
upstream_for() {
    local name="$1" url="$2"
    local dir="${url%/*}" base="${url##*/}"
    local newest="" consulted=""

    case "$name" in
        # A longterm kernel is not "behind" a newer series; check-kernel-eol.sh
        # checks its support status instead.
        linux|linux-hardened)
            printf '%s|%s' "" "tools/check-kernel-eol.sh (support status, not version)"
            return
            ;;
    esac

    # --- hosts with no directory listing to read ---------------------------
    local fd="https://gitlab.freedesktop.org/api/v4/projects"
    case "$name" in
        glibc-fhs-patch)
            # The LFS patch for the pinned glibc; it moves only when glibc does.
            printf '%s|%s' "" "tools/check-source-currency.sh, the glibc row (the patch follows glibc's pin)"
            return ;;
        less)
            # The front page names the current release; newer tarballs are betas.
            consulted="https://www.greenwoodsoftware.com/less/ (released for general use)"
            newest="$(fetch "https://www.greenwoodsoftware.com/less/" \
                | grep -oE 'less-[0-9]+ has been released for general use' \
                | sed -E 's/less-([0-9]+) .*/\1/' | sort -V -u | tail -1 || true)" ;;
        procps-ng)
            consulted="gitlab.com procps-ng/procps releases"
            newest="$(api_values "https://gitlab.com/api/v4/projects/procps-ng%2Fprocps/releases?per_page=50" tag_name | numeric_newest)" ;;
        psmisc)
            # Tags: the release list misses a release.
            consulted="gitlab.com psmisc/psmisc tags"
            newest="$(api_values "https://gitlab.com/api/v4/projects/psmisc%2Fpsmisc/repository/tags?per_page=100" name | numeric_newest)" ;;
        lvm2)
            consulted="https://sourceware.org/pub/lvm2/"
            newest="$(newest_in_listing "$consulted" 'LVM2\.([0-9]+(\.[0-9]+)+)\.tgz')" ;;
        openssh)
            consulted="https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/"
            newest="$(newest_in_listing "$consulted" 'openssh-([0-9]+\.[0-9]+p[0-9]+)\.tar\.gz')" ;;
        ca-bundle)
            # curl.se/ca/ is a meta refresh, which curl -L does not follow.
            consulted="https://curl.se/docs/caextract.html"
            newest="$(newest_in_listing "$consulted" 'cacert-([0-9]{4}-[0-9]{2}-[0-9]{2})\.pem')" ;;
        wayland|libinput)
            consulted="gitlab.freedesktop.org ${name}/${name} releases"
            newest="$(api_values "${fd}/${name}%2F${name}/releases?per_page=50" tag_name | drop_ninety | numeric_newest)" ;;
        wayland-protocols)
            consulted="gitlab.freedesktop.org wayland/wayland-protocols releases"
            newest="$(api_values "${fd}/wayland%2Fwayland-protocols/releases?per_page=50" tag_name | numeric_newest)" ;;
        libdisplay-info)
            consulted="gitlab.freedesktop.org emersion/libdisplay-info releases"
            newest="$(api_values "${fd}/emersion%2Flibdisplay-info/releases?per_page=50" tag_name | numeric_newest)" ;;
        wlroots)
            # The pinned series only: each series changes the API dwl uses.
            local wseries="${V_WLROOTS%.*}"
            consulted="gitlab.freedesktop.org wlroots/wlroots tags (series ${wseries})"
            newest="$(api_values "${fd}/wlroots%2Fwlroots/repository/tags?per_page=100" name \
                | grep -E "^${wseries//./\\.}\.[0-9]+$" | numeric_newest || true)" ;;
        seatd)
            consulted="https://git.sr.ht/~kennylevinsen/seatd/refs/rss.xml"
            newest="$(fetch "$consulted" | grep -oE '<title>[0-9]+(\.[0-9]+)+</title>' \
                | sed -E 's/<[^>]*>//g' | sort -V -u | tail -1 || true)" ;;
        dwl)
            consulted="codeberg.org dwl/dwl tags"
            newest="$(api_values "https://codeberg.org/api/v1/repos/dwl/dwl/tags?limit=50" name | numeric_newest)" ;;
        lynx)
            consulted="https://invisible-mirror.net/archives/lynx/tarballs/"
            newest="$(newest_in_listing "$consulted" 'lynx([0-9]+(\.[0-9]+)+)\.tar\.gz')" ;;
        kernel-hardening-checker)
            # Tags only: it publishes no releases.
            consulted="https://github.com/a13xp0p0v/kernel-hardening-checker/tags.atom"
            newest="$(fetch "$consulted" | grep -oE '<title>v[0-9]+(\.[0-9]+)+</title>' \
                | sed -E 's/<title>v//; s/<.*//' | sort -V -u | tail -1 || true)" ;;
    esac
    if [[ -n "$consulted" ]]; then
        printf '%s|%s' "$newest" "$consulted"
        return
    fi

    case "$url" in
        # Per-series subdirectories only offer their own series, so find the
        # newest series in the parent first. kernel.org only: GitHub asset URLs
        # have a /v1.2.3/ element too.
        *kernel.org/*/v[0-9]*/*)
            local parent="${dir%/*}"
            local vdir
            # `|| true`: no match is an answer, not an error.
            vdir="$(fetch "${parent}/" | grep -oE 'v[0-9]+(\.[0-9]+)*/' \
                    | sed -E 's@v(.*)/@\1@' | sort -V -u | tail -1 || true)"
            if [[ -n "$vdir" ]]; then
                consulted="${parent}/v${vdir}/"
                local stem="${base%%-[0-9]*}"
                newest="$(newest_in_listing "$consulted" \
                          "${stem}-([0-9]+(\.[0-9]+)*)\.tar\.(xz|gz|bz2)")"
            fi
            if [[ -z "$newest" ]]; then
                consulted="${dir}/"
                local stem2="${base%%-[0-9]*}"
                newest="$(newest_in_listing "$consulted" \
                          "${stem2}-([0-9]+(\.[0-9]+)*)\.tar\.(xz|gz|bz2)")"
            fi
            ;;

        # GNU: the canonical host, because mirrors lag and 403 on listings.
        *ftpmirror.gnu.org/*|*ftp.gnu.org/*|*mirrors.kernel.org/gnu/*)
            local rel="${url#*://*/}"          # e.g. gnu/grub/grub-2.12.tar.xz
            rel="${rel#gnu/}"
            local pkgdir="https://ftp.gnu.org/gnu/${rel%/*}"
            consulted="$pkgdir/"
            # gcc has per-version subdirectories, listed in the parent.
            [[ "$name" == gcc ]] && { consulted="https://ftp.gnu.org/gnu/gcc/"; \
                newest="$(newest_in_listing "$consulted" 'gcc-([0-9]+\.[0-9]+\.[0-9]+)/')"; }
            [[ -z "$newest" ]] && newest="$(newest_in_listing "$consulted" \
                "${name}-([0-9]+(\.[0-9]+)+)\.tar\.(xz|gz)")"
            ;;

        # GitHub release assets and tag archives: ask the project.
        *github.com/*)
            local repo; repo="$(printf '%s' "$url" \
                | sed -E 's#^https?://github\.com/([^/]+/[^/]+)/.*#\1#')"
            consulted="github ${repo} releases/latest"
            newest="$(newest_github_release "$repo")"
            [[ -n "$newest" ]] || consulted="${consulted} (unavailable: rate limit? set GH_TOKEN)"
            ;;

        *skarnet.org/software/*)
            consulted="${dir}/"
            newest="$(newest_in_listing "$consulted" "${name}-([0-9]+(\.[0-9]+)+)\.tar\.gz")"
            ;;

        *python.org/ftp/python/*)
            # The pinned series only: a 3.13 exists but is not a drop-in.
            local series="${V_PYTHON%.*}"
            consulted="https://www.python.org/ftp/python/ (series ${series})"
            newest="$(newest_in_listing "https://www.python.org/ftp/python/" \
                      "(${series//./\\.}\.[0-9]+)/")"
            ;;

        *cpan.org/src/*)
            consulted="${dir}/"
            # Filter the whole list, then take the maximum.
            newest="$(versions_in_listing "$consulted" \
                      'perl-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.xz' | drop_odd_minor)"
            ;;

        *openssl.org/source/*)
            consulted="https://openssl-library.org/source/"
            # Stay on the pinned major line: a major bump is not a currency fix.
            local major="${V_OPENSSL%%.*}"
            newest="$(newest_in_listing "$consulted" \
                      "openssl-(${major}\.[0-9]+\.[0-9]+)\.tar\.gz")"
            ;;

        # Everything else: a plain directory listing.
        *)
            consulted="${dir}/"
            local stem="${base%%-[0-9]*}"
            [[ -n "$stem" ]] || stem="$name"
            newest="$(newest_in_listing "$consulted" \
                      "${stem}-([0-9]+(\.[0-9]+)*)\.tar\.(xz|gz|bz2)")"
            ;;
    esac

    printf '%s|%s' "$newest" "$consulted"
}

# --- run --------------------------------------------------------------------

CURRENT=0; BEHIND=0; AHEAD=0; UNKNOWN=0
declare -a BEHIND_LIST=() UNKNOWN_LIST=()

[[ "$TSV" -eq 1 ]] || {
    log "Comparing pinned versions against upstream"
    echo
    printf '%-16s %-12s %-14s %-9s %s\n' SOURCE PINNED "UPSTREAM" STATUS CONSULTED
    printf '%s\n' "----------------------------------------------------------------------------------------"
}

while read -r name pinned url; do
    [[ -n "$name" ]] || continue
    [[ -n "$ONLY" && "$name" != "$ONLY" ]] && continue

    res="$(upstream_for "$name" "$url")"
    newest="${res%%|*}"
    consulted="${res#*|}"

    if [[ -z "$newest" && "$consulted" == tools/* ]]; then
        # Checked elsewhere; the row names where.
        status=deferred
    elif [[ -z "$newest" ]]; then
        status=UNKNOWN
        UNKNOWN=$((UNKNOWN + 1)); UNKNOWN_LIST+=("${name} (consulted ${consulted:-nothing})")
    elif [[ "$newest" == "$pinned" ]]; then
        status=current; CURRENT=$((CURRENT + 1))
    else
        oldest="$(printf '%s\n%s\n' "$pinned" "$newest" | sort -V | head -1)"
        if [[ "$oldest" == "$pinned" ]]; then
            status=BEHIND
            BEHIND=$((BEHIND + 1)); BEHIND_LIST+=("${name} ${pinned} -> ${newest}")
        else
            status=AHEAD
            AHEAD=$((AHEAD + 1))
        fi
    fi

    if [[ "$TSV" -eq 1 ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$pinned" "${newest:-}" "$status" "$consulted"
    else
        printf '%-16s %-12s %-14s %-9s %s\n' \
            "$name" "${pinned:0:12}" "${newest:-?}" "$status" "${consulted:0:44}"
    fi
done < <("${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list)

# glibc is its tarball plus upstream's release branch up to one commit, which
# the patch set's name records (build/patches/glibc-*/0001-release-*-<commit>).
# The branch head, from sourceware's own git, says whether the branch moved on.
glibc_patch=("${KRYPTIK_ROOT}/build/patches/glibc-${V_GLIBC:-none}"/0001-release-*.patch)
if [[ -f "${glibc_patch[0]}" && ( -z "$ONLY" || "$ONLY" == glibc-branch ) ]]; then
    name=glibc-branch
    pinned="${glibc_patch[0]##*-}"; pinned="${pinned%.patch}"
    ref="refs/heads/release/${V_GLIBC}/master"
    consulted="https://sourceware.org/git/glibc.git ${ref}"
    # From /: ls-remote needs no repository, and whatever the current one is
    # (a worktree git cannot open) must not decide the answer.
    newest="$(GIT_TERMINAL_PROMPT=0 timeout 30 git -C / ls-remote "$(resolve https://sourceware.org/git/glibc.git)" "$ref" 2>/dev/null \
        | cut -c1-40 | head -1 || true)"
    if [[ -z "$newest" ]]; then
        status=UNKNOWN
        UNKNOWN=$((UNKNOWN + 1)); UNKNOWN_LIST+=("${name} (consulted ${consulted})")
    elif [[ "$newest" == "$pinned"* ]]; then
        status=current; CURRENT=$((CURRENT + 1))
    else
        status=BEHIND
        BEHIND=$((BEHIND + 1)); BEHIND_LIST+=("glibc release/${V_GLIBC}/master ${pinned} -> ${newest:0:12}")
    fi
    newest="${newest:0:12}"
    if [[ "$TSV" -eq 1 ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$pinned" "$newest" "$status" "$consulted"
    else
        printf '%-16s %-12s %-14s %-9s %s\n' "$name" "$pinned" "${newest:-?}" "$status" "${consulted:0:44}"
    fi
fi

[[ "$TSV" -eq 1 ]] && exit 0

echo
log "Summary"
ok   "current:  ${CURRENT}"
[[ "$BEHIND"  -gt 0 ]] && warn "behind:   ${BEHIND}"
[[ "$AHEAD"   -gt 0 ]] && warn "ahead:    ${AHEAD} (pinned newer than upstream lists - check for a typo)"
[[ "$UNKNOWN" -gt 0 ]] && warn "UNKNOWN:  ${UNKNOWN} (not checked, which is not the same as fine)"

if [[ "$BEHIND" -gt 0 ]]; then
    echo
    dim "Behind upstream:"
    printf '  - %s\n' "${BEHIND_LIST[@]}"
fi
if [[ "$UNKNOWN" -gt 0 ]]; then
    echo
    dim "Could not be determined - the URL shape is not recognised, or the"
    dim "listing yielded nothing that parses as a version:"
    printf '  - %s\n' "${UNKNOWN_LIST[@]}"
fi

echo
dim "Being behind is not automatically a defect: xz is pinned well clear of the"
dim "CVE-2024-3094 window on purpose, and a major bump can change build"
dim "behaviour. Read this with build/config/versions.env open."
dim "For the kernel, support status rather than version number is the question:"
dim "tools/check-kernel-eol.sh."

rc=0
if [[ "$FAIL_BEHIND" -eq 1 && "$BEHIND" -gt 0 ]]; then
    err "${BEHIND} pin(s) behind upstream, and --fail-on-behind was requested"
    rc=1
fi
if [[ "$STRICT" -eq 1 && "$UNKNOWN" -gt 0 ]]; then
    err "${UNKNOWN} pin(s) could not be determined, and --strict was requested"
    rc=1
fi
[[ "$rc" -eq 0 ]] || die "currency check failed as requested."
exit 0
