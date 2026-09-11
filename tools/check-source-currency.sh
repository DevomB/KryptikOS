#!/usr/bin/env bash
# Compare every pinned version against what upstream currently publishes.
#
#   ./tools/check-source-currency.sh                 report everything
#   ./tools/check-source-currency.sh --only NAME     one package
#   ./tools/check-source-currency.sh --fail-on-behind
#   ./tools/check-source-currency.sh --strict        also fail on UNKNOWN
#   ./tools/check-source-currency.sh --tsv           machine-readable
#
# THIS IS INFORMATIONAL BY DESIGN, AND THAT IS NOT A COP-OUT.
#
# "A newer version exists" is not a security verdict. Some pins are old on
# purpose - xz is pinned well clear of the CVE-2024-3094 window and the
# versions.env comment explains why - and some newer versions are major moves
# that change build behaviour. So the default reports and exits 0, and the gate
# is opt-in: --fail-on-behind for a currency policy, --strict to additionally
# refuse a run in which some pins could not be determined.
#
# tools/check-kernel-eol.sh is the opposite and stays that way: kernel.org
# publishes machine-readable support status, so an EOL kernel is a verdict and
# it fails. Nothing else upstream publishes support status, only version
# numbers, which is exactly the difference between the two tools.
#
# WHAT IT REFUSES TO DO
#
# Guess. Every "newest" below comes from a directory listing on the project's
# own host or from the project's own "latest release" designation. Where the
# shape of a URL is not recognised, or a listing yields nothing that parses as
# a version, the answer is UNKNOWN and the row says which URL was consulted.
# An inventory of pins is only useful if a blank means "not checked" rather
# than "fine" - the same rule as everywhere else in these tools.
#
# Known traps, encoded below rather than rediscovered:
#
#   * Perl's odd minor versions are DEVELOPMENT releases. A naive "highest
#     version wins" recommends 5.45.2 over the stable 5.44.0.
#   * GitHub tag lists contain CVS-era imports and fuzz-corpus tags. Asking
#     /releases/latest gets the project's own designation instead of the
#     numerically largest string, which is how a tag max produced "V20000512"
#     for expat.
#   * A release-candidate is not a release.

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

# Self-test hook: tools/test-check-source-currency.sh serves fixture listings
# from 127.0.0.1 and rewrites upstream hosts onto it, so the parsing runs for
# real offline.
if [[ -n "${KRYPTIK_CURRENCY_BASE:-}" ]]; then
    [[ "${KRYPTIK_CURRENCY_SELFTEST:-0}" == "1" ]] || die \
"KRYPTIK_CURRENCY_BASE is set but KRYPTIK_CURRENCY_SELFTEST is not.
Refusing to compare pinned versions against a substituted upstream."
    warn "SELF-TEST MODE: upstream listings come from ${KRYPTIK_CURRENCY_BASE}"
fi

# Rewrite an upstream URL onto the fixture server, preserving the path so the
# fixtures are laid out the way the real hosts are.
resolve() {
    local url="$1"
    if [[ -n "${KRYPTIK_CURRENCY_BASE:-}" ]]; then
        printf '%s' "${KRYPTIK_CURRENCY_BASE}/$(printf '%s' "$url" | sed -E 's#^https?://##')"
    else
        printf '%s' "$url"
    fi
}

# `|| true`: a 404, a 403 or a refused connection must produce an empty answer
# so the caller can report UNKNOWN. Without it curl's exit 22 propagates
# through the command substitution into common.sh's ERR trap and aborts the
# whole run with a line number, which is how one unreachable host used to take
# the entire report down.
fetch() { curl -fsSL --max-time 25 "$(resolve "$1")" 2>/dev/null || true; }

# versions_in_listing <listing-url> <extended-regex with ONE capture group>
#
# Every version the listing offers, pre-releases dropped, in version order.
# Empty output means "nothing parsed", never "0".
# The regex is interpolated into sed, so it must not contain the delimiter.
# "@" is used rather than "/" because several of the patterns below match a
# trailing slash - a directory listing entry - and "/" ended the s command
# early, which sed reports as "unknown option to `s'".
versions_in_listing() {
    fetch "$1" \
      | grep -oE "$2" \
      | sed -E "s@$2@\1@" \
      | grep -vE '(rc|alpha|beta|pre|dev)[0-9]*$' \
      | sort -V -u || true
}

# The highest of them. Kept separate from versions_in_listing because a
# per-package rule - Perl's odd-minor development series - has to filter the
# whole list before the maximum is taken, not afterwards.
newest_in_listing() { versions_in_listing "$@" | tail -1; }

# The project's own designation of its latest release, which is a different and
# better question than "which tag sorts highest" - that question answered
# "V20000512" for expat, from a CVS-era import tag.
#
# ONLY the API's /releases/latest, deliberately, with no fallback.
#
# The obvious fallback is https://github.com/<repo>/releases.atom, which needs
# no token and is not rate limited. It was tried and removed: for a repository
# that publishes no GitHub Releases the feed serves TAG entries instead, and
# the first of those is whatever was tagged last. Asked about shadow-maint,
# that produced "3.3.1" - a plausible-looking version that is not shadow's at
# all.
#
# A wrong number is worse than no number here. The whole argument of this
# branch is that an unavailable check must report unavailable rather than
# produce something that looks like an answer, and a currency tool that
# occasionally invents a version would be the same defect wearing a different
# hat. So: rate limited or unreachable means UNKNOWN, and the row says so.
#
# The unauthenticated API allows 60 requests an hour, which a 69-source report
# can exhaust by itself. Set GH_TOKEN for a complete GitHub picture.
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

# Drop Perl-style development releases: an odd minor version is a development
# series and must never be recommended.
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

# --- per-source strategy ----------------------------------------------------
#
# Returns "<newest>|<source consulted>", either field possibly empty.

upstream_for() {
    local name="$1" url="$2"
    local dir="${url%/*}" base="${url##*/}"
    local newest="" consulted=""

    case "$name" in
        # The kernel is the one package upstream publishes SUPPORT STATUS for,
        # and a pin in a longterm series is not "behind" because a newer series
        # exists - which is exactly what a version comparison would say. Defer
        # to the tool that asks the right question.
        linux|linux-hardened)
            printf '%s|%s' "" "tools/check-kernel-eol.sh (support status, not version)"
            return
            ;;
    esac

    case "$url" in
        # kernel.org and others put releases in per-series subdirectories, so
        # the file's own directory only ever offers that series. Look in the
        # parent for a newer series first, then list the newest one found.
        # Restricted to kernel.org: a GitHub release-asset URL also has the tag
        # as a path element (.../releases/download/v1.3.1/zlib-1.3.1.tar.gz)
        # and would match a bare */v[0-9]*/* first, sending the check off to
        # look for a directory listing GitHub does not serve.
        *kernel.org/*/v[0-9]*/*)
            local parent="${dir%/*}"
            local vdir
            # `|| true` for the same reason as versions_in_listing: no match is
            # an answer, not an error.
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
            # gcc lives in per-version subdirectories; its listing is the
            # parent, not the file's own directory.
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
            # The whole list, then the odd-minor filter, then the maximum:
            # filtering after taking the maximum would just discard 5.45.2 and
            # report nothing.
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

        # Everything else with a plain directory listing, which covers
        # kernel.org, savannah, sourceware, astron and the rest.
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
        # Deliberately not checked here, and the row says where it IS checked.
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
