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
# Each manifest row's new column says where to look (tools/fetch-sources.sh).

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

# keep <policy> <pinned>: the versions a rule lets the pin move to, in order.
keep() {
    local s
    case "$1" in
        -)      cat ;;
        series) s="${2%.*}"; grep -E "^${s//./\\.}\.[0-9]+$" || true ;;
        major)  s="${2%%.*}"; grep -E "^${s}\." || true ;;
        # Odd minors are Perl development series.
        even)   awk -F. 'NF && ($2 !~ /^[0-9]+$/ || $2 % 2 == 0)' ;;
        # freedesktop projects number a release candidate X.Y.9N or X.Y.90N.
        drop90) grep -vE '\.9[0-9]+$' || true ;;
    esac
}

# --- rules ------------------------------------------------------------------

# Where a row that declares "rule" looks, beside the manifest it serves.
RULES="${KRYPTIK_ROOT}/tools/currency-rules.tsv"
declare -A R_SHAPE=() R_WHERE=() R_MATCH=() R_KEEP=()

load_rules() {
    [[ -f "$RULES" ]] || die "no ${RULES}, so a row that declares a rule has nowhere to look"
    local line n=0 bad=0 name shape where match policy rest why
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
        IFS=$'\t' read -r name shape where match policy rest <<< "$line"
        why=""
        case "$shape" in
            listing) [[ "$match" == *\(* && "$match" != *@* ]] \
                         || why="a listing's match needs a group, and no @" ;;
            api)     [[ "$match" == tag_name || "$match" == name ]] \
                         || why="an api's match is tag_name or name" ;;
            *)       why="the shape is listing or api" ;;
        esac
        if [[ -z "$why" ]]; then
            case "$policy" in
                -|series|major|even|drop90) ;;
                *) why="keep is -, series, major, even or drop90" ;;
            esac
        fi
        [[ -z "$why" && "$where" != https://* ]] && why="where is an https URL"
        [[ -z "$why" && -n "$rest" ]] && why="more than five columns"
        [[ -z "$why" && -n "${R_SHAPE[$name]:-}" ]] && why="a second rule for ${name}"
        if [[ -n "$why" ]]; then
            err "${RULES}:${n}: ${why}"
            bad=$((bad + 1))
            continue
        fi
        R_SHAPE[$name]="$shape"; R_WHERE[$name]="$where"
        R_MATCH[$name]="$match"; R_KEEP[$name]="$policy"
    done < "$RULES"
    [[ "$bad" -eq 0 ]] || die "${bad} malformed row(s) in ${RULES}.
A rule that cannot be read is a tooling fault: its row would read UNKNOWN."
}

load_rules

# rule_newest <name> <pinned> prints "<newest>|<consulted>".
rule_newest() {
    local name="$1" pinned="$2" newest="" consulted
    if [[ -z "${R_SHAPE[$name]:-}" ]]; then
        printf '|%s' "no rule for it in tools/currency-rules.tsv"
        return
    fi
    local where="${R_WHERE[$name]}" policy="${R_KEEP[$name]}"
    consulted="$where"
    case "$policy" in
        series) consulted="${where} (series ${pinned%.*})" ;;
        major)  consulted="${where} (major ${pinned%%.*})" ;;
    esac
    if [[ "${R_SHAPE[$name]}" == api ]]; then
        newest="$(api_values "$where" "${R_MATCH[$name]}" \
            | keep "$policy" "$pinned" | numeric_newest || true)"
    else
        newest="$(versions_in_listing "$where" "${R_MATCH[$name]}" \
            | keep "$policy" "$pinned" | tail -1 || true)"
    fi
    printf '%s|%s' "$newest" "$consulted"
}

# --- per-source strategy ----------------------------------------------------

# upstream_for <name> <pinned> <url> <new> prints "<newest>|<consulted>";
# either may be empty. new is the manifest's column (tools/fetch-sources.sh).
upstream_for() {
    local name="$1" pinned="$2" url="$3" new="$4"
    local dir="${url%/*}" base="${url##*/}"
    local newest="" consulted="" stem="${base%%-[0-9]*}"

    case "$new" in
        # A longterm kernel is not "behind" a newer series; check-kernel-eol.sh
        # checks its support status instead.
        eol)
            consulted="tools/check-kernel-eol.sh (support status, not version)" ;;
        follows:*)
            consulted="the ${new#follows:} row (this pin moves only with that one)" ;;
        rule)
            rule_newest "$name" "$pinned"
            return ;;

        # The canonical host, because mirrors lag and 403 on listings.
        gnu)
            local rel="${url#*://*/}"          # e.g. gnu/grub/grub-2.12.tar.xz
            rel="${rel#gnu/}"
            consulted="https://ftp.gnu.org/gnu/${rel%/*}/"
            newest="$(newest_in_listing "$consulted" \
                      "${name}-([0-9]+(\.[0-9]+)+)\.tar\.(xz|gz)")"
            ;;

        # A vN/ directory offers only its own series, so the parent's newest
        # vN/ is read first.
        vdir)
            local parent="${dir%/*}"
            local vdir
            # `|| true`: no match is an answer, not an error.
            vdir="$(fetch "${parent}/" | grep -oE 'v[0-9]+(\.[0-9]+)*/' \
                    | sed -E 's@v(.*)/@\1@' | sort -V -u | tail -1 || true)"
            if [[ -n "$vdir" ]]; then
                consulted="${parent}/v${vdir}/"
                newest="$(newest_in_listing "$consulted" \
                          "${stem}-([0-9]+(\.[0-9]+)*)\.tar\.(xz|gz|bz2)")"
            fi
            if [[ -z "$newest" ]]; then
                consulted="${dir}/"
                newest="$(newest_in_listing "$consulted" \
                          "${stem}-([0-9]+(\.[0-9]+)*)\.tar\.(xz|gz|bz2)")"
            fi
            ;;

        # GitHub release assets and tag archives: ask the project.
        github)
            local repo; repo="$(printf '%s' "$url" \
                | sed -E 's#^https?://github\.com/([^/]+/[^/]+)/.*#\1#')"
            consulted="github ${repo} releases/latest"
            newest="$(newest_github_release "$repo")"
            [[ -n "$newest" ]] || consulted="${consulted} (unavailable: rate limit? set GH_TOKEN)"
            ;;

        listing)
            consulted="${dir}/"
            [[ -n "$stem" ]] || stem="$name"
            newest="$(newest_in_listing "$consulted" \
                      "${stem}-([0-9]+(\.[0-9]+)*)\.tar\.(xz|gz|bz2)")"
            ;;

        *)
            consulted="no way this script knows to find it ('${new}')" ;;
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

while read -r name pinned url _ new; do
    [[ -n "$name" ]] || continue
    [[ -n "$ONLY" && "$name" != "$ONLY" ]] && continue

    res="$(upstream_for "$name" "$pinned" "$url" "$new")"
    newest="${res%%|*}"
    consulted="${res#*|}"

    if [[ "$new" == eol || "$new" == follows:* ]]; then
        # Answered elsewhere; the row names where.
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
    dim "Could not be determined - the row names no way to look this script"
    dim "knows, or upstream's answer held nothing that parses as a version:"
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
