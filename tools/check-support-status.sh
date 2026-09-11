#!/usr/bin/env bash
# Fail if a pinned package sits in a release series upstream no longer supports.
#
#   ./tools/check-support-status.sh                     informational
#   ./tools/check-support-status.sh --strict            release gate
#   ./tools/check-support-status.sh --now=2026-04-10    evaluate as of a date
#   ./tools/check-support-status.sh --report=FILE
#
# WHY THIS IS NOT check-source-currency.sh. Currency asks "is there something
# newer?", and the answer is almost always yes and almost always uninteresting.
# This asks a different and much sharper question: does anyone upstream still
# issue security fixes for the series we ship? A pin can be two patches behind
# a maintained series and be fine. A pin in a series that went end-of-life five
# months ago will never receive another fix, no matter how ordinary its version
# number looks in versions.env.
#
# Kryptik shipped exactly that. openssl 3.3.1 looks unremarkable; the OpenSSL
# release strategy retired the whole 3.3 line on 2026-04-09.
#
# WHAT THIS DOES NOT MEASURE. It says nothing about patch-level gaps inside a
# supported series: openssl 3.5.0 and 3.5.8 both sit on the same row here. Use
# tools/check-source-currency.sh for that. A green run of this check means
# "the series is maintained", not "the pin is current", and the summary says so
# every time so that the two can never be quietly conflated.
#
# STRICT VERSUS INFORMATIONAL follows the rule used by the other checks: a
# FALSE assertion fails in both modes, and only an UNTESTABLE one is mode
# dependent. A series past its published support date is false support and
# fails always. A series with no row in the policy file cannot be established
# either way, so it fails --strict and warns otherwise.
#
# The policy data lives in tools/support-policy.tsv, one row per series, each
# carrying the upstream page it was read from and the date it was read. Read
# that file's header before adding to it.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

POLICY="${TOOLS_DIR}/support-policy.tsv"
VERSIONS="${KRYPTIK_ROOT}/build/config/versions.env"
STRICT=0
REPORT=""
NOW=""
NOW_SRC="today"

for a in "$@"; do
    case "$a" in
        --strict)     STRICT=1 ;;
        --policy=*)   POLICY="${a#--policy=}" ;;
        --versions=*) VERSIONS="${a#--versions=}" ;;
        --report=*)   REPORT="${a#--report=}" ;;
        --now=*)      NOW="${a#--now=}"; NOW_SRC="--now" ;;
        -h|--help)    sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done

# ---------------------------------------------------------------------------
# dates
# ---------------------------------------------------------------------------

valid_day()   { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && date -u -d "$1" +%F >/dev/null 2>&1; }
valid_month() { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}$ ]]          && date -u -d "${1}-01" +%F >/dev/null 2>&1; }

TODAY="$(date -u +%F)"
if [[ -n "$NOW" ]]; then
    valid_day "$NOW" || die "--now must be YYYY-MM-DD, got: ${NOW}"
else
    NOW="$TODAY"
fi

# Month precision resolves to the LAST day of that month. Upstream publishing
# "2028-10" is a claim about October, so treating it as 2028-10-01 would report
# a supported series as dead for most of a month.
last_supported_day() {
    local e="$1"
    if valid_day "$e"; then
        printf '%s' "$e"
    else
        date -u -d "${e}-01 +1 month -1 day" +%F
    fi
}

# ISO dates compare correctly as YYYYMMDD integers, and doing it numerically
# keeps the intent unambiguous to a reader and to shellcheck.
date_after() { [[ "${1//-/}" -gt "${2//-/}" ]]; }

days_between() {  # $1 earlier, $2 later; negative if $1 is later
    local a b
    a="$(date -u -d "$1" +%s)"
    b="$(date -u -d "$2" +%s)"
    printf '%s' "$(( (b - a) / 86400 ))"
}

# ---------------------------------------------------------------------------
# report buffer
# ---------------------------------------------------------------------------

if [[ -n "$REPORT" ]]; then
    # Checked before any work, so an unwritable path is a clean refusal rather
    # than a complete run whose output goes nowhere.
    mkdir -p "$(dirname "$REPORT")" 2>/dev/null || true
    : > "$REPORT" || die "cannot write the report to ${REPORT}"
fi

BUF="$(mktemp)"
trap 'rm -f "$BUF"' EXIT

row() {  # row STATE TEXT
    local state="$1"; shift
    printf '%-11s %s\n' "$state" "$*" >> "$BUF"
    case "$state" in
        ok)            ok    "$*" ;;
        FAIL)          err   "$*" ;;
        warn)          warn  "$*" ;;
        "NOT CHECKED") printf '%sNOT %s %s\n' "$C_YEL" "$C_RST" "$*" ;;
        *)             dim   "  $*" ;;
    esac
}

note() {
    printf '%s\n' "$*" >> "$BUF"
    dim "$*"
}

# ---------------------------------------------------------------------------
# the policy file
# ---------------------------------------------------------------------------

[[ -f "$POLICY" ]] || die "no policy file at ${POLICY}
This check cannot establish anything without it, and reporting nothing as
though it were a pass is the failure mode this tool exists to prevent."

declare -a P_PKG=() P_VAR=() P_SER=() P_ST=() P_END=() P_URL=() P_RET=() P_NOTE=()
lineno=0
malformed=0

while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    # The last variable takes the remainder of the line, so a note may contain
    # spaces while every field before it may not.
    read -r f_pkg f_var f_ser f_st f_end f_url f_ret f_note <<< "$line"

    bad=""
    [[ -n "$f_pkg" && -n "$f_var" && -n "$f_ser" && -n "$f_st" \
       && -n "$f_end" && -n "$f_url" && -n "$f_ret" ]] \
        || bad="expected 7 fields and an optional note"

    if [[ -z "$bad" ]]; then
        case "$f_st" in
            supported|security-only|none-published|delegated) ;;
            *) bad="unknown status '${f_st}'" ;;
        esac
    fi
    if [[ -z "$bad" && "$f_end" != "-" ]]; then
        valid_day "$f_end" || valid_month "$f_end" \
            || bad="support_ends '${f_end}' is neither YYYY-MM-DD, YYYY-MM nor -"
    fi
    # Some projects publish a tier rather than a date: perlpolicy names the two
    # most recent stable series and calls everything older end of life, with no
    # calendar attached to any of them. Such a row is legitimate but it can
    # never expire on its own, so it has to say which tier it was read from.
    if [[ -z "$bad" && "$f_st" == "supported" && "$f_end" == "-" ]]; then
        case "${f_note// }" in
            ""|"-") bad="a 'supported' row with no support_ends date must record in its note the support tier upstream published" ;;
        esac
    fi
    if [[ -z "$bad" ]]; then
        [[ "$f_url" == https://* ]] || bad="policy_url '${f_url}' is not an https URL"
    fi
    if [[ -z "$bad" ]]; then
        if ! valid_day "$f_ret"; then
            bad="retrieved '${f_ret}' is not a YYYY-MM-DD date"
        elif [[ "$f_ret" > "$TODAY" ]]; then
            # A row cannot have been read from upstream tomorrow.
            bad="retrieved '${f_ret}' is in the future"
        fi
    fi
    if [[ -z "$bad" && "$f_st" == "delegated" ]]; then
        case "${f_note// }" in
            ""|"-") bad="a delegated row must name the tool that establishes the status" ;;
        esac
    fi

    if [[ -n "$bad" ]]; then
        err "${POLICY}:${lineno}: ${bad}"
        malformed=$((malformed + 1))
        continue
    fi

    P_PKG+=("$f_pkg"); P_VAR+=("$f_var"); P_SER+=("$f_ser"); P_ST+=("$f_st")
    P_END+=("$f_end"); P_URL+=("$f_url"); P_RET+=("$f_ret"); P_NOTE+=("$f_note")
done < "$POLICY"

if [[ "$malformed" -gt 0 ]]; then
    die "${malformed} malformed row(s) in ${POLICY}.
A policy file that cannot be parsed is a tooling fault, not a support result:
nothing here has been checked, in either mode."
fi

[[ "${#P_PKG[@]}" -gt 0 ]] || die "${POLICY} contains no rows"

# ---------------------------------------------------------------------------
# the pins
# ---------------------------------------------------------------------------

[[ -f "$VERSIONS" ]] || die "no versions file at ${VERSIONS}"

pinned_version() {
    local var="$1" line val
    line="$(grep -m1 -E "^${var}=" "$VERSIONS" || true)"
    [[ -n "$line" ]] || return 0
    val="${line#*=}"
    val="${val%%#*}"
    val="$(printf '%s' "$val" | sed -e "s/[\"']//g" -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    printf '%s' "$val"
}

# 3.3.1 -> 3.3, 5.40.0 -> 5.40, 2.6.2 -> 2.6, 6.5 -> 6.5, 33 -> 33
series_of() {
    local v="$1"
    case "$v" in
        *.*.*) printf '%s' "${v%.*}" ;;
        *)     printf '%s' "$v" ;;
    esac
}

TOTAL_PINS="$(grep -cE '^V_[A-Z0-9_]+=' "$VERSIONS" || true)"
[[ "$TOTAL_PINS" =~ ^[0-9]+$ ]] || TOTAL_PINS=0

# ---------------------------------------------------------------------------
# evaluate, one package at a time, in the order the policy file lists them
# ---------------------------------------------------------------------------

log "Upstream support status of Kryptik's pinned series"
note "evaluated as of ${NOW} (${NOW_SRC}); policy data from ${POLICY}"
printf '\n' >> "$BUF"

n_ok=0; n_sec=0; n_eol=0; n_offmap=0; n_deleg=0; n_nopol=0; n_unpinned=0
n_stale=0
hard_fail=0     # false support: fails in both modes
soft_fail=0     # cannot be established: fails --strict only
declare -a EOL_LINES=()
seen=""

for i in "${!P_PKG[@]}"; do
    pkg="${P_PKG[$i]}"
    case " ${seen} " in *" ${pkg} "*) continue ;; esac
    seen="${seen} ${pkg}"

    var="${P_VAR[$i]}"
    pin="$(pinned_version "$var")"

    if [[ -z "$pin" || "$pin" == "unset" ]]; then
        row "-" "${pkg} is not pinned in $(basename "$VERSIONS") (${var}); nothing to check"
        n_unpinned=$((n_unpinned + 1))
        continue
    fi

    ser="$(series_of "$pin")"

    # Exact series row first, then a * row. A specific row must win, or adding
    # a catch-all to a package would silently mask every dated series it has.
    hit=""
    for j in "${!P_PKG[@]}"; do
        if [[ "${P_PKG[$j]}" == "$pkg" && "${P_SER[$j]}" == "$ser" ]]; then
            hit="$j"
            break
        fi
    done
    if [[ -z "$hit" ]]; then
        for j in "${!P_PKG[@]}"; do
            if [[ "${P_PKG[$j]}" == "$pkg" && "${P_SER[$j]}" == "*" ]]; then
                hit="$j"
                break
            fi
        done
    fi

    if [[ -z "$hit" ]]; then
        n_offmap=$((n_offmap + 1))
        soft_fail=$((soft_fail + 1))
        row FAIL "${pkg} ${pin}: series ${ser} is OFF THE POLICY MAP"
        note "            ${POLICY} has rows for ${pkg} but none for ${ser}, so"
        note "            whether it is still supported has not been established."
        note "            Read the series off ${P_URL[$i]} and add the row."
        continue
    fi

    st="${P_ST[$hit]}"; ends="${P_END[$hit]}"; url="${P_URL[$hit]}"
    ret="${P_RET[$hit]}"; nte="${P_NOTE[$hit]}"

    # The policy data itself can rot. A row read fourteen months ago may be
    # describing a schedule upstream has since changed.
    age="$(days_between "$ret" "$NOW")"
    if [[ "$age" -gt 180 ]]; then
        n_stale=$((n_stale + 1))
    fi

    case "$st" in
        delegated)
            tool=""
            case "$nte" in
                *tools/*) tool="${nte#*tools/}"; tool="tools/${tool%% *}" ;;
            esac
            if [[ -n "$tool" && ! -x "${KRYPTIK_ROOT}/${tool}" && ! -x "${TOOLS_DIR}/$(basename "$tool")" ]]; then
                n_deleg=$((n_deleg + 1))
                soft_fail=$((soft_fail + 1))
                row FAIL "${pkg} ${pin}: delegated to ${tool}, which is MISSING"
                note "            A delegation to a tool that is not there is a skipped"
                note "            check, and a skipped check is not a pass."
            else
                n_deleg=$((n_deleg + 1))
                row "NOT CHECKED" "${pkg} ${pin}: established by ${tool:-another tool}, not here"
                note "            run that check too; this one has said nothing about ${pkg}"
            fi
            ;;
        none-published)
            n_nopol=$((n_nopol + 1))
            row "-" "${pkg} ${pin}: upstream publishes no support window"
            note "            ${nte}"
            note "            This is NOT a statement that ${pin} is current."
            ;;
        supported|security-only)
            # A tier row carries no date; do not hand "-" to date(1), whose
            # failure the ERR trap would turn into an abort mid-report.
            eff="-"
            prec=""
            if [[ "$ends" != "-" ]]; then
                eff="$(last_supported_day "$ends")"
                [[ "$ends" == "$eff" ]] || prec=" (month precision: ${ends})"
            fi

            if [[ "$eff" != "-" ]] && date_after "$NOW" "$eff"; then
                n_eol=$((n_eol + 1))
                hard_fail=$((hard_fail + 1))
                row FAIL "${pkg} ${pin}: series ${ser} went END OF LIFE on ${eff}${prec}"
                note "            $(days_between "$eff" "$NOW") days ago. It will receive no further"
                note "            security fixes. Source: ${url} (read ${ret})"
                EOL_LINES+=("${pkg} ${pin} - series ${ser} unsupported since ${eff}")
            elif [[ "$st" == "security-only" ]]; then
                n_sec=$((n_sec + 1))
                row warn "${pkg} ${pin}: series ${ser} is SECURITY FIXES ONLY${prec}"
                note "            ${nte:--}"
                if [[ "$eff" == "-" ]]; then
                    note "            no end date published; this is the last tier before EOL"
                else
                    note "            ends ${eff}; plan the move before then"
                fi
            elif [[ "$eff" == "-" ]]; then
                # Tier-based support. Reported as ok because upstream does
                # support it, but a row that cannot expire has to say so.
                n_ok=$((n_ok + 1))
                row ok "${pkg} ${pin}: series ${ser} supported - ${nte}"
                note "            upstream publishes a tier and no end date, so this row"
                note "            cannot expire by itself; re-read ${url} when the pin moves"
            else
                n_ok=$((n_ok + 1))
                row ok "${pkg} ${pin}: series ${ser} supported until ${eff}${prec}"
            fi
            ;;
    esac
done

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

covered=0
seen=""
for i in "${!P_PKG[@]}"; do
    pkg="${P_PKG[$i]}"
    case " ${seen} " in *" ${pkg} "*) continue ;; esac
    seen="${seen} ${pkg}"
    covered=$((covered + 1))
done

printf '\n' >> "$BUF"
log "Summary"
note "  ${n_ok} supported, ${n_sec} security-fixes-only, ${n_eol} END OF LIFE,"
note "  ${n_offmap} off the policy map, ${n_deleg} established elsewhere,"
note "  ${n_nopol} with no published window, ${n_unpinned} not pinned."
note ""
note "  COVERAGE FLOOR: ${covered} of ${TOTAL_PINS} pins in $(basename "$VERSIONS") have a"
note "  retrieved upstream support policy. This check says NOTHING about the"
note "  other $((TOTAL_PINS - covered)). Read a green run as 'the series named above are"
note "  maintained', never as 'Kryptik ships nothing unsupported'."
note "  It also does not measure patch gaps inside a supported series:"
note "  that is tools/check-source-currency.sh."

if [[ "$n_stale" -gt 0 ]]; then
    warn "${n_stale} policy row(s) were read more than 180 days before ${NOW}"
    note "  re-read them from upstream; a support schedule can change"
fi

if [[ -n "$REPORT" ]]; then
    cp "$BUF" "$REPORT"
    dim "  report written to ${REPORT}"
fi

if [[ "$hard_fail" -gt 0 ]]; then
    printf '\n'
    err "pinned series no longer supported upstream: ${n_eol}"
    for l in "${EOL_LINES[@]}"; do err "  ${l}"; done
    die "An end-of-life series is a false claim of support, so this fails in
both modes. Propose the upgrade to the build tab; do not edit a pin under a
running build."
fi

if [[ "$soft_fail" -gt 0 ]]; then
    if [[ "$STRICT" -eq 1 ]]; then
        printf '\n'
        die "${soft_fail} pinned series whose support status could NOT be
established. Unknown support is not support, so --strict fails."
    fi
    printf '\n'
    warn "${soft_fail} pinned series whose support status could not be established."
    warn "--strict would fail here. Informational mode does not."
fi

ok "no pinned series is known to be out of support"
