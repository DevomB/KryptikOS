#!/usr/bin/env bash
# Hold every pin that is behind its upstream to a written review.
#
#   ./tools/check-source-currency.sh --tsv > survey.tsv
#   ./tools/check-pin-reviews.sh --survey survey.tsv [--reviews FILE]
#                                [--max-age DAYS] [--strict] [--no-held]
#                                [--today YYYY-MM-DD]
#
#   --survey FILE    check-source-currency.sh's --tsv output
#   --reviews FILE   default tools/pin-reviews.tsv
#   --max-age DAYS   a review older than this has expired; default 180
#   --strict         a pin the survey could not determine is a failure
#   --no-held        a held pin is a failure; this is what a release asks
#   --today DATE     the date reviews are aged against; default today (tests)
#
# "A newer version exists" is not a security verdict, which is why
# check-source-currency.sh reports and does not judge. This is where the
# judging is written down. A pin that is behind is one of three things: moved,
# reviewed as fine (someone read what upstream released after it and nothing
# there is a security fix that reaches Kryptik), or held (there is such a fix,
# and the row says why the pin stays anyway). A row with no reason is a
# failure. What makes this a gate and not a list is the other direction: a
# review covers upstream releases up to a named version, so the next upstream
# release makes the row fail until someone has read that one too.
#
# It reads a survey and never the network, so it is deterministic: the same two
# files give the same answer, in a test or a year later.
#
# Exit status: 0 when every behind pin has a current review; 1 otherwise.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

SURVEY=""; REVIEWS="${KRYPTIK_ROOT}/tools/pin-reviews.tsv"
MAX_AGE=180; STRICT=0; NO_HELD=0; TODAY="$(date -u +%Y-%m-%d)"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --survey)  SURVEY="${2:?--survey needs a file}"; shift 2 ;;
        --reviews) REVIEWS="${2:?--reviews needs a file}"; shift 2 ;;
        --max-age) MAX_AGE="${2:?--max-age needs a number of days}"; shift 2 ;;
        --today)   TODAY="${2:?--today needs a date}"; shift 2 ;;
        --strict)  STRICT=1; shift ;;
        --no-held) NO_HELD=1; shift ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | cut -c3-; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$SURVEY" ]] || die "--survey FILE is required (check-source-currency.sh --tsv)"
[[ -s "$SURVEY" ]] || die "the survey ${SURVEY} is missing or empty: a gate with nothing to read has not passed"
[[ -f "$REVIEWS" ]] || die "no reviews file at ${REVIEWS}"
[[ "$MAX_AGE" =~ ^[0-9]+$ ]] || die "--max-age wants a whole number of days, got ${MAX_AGE}"
is_date() { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && date -u -d "$1" +%s >/dev/null 2>&1; }
is_date "$TODAY" || die "--today wants YYYY-MM-DD, got ${TODAY}"
today_s="$(date -u -d "$TODAY" +%s)"

# newer A B: A sorts strictly after B, by the same ordering the survey uses.
newer() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]; }

# --- the reviews ------------------------------------------------------------
declare -A R_PINNED=() R_UPTO=() R_VERDICT=() R_DATE=() R_NOTE=() R_SEEN=()
declare -a MALFORMED=()
CR=$'\r'
lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    line="${line%"$CR"}"
    [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
    read -r pkg pinned upto verdict reviewed note <<<"$line"
    where="${REVIEWS##*/}:${lineno}"
    if [[ -z "$pkg" || -z "$pinned" || -z "$upto" || -z "$verdict" || -z "$reviewed" ]]; then
        MALFORMED+=("${where}: wants package, pinned, reviewed_up_to, verdict, reviewed, note"); continue
    fi
    [[ "$verdict" == fine || "$verdict" == held ]] || { MALFORMED+=("${where}: ${pkg}: verdict '${verdict}' is neither fine nor held"); continue; }
    is_date "$reviewed" || { MALFORMED+=("${where}: ${pkg}: reviewed '${reviewed}' is not a date"); continue; }
    [[ -n "${note//[[:space:]]/}" ]] || { MALFORMED+=("${where}: ${pkg}: no note. What was read, and why is the pin ${verdict}?"); continue; }
    [[ -z "${R_PINNED[$pkg]:-}" ]] || { MALFORMED+=("${where}: ${pkg}: a second row for the same package"); continue; }
    R_PINNED[$pkg]="$pinned"; R_UPTO[$pkg]="$upto"; R_VERDICT[$pkg]="$verdict"
    R_DATE[$pkg]="$reviewed"; R_NOTE[$pkg]="$note"
done < "$REVIEWS"

# --- the survey against them ------------------------------------------------
declare -a NOT_REVIEWED=() STALE=() NEW_RELEASE=() EXPIRED=() HELD=() FINE=() UNDETERMINED=()
rows=0
# A tab is whitespace to read, and read merges a run of whitespace into one
# separator: a row with an empty 'newest' column would lose the column and
# every field after it would move left, so an UNKNOWN row would read as a
# status nobody tests for and pass in silence. The unit separator is not
# whitespace, so an empty field stays an empty field.
US=$'\037'
while IFS="$US" read -r name pinned newest status consulted; do
    [[ -n "$name" ]] || continue
    rows=$((rows + 1))
    R_SEEN[$name]=1
    if [[ "$status" == UNKNOWN ]]; then
        UNDETERMINED+=("${name} ${pinned} (consulted ${consulted:-nothing})")
    fi
    if [[ "$status" != BEHIND ]]; then
        [[ -z "${R_PINNED[$name]:-}" ]] || STALE+=("${name}: reviewed as behind, but the survey says ${status}; remove the row")
        continue
    fi
    if [[ -z "${R_PINNED[$name]:-}" ]]; then
        NOT_REVIEWED+=("${name} ${pinned} -> ${newest}"); continue
    fi
    if [[ "${R_PINNED[$name]}" != "$pinned" ]]; then
        STALE+=("${name}: the review is of ${R_PINNED[$name]}, the pin is ${pinned}"); continue
    fi
    if newer "$newest" "${R_UPTO[$name]}"; then
        NEW_RELEASE+=("${name} ${pinned}: reviewed up to ${R_UPTO[$name]}, upstream is at ${newest}"); continue
    fi
    age=$(( (today_s - $(date -u -d "${R_DATE[$name]}" +%s)) / 86400 ))
    if [[ "$age" -gt "$MAX_AGE" ]]; then
        EXPIRED+=("${name} ${pinned}: reviewed ${R_DATE[$name]}, ${age} days ago (limit ${MAX_AGE})"); continue
    fi
    if [[ "${R_VERDICT[$name]}" == held ]]; then
        HELD+=("${name} ${pinned} (upstream ${newest}): ${R_NOTE[$name]}")
    else
        FINE+=("${name} ${pinned} (upstream ${newest})")
    fi
done < <(tr '\t' '\037' < "$SURVEY")
[[ "$rows" -gt 0 ]] || die "the survey ${SURVEY} has no rows"
for pkg in "${!R_PINNED[@]}"; do
    [[ -n "${R_SEEN[$pkg]:-}" ]] || STALE+=("${pkg}: reviewed, but the survey has no such source")
done

# --- the report -------------------------------------------------------------
section() {  # section TITLE ITEM...
    local title="$1"; shift
    [[ $# -gt 0 ]] || return 0
    echo; echo "${title}"
    printf '%s\n' "$@" | sort | sed 's/^/  - /'
}
log "Pins behind upstream, held to ${REVIEWS##*/} (survey: ${rows} sources, reviews aged against ${TODAY})"
section "MALFORMED rows:" "${MALFORMED[@]}"
section "BEHIND AND NOT REVIEWED (move the pin, or read what upstream released and write the row):" "${NOT_REVIEWED[@]}"
section "NEW UPSTREAM RELEASE SINCE THE REVIEW (read it, then move reviewed_up_to):" "${NEW_RELEASE[@]}"
section "EXPIRED reviews (a vulnerability can be published long after its fix; read again):" "${EXPIRED[@]}"
section "STALE rows:" "${STALE[@]}"
section "HELD: known security fixes upstream, pin kept for the reason given:" "${HELD[@]}"
section "NOT DETERMINED by the survey (not checked, which is not the same as fine):" "${UNDETERMINED[@]}"
section "reviewed as fine:" "${FINE[@]}"
echo
echo "COUNTS not-reviewed=${#NOT_REVIEWED[@]} new-release=${#NEW_RELEASE[@]} expired=${#EXPIRED[@]} stale=${#STALE[@]} malformed=${#MALFORMED[@]} held=${#HELD[@]} undetermined=${#UNDETERMINED[@]} fine=${#FINE[@]}"

bad=$(( ${#NOT_REVIEWED[@]} + ${#NEW_RELEASE[@]} + ${#EXPIRED[@]} + ${#STALE[@]} + ${#MALFORMED[@]} ))
[[ "$NO_HELD" -eq 1 ]] && bad=$(( bad + ${#HELD[@]} ))
[[ "$STRICT" -eq 1 ]] && bad=$(( bad + ${#UNDETERMINED[@]} ))
if [[ "$bad" -gt 0 ]]; then
    err "${bad} pin(s) are not covered by a current review"
    exit 1
fi
ok "every pin that is behind upstream has a current review"
