#!/usr/bin/env bash
# Fail unless every pin behind its upstream has a current review in tools/pin-reviews.tsv.
# A review lapses when the pin moves or upstream releases past it; --no-held refuses held pins.
#
#   tools/check-source-currency.sh --tsv > survey.tsv
#   tools/check-pin-reviews.sh --survey survey.tsv [--reviews FILE] [--no-held]
set -uo pipefail

SURVEY=""; REVIEWS="$(dirname "${BASH_SOURCE[0]}")/pin-reviews.tsv"; NO_HELD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --survey)  SURVEY="${2:-}"; shift 2 ;;
        --reviews) REVIEWS="${2:-}"; shift 2 ;;
        --no-held) NO_HELD=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -s "$SURVEY" && -f "$REVIEWS" ]] || { echo "FAIL: need a non-empty --survey and a reviews file" >&2; exit 1; }

# A short commit ID and its full form are the same commit.
same() {
    [[ "$1" == "$2" ]] && return 0
    [[ "$1" =~ ^[0-9a-f]{12,40}$ && "$2" =~ ^[0-9a-f]{12,40}$ && ( "$1" == "$2"* || "$2" == "$1"* ) ]]
}
# Commit IDs have no order, so any commit other than the one reviewed is new.
newer() {
    ! same "$1" "$2" || return 1
    [[ "$1" =~ ^[0-9a-f]{12,40}$ && "$2" =~ ^[0-9a-f]{12,40}$ ]] && return 0
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}
bad=0
fail() { echo "  $*"; bad=$((bad + 1)); }

declare -A PIN UPTO VERDICT NOTE SEEN
while read -r pkg pinned upto verdict _date note; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue
    if [[ "$verdict" =~ ^(fine|held)$ && -n "$note" && -z "${PIN[$pkg]:-}" ]]; then
        PIN[$pkg]="$pinned"; UPTO[$pkg]="$upto"; VERDICT[$pkg]="$verdict"; NOTE[$pkg]="$note"
    else
        fail "MALFORMED: ${pkg}: one row per package, verdict fine or held, and a note"
    fi
done < "$REVIEWS"

# read merges a run of tabs, so an empty "newest" would shift the fields; \037 is not whitespace.
while IFS=$'\037' read -r name pinned newest status _; do
    [[ -n "$name" ]] || continue
    SEEN[$name]=1
    row="${PIN[$name]:-}"
    if [[ "$status" == UNKNOWN ]]; then
        # An upstream that did not answer says nothing about the review: it stays.
        echo "  not determined, which is not the same as fine: ${name} ${pinned}"
    elif [[ "$status" != BEHIND ]]; then
        [[ -n "$row" ]] && fail "STALE: ${name} is ${status} now; remove its row"
    elif [[ -z "$row" ]]; then            fail "NOT REVIEWED: ${name} ${pinned} -> ${newest}"
    elif ! same "$row" "$pinned"; then    fail "STALE: ${name}: the row reviews ${row}, the pin is ${pinned}"
    elif newer "$newest" "${UPTO[$name]}"; then fail "NEW RELEASE: ${name}: reviewed up to ${UPTO[$name]}, upstream is at ${newest}"
    elif [[ "${VERDICT[$name]}" == held ]]; then
        echo "  HELD: ${name} ${pinned}: ${NOTE[$name]}"
        [[ "$NO_HELD" -eq 1 ]] && bad=$((bad + 1))
    fi
done < <(tr '\t' '\037' < "$SURVEY")
for pkg in "${!PIN[@]}"; do [[ -n "${SEEN[$pkg]:-}" ]] || fail "STALE: ${pkg} is not a source"; done

[[ "$bad" -eq 0 ]] || { echo "FAIL: ${bad} pin(s) without a current review"; exit 1; }
echo "ok: every pin that is behind upstream has a current review"
