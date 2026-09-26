#!/usr/bin/env bash
# Audit the hardening of the ELF objects a build actually produced.
#
#   tools/check-artifact-hardening.sh [ROOT] [--strict] [--json FILE]
#
# ROOT defaults to the sysroot for the current KRYPTIK_WORK. RWX, TEXTREL,
# EXEC-STACK and BUILD-RPATH (an rpath into the build tree) always fail. The
# rest fail only with --strict: a sysroot mid-build holds unfinished objects.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

# Checks fail routinely here; the ERR trap would abort on the first one.
trap - ERR
set +e

STRICT=0
JSON=""
ROOT=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --strict) STRICT=1; shift ;;
        --json)   JSON="${2:?--json needs a path}"; shift 2 ;;
        -*)       die "unknown option: $1" ;;
        *)        ROOT="$1"; shift ;;
    esac
done
ROOT="${ROOT:-$KRYPTIK_SYSROOT}"
ROOT="${ROOT%/}"
[[ -d "$ROOT" ]] || die "no such directory: ${ROOT}

Give a root to inspect, or build one first:
  make temp-tools && make system"

have readelf || die "readelf is required (binutils)"

# Not shipped: /tools is the stage 01 cross toolchain, built without hardening
# and deleted before release; /kryptik* are bind-mount points.
EXCLUDE_RE='^(tools|kryptik|kryptik-work|kryptik-sources|usr/src|usr/share/doc)(/|$)'

log "Artifact hardening audit"
dim "  root   : ${ROOT}"
dim "  mode   : $([[ "$STRICT" -eq 1 ]] && echo strict || echo report)"
echo

TOTAL=0; EXECS=0; LIBS=0
HARD=0
declare -A COUNT=()
declare -a HARD_LINES=()
declare -a SOFT_LINES=()

bump() { COUNT["$1"]=$(( ${COUNT["$1"]:-0} + 1 )); }

hard() { HARD=$((HARD + 1)); HARD_LINES+=("  $1  $2"); bump "$1"; }
soft() { SOFT_LINES+=("  $1  $2"); bump "$1"; }

is_elf() {
    local magic
    magic="$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n')"
    [[ "$magic" == "7f454c46" ]]
}

audit_one() {
    local f="$1" rel="${1#"$ROOT"/}"
    local out
    # One readelf run per file covers everything read below.
    out="$(readelf -W -h -l -d -n --dyn-syms "$f" 2>/dev/null)" || return 0
    [[ -n "$out" ]] || return 0

    local type kind
    type="$(sed -n 's/^ *Type: *\([A-Z]*\).*/\1/p' <<<"$out" | head -1)"
    case "$type" in
        EXEC|DYN) ;;
        *) return 0 ;;   # REL objects, cores: not shipped executables
    esac

    TOTAL=$((TOTAL + 1))
    if grep -q 'Requesting program interpreter' <<<"$out"; then
        kind=exe; EXECS=$((EXECS + 1))
    else
        kind=lib; LIBS=$((LIBS + 1))
    fi

    # Hard failures. First, a LOAD segment carrying all three permission bits.
    if awk '/^ +LOAD/ { if ($0 ~ /RWE/) exit 1 } END { exit 0 }' <<<"$out"; then :; else
        hard "RWX" "$rel"
    fi

    if grep -qE '^ +GNU_STACK.*RWE' <<<"$out"; then
        hard "EXEC-STACK" "$rel"
    fi

    if grep -q 'TEXTREL' <<<"$out"; then
        hard "TEXTREL" "$rel"
    fi

    # An rpath into the build tree loads whatever a target has at that path.
    local rpath
    rpath="$(sed -n 's/.*(R\(UN\)\?PATH).*\[\(.*\)\]/\2/p' <<<"$out")"
    if [[ -n "$rpath" ]]; then
        local leaked=0
        case "$rpath" in
            *"$KRYPTIK_WORK"*|*/build/work/*|*/kryptik-work/*|*/tmp/*) leaked=1 ;;
        esac
        # The sysroot's own path counts too, unless ROOT is "/" (in the chroot).
        if [[ "$leaked" -eq 0 && "$ROOT" != "" && "$ROOT" != "/" && "$rpath" == *"$ROOT"* ]]; then
            leaked=1
        fi
        if [[ "$leaked" -eq 1 ]]; then
            hard "BUILD-RPATH" "${rel}  [${rpath}]"
        else
            soft "RPATH" "${rel}  [${rpath}]"
        fi
    fi

    # Reported; fatal only with --strict.
    grep -qE '^ +GNU_RELRO' <<<"$out" || soft "NO-RELRO" "$rel"

    if ! grep -qE 'BIND_NOW|FLAGS_1.*NOW' <<<"$out"; then
        soft "NO-BIND-NOW" "$rel"
    fi

    # GCC is --enable-default-pie: a non-PIE executable overrode it at link time.
    if [[ "$kind" == exe && "$type" == EXEC ]]; then
        soft "NO-PIE" "$rel"
    fi

    grep -qE 'IBT|SHSTK' <<<"$out" || soft "NO-CET" "$rel"

    # Counted, never failed: code with no arrays needs no __stack_chk_fail.
    if grep -q '__stack_chk_fail' <<<"$out"; then
        bump "HAS-SSP"
    fi
    if grep -qE '__[a-z_]+_chk@|__[a-z_]+_chk$' <<<"$out"; then
        bump "HAS-FORTIFY"
    fi
}

log "scanning"
while IFS= read -r -d '' f; do
    rel="${f#"$ROOT"/}"
    [[ "$rel" =~ $EXCLUDE_RE ]] && continue
    is_elf "$f" || continue
    audit_one "$f"
done < <(find "$ROOT" -xdev -type f -print0 2>/dev/null)

echo
if [[ "$TOTAL" -eq 0 ]]; then
    warn "no ELF objects found under ${ROOT}"
    warn "Either the build has not produced anything yet, or ROOT is wrong."
    exit 1
fi

log "Population"
printf '  %-14s %d\n' "objects"     "$TOTAL"
printf '  %-14s %d\n' "executables" "$EXECS"
printf '  %-14s %d\n' "libraries"   "$LIBS"
printf '  %-14s %d\n' "with SSP"    "${COUNT[HAS-SSP]:-0}"
printf '  %-14s %d\n' "with FORTIFY" "${COUNT[HAS-FORTIFY]:-0}"

echo
log "Findings"
for k in RWX EXEC-STACK TEXTREL BUILD-RPATH NO-RELRO NO-BIND-NOW NO-PIE NO-CET RPATH; do
    n="${COUNT[$k]:-0}"
    [[ "$n" -eq 0 ]] && continue
    printf '  %-13s %5d\n' "$k" "$n"
done
[[ "${#HARD_LINES[@]}" -eq 0 && "${#SOFT_LINES[@]}" -eq 0 ]] && ok "nothing to report"

if [[ "${#HARD_LINES[@]}" -gt 0 ]]; then
    echo
    err "objects with no legitimate explanation:"
    printf '%s\n' "${HARD_LINES[@]}" | sort | head -50 >&2
    [[ "${#HARD_LINES[@]}" -gt 50 ]] && echo "  ... and $(( ${#HARD_LINES[@]} - 50 )) more" >&2
fi

if [[ "$STRICT" -eq 1 && "${#SOFT_LINES[@]}" -gt 0 ]]; then
    echo
    warn "reported findings (--strict promotes these to failures):"
    printf '%s\n' "${SOFT_LINES[@]}" | sort | head -50 >&2
    [[ "${#SOFT_LINES[@]}" -gt 50 ]] && echo "  ... and $(( ${#SOFT_LINES[@]} - 50 )) more" >&2
fi

if [[ -n "$JSON" ]]; then
    {
        printf '{\n  "root": "%s",\n  "objects": %d,\n  "executables": %d,\n  "libraries": %d,\n' \
               "$ROOT" "$TOTAL" "$EXECS" "$LIBS"
        printf '  "findings": {\n'
        sep=""
        for k in "${!COUNT[@]}"; do
            # A real newline: through %s, "\n" would print as two characters.
            printf '%s    "%s": %d' "$sep" "$k" "${COUNT[$k]}"
            sep=$',\n'
        done
        printf '\n  },\n'
        # The objects behind the counts, one string each as text mode prints them.
        json_list() {   # json_list NAME LINE...
            local name="$1"; shift
            local first=1 l
            printf '  "%s": [' "$name"
            for l in "$@"; do
                [[ "$first" -eq 1 ]] || printf ','
                first=0
                printf '\n    "%s"' "$(printf '%s' "$l" | sed 's/\\/\\\\/g; s/"/\\"/g')"
            done
            [[ "$first" -eq 1 ]] || printf '\n  '
            printf ']'
        }
        json_list hard "${HARD_LINES[@]}"; printf ',\n'
        json_list reported "${SOFT_LINES[@]}"; printf '\n}\n'
    } > "$JSON"
    dim "wrote ${JSON}"
fi

echo
if [[ "$HARD" -gt 0 ]]; then
    die "${HARD} object(s) failed a check that has no legitimate explanation.

Do not fix these by removing flags from build/config/hardening.env. Find the
package, read its link line in ${KRYPTIK_WORK}/logs, and either correct how it
takes LDFLAGS or add a justified per-package exception."
fi
if [[ "$STRICT" -eq 1 && "${#SOFT_LINES[@]}" -gt 0 ]]; then
    die "${#SOFT_LINES[@]} reported finding(s), and --strict was requested."
fi
ok "no object failed a hard check"
[[ "${#SOFT_LINES[@]}" -gt 0 ]] && dim "${#SOFT_LINES[@]} reported finding(s); re-run with --strict to fail on them"
exit 0
