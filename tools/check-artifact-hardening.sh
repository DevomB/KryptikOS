#!/usr/bin/env bash
# Inspect the binaries a build PRODUCED, rather than the flags it was asked to
# use.
#
#   tools/check-artifact-hardening.sh [ROOT] [--strict] [--json FILE]
#
# ROOT defaults to the sysroot for the current KRYPTIK_WORK.
#
# WHY THIS IS NOT tools/test-hardening-flags.sh
#
# That script proves the flag set can build a hardened executable and a
# hardened shared library. It compiles two toy files. It cannot tell you
# whether the fifty-eight packages in stage 04 actually got those flags -
# and the ways they silently do not are numerous and boring:
#
#   * a configure script that overwrites CFLAGS instead of appending
#   * a Makefile that hardcodes its own -O2 and drops the environment
#   * a package built before load_hardening ran
#   * a hardening exception that was meant for one package and matched three
#   * libtool relinking at install time without the LDFLAGS it linked with
#
# None of those fail the build. All of them are visible in the ELF.
#
# So this reads the objects: their program headers, dynamic section, notes and
# dynamic symbols. What comes out is what actually shipped.
#
# HARD FAILURES (exit 1 in every mode) are the ones with no legitimate
# explanation in a distribution:
#
#   RWX          a segment that is writable and executable at once
#   TEXTREL      relocations against the text segment; implies writable text
#   EXEC-STACK   an executable stack
#   BUILD-RPATH  an RPATH or RUNPATH naming the build tree, which makes the
#                binary load libraries from a directory that will not exist on
#                the target - or, worse, will
#
# Everything else is counted and reported, and --strict promotes it. A sysroot
# mid-build legitimately contains objects that are not finished being replaced,
# and a check that cries wolf on those gets switched off.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

# This script reports its own findings; the ERR trap would abort on the first
# non-zero readelf.
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

# Directories that are not part of the shipped system.
#
#   /tools          the stage 01 cross toolchain. It is deleted before release
#                   and is built deliberately WITHOUT hardening - see the
#                   comment at the top of build/stages/01-toolchain.sh. Auditing
#                   it would report ~200 expected failures and teach everyone to
#                   ignore this script's output.
#   /kryptik*       bind-mount points for the repository, sources and work tree.
#                   Empty outside the chroot; not ours even when they are not.
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
    # One readelf pass for everything: header, program headers, dynamic
    # section, notes, dynamic symbols. Thousands of files times five processes
    # each is the difference between a check people run and one they do not.
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

    # --- hard failures --------------------------------------------------
    # A LOAD segment carrying all three permission bits.
    if awk '/^ +LOAD/ { if ($0 ~ /RWE/) exit 1 } END { exit 0 }' <<<"$out"; then :; else
        hard "RWX" "$rel"
    fi

    if grep -qE '^ +GNU_STACK.*RWE' <<<"$out"; then
        hard "EXEC-STACK" "$rel"
    fi

    if grep -q 'TEXTREL' <<<"$out"; then
        hard "TEXTREL" "$rel"
    fi

    # An RPATH/RUNPATH that names the build tree. This is how a binary ends up
    # resolving libraries from a directory that exists only on the machine that
    # built it - and the failure is not a missing library, it is the WRONG one
    # loading silently on a host where that path happens to exist.
    local rpath
    rpath="$(sed -n 's/.*(R\(UN\)\?PATH).*\[\(.*\)\]/\2/p' <<<"$out")"
    if [[ -n "$rpath" ]]; then
        local leaked=0
        case "$rpath" in
            *"$KRYPTIK_WORK"*|*/build/work/*|*/kryptik-work/*|*/tmp/*) leaked=1 ;;
        esac
        # The sysroot's own absolute path must not appear either - but only
        # when ROOT is a directory. Inside the chroot ROOT is "/", and matching
        # that would flag every ordinary rpath in the system.
        if [[ "$leaked" -eq 0 && "$ROOT" != "" && "$ROOT" != "/" && "$rpath" == *"$ROOT"* ]]; then
            leaked=1
        fi
        if [[ "$leaked" -eq 1 ]]; then
            hard "BUILD-RPATH" "${rel}  [${rpath}]"
        else
            soft "RPATH" "${rel}  [${rpath}]"
        fi
    fi

    # --- reported ------------------------------------------------------
    grep -qE '^ +GNU_RELRO' <<<"$out" || soft "NO-RELRO" "$rel"

    if ! grep -qE 'BIND_NOW|FLAGS_1.*NOW' <<<"$out"; then
        soft "NO-BIND-NOW" "$rel"
    fi

    # Executables should be PIE. Kryptik's GCC is --enable-default-pie, so a
    # non-PIE executable means that package's link line overrode it.
    if [[ "$kind" == exe && "$type" == EXEC ]]; then
        soft "NO-PIE" "$rel"
    fi

    grep -qE 'IBT|SHSTK' <<<"$out" || soft "NO-CET" "$rel"

    # Anything that references __stack_chk_fail proves the stack protector is
    # on. Its ABSENCE proves nothing - a function with no arrays needs no
    # canary - so this is counted, never failed, and read as a population
    # statistic across the tree.
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
            # A real newline in the separator: through %s, "\n" would be two
            # literal characters, and the file would not parse.
            printf '%s    "%s": %d' "$sep" "$k" "${COUNT[$k]}"
            sep=$',\n'
        done
        printf '\n  },\n'
        # The objects behind the counts, so a report can be read without
        # re-running the scan. One string per finding, as the text mode
        # prints it.
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
