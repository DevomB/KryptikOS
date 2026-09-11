#!/usr/bin/env bash
# Release gates over a built tree and the sources it came from.
#
#   ./tools/release-check.sh --root DIR            report
#   ./tools/release-check.sh --root DIR --strict   release gate
#   ./tools/release-check.sh --root DIR --inventory FILE
#   ./tools/release-check.sh --root DIR --only setuid,perms
#   ./tools/release-check.sh --list                name the checks
#
# WHAT THIS IS FOR.
#
# The verification tools answer "are these the right sources". This answers
# "is the thing we built fit to hand to someone", which is a different
# question with different failure modes: a setuid binary nobody justified, a
# world-writable file, a capability nobody asked for, a library without the
# hardening the build claims, a source in the release nobody can obtain, or a
# licence nobody has established.
#
# THE RULE, THE SAME AS EVERYWHERE ELSE HERE.
#
# Each check reports PASS, FAIL, or UNAVAIL - it could not be run. UNAVAIL is
# never a pass: under --strict it ends the run, because a release gate that
# succeeds because it could not look is not a gate. Checks compose existing
# tools rather than reimplementing them, so there is one implementation of
# each question.
#
# It does not fix anything. Whether `su` keeps its setuid bit is a hardening
# decision, and a tool that silently chmods a release tree would be making
# that decision on someone's behalf.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

# --list answers a question about this tool, not about a tree, so it must work
# without a configured checkout - load_config reads
# build/config/versions.env and dies without one.
for _a in "$@"; do
    if [[ "$_a" == "--list" ]]; then
        printf '%s
' setuid caps perms hardening source-availability                        provenance licences
        exit 0
    fi
done

load_config

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ROOT_DIR=""
INVENTORY=""
STRICT=0
ONLY=""
LIST=0
for a in "$@"; do
    case "$a" in
        --root=*)      ROOT_DIR="${a#--root=}" ;;
        --inventory=*) INVENTORY="${a#--inventory=}" ;;
        --only=*)      ONLY="${a#--only=}" ;;
        --strict)      STRICT=1 ;;
        --list)        LIST=1 ;;
        -h|--help)     sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done

CHECKS="setuid caps perms hardening source-availability provenance licences"

if [[ "$LIST" -eq 1 ]]; then
    printf '%s\n' $CHECKS
    exit 0
fi

[[ -n "$ROOT_DIR" ]] || die "--root=DIR is required (the built tree to check)"

wanted() {
    [[ -z "$ONLY" ]] && return 0
    printf '%s' ",${ONLY}," | grep -q ",$1,"
}

PASS_N=0; FAIL_N=0; UNAVAIL_N=0
declare -a FAIL_LIST=() UNAVAIL_LIST=()
pass()    { ok   "[$1] $2"; PASS_N=$((PASS_N+1)); }
fail()    { err  "[$1] $2"; FAIL_N=$((FAIL_N+1)); FAIL_LIST+=("[$1] $2"); }
unavail() { warn "[$1] NOT CHECKED: $2"; UNAVAIL_N=$((UNAVAIL_N+1)); UNAVAIL_LIST+=("[$1] $2"); }

if [[ ! -d "$ROOT_DIR" ]]; then
    err "no tree at ${ROOT_DIR}"
    die "release-check: there is nothing to check. That is not a pass."
fi

# A TREE BEING WRITTEN CANNOT BE CHECKED.
#
# Learned the hard way: the setuid check reported "no unjustified setuid/setgid
# binaries" against a sysroot the build tab was mid-rebuild on, because
# /usr/bin had not been installed yet at that instant. A minute later the same
# check found sixteen. A gate that answers differently depending on when you
# run it is worse than no gate, so the tree is fingerprinted before and after
# and a change invalidates the whole run.
tree_fingerprint() {
    # Count and newest mtime. Cheap, and enough to notice an install landing.
    local n newest
    n="$(find "$ROOT_DIR" -type f 2>/dev/null | wc -l || true)"
    newest="$(find "$ROOT_DIR" -type f -newermt '@0' -printf '%T@ ' 2>/dev/null \
              | tr ' ' '\n' | sort -n | tail -1 || true)"
    printf '%s:%s' "${n:-?}" "${newest:-?}"
}
FP_BEFORE="$(tree_fingerprint)"

log "Release checks over ${ROOT_DIR}"
[[ "$STRICT" -eq 1 ]] && dim "  strict: anything not checked ends the run"
echo

# ---------------------------------------------------------------------------
# setuid / setgid  -- delegated, not reimplemented
# ---------------------------------------------------------------------------

if wanted setuid; then
    if [[ ! -x "${TOOLS_DIR}/audit-setuid.sh" ]]; then
        unavail setuid "tools/audit-setuid.sh is not present"
    else
        out="${KRYPTIK_WORK}/release-setuid.log"
        mkdir -p "$(dirname "$out")"
        if "${TOOLS_DIR}/audit-setuid.sh" "$ROOT_DIR" > "$out" 2>&1; then
            pass setuid "no unjustified setuid/setgid binaries"
        else
            # Read the audit's own count rather than counting matches: its
            # summary line contains the phrase too, so grep -c reported 17
            # for 16 binaries.
            n="$(grep -oE '[0-9]+ unjustified setuid/setgid binary' "$out"                  | grep -oE '^[0-9]+' | head -1 || true)"
            fail setuid "${n:-some} unjustified setuid/setgid binary(ies); see ${out}"
            grep 'unjustified setuid/setgid binary:' "$out" | head -6                 | sed 's/^/       /' >&2 || true
            [[ "${n:-0}" -gt 6 ]] && dim "       ... and $((n - 6)) more"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# file capabilities
# ---------------------------------------------------------------------------
#
# A capability is a setuid bit that does not look like one. The allowlist is
# shared with setuid deliberately: the question "who justified this privilege"
# is the same question, and two lists drift.

if wanted caps; then
    if ! have getcap; then
        unavail caps "getcap is not installed (libcap); capabilities unchecked"
    else
        capfile="${KRYPTIK_WORK}/release-caps.log"
        mkdir -p "$(dirname "$capfile")"
        getcap -r "$ROOT_DIR" 2>/dev/null > "$capfile" || true
        allow="${KRYPTIK_ROOT}/build/config/setuid-allowlist.txt"
        n=0
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            binp="${line%% *}"
            rel="/${binp#"$ROOT_DIR"/}"
            if [[ -f "$allow" ]] && grep -vE '^\s*(#|$)' "$allow" \
                 | awk '{print $1}' | grep -qxF "$rel"; then
                continue
            fi
            err "       unjustified capability: ${line}"
            n=$((n + 1))
        done < "$capfile"
        if [[ "$n" -eq 0 ]]; then
            pass caps "no file capabilities outside the allowlist"
        else
            fail caps "${n} file capability(ies) with no allowlist entry"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# permissions
# ---------------------------------------------------------------------------

if wanted perms; then
    # find exits non-zero on directories it cannot read, which a chroot-built
    # tree always has. That is a gap in coverage, not a clean result, so it is
    # reported rather than swallowed.
    readable=yes
    find "$ROOT_DIR" -type d >/dev/null 2>&1 || readable=partial

    ww_files="$(find "$ROOT_DIR" -type f -perm -0002 2>/dev/null | wc -l || true)"
    ww_dirs="$(find "$ROOT_DIR" -type d -perm -0002 ! -perm -1000 2>/dev/null | wc -l || true)"

    if [[ "${ww_files:-0}" -eq 0 && "${ww_dirs:-0}" -eq 0 ]]; then
        if [[ "$readable" == partial ]]; then
            unavail perms "no world-writable paths found, but part of the tree
       could not be read; this is a floor, not a clean bill of health"
        else
            pass perms "no world-writable files, and no world-writable
       directories without the sticky bit"
        fi
    else
        fail perms "${ww_files} world-writable file(s) and ${ww_dirs} world-writable
       directory(ies) without the sticky bit"
        find "$ROOT_DIR" -type f -perm -0002 2>/dev/null | head -5 \
            | sed "s#^${ROOT_DIR}#       #" >&2 || true
    fi
fi

# ---------------------------------------------------------------------------
# ELF hardening on what was actually produced
# ---------------------------------------------------------------------------
#
# build/config/hardening.env states what the flags are meant to be; this looks
# at the binaries to see whether they carry it. Three properties readelf can
# answer without running anything:
#
#   RELRO      a PT_GNU_RELRO segment, and BIND_NOW for full relro
#   NX         a non-executable stack (PT_GNU_STACK without E)
#   PIE        ET_DYN rather than ET_EXEC for executables
#
# A stack canary needs a symbol lookup (__stack_chk_fail), which is absent
# from a fully static strip in ways that are not a defect, so it is reported
# and not failed on.

if wanted hardening; then
    if ! have readelf; then
        unavail hardening "readelf is not installed (binutils); ELF hardening unchecked"
    else
        mapfile -t bins < <(find "$ROOT_DIR" -type f \
            \( -path '*/bin/*' -o -path '*/sbin/*' -o -name '*.so' -o -name '*.so.*' \) \
            2>/dev/null | head -400 || true)
        if [[ "${#bins[@]}" -eq 0 ]]; then
            unavail hardening "no binaries found under bin/, sbin/ or *.so"
        else
            checked=0; no_relro=0; exec_stack=0; not_pie=0
            declare -a bad=()
            for b in "${bins[@]}"; do
                head -c 4 "$b" 2>/dev/null | grep -q $'\x7fELF' || continue
                hdr="$(readelf -lhW "$b" 2>/dev/null)" || continue
                checked=$((checked + 1))
                printf '%s' "$hdr" | grep -q 'GNU_RELRO' \
                    || { no_relro=$((no_relro + 1)); bad+=("no-relro ${b#"$ROOT_DIR"}"); }
                # A GNU_STACK segment with E is an executable stack.
                if printf '%s' "$hdr" | grep -E 'GNU_STACK' | grep -q 'RWE'; then
                    exec_stack=$((exec_stack + 1)); bad+=("exec-stack ${b#"$ROOT_DIR"}")
                fi
                case "$b" in
                    *.so|*.so.*) ;;
                    *) printf '%s' "$hdr" | grep -qE 'Type:[[:space:]]+DYN' \
                           || { not_pie=$((not_pie + 1)); bad+=("not-pie ${b#"$ROOT_DIR"}"); } ;;
                esac
            done
            if [[ "$checked" -eq 0 ]]; then
                unavail hardening "found candidate files but none were ELF"
            elif [[ "$exec_stack" -gt 0 ]]; then
                fail hardening "${exec_stack} of ${checked} binaries have an
       EXECUTABLE STACK; ${no_relro} lack RELRO; ${not_pie} executables are not PIE"
                printf '       %s\n' "${bad[@]:0:6}" >&2
            else
                pass hardening "${checked} ELF objects: no executable stacks
       (${no_relro} without RELRO, ${not_pie} non-PIE executables - reported,
       not failed; see build/config/hardening.env for the intent)"
                [[ "${#bad[@]}" -gt 0 ]] && printf '       %s\n' "${bad[@]:0:6}" >&2
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# every source in the release can still be obtained
# ---------------------------------------------------------------------------
#
# A release whose sources cannot be fetched is not reproducible and, for the
# copyleft components the licence scan finds, not distributable either. This
# checks the bytes are present and match the lock - not that the URL still
# resolves, which is tools/check-source-currency.sh's business.

if wanted source-availability; then
    if [[ ! -f "$KRYPTIK_LOCK" ]]; then
        unavail source-availability "no sources.lock at ${KRYPTIK_LOCK}"
    else
        missing=0; mismatch=0; total=0
        while read -r want file; do
            [[ -n "$file" ]] || continue
            total=$((total + 1))
            p="${KRYPTIK_SOURCES}/${file}"
            if [[ ! -f "$p" ]]; then
                missing=$((missing + 1)); continue
            fi
            [[ "$(sha256_of "$p")" == "$want" ]] || mismatch=$((mismatch + 1))
        done < "$KRYPTIK_LOCK"
        if [[ "$mismatch" -gt 0 ]]; then
            fail source-availability "${mismatch} of ${total} locked sources do not
       match their recorded hash"
        elif [[ "$missing" -gt 0 ]]; then
            fail source-availability "${missing} of ${total} locked sources are not
       present in ${KRYPTIK_SOURCES}; this release cannot be rebuilt from them"
        else
            pass source-availability "${total} locked sources present and matching"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# provenance and licences, from the inventory
# ---------------------------------------------------------------------------
#
# Read from the inventory document rather than recomputed. If none is supplied,
# that is UNAVAIL: guessing would be worse than saying nobody looked.

inv_query() {  # inv_query <python expression over `d`>
    python3 - "$INVENTORY" "$1" <<'PY' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1]))
print(eval(sys.argv[2]))
PY
}

if wanted provenance || wanted licences; then
    if [[ -z "$INVENTORY" ]]; then
        wanted provenance && unavail provenance \
            "no --inventory=FILE supplied; run tools/provenance-inventory.sh --json"
        wanted licences && unavail licences \
            "no --inventory=FILE supplied; run with --licences to populate it"
    elif [[ ! -f "$INVENTORY" ]]; then
        wanted provenance && unavail provenance "no inventory at ${INVENTORY}"
        wanted licences   && unavail licences   "no inventory at ${INVENTORY}"
    else
        if wanted provenance; then
            n="$(inv_query "sum(1 for s in d['sources'] if s['assurance_class'] in ('lock-only','not-downloaded','unverified'))")"
            t="$(inv_query "len(d['sources'])")"
            offline_inv="$(inv_query "d.get('offline', False)")"
            if [[ -z "$n" ]]; then
                unavail provenance "the inventory at ${INVENTORY} could not be read"
            elif [[ "$offline_inv" == "True" ]]; then
                # Every source reads lock-only in an --offline inventory,
                # because no signature evidence was collected. Reporting that
                # as 70 provenance failures would be blaming the release for
                # how the document was generated.
                unavail provenance "the inventory was generated with --offline, so it
       carries no signature evidence; regenerate it without --offline before
       using it as a release gate"
            elif [[ "$n" -gt 0 ]]; then
                fail provenance "${n} of ${t} sources rest on sources.lock alone or
       were not verified at all; a release should say so deliberately, and
       --strict refuses to do it silently"
            else
                pass provenance "all ${t} sources carry more than a lockfile hash"
            fi
        fi
        if wanted licences; then
            meth="$(inv_query "sorted({s['licence']['method'] for s in d['sources']})")"
            if [[ "$meth" == "['not-collected']" ]]; then
                unavail licences "the inventory carries no licence evidence; rerun
       tools/provenance-inventory.sh --json --licences"
            else
                n="$(inv_query "sum(1 for s in d['sources'] if s['licence']['spdx'] in ('unknown','not-collected'))")"
                t="$(inv_query "len(d['sources'])")"
                if [[ "${n:-0}" -gt 0 ]]; then
                    fail licences "${n} of ${t} sources have no established licence"
                    inv_query "'; '.join(s['name'] for s in d['sources'] if s['licence']['spdx'] in ('unknown','not-collected'))" \
                        | fold -w 66 | sed 's/^/       /' >&2
                else
                    pass licences "all ${t} sources have an established licence"
                fi
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------

FP_AFTER="$(tree_fingerprint)"
if [[ "$FP_BEFORE" != "$FP_AFTER" ]]; then
    echo
    err "the tree changed while it was being checked:"
    err "  before ${FP_BEFORE}"
    err "  after  ${FP_AFTER}"
    die "release-check: ${ROOT_DIR} is being written to. Every result above is
about a tree that no longer exists, including any that passed. Wait for the
build to finish and run this again."
fi

echo
log "Summary"
ok "passed:      ${PASS_N}"
[[ "$UNAVAIL_N" -gt 0 ]] && warn "not checked: ${UNAVAIL_N}"
[[ "$FAIL_N"    -gt 0 ]] && err  "FAILED:      ${FAIL_N}"

if [[ "$FAIL_N" -gt 0 ]]; then
    echo
    printf '  - %s\n' "${FAIL_LIST[@]}" >&2
fi
if [[ "$UNAVAIL_N" -gt 0 ]]; then
    echo
    dim "Not checked - not a pass:"
    printf '  - %s\n' "${UNAVAIL_LIST[@]}"
fi

echo
if [[ "$FAIL_N" -gt 0 ]]; then
    die "release-check: ${FAIL_N} check(s) failed. This tree is not fit to
release as it stands. Nothing has been changed: what to do about a setuid bit
or an unestablished licence is a decision, not a cleanup."
fi
if [[ "$STRICT" -eq 1 && "$UNAVAIL_N" -gt 0 ]]; then
    err "${UNAVAIL_N} check(s) could not be run"
    die "--strict will not pass a release whose checks did not all run."
fi
if [[ "$UNAVAIL_N" -gt 0 ]]; then
    warn "${UNAVAIL_N} check(s) did not run. This is informational;"
    warn "--strict fails here."
fi
ok "release-check: ${PASS_N} check(s) passed."
