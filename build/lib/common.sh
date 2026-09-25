#!/usr/bin/env bash
# Kryptik shared build helpers. Source this; do not execute it.

set -Eeuo pipefail

KRYPTIK_ROOT="${KRYPTIK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
KRYPTIK_SOURCES="${KRYPTIK_SOURCES:-${KRYPTIK_ROOT}/sources}"
KRYPTIK_WORK="${KRYPTIK_WORK:-${KRYPTIK_ROOT}/build/work}"
KRYPTIK_OUT="${KRYPTIK_OUT:-${KRYPTIK_ROOT}/out}"
# shellcheck disable=SC2034  # consumed by tools/fetch-sources.sh
KRYPTIK_LOCK="${KRYPTIK_ROOT}/sources.lock"

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_BLU=$'\033[34m'; C_DIM=$'\033[2m';  C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""
fi

log()   { printf '%s==>%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()    { printf '%s  ok%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn()  { printf '%swarn%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()   { printf '%s fail%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()   { err "$*"; exit 1; }
dim()   { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RST"; }

# Report the failing line rather than a bare non-zero exit.
_kryptik_trap() {
    local ec=$? line=${BASH_LINENO[0]} src=${BASH_SOURCE[1]:-?}
    err "aborted at ${src}:${line} (exit ${ec})"
    exit "$ec"
}
trap _kryptik_trap ERR

# nproc, capped at one job per 1.5 GB of RAM, or GCC and glibc builds meet the
# OOM killer ("internal compiler error: Killed"). KRYPTIK_JOBS overrides it.
kryptik_default_jobs() {
    local cpus mem_kb mem_gb by_mem
    cpus="$(nproc 2>/dev/null || echo 1)"
    mem_kb="$(awk '/MemTotal/{print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
    mem_gb=$(( mem_kb / 1024 / 1024 ))
    by_mem=$(( mem_gb * 2 / 3 ))
    [[ "$by_mem" -lt 1 ]] && by_mem=1
    if [[ "$by_mem" -lt "$cpus" ]]; then printf '%s' "$by_mem"
    else printf '%s' "$cpus"; fi
}

have() { command -v "$1" >/dev/null 2>&1; }

sha256_of() {
    if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
    elif have shasum;   then shasum -a 256 "$1" | cut -d' ' -f1
    else die "no sha256sum or shasum available"
    fi
}

sha256_of_stdin() {
    if have sha256sum; then sha256sum | cut -d' ' -f1
    elif have shasum;   then shasum -a 256 | cut -d' ' -f1
    else die "no sha256sum or shasum available"
    fi
}

# A source tarball's top-level licence files: what tools/scan-licenses.sh
# reads, and what stage 04 installs under /usr/share/licenses.
LICENCE_RE='^[^/]+/(COPYING[^/]*|COPYRIGHT[^/]*|LICEN[CS]E[^/]*|License)$'
licence_members() { tar -tf "$1" 2>/dev/null | grep -E "$LICENCE_RE" || true; }

# Stages 01-03 run on the host and install into ${KRYPTIK_WORK}/sysroot; stages
# 04 and 05 run inside the chroot, where the sysroot is /. A KRYPTIK_WORK path
# may not exist in there, and installing to it would build a nested tree.
# KRYPTIK_DESTDIR is the DESTDIR= value: empty inside the chroot.
KRYPTIK_CHROOT_MARKER="/etc/kryptik/inside-chroot"

kryptik_in_chroot() { [[ -f "$KRYPTIK_CHROOT_MARKER" ]]; }

# shellcheck disable=SC2034  # KRYPTIK_DESTDIR is consumed by stage 05
if kryptik_in_chroot; then
    KRYPTIK_CHROOT=1
    KRYPTIK_SYSROOT="/"
    KRYPTIK_DESTDIR=""
else
    KRYPTIK_CHROOT=0
    KRYPTIK_SYSROOT="${KRYPTIK_WORK}/sysroot"
    KRYPTIK_DESTDIR="${KRYPTIK_SYSROOT}"
fi

require_outside_chroot() {
    [[ "$KRYPTIK_CHROOT" -eq 0 ]] || die \
"${1:-this stage} populates the sysroot and must run OUTSIDE the chroot.
Inside the chroot the sysroot is / and there is nothing left to cross-build."
}

require_inside_chroot() {
    [[ "$KRYPTIK_CHROOT" -eq 1 ]] && return 0
    [[ "${KRYPTIK_ALLOW_UNCHROOTED:-0}" == "1" ]] && {
        warn "${1:-this stage} running outside the chroot (KRYPTIK_ALLOW_UNCHROOTED=1)"
        return 0
    }
    die \
"${1:-this stage} must run INSIDE the chroot.

  make ${2:-system}

mounts the chroot, runs this stage in it and unmounts again, escalating only
for the mount and the chroot call themselves. Set KRYPTIK_ALLOW_UNCHROOTED=1
only if you know exactly why."
}

require_linux() {
    [[ "$(uname -s)" == "Linux" ]] || die \
"Kryptik must be built on Linux. Detected: $(uname -s).
On Windows, use WSL2:  wsl --install -d Debian"
}

# As root, a stray 'rm -rf $LFS/' removes the host.
refuse_root() {
    [[ "${EUID}" -ne 0 ]] || die \
"Do not run the Kryptik build as root.
LFS stages that need privilege escalate explicitly and narrowly."
}

load_config() {
    # shellcheck source=/dev/null
    source "${KRYPTIK_ROOT}/build/config/versions.env"
}

load_hardening() {
    # shellcheck source=/dev/null
    source "${KRYPTIK_ROOT}/build/config/hardening.env"
}

# Fail on hardening exceptions lacking a justification comment.
validate_hardening_exceptions() {
    local f="${KRYPTIK_ROOT}/build/config/hardening-exceptions.txt"
    [[ -f "$f" ]] || return 0
    local n=0
    while IFS= read -r line; do
        [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" != *"#"* ]]; then
            err "hardening exception without justification: ${line}"
            n=$((n + 1))
        fi
    done < "$f"
    [[ "$n" -eq 0 ]] || die "${n} undocumented hardening exception(s). See docs/hardening.md."
}

# Build stamps carry a fingerprint of the step's inputs. A mismatch stops the
# build (KRYPTIK_STALE=refuse, the default), since one rebuilt step leaves a
# sysroot built from two configurations; KRYPTIK_STALE=rebuild rebuilds the
# affected steps. Stamps without a fingerprint are moved to .stamps/legacy/.

# Bump when the set of fingerprint inputs changes.
KRYPTIK_STAMP_FORMAT=4

STAMP_PREFIX=""
STAGE_FILE=""
STAMP_CC=""

#   stage_contract <this-file> <stamp-prefix> <compiler>
# Called before a stage's first step(). <compiler> is the one the stage drives:
# the host gcc for stage 01, whose cross gcc exists only halfway through.
stage_contract() {
    STAGE_FILE="${1:?stage_contract needs the stage file}"
    STAMP_PREFIX="${2-}"
    STAMP_CC="${3:?stage_contract needs the compiler this stage drives}"
}

# "name=fingerprint;" for every step so far, seeded by stage_depends_on(). Each
# stamp hashes it, so a changed step invalidates every later step and every
# stage built on it, while an unchanged prefix still resumes.
STAMP_DEPS=""

#   stage_depends_on <stamp-prefix> <step-name>
# Seed the chain from an earlier stage's step, so stamps also record the
# toolchain a stage was built with. That stamp must exist.
stage_depends_on() {
    local prefix="$1" name="$2"
    local stamp="${STAMPS}/${prefix}${name}" fp
    [[ -f "$stamp" ]] || die "${name}: the stage this one builds on has not completed.
No stamp at ${stamp}. Finish that stage first."
    fp="$(_stamp_read "$stamp")"
    [[ -n "$fp" ]] || die "${stamp} carries no fingerprint. Rebuild that stage under the
current harness before building on it."
    STAMP_DEPS="${STAMP_DEPS}stage:${prefix}${name}=${fp};"
}

_hash_file() {
    local f="${1:-}"
    if [[ -n "$f" && -f "$f" ]]; then sha256_of "$f"; else printf 'absent'; fi
}

# One digest over what apply_repo_patches reads of a patch set: its patches
# and their SHA256SUMS. Not a README, which a documentation edit changes.
_hash_patchset() {
    local d="${1:-}"
    if [[ -n "$d" && -d "$d" ]]; then
        ( cd "$d" && find . -maxdepth 1 -type f \( -name '*.patch' -o -name SHA256SUMS \) -print0 \
            | LC_ALL=C sort -z | xargs -0r sha256sum ) | sha256_of_stdin
    else
        printf 'absent'
    fi
}

# Expand ${V_*}, the only substitution a patch-set name may use, without eval.
_expand_v() {
    local t="$1" v pat
    while [[ "$t" =~ \$\{(V_[A-Z0-9_]+)\} ]]; do
        v="${BASH_REMATCH[1]}"
        pat='${'"$v"'}'
        t="${t//"$pat"/${!v-unset}}"
    done
    printf '%s' "$t"
}

# In-repository patch sets; only the harness test overrides the location.
KRYPTIK_PATCHES="${KRYPTIK_PATCHES:-${KRYPTIK_ROOT}/build/patches}"

# Apply build/patches/<set>/*.patch here in name order (-p1, no fuzz). Every
# patch must be listed in the set's SHA256SUMS and match it.
apply_repo_patches() {
    local set="${1:?apply_repo_patches needs a patch-set name}"
    local pdir="${KRYPTIK_PATCHES}/${set}"
    [[ -d "$pdir" ]] || die "no patch set at ${pdir}"
    [[ -f "${pdir}/SHA256SUMS" ]] || die "${pdir} has no SHA256SUMS"
    ( cd "$pdir" && sha256sum --check --quiet --strict SHA256SUMS ) \
        || die "patch set ${set}: a patch does not match SHA256SUMS"
    local p n=0
    for p in "${pdir}"/*.patch; do
        [[ -f "$p" ]] || continue
        grep -q "  $(basename "$p")\$" "${pdir}/SHA256SUMS" \
            || die "patch set ${set}: ${p##*/} is not listed in SHA256SUMS"
        echo "applying ${p##*/}"
        patch -Np1 -F0 --no-backup-if-mismatch -i "$p" \
            || die "patch set ${set}: ${p##*/} did not apply"
        n=$((n + 1))
    done
    [[ "$n" -gt 0 ]] || die "patch set ${set} contains no patches"
    echo "applied ${n} patch(es) from ${set}"
}

# GCC's math libraries, unpacked into its tree under the names it builds them
# from. One command per line: after `tar ... && mv ...`, a failed tar let
# configure find the host's copies.
gcc_prereqs() {
    local t
    for t in "mpfr-${V_MPFR}.tar.xz" "gmp-${V_GMP}.tar.xz" "mpc-${V_MPC}.tar.gz"; do
        tar -xf "${KRYPTIK_SOURCES}/${t}"
        mv "${t%.tar.*}" "${t%%-*}"
    done
}

# Triple and version of the compiler the stage drives (see stage_contract).
stamp_compiler_id() {
    local cc="${STAMP_CC:-${CC:-gcc}}"
    if have "$cc"; then
        # No pipe: `| head -1` can SIGPIPE the compiler and make this racy.
        local ver
        ver="$("$cc" --version 2>/dev/null || echo unknown)"
        printf '%s %s' \
            "$("$cc" -dumpmachine 2>/dev/null || echo unknown)" \
            "${ver%%$'\n'*}"
    else
        printf 'absent:%s' "$cc"
    fi
}

# The functions FN names, the ones those name, and so on, as text in name
# order. declare -f leaves comments out, so only code counts. The step runner
# and its parts run around a recipe, never inside one: "step" in a recipe's
# message is not a call, and an edit to the runner is a stamp format change.
_helpers_of() {
    local -A seen=(["$1"]=1)
    local -a todo=("$1")
    local f w runner=" step stage_contract stage_depends_on stamp_fingerprint recipe_fingerprint _helpers_of _stamp_read _stamp_write _stamp_stale "
    while [[ "${#todo[@]}" -gt 0 ]]; do
        f="${todo[-1]}"; unset 'todo[-1]'
        for w in $(declare -f "$f" | grep -oE '[A-Za-z_][A-Za-z0-9_]*' | sort -u); do
            if [[ -z "${seen[$w]:-}" && "$runner" != *" $w "* ]] && declare -F "$w" >/dev/null; then
                seen[$w]=1; todo+=("$w")
            fi
        done
    done
    for f in $(printf '%s\n' "${!seen[@]}" | LC_ALL=C sort); do
        if [[ "$f" != "$1" ]]; then declare -f "$f"; fi
    done
}

# What one step was built from: the text of the recipe and of every helper it
# reaches, its arguments, the tarballs, patches and patch sets they name, and
# every V_* that text reads. Not the whole stage file, so a fix to one recipe
# does not invalidate every stamp; not all of common.sh, so a comment changes
# none.
recipe_fingerprint() {
    local fn="${1:-}"; shift || true
    local body
    if declare -F "$fn" >/dev/null 2>&1; then
        body="$(declare -f "$fn"; _helpers_of "$fn")"
    else
        body="external:${fn}"
    fi
    {
        printf '%s\n' "$body"
        printf 'args:'; printf ' %q' "$@"; printf '\n'

        local a
        for a in "$@"; do
            case "$a" in
                *.tar.*|*.tgz|*.patch)
                    printf 'src:%s=%s\n' "$a" "$(_hash_file "${KRYPTIK_SOURCES}/${a}")"
                    ;;
            esac
            # A patch set named as an argument.
            if [[ -d "${KRYPTIK_PATCHES}/${a}" && -f "${KRYPTIK_PATCHES}/${a}/SHA256SUMS" ]]; then
                printf 'patchset:%s=%s\n' "$a" "$(_hash_patchset "${KRYPTIK_PATCHES}/${a}")"
            fi
        done

        # A patch set the recipe's text applies.
        local ps
        while IFS= read -r ps; do
            [[ -z "$ps" ]] && continue
            ps="$(_expand_v "$ps")"
            printf 'patchset:%s=%s\n' "$ps" "$(_hash_patchset "${KRYPTIK_PATCHES}/${ps}")"
        done < <(printf '%s\n' "$body" \
                 | sed -n 's/.*apply_repo_patches[[:space:]]\{1,\}"\{0,1\}\([^" ;)]*\).*/\1/p' \
                 | sort -u || true)

        local v
        while IFS= read -r v; do
            [[ -z "$v" ]] && continue
            printf 'ver:%s=%s\n' "$v" "${!v-unset}"
        # `|| true`: grep exits 1 for a recipe with no V_*, which would fire
        # the ERR trap inside the process substitution.
        done < <(printf '%s
%s
' "$body" "$*" \
                 | grep -oE 'V_[A-Z0-9_]+' | sort -u || true)
    } | sha256_of_stdin
}

# The step's inputs plus what affects every step. versions.env and
# hardening.env are not hashed whole: they reach a step through tarball names,
# V_* values and the flags below, so an unrelated edit invalidates nothing.
stamp_fingerprint() {
    local name="$1"; shift
    {
        printf 'format=%s\n'   "$KRYPTIK_STAMP_FORMAT"
        printf 'stage=%s\n'    "$(basename "${STAGE_FILE:-unknown}")"
        printf 'step=%s\n'     "$name"
        printf 'recipe=%s\n'   "$(recipe_fingerprint "$@")"
        printf 'cc=%s\n'       "$(stamp_compiler_id)"
        printf 'cflags=%s\n'   "${CFLAGS:-}"
        printf 'cxxflags=%s\n' "${CXXFLAGS:-}"
        printf 'ldflags=%s\n'  "${LDFLAGS:-}"
        printf 'deps=%s\n'     "${STAMP_DEPS}"
    } | sha256_of_stdin
}

_stamp_read() {
    [[ -f "$1" ]] || { printf ''; return 0; }
    awk '$1 == "fingerprint:" { print $2; exit }' "$1"
}

_stamp_write() {
    local stamp="$1" name="$2" fp="$3" secs="$4" logfile="$5"
    local tmp="${stamp}.tmp.$$"
    {
        printf '# kryptik build stamp v%s\n' "$KRYPTIK_STAMP_FORMAT"
        printf 'fingerprint: %s\n' "$fp"
        printf 'step: %s\n' "$name"
        printf 'stage: %s\n' "$(basename "${STAGE_FILE:-unknown}")"
        printf 'completed: %s\n' "$(date -Iseconds)"
        printf 'duration_s: %s\n' "$secs"
        printf 'log: %s\n' "$logfile"
        printf 'cc: %s\n' "$(stamp_compiler_id)"
    } > "$tmp"
    mv -f "$tmp" "$stamp"
}

_stamp_stale() {
    local name="$1" stamp="$2" got="$3"

    if [[ -z "$got" ]]; then
        # No fingerprint: keep the stamp for reference, but rebuild.
        local archive="${STAMPS}/legacy"
        mkdir -p "$archive"
        mv -f "$stamp" "${archive}/$(basename "$stamp")"
        warn "${name}: stamp carries no fingerprint - it predates this harness,"
        warn "${name}: which means it was written by the step() that recorded"
        warn "${name}: FAILED builds as successful. It proves nothing."
        warn "${name}: archived to ${archive}/ and rebuilding."
        return 0
    fi

    local reason="records a different fingerprint than the current inputs.
One of: the recipe or a helper it calls, an in-repository patch set it applies,
versions.env, the hardening flags, sources.lock, the compiler in use, an
earlier step in this stage, or a stage this one builds on has changed since
${name} was built."

    case "${KRYPTIK_STALE:-refuse}" in
        rebuild)
            warn "${name}: stamp ${reason}"
            warn "${name}: KRYPTIK_STALE=rebuild - rebuilding this step."
            rm -f "$stamp"
            return 0
            ;;
        *)
            err "${name}: stamp ${reason}"
            die "Refusing to resume onto changed inputs.

A stamped step whose inputs moved leaves a sysroot built from two different
configurations, and nothing downstream can tell. Choose deliberately:

  KRYPTIK_STALE=rebuild <command>   rebuild only the affected steps
  make reset-stamps                 archive every stamp and start clean
                                    (archives under .stamps/legacy, never
                                     deletes)

Stamp: ${stamp}"
            ;;
    esac
}

#   step <name> <recipe> [args...]
# Stages provide STAMPS, LOGS, STAMP_PREFIX and STAGE_FILE, and optionally
# REDO, set_flags_for() (per-package hardening) and step_failure_hint().
step() {
    local name="$1"; shift
    local stamp="${STAMPS}/${STAMP_PREFIX}${name}"

    # Before fingerprinting, so the stamp hashes the flags the recipe uses.
    if declare -F set_flags_for >/dev/null; then set_flags_for "$name"; fi

    local want; want="$(stamp_fingerprint "$name" "$@")"

    if [[ "${REDO:-}" == "$name" ]]; then
        warn "forcing rebuild of ${name}"
        rm -f "$stamp"
    fi

    if [[ -f "$stamp" ]]; then
        local got; got="$(_stamp_read "$stamp")"
        if [[ "$got" == "$want" ]]; then
            dim "  skip ${name} (already built, inputs unchanged)"
            STAMP_DEPS="${STAMP_DEPS}${name}=${want};"
            return 0
        fi
        # Dies unless KRYPTIK_STALE=rebuild, or the stamp was fingerprint-less.
        _stamp_stale "$name" "$stamp" "$got"
    fi

    log "${name}"

    local logfile="${LOGS}/${STAMP_PREFIX}${name}.log"
    local start=$SECONDS

    # A bare subshell, never a condition: `( ... ) || rc=$?` or `if ! ( ... )`
    # turns errexit off inside the recipe too. The ERR trap fires even without
    # errexit and would exit this shell, so it is lifted here and re-armed in
    # the subshell, where the recipe's abort line lands in its log.
    # Tested by tools/test-step-errexit.sh.
    local rc=0
    set +e
    trap - ERR
    ( set -Eeuo pipefail; trap _kryptik_trap ERR; "$@" ) > "$logfile" 2>&1
    rc=$?
    trap _kryptik_trap ERR
    set -e

    STAMP_DEPS="${STAMP_DEPS}${name}=${want};"

    if [[ "$rc" -eq 0 ]]; then
        _stamp_write "$stamp" "$name" "$want" "$(( SECONDS - start ))" "$logfile"
        ok "${name} ($(( SECONDS - start ))s)"
    else
        err "${name} failed. Last ${KRYPTIK_FAIL_TAIL:-30} lines of ${logfile}:"
        tail -"${KRYPTIK_FAIL_TAIL:-30}" "$logfile" >&2
        if declare -F step_failure_hint >/dev/null; then step_failure_hint "$name"; fi
        die "$(basename "${STAGE_FILE:-stage}") aborted at ${name}"
    fi
}
