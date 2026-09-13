#!/usr/bin/env bash
# Kryptik shared build helpers. Source this; do not execute it.

set -Eeuo pipefail

KRYPTIK_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
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

# Parallelism.
#
# GCC's bootstrap and glibc's build are memory-hungry: on a host with less than
# roughly 1.5GB of RAM per job, -j$(nproc) meets the OOM killer partway through
# a forty-minute link, and the failure looks like a compiler crash rather than
# what it is. So the default is capped by memory as well as by CPU count.
#
# KRYPTIK_JOBS overrides it. Raise it when you have the RAM; lower it when a
# build dies with "internal compiler error: Killed".
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

# ---------------------------------------------------------------------------
# Where things get installed
#
# Stages 01, 02 and 03 run on the host and install into a sysroot DIRECTORY.
# Stages 04 and 05 run INSIDE that sysroot, after stage 03 chroots into it,
# and there the sysroot is simply "/".
#
# Deriving "${KRYPTIK_WORK}/sysroot" unconditionally is what stage 05 used to
# do, and it is wrong inside the chroot in two separate ways:
#
#   * With the default KRYPTIK_WORK the path resolves, through the /kryptik
#     bind mount, back to the chroot's own root - so it happened to work by
#     coincidence, and nobody noticed the reasoning was broken.
#
#   * With KRYPTIK_WORK pointed anywhere else - which a real build needs,
#     because the work tree belongs on native storage - the path does not
#     exist inside the chroot, and `cp` and `modules_install` cheerfully
#     CREATE it. The result is a second, nested, half-populated target tree
#     inside the real one: /boot looks empty while the kernel sits several
#     levels down, and nothing reports an error.
#
# So the sysroot is resolved once, here, from which side of the chroot
# boundary we are on. KRYPTIK_DESTDIR is the DESTDIR= value - empty inside the
# chroot, which is what "install into the live root" means to every build
# system there is.
# ---------------------------------------------------------------------------

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

# Stages that only make sense on one side of the boundary say so.
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

# Refuse to build as root. A stray 'rm -rf $LFS/' as root removes your host.
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

# ---------------------------------------------------------------------------
# Build stamps
#
# A stamp used to be an empty file meaning "this step ran once". That is not
# enough to resume a build safely, for two separate reasons.
#
#   1. It cannot distinguish a completed step from one whose INPUTS have since
#      moved. Edit a recipe, bump a version, change a hardening flag - the
#      stamp still says "built", and the sysroot quietly contains something
#      nobody asked for.
#
#   2. Stamps written before tools/test-step-errexit.sh caught the errexit bug
#      came from a step() that recorded FAILED builds as successful. An empty
#      file from that harness is not weak evidence of a good build; it is no
#      evidence at all.
#
# So a stamp now carries a fingerprint of what the step was built from, and a
# stamp whose fingerprint does not match current inputs is REFUSED rather than
# trusted. The refusal is deliberately conservative: rebuilding one step in the
# middle of an otherwise finished sysroot produces a tree built from two
# different configurations, which is worse than stopping and saying so.
#
#   KRYPTIK_STALE=refuse    (default) stop and explain
#   KRYPTIK_STALE=rebuild   rebuild the affected steps in place
#
# Fingerprint-less stamps are ARCHIVED under .stamps/legacy/ rather than
# deleted - evidence of what an earlier run did is preserved, it is just not
# trusted.
# ---------------------------------------------------------------------------

# Bump when the set of fingerprint inputs changes.
KRYPTIK_STAMP_FORMAT=3

STAMP_PREFIX=""
STAGE_FILE=""
STAMP_CC=""

# Declared by each stage before its first step() call:
#
#   stage_contract <this-file> <stamp-prefix> <compiler>
#
# The compiler is the one the STAGE DRIVES, which is not always the
# obvious one: stage 01 builds the cross toolchain with the HOST gcc, so
# the host gcc is what its stamps are fingerprinted against - the cross
# compiler does not exist until halfway through that stage, and naming it
# would invalidate every early stamp the moment it appeared.
stage_contract() {
    STAGE_FILE="${1:?stage_contract needs the stage file}"
    STAMP_PREFIX="${2-}"
    STAMP_CC="${3:?stage_contract needs the compiler this stage drives}"
}

# Accumulated by step(): "name=fingerprint;" for every step declared so far
# in this stage, seeded by stage_depends_on() with the fingerprint an earlier
# stage finished on.
#
# It used to hold the ordered NAMES only. That catches a reordered or inserted
# package and misses the case that matters more: a step whose recipe, source
# or flags changed and was rebuilt in place, followed by steps whose stamps
# still matched because nothing THEY hashed had moved. A glibc rebuilt with a
# fix would have left sixty packages linked against the old one, every one of
# them reporting "inputs unchanged". With the fingerprint in the chain, a
# change to step k invalidates k and everything after it in this stage, and
# every stage that seeds from it - and nothing before it, so an unchanged
# prefix still resumes without rebuilding.
STAMP_DEPS=""

# Seed this stage's dependency chain from a step of an earlier stage.
#
#   stage_depends_on <stamp-prefix> <step-name>
#
# Stage 02 is built by stage 01's compiler, stage 04 by stage 02's, and the
# kernel by stage 04's toolchain closure, so their stamps have to carry the
# fingerprint of what they were built WITH, not only what they were built
# FROM. The named stamp must exist: a stage that starts on top of an
# unfinished predecessor is building on nothing, and says so.
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

# One digest over every regular file in a directory: relative path and
# content, in a fixed order, so the same set of files hashes the same
# anywhere.
_hash_dir() {
    local d="${1:-}"
    if [[ -n "$d" && -d "$d" ]]; then
        ( cd "$d" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum ) \
            | sha256_of_stdin
    else
        printf 'absent'
    fi
}

# Expand ${V_*} references in a token lifted from a recipe's own text, without
# eval: a version variable is the only substitution a patch-set name may use.
_expand_v() {
    local t="$1" v pat
    while [[ "$t" =~ \$\{(V_[A-Z0-9_]+)\} ]]; do
        v="${BASH_REMATCH[1]}"
        pat='${'"$v"'}'
        t="${t//"$pat"/${!v-unset}}"
    done
    printf '%s' "$t"
}

# Where in-repository patch sets live. Overridable so the harness test can
# supply its own; the build never sets it.
KRYPTIK_PATCHES="${KRYPTIK_PATCHES:-${KRYPTIK_ROOT}/build/patches}"

# Apply the in-repository patch set build/patches/<set>/ to the current
# directory: every *.patch in name order, -p1, no fuzz, stopping at the first
# reject. SHA256SUMS is verified first and every patch must be listed in it,
# so a patch cannot be added or altered without the record beside it moving.
# recipe_fingerprint() hashes the whole set for any recipe that names it, so a
# changed patch invalidates the step that applies it.
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

# The compiler a stage actually drives. Stage 01 builds the cross toolchain
# with the HOST gcc, so that is its compiler; stage 02 drives the cross gcc;
# stages 04 and 05 drive the native target gcc inside the chroot. Getting this
# wrong in either direction makes stamps churn on every run or never at all.
stamp_compiler_id() {
    local cc="${STAMP_CC:-${CC:-gcc}}"
    if have "$cc"; then
        # No pipe. `"$cc" --version | head -1` can hand the compiler a SIGPIPE
        # and, with the `|| echo unknown` below it, silently substitute a
        # DIFFERENT fingerprint input depending on a race. A fingerprint input
        # that can vary between two identical runs is not a fingerprint.
        local ver
        ver="$("$cc" --version 2>/dev/null || echo unknown)"
        printf '%s %s' \
            "$("$cc" -dumpmachine 2>/dev/null || echo unknown)" \
            "${ver%%$'\n'*}"
    else
        printf 'absent:%s' "$cc"
    fi
}

# What a single step was built from.
#
# Deliberately NOT the whole stage file. Hashing that meant a one-line fix to
# one package's recipe invalidated all fifty-eight stamps in stage 04 - which
# is conservative to the point of being unusable, and is the pressure that
# makes people delete the check rather than answer it.
#
# So: the recipe function's own text, the arguments it was called with, the
# content of any tarball or patch those arguments name, and the values of any
# V_* version variables the recipe interpolates (s_glibc names no tarball in
# its arguments - it builds the name from ${V_GLIBC} inside the function, and a
# version bump has to invalidate it all the same).
recipe_fingerprint() {
    local fn="${1:-}"; shift || true
    local body
    if declare -F "$fn" >/dev/null 2>&1; then
        body="$(declare -f "$fn")"
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
            # An argument naming an in-repository patch set is an input too.
            if [[ -d "${KRYPTIK_PATCHES}/${a}" && -f "${KRYPTIK_PATCHES}/${a}/SHA256SUMS" ]]; then
                printf 'patchset:%s=%s\n' "$a" "$(_hash_dir "${KRYPTIK_PATCHES}/${a}")"
            fi
        done

        # And so is any patch set the recipe's own text applies, with a
        # ${V_*} in the name expanded the way the recipe would.
        local ps
        while IFS= read -r ps; do
            [[ -z "$ps" ]] && continue
            ps="$(_expand_v "$ps")"
            printf 'patchset:%s=%s\n' "$ps" "$(_hash_dir "${KRYPTIK_PATCHES}/${ps}")"
        done < <(printf '%s\n' "$body" \
                 | sed -n 's/.*apply_repo_patches[[:space:]]\{1,\}"\{0,1\}\([^" ;)]*\).*/\1/p' \
                 | sort -u || true)

        local v
        while IFS= read -r v; do
            [[ -z "$v" ]] && continue
            printf 'ver:%s=%s\n' "$v" "${!v-unset}"
        # `|| true`: a recipe with no V_* variables is normal, and grep
        # exits 1 when it matches nothing. Without this the ERR trap fires
        # inside the process substitution and prints a failure line for a
        # step that is about to succeed.
        done < <(printf '%s
%s
' "$body" "$*" \
                 | grep -oE 'V_[A-Z0-9_]+' | sort -u || true)
    } | sha256_of_stdin
}

# The full fingerprint: the step's own inputs, plus the things that legitimately
# affect every step in the build.
#
# versions.env and hardening.env are NOT hashed wholesale. Their effect is
# already here, precisely: a version reaches a step through a tarball name or a
# V_* value, and a hardening flag reaches it through CFLAGS/LDFLAGS below.
# Hashing the files instead would invalidate every stamp in the build whenever
# any unrelated line in them moved.
stamp_fingerprint() {
    local name="$1"; shift
    {
        printf 'format=%s\n'   "$KRYPTIK_STAMP_FORMAT"
        printf 'stage=%s\n'    "$(basename "${STAGE_FILE:-unknown}")"
        printf 'step=%s\n'     "$name"
        printf 'recipe=%s\n'   "$(recipe_fingerprint "$@")"
        printf 'common=%s\n'   "$(_hash_file "${KRYPTIK_LIB:-}")"
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
        # Fingerprint-less: preserve the evidence, do not trust it.
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
One of: the recipe, an in-repository patch set it applies, build/lib/common.sh,
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

# The step runner.
#
# ONE implementation, used by every stage. Four near-identical copies is how
# the errexit bug below shipped twice in two different disguises: a fix landed
# in one copy and not the others, and the regression test had to re-derive the
# code it was testing from each file in turn.
#
# Stages provide: STAMPS, LOGS, STAMP_PREFIX, STAGE_FILE, and optionally REDO,
# a set_flags_for() hook (stage 04's per-package hardening) and a
# step_failure_hint() hook.
step() {
    local name="$1"; shift
    local stamp="${STAMPS}/${STAMP_PREFIX}${name}"

    # Narrow the flags BEFORE fingerprinting, not after.
    #
    # This used to happen further down, just before running the recipe, with
    # the fingerprint recomputed afterwards and that second value written into
    # the stamp. The comparison above it still used the first value - computed
    # with whatever flags the PREVIOUS package had left in the environment.
    #
    # For 63 of stage 04's 64 packages those are the same string, because
    # set_flags_for changes nothing. glibc is the exception - literally: it is
    # the one package with an entry in hardening-exceptions.txt - so glibc's
    # stamp was written with -D_FORTIFY_SOURCE=3 dropped and compared with it
    # present. It could never match. It went stale on every resume, and the
    # "inputs unchanged" the other packages reported was not true of it.
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

    # Capture the subshell's status WITHOUT putting it in a condition.
    #
    # `( set -e; "$@" ) || rc=$?` looks like it fixes this and does not: the
    # trailing || still suppresses errexit inside the subshell, even though the
    # subshell sets it explicitly. Verified - a recipe of `false` followed by a
    # succeeding command runs to completion and returns 0.
    #
    # `if ! ( ... ); then` is broken the same way. Only disabling errexit
    # around a bare subshell, then reading $?, actually works.
    #
    # tools/test-step-errexit.sh is the regression test for this. It has caught
    # the bug twice now: once as `if "$@"; then`, once as the || form above.
    #
    # AND `set +e` is not enough on its own. An ERR trap fires whether or not
    # errexit is enabled, and _kryptik_trap calls exit - so without the
    # `trap - ERR` below, this shell died on the next line and everything
    # after it (the log tail, step_failure_hint, die) was unreachable code.
    # The stamp logic still held, so failures were still failures; they just
    # arrived with no diagnosis at all. Re-armed inside the subshell so the
    # recipe's own abort line still lands in its log.
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
