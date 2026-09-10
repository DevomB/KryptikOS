#!/usr/bin/env bash
# Kryptik shared build helpers. Source this; do not execute it.

set -Eeuo pipefail

KRYPTIK_ROOT="${KRYPTIK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
KRYPTIK_SOURCES="${KRYPTIK_SOURCES:-${KRYPTIK_ROOT}/sources}"
KRYPTIK_WORK="${KRYPTIK_WORK:-${KRYPTIK_ROOT}/build/work}"
KRYPTIK_OUT="${KRYPTIK_OUT:-${KRYPTIK_ROOT}/out}"
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

require_linux() {
    [[ "$(uname -s)" == "Linux" ]] || die \
"Kryptik must be built on Linux. Detected: $(uname -s).
On Windows, use WSL2:  wsl --install -d Debian"
}

# Refuse to build as root. A stray 'rm -rf \$LFS/' as root removes your host.
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

have() { command -v "$1" >/dev/null 2>&1; }

sha256_of() {
    if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
    elif have shasum;   then shasum -a 256 "$1" | cut -d' ' -f1
    else die "no sha256sum or shasum available"
    fi
}
