#!/usr/bin/env bash
# What the later stages' stamps are built from, read from the stage files
# themselves: stage 06 builds on stage 04's last step as well as on stage 05,
# and stage 05's config and hardening-check steps pass as arguments what their
# function text cannot show, so their fingerprints move when it changes.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# Stage 04's last step, by its own --list, which exits before the chroot check.
last="$(cd "$ROOT" && NO_COLOR=1 bash build/stages/04-base-system.sh --list 2>/dev/null \
        | awk '$1 ~ /^[0-9]+\.$/ { n = $2 } END { print n }')"
[[ -n "$last" ]] && ok "stage 04 lists its steps; the last is ${last}" || bad "stage 04 --list named no steps"

# The stamps stage 06 builds on, from its stage_depends_on lines.
seeds="$(stage_depends_on() { printf '%s%s\n' "$1" "$2"; }
         eval "$(grep -E '^stage_depends_on ' "$ROOT/build/stages/06-iso.sh")")"
[[ "$seeds" == *"kernel-verify-install"* ]] && ok "stage 06 builds on stage 05's last step" || bad "stage 06 seeds: ${seeds:-none}"
[[ -n "$last" && "$seeds" == *"bs-${last}"* ]] && ok "stage 06 builds on stage 04's last step too, so a later stage 04 step reaches it" \
    || bad "stage 06 does not build on bs-${last}: ${seeds:-none}"

# step_line NAME: stage 05's `step NAME ...` command, joined across lines.
step_line() {
    awk -v n="$1" '$1 == "step" && $2 == n { on = 1 }
        on { line = $0; more = sub(/\\$/, "", line); printf "%s ", line; if (!more) exit }' \
        "$ROOT/build/stages/05-kernel.sh"
}
# args_of NAME TREE [VAR=VALUE...]: the arguments that command passes after the
# recipe's name, evaluated with TREE as the repository.
args_of() {
    local name="$1" tree="$2"; shift 2
    env "$@" KRYPTIK_ROOT="$tree" bash -c 'source "$1/build/lib/common.sh" || exit 1
        step() { shift 2; printf "%s\n" "$@"; }
        eval "$2"' _ "$ROOT" "$(step_line "$name")" 2>&1
}

A="$T/a"; B="$T/b"
mkdir -p "$A/tools" "$B/tools"
cp "$ROOT/tools/check-kernel-hardening.sh" "$A/tools/"
cp "$ROOT/tools/check-kernel-hardening.sh" "$B/tools/"
echo "# an edit" >> "$B/tools/check-kernel-hardening.sh"
hc=(KSRC="$T/nokernel" ACCEPTED_LIST="$ROOT/build/config/kernel/checker-accepted.txt" COMMON_ARGS_DIGEST=x)
a="$(args_of hardening-check "$A" "${hc[@]}" V_KERNEL_HARDENING_CHECKER=1.0)"
b="$(args_of hardening-check "$B" "${hc[@]}" V_KERNEL_HARDENING_CHECKER=1.0)"
c="$(args_of hardening-check "$A" "${hc[@]}" V_KERNEL_HARDENING_CHECKER=1.1)"
[[ -n "$a" && "$a" != *"aborted"* ]] && ok "stage 05's hardening-check line evaluates" || bad "hardening-check: ${a}"
[[ "$a" != "$b" ]] && ok "hardening-check's stamp moves when tools/check-kernel-hardening.sh changes" \
    || bad "hardening-check passes the same arguments for an edited checker script"
[[ "$a" != "$c" ]] && ok "and when the pinned checker version changes" \
    || bad "hardening-check passes the same arguments for another checker version"

cf=(FRAG_DIGEST=x V_INTEL_MICROCODE=1 V_LINUX_FIRMWARE=2)
a="$(args_of config "$A" "${cf[@]}" KCONFIG_CRITICAL="CONFIG_A CONFIG_B")"
b="$(args_of config "$A" "${cf[@]}" KCONFIG_CRITICAL="CONFIG_A CONFIG_B CONFIG_C")"
[[ -n "$a" && "$a" != *"aborted"* ]] && ok "stage 05's config line evaluates" || bad "config: ${a}"
[[ "$a" != "$b" ]] && ok "config's stamp moves when the critical option list changes, which is data, not a function" \
    || bad "config passes the same arguments for another critical option list"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
