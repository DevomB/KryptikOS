#!/usr/bin/env bash
# measure.sh — what a boot cost, read out of the serial log it already wrote.
#
# Every number here comes from a kernel timestamp the guest printed at the
# moment the thing happened. Nothing is timed from the host, because the host's
# clock includes QEMU's startup, the image being faulted in from the page cache,
# and whatever else the machine was doing - and on an emulated guest with no KVM
# that noise is larger than most of the intervals being measured.
#
# WHAT THESE NUMBERS ARE NOT. This is TCG, software emulation, because the
# developer host has no KVM. Everything below is therefore an upper bound of an
# upper bound, and the ratios between the phases are the useful part rather than
# the absolute values. A number from here must never be quoted as "Kryptik boots
# in N seconds"; it is "this emulated harness reached s6 in N seconds".
set -uo pipefail

LOG="${1:-}"
IMAGE="${2:-}"
[[ -n "$LOG" && -r "$LOG" ]] || {
    cat >&2 <<USAGE
usage: measure.sh SERIAL-LOG [IMAGE]

Reports the phases of a boot from the timestamps in a serial log written by
run-qemu.sh, and the size of the image if you name one.
USAGE
    exit 2
}

C_B=""; C_DIM=""; C_RST=""
if [[ -t 1 ]]; then C_B=$'\033[1m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'; fi

strip() { sed 's/\x1b\[[0-9;]*m//g' "$LOG"; }

# The kernel timestamp on the FIRST line carrying a marker. Printed by the
# kernel as [ ssss.uuuuuu] at the start of the line; a marker echoed by a
# userspace process appears after the console's own prefix, so this looks for
# the marker anywhere and takes the bracketed time from the same line.
at() { # marker -> seconds, or empty
    strip | grep -a -m1 -- "$1" 2>/dev/null \
        | sed -n 's/.*\[ *\([0-9][0-9]*\.[0-9]*\)\].*/\1/p' | head -1
}

# Markers that come from userspace are printed without a kernel prefix on some
# consoles. Fall back to the timestamp of the nearest preceding kernel line.
at_or_before() {
    local t; t="$(at "$1")"
    if [[ -n "$t" ]]; then printf '%s' "$t"; return; fi
    strip | awk -v m="$1" '
        /\[ *[0-9]+\.[0-9]+\]/ { if (match($0, /\[ *[0-9]+\.[0-9]+\]/)) {
            s = substr($0, RSTART+1, RLENGTH-2); gsub(/ /, "", s); last = s } }
        index($0, m) { print last; exit }' 2>/dev/null
}

fmt() { # seconds -> "12.34s", or "—"
    local v="$1"
    [[ -n "$v" ]] || { printf '%s' "—"; return; }
    printf '%.2fs' "$v"
}

delta() { # a b -> b-a
    local a="$1" b="$2"
    [[ -n "$a" && -n "$b" ]] || { printf ''; return; }
    awk -v a="$a" -v b="$b" 'BEGIN{ d=b-a; if (d<0) d=0; printf "%.6f", d }'
}

# The guest's own uptime at each phase, which is the only clock that can see
# the difference between them. The kernel timestamps on the console are a
# fallback for logs written before the payload stamped itself - and they are a
# poor one, because a userspace console write carries no timestamp of its own,
# so every marker resolves to the same preceding kernel line and every phase
# reads 0.00s. That is exactly what the first version of this reported.
t_of() { strip | grep -a -m1 "KRYPTIK_VM_T_$1=" | sed 's/.*=//' | tr -d '\r'; }

K_STAGE1="$(t_of STAGE1)"; [[ -n "$K_STAGE1" ]] || K_STAGE1="$(at_or_before KRYPTIK_VM_STAGE1_OK)"
K_STAGE2="$(t_of STAGE2)"; [[ -n "$K_STAGE2" ]] || K_STAGE2="$(at_or_before KRYPTIK_VM_STAGE2_OK)"
K_S6="$(t_of S6)";         [[ -n "$K_S6"     ]] || K_S6="$(at_or_before KRYPTIK_VM_S6_START)"
K_SMOKE="$(t_of PAYLOAD)"; [[ -n "$K_SMOKE"  ]] || K_SMOKE="$(at_or_before KRYPTIK_VM_SMOKE_BEGIN)"
K_END="$(t_of END)";       [[ -n "$K_END"    ]] || K_END="$(at_or_before KRYPTIK_VM_SMOKE_END)"

if [[ -z "$(t_of STAGE1)" ]]; then
    printf '%snote: this log predates the guest-side timestamps, so the phases below\n' "$C_DIM"
    printf 'come from kernel console times and the userspace ones collapse together.%s\n\n' "$C_RST"
fi
K_POWER="$(at_or_before 'Power down\|Powering off\|reboot: Power down')"

printf '%sboot phases%s  %s\n' "$C_B" "$C_RST" "$LOG"
printf '%s(software-emulated guest, no KVM: upper bounds, useful as ratios)%s\n\n' "$C_DIM" "$C_RST"
printf '  %-34s %s\n' "kernel start -> /init running"        "$(fmt "$K_STAGE1")"
printf '  %-34s %s\n' "/init -> real root, stage 2"          "$(fmt "$(delta "$K_STAGE1" "$K_STAGE2")")"
printf '  %-34s %s\n' "stage 2 -> s6 supervising"            "$(fmt "$(delta "$K_STAGE2" "$K_S6")")"
printf '  %-34s %s\n' "s6 -> first payload line"             "$(fmt "$(delta "$K_S6" "$K_SMOKE")")"
printf '  %-34s %s\n' "  = kernel start -> usable system"    "$(fmt "$K_SMOKE")"
printf '\n'
printf '  %-34s %s\n' "payload (the test suites)"            "$(fmt "$(delta "$K_SMOKE" "$K_END")")"
printf '  %-34s %s\n' "whole run, to power down"             "$(fmt "$K_POWER")"

# --- what the guest said about itself ---------------------------------------
mem_total="$(strip | grep -a -m1 'KRYPTIK_VM_MEM_TOTAL_KB=' | sed 's/.*=//')"
mem_free="$(strip  | grep -a -m1 'KRYPTIK_VM_MEM_AVAIL_KB=' | sed 's/.*=//')"
procs="$(strip     | grep -a -m1 'KRYPTIK_VM_PROCS='        | sed 's/.*=//')"
if [[ -n "$mem_total" || -n "$procs" ]]; then
    printf '\n%sidle cost, measured in the guest before the suites ran%s\n\n' "$C_B" "$C_RST"
    if [[ -n "$mem_total" && -n "$mem_free" ]]; then
        printf '  %-34s %s MiB of %s MiB\n' "memory in use" \
            "$(( (mem_total - mem_free) / 1024 ))" "$(( mem_total / 1024 ))"
    fi
    [[ -n "$procs" ]] && printf '  %-34s %s\n' "processes" "$procs"
fi

# --- image -------------------------------------------------------------------
if [[ -n "$IMAGE" && -r "$IMAGE" ]]; then
    printf '\n%simage%s\n\n' "$C_B" "$C_RST"
    bytes="$(stat -c %s "$IMAGE")"
    # du reports what the file COSTS; stat -c %s reports how big it claims to
    # be. For a sparse image built by mke2fs those differ by gigabytes, and the
    # one that matters for shipping it is the cost.
    used="$(du -B1 "$IMAGE" 2>/dev/null | cut -f1)"
    printf '  %-34s %s MiB\n' "declared size" "$(( bytes / 1048576 ))"
    # The apparent size of a sparse image is the size it was created with; what
    # it costs on disk, and what it would cost to ship, is what is allocated.
    [[ -n "$used" ]] && printf '  %-34s %s MiB\n' "actually allocated" "$(( used / 1048576 ))"
    printf '  %-34s %s\n' "sha256" "$(sha256sum "$IMAGE" | cut -d' ' -f1)"
fi

# A boot that failed is not a boot to quote timings from.
if strip | grep -qa 'KRYPTIK_VM_FAIL'; then
    printf '\n%sNOTE: this log contains a failure marker. The timings above describe\n' "$C_DIM"
    printf 'a run that did not do what it was supposed to.%s\n' "$C_RST"
fi
