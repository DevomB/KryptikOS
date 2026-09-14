#!/usr/bin/env bash
#
# make acceptance: the gates G1-G10 of docs/OVERNIGHT_GOAL.md, run against
# named artifacts in one invocation, with one verdict and a report that ties
# every result to the source revision, the image hashes, the firmware, the
# command, the exit status and the log.
#
#   tools/acceptance.sh [--media-usb IMG] [--media-iso ISO]
#                       [--payload-a DIR] [--payload-b DIR]
#                       [--out DIR] [--export DIR] [--only G3,G8] [--no-host]
#
# Three results, and only one of them is a pass:
#   PASS        the item ran and every check inside it passed
#   FAIL        the item ran and something in it failed
#   INCOMPLETE  the item could not run here - a tool, an artifact, a device
#               or a privilege is missing, or a suite reported 77 - or it
#               was left out by --only. Never a pass.
#
# The verdict is PASS only when every mandatory item is PASS: exit 0. Any
# FAIL: exit 1. No FAIL but an INCOMPLETE mandatory item: exit 2.
#
# Host-side suites (the unit and fixture suites, the compositor tests, the
# chroot proofs) are tagged "host" in the report. They are mandatory - they
# are the regressions this work repaired - but they are not installed-system
# evidence, and the report keeps the two apart: a gate whose only evidence is
# host-side says so.
#
# Every VM driver carries its own positive controls; this script adds one
# more at the boundary: a driver must report at least a minimum number of
# checks passed, so a launcher that starts nothing cannot pass every denial.
#
# --export DIR copies the tested media, their hashes, the trust material, the
# revision, this report and the boot/install/recovery instructions to DIR
# and verifies that the copies hash the same as what was tested (gate G10).
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SELF}/.." && pwd)"
export NO_COLOR=1
# shellcheck source=/dev/null
source "${ROOT}/build/lib/common.sh"
trap - ERR; set +e
[[ -d "${HOME:-/root}/.cargo/bin" ]] && PATH="${HOME:-/root}/.cargo/bin:${PATH}"
export PATH KRYPTIK_ROOT="$ROOT" KRYPTIK_WORK KRYPTIK_SOURCES

MEDIA_USB=""; MEDIA_ISO=""; PAYLOAD_A=""; PAYLOAD_B=""; OUT=""; EXPORT=""; ONLY=""; NOHOST=0
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --media-usb) MEDIA_USB="${2:?}"; shift 2 ;;
        --media-iso) MEDIA_ISO="${2:?}"; shift 2 ;;
        --payload-a) PAYLOAD_A="${2:?}"; shift 2 ;;
        --payload-b) PAYLOAD_B="${2:?}"; shift 2 ;;
        --out)       OUT="${2:?}"; shift 2 ;;
        --export)    EXPORT="${2:?}"; shift 2 ;;
        --only)      ONLY="${2:?}"; shift 2 ;;
        --no-host)   NOHOST=1; shift ;;
        -h|--help)   sed -n '2,36p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

START_TS="$(date +%Y%m%dT%H%M%S)"
OUT="${OUT:-${KRYPTIK_WORK}/acceptance/${START_TS}}"
mkdir -p "$OUT" || die "cannot create ${OUT}"
MARK="${OUT}/.start"; : > "$MARK"
IMGDIR="${KRYPTIK_WORK}/images"
IMG="${SELF}/image"
SYSROOT="${KRYPTIK_WORK}/sysroot"

# ---------------------------------------------------------------- inputs --
newest() { ls -t "$@" 2>/dev/null | head -1; }
[[ -z "$MEDIA_USB" ]] && MEDIA_USB="$(newest "${IMGDIR}"/kryptik-*-usb.img)"
[[ -z "$MEDIA_ISO" ]] && MEDIA_ISO="$(newest "${IMGDIR}"/kryptik-*.iso)"
VER_A=""
if [[ -n "$MEDIA_USB" ]]; then b="$(basename "$MEDIA_USB")"; VER_A="${b#kryptik-}"; VER_A="${VER_A%-usb.img}"; fi
[[ -z "$PAYLOAD_A" && -n "$VER_A" && -d "${IMGDIR}/payload-${VER_A}" ]] && PAYLOAD_A="${IMGDIR}/payload-${VER_A}"
if [[ -z "$PAYLOAD_B" ]]; then
    for d in $(ls -td "${IMGDIR}"/payload-* 2>/dev/null); do
        [[ -d "$d" && "$d" != "$PAYLOAD_A" ]] && { PAYLOAD_B="$d"; break; }
    done
fi
VER_B=""
if [[ -n "$PAYLOAD_B" ]]; then VER_B="$(basename "$PAYLOAD_B")"; VER_B="${VER_B#payload-}"; fi

sha_of() { sha256sum "$1" | cut -c1-64; }
H_USB=""; H_ISO=""
[[ -f "$MEDIA_USB" ]] && H_USB="$(sha_of "$MEDIA_USB")"
[[ -f "$MEDIA_ISO" ]] && H_ISO="$(sha_of "$MEDIA_ISO")"

OVMF_DIR="${KRYPTIK_OVMF_DIR:-/usr/share/OVMF}"
FW="${OVMF_DIR}/OVMF_CODE_4M.secboot.fd"
H_FW=""; [[ -f "$FW" ]] && H_FW="$(sha_of "$FW")"
FW_PKG="$(dpkg-query -W -f='${Package} ${Version}' ovmf 2>/dev/null || echo 'ovmf (version unknown)')"
QEMU_VER="$(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo 'no qemu-system-x86_64')"
KVM="no"; [[ -r /dev/kvm && -w /dev/kvm ]] && KVM="yes"

REV="$(git -c safe.directory='*' -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
REV_DESC="$(git -c safe.directory='*' -C "$ROOT" describe --always --dirty --long 2>/dev/null || echo unknown)"
DIRTY="$(git -c safe.directory='*' -C "$ROOT" status --porcelain 2>/dev/null)"

# --------------------------------------------------------------- results --
R_GATE=(); R_NAME=(); R_MAND=(); R_KIND=(); R_RES=(); R_CHECKS=(); R_RC=(); R_SECS=(); R_LOG=(); R_NOTE=()
wanted() { [[ -z "$ONLY" || ",${ONLY}," == *",$1,"* ]]; }
record() { R_GATE+=("$1"); R_NAME+=("$2"); R_MAND+=("$3"); R_KIND+=("$4"); R_RES+=("$5"); R_CHECKS+=("$6"); R_RC+=("$7"); R_SECS+=("$8"); R_LOG+=("$9"); R_NOTE+=("${10}"); }

# checks_in LOG: "passed/failed" from the driver's own summary line, or "-"
checks_in() {
    local s
    s="$(grep -oE '[0-9]+ passed, [0-9]+ failed' "$1" | tail -1)"
    if [[ -n "$s" ]]; then printf '%s/%s' "${s%% *}" "$(sed -E 's/.* ([0-9]+) failed/\1/' <<<"$s")"; return; fi
    s="$(grep -oE 'All [0-9]+ checks passed' "$1" | tail -1)"
    if [[ -n "$s" ]]; then printf '%s/0' "$(grep -oE '[0-9]+' <<<"$s")"; return; fi
    s="$(grep -oE '[0-9]+ check\(s\) failed, [0-9]+ passed' "$1" | tail -1)"
    if [[ -n "$s" ]]; then printf '%s/%s' "$(sed -E 's/.*, ([0-9]+) passed/\1/' <<<"$s")" "${s%% *}"; return; fi
    s="$(grep -oE '[0-9]+ suites: [0-9]+ passed, [0-9]+ failed, [0-9]+ did not run' "$1" | tail -1)"
    if [[ -n "$s" ]]; then printf '%s/%s' "$(sed -E 's/.*: ([0-9]+) passed.*/\1/' <<<"$s")" "$(sed -E 's/.*, ([0-9]+) failed.*/\1/' <<<"$s")"; return; fi
    s="$(grep -oE 'passed [0-9]+, failed [0-9]+' "$1" | tail -1)"
    if [[ -n "$s" ]]; then printf '%s/%s' "$(sed -E 's/passed ([0-9]+).*/\1/' <<<"$s")" "$(sed -E 's/.*failed ([0-9]+)/\1/' <<<"$s")"; return; fi
    printf '%s' "-"
}

# item GATE NAME M|O host|vm|post MINPASS FN [PREREQ-FN]
#   PREREQ-FN prints a reason when the item cannot run here.
item() {
    local gate="$1" name="$2" mand="$3" kind="$4" minp="$5" fn="$6" pre="${7:-}"
    local log="${OUT}/${gate//\//-}-${name}.log" rc res checks="-" note="" reason="" t0
    if ! wanted "$gate"; then record "$gate" "$name" "$mand" "$kind" INCOMPLETE "-" "-" 0 "-" "not run (--only ${ONLY})"; return; fi
    printf '\n==> [%s] %s\n' "$gate" "$name"
    [[ -n "$pre" ]] && reason="$("$pre" 2>&1)"
    if [[ -n "$reason" ]]; then
        printf 'INCOMPLETE: %s\n' "$reason" | tee "$log"
        record "$gate" "$name" "$mand" "$kind" INCOMPLETE "-" 77 0 "$log" "$reason"; return
    fi
    t0=$SECONDS
    "$fn" 2>&1 | tee "$log"
    rc="${PIPESTATUS[0]}"
    checks="$(checks_in "$log")"
    if [[ "$rc" -eq 77 ]]; then res=INCOMPLETE; note="the suite reported 77: a missing dependency, not a result"
    elif [[ "$rc" -ne 0 ]]; then res=FAIL; note="exit ${rc}"
    else
        res=PASS
        if [[ "$minp" -gt 0 ]]; then
            local p="${checks%%/*}"
            if [[ "$checks" == "-" || "$p" -lt "$minp" ]]; then
                res=FAIL; note="exit 0 but only ${p:-no} checks reported passed (minimum ${minp}): the driver did not exercise what it claims"
            fi
        fi
    fi
    printf -- '-- %s: %s (exit %s, %ss, checks %s)%s\n' "$name" "$res" "$rc" "$((SECONDS - t0))" "$checks" "${note:+ - $note}"
    record "$gate" "$name" "$mand" "$kind" "$res" "$checks" "$rc" "$((SECONDS - t0))" "$log" "$note"
}

# ------------------------------------------------------------- prereqs --
need_root()    { [[ "$EUID" -eq 0 ]] || echo "needs root (the chroot and the VM disks)"; }
need_sysroot() { [[ -x "${SYSROOT}/usr/bin/gcc" ]] || echo "no built sysroot at ${SYSROOT} (make system)"; }
need_usb()     { [[ -f "$MEDIA_USB" ]] || echo "no USB image (make media)"; }
need_iso()     { [[ -f "$MEDIA_ISO" ]] || echo "no ISO (make media)"; }
need_vm() {
    local r t
    r="$(need_root)"; [[ -n "$r" ]] && { echo "$r"; return; }
    r="$(need_usb)"; [[ -n "$r" ]] && { echo "$r"; return; }
    have qemu-system-x86_64 || { echo "no qemu-system-x86_64"; return; }
    [[ -f "$FW" ]] || { echo "no OVMF firmware at ${FW}"; return; }
    [[ "$KVM" == yes ]] || { echo "no usable /dev/kvm"; return; }
    for t in sfdisk python3 openssl truncate; do have "$t" || { echo "missing tool: $t"; return; }; done
}
need_vm_iso()  { local r; r="$(need_vm)"; [[ -n "$r" ]] && { echo "$r"; return; }; need_iso; }
need_enrolled() {
    local r; r="$(need_vm)"; [[ -n "$r" ]] && { echo "$r"; return; }
    [[ -f "${KRYPTIK_WORK}/keys/sb/vars/enrolled.fd" ]] || echo "no enrolled variable store (the ovmf-vars item did not produce it)"
}
need_ms() {
    local r; r="$(need_vm)"; [[ -n "$r" ]] && { echo "$r"; return; }
    [[ -f "${OVMF_DIR}/OVMF_VARS_4M.ms.fd" ]] || echo "no Microsoft-keyed variable store at ${OVMF_DIR}/OVMF_VARS_4M.ms.fd"
}
need_update() {
    local r; r="$(need_vm)"; [[ -n "$r" ]] && { echo "$r"; return; }
    [[ -n "$PAYLOAD_A" && -f "${PAYLOAD_A}/manifest" ]] || { echo "no payload for release A (${PAYLOAD_A:-none}); make media writes images/payload-VERSION"; return; }
    [[ -n "$PAYLOAD_B" && -f "${PAYLOAD_B}/manifest" ]] || { echo "no second release to update to: make media KRYPTIK_VERSION=... once more"; return; }
    [[ "$VER_A" != "$VER_B" ]] || echo "release A and B carry the same version (${VER_A})"
}
need_cargo()   { have cargo || echo "no cargo on PATH"; }
need_sources() { [[ -d "$KRYPTIK_SOURCES" && -f "${ROOT}/sources.lock" ]] || echo "no sources directory or sources.lock"; }
need_export()  { [[ -n "$EXPORT" ]] || echo "no --export DIR given (EXPORT=... for make acceptance)"; }

# --------------------------------------------------------------- items --
it_revision() {
    echo "revision : ${REV}"
    echo "describe : ${REV_DESC}"
    echo "branch   : $(git -c safe.directory='*' -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
    echo "tree     : ${ROOT}"
    printf 'revision=%s\ndescribe=%s\ntree=%s\ndate=%s\n' "$REV" "$REV_DESC" "$ROOT" "$(date -Iseconds)" > "${OUT}/REVISION.txt"
    if [[ -n "$DIRTY" ]]; then
        echo "the tree is not clean; what was tested is not what the revision names:"
        printf '  %s\n' "$DIRTY"
        return 1
    fi
    echo "tree is clean: the revision names exactly what was tested"
}
it_compositor_sources() {
    local ok=0 p
    for p in compositor/wlproxy/src/main.rs compositor/zoneid/src/palette.rs tools/desktop/dwl-zone-borders.py build/desktop/zone-colours.h compartments/zones; do
        if [[ -e "${ROOT}/${p}" ]]; then echo "  present  ${p}"; else echo "  MISSING  ${p}"; ok=1; fi
    done
    echo "-- the colour table dwl was built with matches the shipped zones"
    python3 "${ROOT}/tools/desktop/gen-zone-colours.py" --check "${ROOT}/build/desktop/zone-colours.h" "${ROOT}/compartments/zones" || ok=1
    return "$ok"
}
it_sources_lock() {
    echo "-- every build input matches sources.lock (offline)"
    ( cd "$KRYPTIK_SOURCES" && sha256sum --check --quiet --strict "${ROOT}/sources.lock" ) || return 1
    echo "  ok: $(grep -c . "${ROOT}/sources.lock") entries verified"
}
it_media_hashes() {
    local ok=0 f h
    for f in "$MEDIA_USB" "$MEDIA_ISO"; do
        [[ -f "$f" ]] || continue
        h="$(sha_of "$f")"
        printf '%s  %s\n' "$h" "$f"
        if [[ -f "${f}.sha256" ]]; then
            if [[ "$(cut -c1-64 "${f}.sha256")" == "$h" ]]; then echo "  matches ${f}.sha256"; else echo "  DOES NOT MATCH ${f}.sha256"; ok=1; fi
        else echo "  no ${f}.sha256 sidecar"; ok=1; fi
    done
    [[ -n "$PAYLOAD_A" ]] && { echo "payload A: ${PAYLOAD_A}"; sed -n '1,12p' "${PAYLOAD_A}/manifest"; }
    [[ -n "$PAYLOAD_B" ]] && { echo "payload B: ${PAYLOAD_B}"; sed -n '1,12p' "${PAYLOAD_B}/manifest"; }
    return "$ok"
}
it_host_suites()   { "${SELF}/run-tests.sh" --strict; }
it_libc_unwind()   { env KRYPTIK_ROOT="$ROOT" KRYPTIK_WORK="$KRYPTIK_WORK" KRYPTIK_SOURCES="$KRYPTIK_SOURCES" "${ROOT}/build/stages/03-chroot-prep.sh" run /kryptik/tools/test-libc-unwind.sh; }
it_userspace()     { "${SELF}/test-userspace-smoke.sh"; }
it_artifacts()     { "${SELF}/check-artifact-hardening.sh" "$SYSROOT" --json "${OUT}/artifact-hardening.json"; }
it_kernel_config() { "${SELF}/validate-kernel-config.sh" --boot && "${SELF}/validate-kernel-config.sh" --hardened; }
it_ovmf_vars()     { "${IMG}/ovmf-vars.sh"; }
it_smoke_usb()     { "${IMG}/media-smoke.sh" --usb "$MEDIA_USB" --vars clean; }
it_smoke_iso()     { "${IMG}/media-smoke.sh" --iso "$MEDIA_ISO" --vars clean; }
it_smoke_sb()      { "${IMG}/media-smoke.sh" --usb "$MEDIA_USB" --vars enrolled; }
it_refused()       { "${IMG}/media-smoke.sh" --usb "$MEDIA_USB" --vars ms --expect-refused; }
it_install()       { "${IMG}/install-test.sh" --usb "$MEDIA_USB" --vars clean; }
it_state()         { "${IMG}/state-test.sh" --usb "$MEDIA_USB"; }
it_integrity()     { "${IMG}/integrity-test.sh" --usb "$MEDIA_USB"; }
it_zones()         { "${IMG}/zones-test.sh" --usb "$MEDIA_USB"; }
it_gui()           { "${IMG}/gui-test.sh" --usb "$MEDIA_USB"; }
it_update()        { "${IMG}/update-test.sh" --usb-a "$MEDIA_USB" --payload-a "$PAYLOAD_A" --payload-b "$PAYLOAD_B" --vars clean; }

# Every boot this run started, read back from the runner's own record: the
# firmware image, a variable store, disks and a serial line - and none of
# -kernel, -initrd, -append, a shared host directory or a FAT-from-directory.
it_firmware_only() {
    local n=0 bad=0 f
    while IFS= read -r f; do
        n=$((n + 1))
        if ! grep -q 'if=pflash' "$f" || ! grep -q 'OVMF_CODE_4M.secboot.fd' "$f"; then echo "  no firmware image in: $f"; bad=$((bad + 1)); continue; fi
        if grep -qE -- '(^| )-(kernel|initrd|append|hda|hdb|virtfs|fsdev)( |$)|file=fat:|-nic .*smb=' "$f"; then echo "  host-side boot input in: $f"; bad=$((bad + 1)); continue; fi
    done < <(find "${KRYPTIK_WORK}/logs" -name 'ovmf-serial.*.log.cmd' -newer "$MARK" 2>/dev/null | sort)
    echo "boots recorded during this run: ${n}; with host-side boot inputs or without firmware: ${bad}"
    [[ "$n" -gt 0 ]] || { echo "no boot was recorded: nothing to attest"; return 1; }
    [[ "$bad" -eq 0 ]]
}

# ------------------------------------------------------------ the run --
echo "Kryptik acceptance ${START_TS}"
echo "  tree      : ${ROOT} @ ${REV_DESC}"
echo "  media usb : ${MEDIA_USB:-none}${H_USB:+ sha256 $H_USB}"
echo "  media iso : ${MEDIA_ISO:-none}${H_ISO:+ sha256 $H_ISO}"
echo "  payload A : ${PAYLOAD_A:-none}   payload B: ${PAYLOAD_B:-none}"
echo "  firmware  : ${FW} ${H_FW:+sha256 $H_FW} (${FW_PKG}); ${QEMU_VER}; kvm=${KVM}"
echo "  output    : ${OUT}"

item G1 revision            M host 0 it_revision
item G1 compositor-sources  M host 0 it_compositor_sources
item G1 sources-lock        M host 0 it_sources_lock need_sources
item G1 media-hashes        M host 0 it_media_hashes need_usb
if [[ "$NOHOST" -eq 0 ]]; then
item G2 host-suites         M host 0 it_host_suites need_cargo
fi
item G2 libc-unwind         M host 0 it_libc_unwind need_sysroot
item G2 userspace-smoke     M host 0 it_userspace need_sysroot
item G2 artifact-hardening  M host 0 it_artifacts need_sysroot
item G2 kernel-config       M host 0 it_kernel_config need_sources
item G3 media-smoke-usb     M vm  25 it_smoke_usb need_vm
item G3 media-smoke-iso     M vm  25 it_smoke_iso need_vm_iso
item G4 install-test        M vm  10 it_install need_vm
item G4 state-test          M vm  10 it_state need_vm
item G5 ovmf-vars           M host 0 it_ovmf_vars need_usb
item G5 media-smoke-secureboot M vm 25 it_smoke_sb need_enrolled
item G5 media-refused-foreign-keys M vm 5 it_refused need_ms
item G5 integrity-test      M vm   8 it_integrity need_enrolled
item G6/G7 zones-test       M vm  10 it_zones need_vm
item G8 gui-test            M vm  25 it_gui need_vm
item G9 update-test         M vm  10 it_update need_update
item G3 firmware-only-boot  M post 0 it_firmware_only

# ------------------------------------------------------------- report --
KERNEL_LINE="$(grep -h -o 'KRYPTIK_SMOKE: kernel=[^ ]*' "${OUT}"/G3-media-smoke-usb.log 2>/dev/null | head -1 | sed 's/KRYPTIK_SMOKE: kernel=//')"
verdict_of() {
    local i fail=0 inc=0
    for i in "${!R_GATE[@]}"; do
        [[ "${R_MAND[$i]}" == M ]] || continue
        case "${R_RES[$i]}" in FAIL) fail=1 ;; INCOMPLETE) inc=1 ;; esac
    done
    if [[ "$fail" -eq 1 ]]; then echo FAIL; elif [[ "$inc" -eq 1 ]]; then echo INCOMPLETE; else echo PASS; fi
}
write_report() {
    local v="$1" i g gs any
    {
        echo "# Kryptik acceptance ${START_TS}"
        echo
        echo "Verdict: **${v}**"
        echo
        echo "| what | value |"
        echo "|---|---|"
        echo "| source revision | \`${REV}\` (${REV_DESC}) |"
        echo "| tree | ${ROOT} |"
        echo "| USB medium | ${MEDIA_USB:-none}${H_USB:+ (sha256 \`$H_USB\`)} |"
        echo "| ISO | ${MEDIA_ISO:-none}${H_ISO:+ (sha256 \`$H_ISO\`)} |"
        echo "| release A / B | ${VER_A:-none} / ${VER_B:-none} (${PAYLOAD_A:-no payload}; ${PAYLOAD_B:-no payload}) |"
        echo "| kernel (as the medium reported it) | ${KERNEL_LINE:-not observed} |"
        echo "| firmware | ${FW}${H_FW:+ (sha256 \`$H_FW\`)}; ${FW_PKG} |"
        echo "| QEMU | ${QEMU_VER}; kvm=${KVM} |"
        echo "| host | $(uname -srmo) |"
        echo "| run as | uid ${EUID} on $(hostname) at $(date -Iseconds) |"
        echo "| logs | ${OUT} |"
        echo
        echo "Results: PASS, FAIL, or INCOMPLETE (could not run here; never a pass)."
        echo "Kind: host = a host-side or chroot suite, not installed-system evidence; vm = the installed system or the medium under firmware; post = read from this run's own records."
        echo
        echo "| gate | item | mandatory | kind | result | checks passed/failed | exit | seconds | log | note |"
        echo "|---|---|---|---|---|---|---|---|---|---|"
        for i in "${!R_GATE[@]}"; do
            printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' "${R_GATE[$i]}" "${R_NAME[$i]}" "$([[ "${R_MAND[$i]}" == M ]] && echo yes || echo no)" "${R_KIND[$i]}" "${R_RES[$i]}" "${R_CHECKS[$i]}" "${R_RC[$i]}" "${R_SECS[$i]}" "$(basename "${R_LOG[$i]}")" "${R_NOTE[$i]}"
        done
        echo
        echo "## Gates"
        echo
        for g in G1 G2 G3 G4 G5 G6/G7 G8 G9 G10; do
            gs="PASS"; any=0
            for i in "${!R_GATE[@]}"; do
                [[ "${R_GATE[$i]}" == "$g" ]] || continue; any=1
                case "${R_RES[$i]}" in FAIL) gs=FAIL ;; INCOMPLETE) [[ "$gs" == FAIL ]] || gs=INCOMPLETE ;; esac
            done
            [[ "$any" -eq 1 ]] || gs="INCOMPLETE (no item)"
            echo "- ${g}: ${gs}"
        done
        echo
        echo "Exit status: 0 only for PASS; 1 for FAIL; 2 for INCOMPLETE."
    } > "${OUT}/REPORT.md"
    {
        printf 'gate\titem\tmandatory\tkind\tresult\tchecks\texit\tseconds\tlog\tnote\n'
        for i in "${!R_GATE[@]}"; do
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${R_GATE[$i]}" "${R_NAME[$i]}" "${R_MAND[$i]}" "${R_KIND[$i]}" "${R_RES[$i]}" "${R_CHECKS[$i]}" "${R_RC[$i]}" "${R_SECS[$i]}" "${R_LOG[$i]}" "${R_NOTE[$i]}"
        done
    } > "${OUT}/results.tsv"
}

# ------------------------------------------------------------- export --
it_export() {
    local d="$EXPORT" ok=0 f want got
    mkdir -p "$d" || { echo "cannot create ${d}"; return 1; }
    echo "exporting to ${d}"
    for f in "$MEDIA_USB" "$MEDIA_ISO"; do
        [[ -f "$f" ]] || continue
        cp --sparse=always "$f" "${d}/" || ok=1
        [[ -f "${f}.sha256" ]] && cp "${f}.sha256" "${d}/"
    done
    # root.json from release A's payload, not images/root.json: a second
    # release built after A overwrites the latter with its own record.
    if [[ -n "$PAYLOAD_A" && -f "${PAYLOAD_A}/root.json" ]]; then cp "${PAYLOAD_A}/root.json" "${d}/"
    elif [[ -f "${IMGDIR}/root.json" ]]; then cp "${IMGDIR}/root.json" "${d}/"; fi
    for f in "${KRYPTIK_WORK}/keys/sb/kryptik-sb.crt" "${KRYPTIK_WORK}/keys/sb/kryptik-sb.der"; do
        if [[ -f "$f" ]]; then cp "$f" "${d}/"; else echo "  missing trust material: $f"; ok=1; fi
    done
    if [[ -n "$PAYLOAD_A" && -f "${PAYLOAD_A}/manifest" ]]; then
        cp "${PAYLOAD_A}/manifest" "${d}/manifest-${VER_A}"
        [[ -f "${PAYLOAD_A}/manifest.sig" ]] && cp "${PAYLOAD_A}/manifest.sig" "${d}/manifest-${VER_A}.sig"
    fi
    if [[ -n "$PAYLOAD_B" && -f "${PAYLOAD_B}/manifest" ]]; then
        cp "${PAYLOAD_B}/manifest" "${d}/manifest-${VER_B}"
        [[ -f "${PAYLOAD_B}/manifest.sig" ]] && cp "${PAYLOAD_B}/manifest.sig" "${d}/manifest-${VER_B}.sig"
    fi
    if [[ -f "${ROOT}/docs/BOOT_INSTALL_RECOVER.md" ]]; then cp "${ROOT}/docs/BOOT_INSTALL_RECOVER.md" "${d}/INSTRUCTIONS.md"; else echo "  no docs/BOOT_INSTALL_RECOVER.md to ship"; ok=1; fi
    cp "${OUT}/REVISION.txt" "${d}/" 2>/dev/null
    mkdir -p "${d}/acceptance-logs" && cp "${OUT}"/*.log "${OUT}/results.tsv" "${d}/acceptance-logs/" 2>/dev/null
    echo "-- the copies hash the same as what was tested"
    for f in "$MEDIA_USB" "$MEDIA_ISO"; do
        [[ -f "$f" ]] || continue
        want="$(sha_of "$f")"; got="$(sha_of "${d}/$(basename "$f")")"
        if [[ "$want" == "$got" ]]; then echo "  ok  $(basename "$f") ${got}"; else echo "  MISMATCH $(basename "$f"): tested ${want}, exported ${got}"; ok=1; fi
    done
    ( cd "$d" && sha256sum ./*.img ./*.iso ./*.crt ./*.der ./root.json 2>/dev/null ) > "${d}/SHA256SUMS"
    echo "  wrote ${d}/SHA256SUMS"
    return "$ok"
}
V="$(verdict_of)"
write_report "$V"
if [[ -n "$EXPORT" ]] || wanted G10; then
    item G10 export M host 0 it_export need_export
    V="$(verdict_of)"
    write_report "$V"
    if [[ -n "$EXPORT" && -d "$EXPORT" ]]; then
        cp "${OUT}/REPORT.md" "${EXPORT}/ACCEPTANCE-REPORT.md"
        {
            echo "Kryptik ${VER_A:-unknown}"
            echo "acceptance : ${V} (${START_TS}; see ACCEPTANCE-REPORT.md)"
            echo "revision   : ${REV}"
            echo "usb image  : $(basename "${MEDIA_USB:-none}") sha256 ${H_USB:-none}"
            echo "iso        : $(basename "${MEDIA_ISO:-none}") sha256 ${H_ISO:-none}"
            echo "firmware   : ${FW_PKG} (${FW})"
            echo "kernel     : ${KERNEL_LINE:-not observed}"
            echo "trust      : kryptik-sb.crt / kryptik-sb.der (the developer Secure Boot key, a test anchor)"
            echo "read       : INSTRUCTIONS.md"
        } > "${EXPORT}/RELEASE.txt"
    fi
fi

echo
echo "================================================================"
sed -n '/^| gate/,/^$/p' "${OUT}/REPORT.md"
echo "Verdict: ${V}   (report: ${OUT}/REPORT.md)"
# The VM drivers each make 12 GB disks and clones under work/vm. The
# transcripts carry the evidence; the disks are worth keeping only when an
# item failed and someone may want to look inside. On a WSL host every byte
# written into them grows the virtual disk file on the Windows side and never
# comes back by itself, so a run in which everything passed removes them all
# here. (Removing after each passing item, as an earlier version did, took
# the disks of items that had failed EARLIER in the same run with them.)
if [[ "$V" == PASS ]]; then
    rm -f "${KRYPTIK_WORK}"/vm/*.img "${KRYPTIK_WORK}"/vm/*.fd "${KRYPTIK_WORK}"/vm/*.pristine 2>/dev/null
    rm -rf "${KRYPTIK_WORK}"/vm/bad 2>/dev/null
    echo "VM disks removed (every item passed; the transcripts under ${KRYPTIK_WORK}/logs are the evidence)"
fi
case "$V" in PASS) exit 0 ;; FAIL) exit 1 ;; *) exit 2 ;; esac
