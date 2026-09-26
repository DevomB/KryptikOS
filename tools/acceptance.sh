#!/usr/bin/env bash
# make acceptance: run the acceptance suites against the built media and write
# REPORT.md, with one verdict.
#
#   tools/acceptance.sh [--media-usb IMG] [--media-iso ISO]
#                       [--payload-a DIR] [--payload-b DIR]
#                       [--out DIR] [--export DIR] [--only boot,desktop] [--no-host]
#                       [--merge DIR]...
#
#   --only SUITES  run only these suites
#   --no-host      skip the host test suites (run-tests.sh)
#   --export DIR   copy the tested media, hashes, trust material, report and
#                  instructions to DIR, and check the copies hash as tested
#   --merge DIR    judge parts run with --only on other machines: each item's
#                  row comes from the results.tsv under DIR; only the items
#                  done after the suites (firmware record, export) run here
#
# Each item is PASS, FAIL or INCOMPLETE (could not run here, exit 77, or not
# selected; never a pass). "host" items are not installed-system evidence.
# Exit 0 when every mandatory item passed, 1 on any FAIL, 2 otherwise.
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SELF}/.." && pwd)"
export NO_COLOR=1
# shellcheck source=/dev/null
source "${ROOT}/build/lib/common.sh"
trap - ERR; set +e
# sudo resets PATH and HOME, and rustup installs per user: take cargo from
# $HOME or else the sudo user's home, and point RUSTUP_HOME there too.
for h in "${HOME:-/root}" "$(getent passwd "${SUDO_USER:-}" 2>/dev/null | cut -d: -f6)"; do
    [[ -n "$h" && -d "$h/.cargo/bin" ]] || continue
    PATH="$h/.cargo/bin:${PATH}"
    [[ -z "${RUSTUP_HOME:-}" && -d "$h/.rustup" ]] && export RUSTUP_HOME="$h/.rustup"
    break
done
export PATH KRYPTIK_ROOT="$ROOT" KRYPTIK_WORK KRYPTIK_SOURCES

MEDIA_USB=""; MEDIA_ISO=""; PAYLOAD_A=""; PAYLOAD_B=""; OUT=""; EXPORT=""; ONLY=""; NOHOST=0; MERGE=()
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
        --merge)     MERGE+=("${2:?}"); shift 2 ;;
        -h|--help)   sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ "${#MERGE[@]}" -eq 0 || -z "$ONLY" ]] || die "--merge and --only do not go together"

START_TS="$(date +%Y%m%dT%H%M%S)"
OUT="${OUT:-${KRYPTIK_WORK}/acceptance/${START_TS}}"
mkdir -p "$OUT" || die "cannot create ${OUT}"
MARK="${OUT}/.start"; : > "$MARK"

# The parts' results, and everything beside them (logs, boot records,
# REVISION.txt) copied here, where the report and the export look.
PARTS=()
if [[ "${#MERGE[@]}" -gt 0 ]]; then
    mapfile -t PARTS < <(find "${MERGE[@]}" -name results.tsv | sort)
    [[ "${#PARTS[@]}" -gt 0 ]] || die "no results.tsv under ${MERGE[*]}"
    for f in "${PARTS[@]}"; do
        find "$(dirname "$f")" -maxdepth 1 -type f ! -name results.tsv ! -name REPORT.md ! -name identity -exec cp -n -t "$OUT" {} +
    done
fi
IMGDIR="${KRYPTIK_WORK}/images"
IMG="${SELF}/image"
SYSROOT="${KRYPTIK_WORK}/sysroot"

# ---------------------------------------------------------------- inputs --
# The release under test is the named medium, or the highest version on hand
# (by version, not mtime); its payload is B. A is the highest lower version
# with both a payload and a USB medium: the update test installs A, applies B.
# Explicit --media-*/--payload-* win.
version_of_medium()  { local b; b="$(basename "$1")"; b="${b#kryptik-}"; printf '%s' "${b%-usb.img}"; }
version_of_payload() { local b; b="$(basename "$1")"; printf '%s' "${b#payload-}"; }
if [[ -z "$MEDIA_USB" ]]; then
    media=()
    for f in "${IMGDIR}"/kryptik-*-usb.img; do [[ -f "$f" ]] && media+=("$(version_of_medium "$f")"); done
    if [[ "${#media[@]}" -gt 0 ]]; then
        mapfile -t media < <(printf '%s\n' "${media[@]}" | sort -V)
        MEDIA_USB="${IMGDIR}/kryptik-${media[-1]}-usb.img"
    fi
fi
VER=""; [[ -n "$MEDIA_USB" ]] && VER="$(version_of_medium "$MEDIA_USB")"
# Only this release's own ISO; without it the ISO items are INCOMPLETE.
[[ -z "$MEDIA_ISO" && -n "$VER" && -f "${IMGDIR}/kryptik-${VER}.iso" ]] && MEDIA_ISO="${IMGDIR}/kryptik-${VER}.iso"
[[ -z "$PAYLOAD_B" && -n "$VER" && -d "${IMGDIR}/payload-${VER}" ]] && PAYLOAD_B="${IMGDIR}/payload-${VER}"
VER_B=""; [[ -n "$PAYLOAD_B" ]] && VER_B="$(version_of_payload "$PAYLOAD_B")"
if [[ -z "$PAYLOAD_A" && -n "$VER_B" ]]; then
    versions=()
    for d in "${IMGDIR}"/payload-*; do [[ -d "$d" ]] && versions+=("$(version_of_payload "$d")"); done
    mapfile -t versions < <(printf '%s\n' "${versions[@]}" "$VER_B" | sort -uV)
    idx=-1
    for ((i = 0; i < ${#versions[@]}; i++)); do [[ "${versions[$i]}" == "$VER_B" ]] && idx=$i; done
    for ((i = idx - 1; i >= 0; i--)); do
        [[ -f "${IMGDIR}/kryptik-${versions[$i]}-usb.img" ]] || continue
        PAYLOAD_A="${IMGDIR}/payload-${versions[$i]}"
        break
    done
fi
VER_A=""; [[ -n "$PAYLOAD_A" ]] && VER_A="$(version_of_payload "$PAYLOAD_A")"
MEDIA_USB_A=""; [[ -n "$VER_A" && -f "${IMGDIR}/kryptik-${VER_A}-usb.img" ]] && MEDIA_USB_A="${IMGDIR}/kryptik-${VER_A}-usb.img"

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

# A part of a split run writes down what it tested and what it ran on. The
# merge takes only parts that tested this revision on these media and ran on
# one firmware and one QEMU, and its report names theirs: the merging machine
# boots nothing, and its packages may be newer than the parts' were.
tested() { printf 'revision %s (%s)\nusb %s\niso %s\n' "$REV" "$REV_DESC" "$H_USB" "$H_ISO"; }
ran_on() { printf 'firmware-sha256 %s\nfirmware-package %s\nqemu %s\nkvm %s\n' "$H_FW" "$FW_PKG" "$QEMU_VER" "$KVM"; }
parts_disagree() {   # the first part that tested or ran on something else, and what
    local f d id first="" k
    for f in "${PARTS[@]}"; do
        d="$(dirname "$f")"; id="${d}/identity"
        if [[ ! -f "$id" ]]; then echo "the part in ${d} has no identity"; return; fi
        if [[ "$(sed -n 1,3p "$id")" != "$(tested)" ]]; then echo "the part in ${d} tested $(sed -n 1,3p "$id" | tr '\n' ';')"; return; fi
        for k in firmware-sha256 firmware-package qemu kvm; do
            grep -q "^${k} " "$id" || { echo "the part in ${d} does not say its ${k}"; return; }
        done
        if [[ -z "$first" ]]; then
            first="$d"
        elif [[ "$(sed -n '4,$p' "$id")" != "$(sed -n '4,$p' "${first}/identity")" ]]; then
            echo "the part in ${d} ran on $(sed -n '4,$p' "$id" | tr '\n' ';') but the part in ${first} on $(sed -n '4,$p' "${first}/identity" | tr '\n' ';')"; return
        fi
    done
}
if [[ -n "$ONLY" ]]; then
    { tested; ran_on; } > "${OUT}/identity"
elif [[ "${#PARTS[@]}" -gt 0 ]]; then
    disagree="$(parts_disagree)"
    [[ -z "$disagree" ]] || die "not one run: ${disagree}; this merge tests $(tested | tr '\n' ';')"
    id="$(dirname "${PARTS[0]}")/identity"
    H_FW="$(sed -n 's/^firmware-sha256 //p' "$id")"; FW_PKG="$(sed -n 's/^firmware-package //p' "$id")"
    QEMU_VER="$(sed -n 's/^qemu //p' "$id")"; KVM="$(sed -n 's/^kvm //p' "$id")"
fi

# --------------------------------------------------------------- results --
R_SUITE=(); R_NAME=(); R_MAND=(); R_KIND=(); R_RES=(); R_CHECKS=(); R_RC=(); R_SECS=(); R_LOG=(); R_NOTE=()
wanted() { [[ -z "$ONLY" || ",${ONLY}," == *",$1,"* ]]; }
record() { R_SUITE+=("$1"); R_NAME+=("$2"); R_MAND+=("$3"); R_KIND+=("$4"); R_RES+=("$5"); R_CHECKS+=("$6"); R_RC+=("$7"); R_SECS+=("$8"); R_LOG+=("$9"); R_NOTE+=("${10}"); }

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

# item SUITE NAME M|O host|vm|post MINPASS FN [PREREQ-FN]
#   MINPASS: passed checks the driver must report, so a launcher that starts
#   nothing cannot pass every denial. PREREQ-FN prints why the item cannot run.
item() {
    local suite="$1" name="$2" mand="$3" kind="$4" minp="$5" fn="$6" pre="${7:-}"
    local log="${OUT}/${suite}-${name}.log" rc res checks="-" note="" reason="" t0
    if ! wanted "$suite"; then record "$suite" "$name" "$mand" "$kind" INCOMPLETE "-" "-" 0 "-" "not run (--only ${ONLY})"; return; fi
    if [[ "${#PARTS[@]}" -gt 0 && "$kind" != post ]]; then merged "$suite" "$name" "$mand" "$kind"; return; fi
    printf '\n==> [%s] %s\n' "$suite" "$name"
    [[ -n "$pre" ]] && reason="$("$pre" 2>&1)"
    if [[ -n "$reason" ]]; then
        printf 'INCOMPLETE: %s\n' "$reason" | tee "$log"
        record "$suite" "$name" "$mand" "$kind" INCOMPLETE "-" 77 0 "$log" "$reason"; return
    fi
    t0=$SECONDS
    "$fn" 2>&1 | tee "$log"
    rc="${PIPESTATUS[0]}"
    checks="$(checks_in "$log")"
    if [[ "$rc" -eq 77 ]]; then res=INCOMPLETE; note="the suite reported 77: a missing dependency, not a result"
    elif [[ "$rc" -ne 0 ]]; then res=FAIL; note="exit ${rc}"
    else
        res=PASS
        local p="${checks%%/*}" f="${checks##*/}"
        if [[ "$checks" != "-" && "$f" -gt 0 ]]; then
            res=FAIL; note="exit 0 but its own summary counts ${f} failed"
        elif [[ "$minp" -gt 0 && ( "$checks" == "-" || "$p" -lt "$minp" ) ]]; then
            res=FAIL; note="exit 0 but only ${p:-no} checks reported passed (minimum ${minp}): the driver did not exercise what it claims"
        fi
    fi
    printf -- '-- %s: %s (exit %s, %ss, checks %s)%s\n' "$name" "$res" "$rc" "$((SECONDS - t0))" "$checks" "${note:+ - $note}"
    record "$suite" "$name" "$mand" "$kind" "$res" "$checks" "$rc" "$((SECONDS - t0))" "$log" "$note"
}

# The row of every part that ran the item. A part records what it left to the
# others as "not run (--only ...)"; an item no part ran is INCOMPLETE.
merged() {
    local suite="$1" name="$2" mand="$3" kind="$4" f n=0 s i res checks rc secs log note
    for f in "${PARTS[@]}"; do
        while IFS=$'\t' read -r s i _ _ res checks rc secs log note; do
            [[ "$s" == "$suite" && "$i" == "$name" && "$note" != "not run (--only "* ]] || continue
            # A row cut short or carrying another word is never a pass.
            if [[ ! "$res" =~ ^(PASS|FAIL|INCOMPLETE)$ || ! "$secs" =~ ^[0-9]+$ ]]; then
                res=INCOMPLETE; secs=0; note="a malformed row in ${f}"
            fi
            [[ "$log" == - ]] || log="${OUT}/${log##*/}"
            record "$suite" "$name" "$mand" "$kind" "$res" "$checks" "$rc" "$secs" "$log" "$note"
            n=$((n + 1))
        done < <(tail -n +2 "$f")
    done
    [[ "$n" -gt 0 ]] || record "$suite" "$name" "$mand" "$kind" INCOMPLETE "-" "-" 0 "-" "no part of the run reported it"
}

# ------------------------------------------------------------- prereqs --
need_host()    { if [[ "$NOHOST" -eq 1 ]]; then echo "not run (--no-host)"; else need_cargo; fi; }
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
    [[ -n "$PAYLOAD_B" && -f "${PAYLOAD_B}/manifest" ]] || { echo "no payload for the release under test (${VER:-unknown}); make media writes images/payload-VERSION"; return; }
    [[ -n "$PAYLOAD_A" && -f "${PAYLOAD_A}/manifest" ]] || { echo "no previous release to update from: none below ${VER_B} has a payload and a USB medium (make media KRYPTIK_VERSION=<older> once more)"; return; }
    [[ -f "$MEDIA_USB_A" ]] || { echo "no USB medium for the previous release ${VER_A} (images/kryptik-${VER_A}-usb.img)"; return; }
    [[ "$VER_A" != "$VER_B" ]] || { echo "release A and B carry the same version (${VER_A})"; return; }
    [[ "$(printf '%s\n' "$VER_A" "$VER_B" | sort -V | tail -1)" == "$VER_B" ]] \
        || echo "release A (${VER_A}) is not older than B (${VER_B}); the update test applies a newer release over an older one"
}
need_cargo()   { have cargo || echo "no cargo on PATH"; }
need_sources() { [[ -d "$KRYPTIK_SOURCES" && -f "${ROOT}/sources.lock" ]] || echo "no sources directory or sources.lock"; }
need_export()  { [[ -n "$EXPORT" ]] || echo "no --export DIR given (EXPORT=... for make acceptance)"; }
need_notes()   { need_export; [[ "$(verdict_of)" == PASS ]] || echo "the run has not passed, and notes come only from one that has"; }

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
it_artifacts()     { "${SELF}/check-artifact-hardening.sh" "$SYSROOT" --strict --json "${OUT}/artifact-hardening.json"; }
it_licences()      { "${SELF}/check-image-licences.sh" "$SYSROOT"; }
it_kernel_config() { "${SELF}/validate-kernel-config.sh" --boot && "${SELF}/validate-kernel-config.sh" --hardened; }
it_support_status() { "${SELF}/check-support-status.sh" --strict; }
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
it_update()        { "${IMG}/update-test.sh" --usb-a "$MEDIA_USB_A" --payload-a "$PAYLOAD_A" --payload-b "$PAYLOAD_B" --vars clean; }

# Every boot this run recorded went through the firmware, with no host-side
# boot input (-kernel, -initrd, -append, shared directory, FAT-from-directory).
it_firmware_only() {
    local n=0 bad=0 f src=("${KRYPTIK_WORK}/logs" -newer "$MARK")
    [[ "${#PARTS[@]}" -gt 0 ]] && src=("$OUT")
    while IFS= read -r f; do
        n=$((n + 1))
        if ! grep -q 'if=pflash' "$f" || ! grep -q 'OVMF_CODE_4M.secboot.fd' "$f"; then echo "  no firmware image in: $f"; bad=$((bad + 1)); continue; fi
        if grep -qE -- '(^| )-(kernel|initrd|append|hda|hdb|virtfs|fsdev)( |$)|file=fat:|-nic .*smb=' "$f"; then echo "  host-side boot input in: $f"; bad=$((bad + 1)); continue; fi
    done < <(find "${src[@]}" -name 'ovmf-serial.*.log.cmd' 2>/dev/null | sort)
    echo "boots recorded during this run: ${n}; with host-side boot inputs or without firmware: ${bad}"
    [[ "$n" -gt 0 ]] || { echo "no boot was recorded: nothing to attest"; return 1; }
    [[ "$bad" -eq 0 ]]
}

# ------------------------------------------------------------ the run --
echo "Kryptik acceptance ${START_TS}"
echo "  tree      : ${ROOT} @ ${REV_DESC}"
echo "  media usb : ${MEDIA_USB:-none}${H_USB:+ sha256 $H_USB}"
echo "  media iso : ${MEDIA_ISO:-none}${H_ISO:+ sha256 $H_ISO}"
echo "  release   : ${VER:-none} (its payload is release B: ${PAYLOAD_B:-none})"
echo "  update    : from A ${VER_A:-none} (${MEDIA_USB_A:-no medium}; ${PAYLOAD_A:-no payload}) to B ${VER_B:-none}"
echo "  firmware  : ${FW} ${H_FW:+sha256 $H_FW} (${FW_PKG}); ${QEMU_VER}; kvm=${KVM}"
echo "  output    : ${OUT}"

item inputs    revision                   M host  0 it_revision
item inputs    compositor-sources         M host  0 it_compositor_sources
item inputs    sources-lock               M host  0 it_sources_lock need_sources
item inputs    media-hashes               M host  0 it_media_hashes need_usb
item build     host-suites                M host  0 it_host_suites need_host
item build     libc-unwind                M host  0 it_libc_unwind need_sysroot
item build     userspace-smoke            M host  0 it_userspace need_sysroot
item build     artifact-hardening         M host  0 it_artifacts need_sysroot
item build     licences                   M host  0 it_licences need_sysroot
item build     kernel-config              M host  0 it_kernel_config need_sources
item build     support-status             M host  0 it_support_status
item boot      media-smoke-usb            M vm   25 it_smoke_usb need_vm
item boot      media-smoke-iso            M vm   25 it_smoke_iso need_vm_iso
item install   install-test               M vm   10 it_install need_vm
item install   state-test                 M vm   10 it_state need_vm
item integrity ovmf-vars                  M host  0 it_ovmf_vars need_usb
item integrity media-smoke-secureboot     M vm   25 it_smoke_sb need_enrolled
item integrity media-refused-foreign-keys M vm    5 it_refused need_ms
item integrity integrity-test             M vm    8 it_integrity need_enrolled
item zones     zones-test                 M vm   10 it_zones need_vm
item desktop   gui-test                   M vm   25 it_gui need_vm
item update    update-test                M vm   10 it_update need_update
item boot      firmware-only-boot         M post  0 it_firmware_only
# A part of a split run leaves its boot records beside its report, for --merge.
[[ -n "$ONLY" ]] && find "${KRYPTIK_WORK}/logs" -name 'ovmf-serial.*.log.cmd' -newer "$MARK" -exec cp -t "$OUT" {} + 2>/dev/null

# ------------------------------------------------------------- report --
KERNEL_LINE="$(grep -h -o 'KRYPTIK_SMOKE: kernel=[^ ]*' "${OUT}"/boot-media-smoke-usb.log 2>/dev/null | head -1 | sed 's/KRYPTIK_SMOKE: kernel=//')"
verdict_of() {
    local i fail=0 inc=0
    for i in "${!R_SUITE[@]}"; do
        [[ "${R_MAND[$i]}" == M ]] || continue
        case "${R_RES[$i]}" in PASS) ;; FAIL) fail=1 ;; *) inc=1 ;; esac
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
        echo "| release under test | ${VER:-none} (payload B: ${PAYLOAD_B:-none}) |"
        echo "| update test, A to B | ${VER_A:-none} (medium ${MEDIA_USB_A:-none}; ${PAYLOAD_A:-no payload}) to ${VER_B:-none} |"
        echo "| kernel (as the medium reported it) | ${KERNEL_LINE:-not observed} |"
        echo "| firmware | ${FW}${H_FW:+ (sha256 \`$H_FW\`)}; ${FW_PKG} |"
        echo "| QEMU | ${QEMU_VER}; kvm=${KVM} |"
        echo "| host | $(uname -srmo) |"
        echo "| run as | uid ${EUID} on $(hostname) at $(date -Iseconds) |"
        echo "| logs | ${OUT} |"
        echo
        echo "Results: PASS, FAIL, or INCOMPLETE (could not run here; never a pass)."
        echo "Kind: host = a host-side or chroot suite, not installed-system evidence; vm = the installed system or the medium under firmware; post = done after the suites, from this run's own records and media."
        echo
        echo "| suite | item | mandatory | kind | result | checks passed/failed | exit | seconds | log | note |"
        echo "|---|---|---|---|---|---|---|---|---|---|"
        for i in "${!R_SUITE[@]}"; do
            printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' "${R_SUITE[$i]}" "${R_NAME[$i]}" "$([[ "${R_MAND[$i]}" == M ]] && echo yes || echo no)" "${R_KIND[$i]}" "${R_RES[$i]}" "${R_CHECKS[$i]}" "${R_RC[$i]}" "${R_SECS[$i]}" "$(basename "${R_LOG[$i]}")" "${R_NOTE[$i]}"
        done
        echo
        echo "## Suites"
        echo
        for g in inputs build boot install integrity zones desktop update release; do
            gs="PASS"; any=0
            for i in "${!R_SUITE[@]}"; do
                [[ "${R_SUITE[$i]}" == "$g" ]] || continue; any=1
                case "${R_RES[$i]}" in FAIL) gs=FAIL ;; INCOMPLETE) [[ "$gs" == FAIL ]] || gs=INCOMPLETE ;; esac
            done
            [[ "$any" -eq 1 ]] || gs="INCOMPLETE (no item)"
            echo "- ${g}: ${gs}"
        done
        echo
        echo "Exit status: 0 only for PASS; 1 for FAIL; 2 for INCOMPLETE."
    } > "${OUT}/REPORT.md"
    {
        printf 'suite\titem\tmandatory\tkind\tresult\tchecks\texit\tseconds\tlog\tnote\n'
        for i in "${!R_SUITE[@]}"; do
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${R_SUITE[$i]}" "${R_NAME[$i]}" "${R_MAND[$i]}" "${R_KIND[$i]}" "${R_RES[$i]}" "${R_CHECKS[$i]}" "${R_RC[$i]}" "${R_SECS[$i]}" "${R_LOG[$i]}" "${R_NOTE[$i]}"
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
    # B's own root.json: images/root.json is whichever release was built last.
    if [[ -n "$PAYLOAD_B" && -f "${PAYLOAD_B}/root.json" ]]; then cp "${PAYLOAD_B}/root.json" "${d}/"
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
    if [[ -f "${ROOT}/docs/user-guide.md" ]]; then cp "${ROOT}/docs/user-guide.md" "${d}/INSTRUCTIONS.md"; else echo "  no docs/user-guide.md to ship"; ok=1; fi
    cp "${OUT}/REVISION.txt" "${d}/" 2>/dev/null
    mkdir -p "${d}/acceptance-logs" && cp "${OUT}"/*.log "${OUT}/results.tsv" "${d}/acceptance-logs/" 2>/dev/null
    echo "-- the copies hash the same as what was tested"
    # Against the hashes taken at the start, so a medium changed mid-run fails.
    : > "${d}/SHA256SUMS"
    for f in "$MEDIA_USB" "$MEDIA_ISO"; do
        [[ -f "$f" ]] || continue
        want="$H_ISO"; [[ "$f" == "$MEDIA_USB" ]] && want="$H_USB"
        got="$(sha_of "${d}/$(basename "$f")")"
        if [[ "$want" == "$got" ]]; then echo "  ok  $(basename "$f") ${got}"; else echo "  MISMATCH $(basename "$f"): tested ${want}, exported ${got}"; ok=1; fi
        printf '%s  ./%s\n' "$got" "$(basename "$f")" >> "${d}/SHA256SUMS"
    done
    return "$ok"
}
# The release's notes (tools/release-notes.sh), from every row before this
# one. What changed runs from the latest release tag before this revision.
it_notes() {
    local prev
    prev="$(git -c safe.directory='*' -C "$ROOT" describe --tags --abbrev=0 --match 'v[0-9]*' HEAD^ 2>/dev/null || true)"
    "${SELF}/release-notes.sh" --run "$OUT" --payload "$PAYLOAD_B" ${prev:+--since "$prev"} > "${EXPORT}/RELEASE-NOTES.md" \
        || { rm -f "${EXPORT}/RELEASE-NOTES.md"; return 1; }
    echo "wrote ${EXPORT}/RELEASE-NOTES.md${prev:+ (changes since ${prev})}"
}
# Hash every export file but the media (it_export's lines); run last, once the
# report, results and RELEASE.txt are final.
seal_export() {   # seal_export DIR
    ( cd "$1" && find . -type f ! -name SHA256SUMS ! -name '*.img' ! -name '*.iso' -print0 | sort -z | xargs -0 sha256sum ) >> "$1/SHA256SUMS"
}
V="$(verdict_of)"
write_report "$V"
if [[ -n "$EXPORT" ]] || wanted release; then
    item release export M post 0 it_export need_export
    # The notes read the report with the export's row in it.
    V="$(verdict_of)"
    write_report "$V"
    item release notes  M post 0 it_notes need_notes
    V="$(verdict_of)"
    write_report "$V"
    if [[ -n "$EXPORT" && -d "$EXPORT" ]]; then
        cp "${OUT}/REPORT.md" "${EXPORT}/ACCEPTANCE-REPORT.md"
        {
            echo "Kryptik ${VER:-unknown}"
            echo "acceptance : ${V} (${START_TS}; see ACCEPTANCE-REPORT.md)"
            echo "revision   : ${REV}"
            echo "usb image  : $(basename "${MEDIA_USB:-none}") sha256 ${H_USB:-none}"
            echo "iso        : $(basename "${MEDIA_ISO:-none}") sha256 ${H_ISO:-none}"
            echo "firmware   : ${FW_PKG} (${FW})"
            echo "kernel     : ${KERNEL_LINE:-not observed}"
            echo "trust      : kryptik-sb.crt / kryptik-sb.der (the developer Secure Boot key, a test anchor)"
            echo "read       : INSTRUCTIONS.md$([[ -f "${EXPORT}/RELEASE-NOTES.md" ]] && echo ", RELEASE-NOTES.md")"
        } > "${EXPORT}/RELEASE.txt"
        # Again, now that the export's own row and log exist.
        cp "${OUT}"/*.log "${OUT}/results.tsv" "${EXPORT}/acceptance-logs/" 2>/dev/null
        seal_export "$EXPORT"
    fi
fi

echo
echo "================================================================"
sed -n '/^| suite/,/^$/p' "${OUT}/REPORT.md"
echo "Verdict: ${V}   (report: ${OUT}/REPORT.md)"
# The 12 GB VM disks only help debug a failure, and on WSL they grow the host's
# virtual disk for good: remove them once the whole run has passed.
if [[ "$V" == PASS ]]; then
    rm -f "${KRYPTIK_WORK}"/vm/*.img "${KRYPTIK_WORK}"/vm/*.fd "${KRYPTIK_WORK}"/vm/*.pristine 2>/dev/null
    rm -rf "${KRYPTIK_WORK}"/vm/bad 2>/dev/null
    echo "VM disks removed (every item passed; the transcripts under ${KRYPTIK_WORK}/logs are the evidence)"
fi
case "$V" in PASS) exit 0 ;; FAIL) exit 1 ;; *) exit 2 ;; esac
