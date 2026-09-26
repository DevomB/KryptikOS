#!/usr/bin/env bash
# Test acceptance.sh's release choice, verdict and export list, running the
# script's own code on a staged images/ directory of empty files.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACC="$ROOT/tools/acceptance.sh"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
sed -n '/ inputs --$/,/^MEDIA_USB_A=/p' "$ACC" > "$T/inputs.sh"
grep -q '^MEDIA_USB_A=' "$T/inputs.sh" || { echo "could not extract the inputs block from $ACC"; exit 1; }
sed -n '/^need_update() {/,/^}/p' "$ACC" > "$T/need.sh"
grep -q '^need_update()' "$T/need.sh" || { echo "could not extract need_update from $ACC"; exit 1; }

release() {   # release VERSION [medium|payload|both]
    local v="$1" what="${2:-both}"
    [[ "$what" != payload ]] && { : > "$IMGDIR/kryptik-$v-usb.img"; : > "$IMGDIR/kryptik-$v.iso"; }
    [[ "$what" != medium ]] && { mkdir -p "$IMGDIR/payload-$v"; : > "$IMGDIR/payload-$v/manifest"; }
    sleep 0.01
}
choose() {   # choose [MEDIA_USB] [PAYLOAD_A] [PAYLOAD_B]: run the block on those inputs
    # shellcheck disable=SC2034  # read by the sourced inputs block
    MEDIA_USB="${1:-}"; MEDIA_ISO=""; PAYLOAD_A="${2:-}"; PAYLOAD_B="${3:-}"
    # shellcheck source=/dev/null
    . "$T/inputs.sh"
    need_vm() { :; }
    # shellcheck source=/dev/null
    . "$T/need.sh"
    NEED="$(need_update)"
}
b() { basename "${1:-}"; }

stage() { rm -rf "$T/images"; IMGDIR="$T/images"; mkdir -p "$IMGDIR"; }

# Built in order, X then X.1: X.1 is under test and A is X, from its own medium.
stage; release 0.1.20260915.abcdef01; release 0.1.20260915.abcdef01.1
choose
[[ "$VER" = 0.1.20260915.abcdef01.1 && "$(b "$PAYLOAD_B")" = payload-0.1.20260915.abcdef01.1 ]] \
    && ok "the newest medium is the release under test and its payload is B" || bad "release under test: VER=$VER B=$(b "$PAYLOAD_B")"
[[ "$(b "$PAYLOAD_A")" = payload-0.1.20260915.abcdef01 && "$(b "$MEDIA_USB_A")" = kryptik-0.1.20260915.abcdef01-usb.img ]] \
    && ok "A is the previous release, installed from its own medium" || bad "A=$(b "$PAYLOAD_A") medium=$(b "$MEDIA_USB_A")"
[[ "$(b "$MEDIA_ISO")" = kryptik-0.1.20260915.abcdef01.1.iso ]] && ok "the ISO is the release under test's" || bad "ISO=$(b "$MEDIA_ISO")"
[[ -z "$NEED" ]] && ok "the update test has what it needs" || bad "need_update: $NEED"

# Built in reverse: the same choice, since version decides, not mtime.
stage; release 0.1.20260915.abcdef01.1; release 0.1.20260915.abcdef01
choose
[[ "$VER" = 0.1.20260915.abcdef01.1 && "$(b "$PAYLOAD_A")" = payload-0.1.20260915.abcdef01 ]] \
    && ok "built in the other order, the choice is the same (version, not mtime)" || bad "reverse order: VER=$VER A=$(b "$PAYLOAD_A")"

# A lone release is B with no A, and need_update says why.
stage; release 0.1.20260915.abcdef01
choose
[[ "$VER" = 0.1.20260915.abcdef01 && -n "$PAYLOAD_B" && -z "$PAYLOAD_A" && -z "$MEDIA_USB_A" ]] \
    && ok "a lone release is B with no A" || bad "lone: VER=$VER A=$(b "$PAYLOAD_A") B=$(b "$PAYLOAD_B")"
[[ "$NEED" == *"no previous release"* ]] && ok "need_update names the missing previous release" || bad "need_update: '$NEED'"

# The previous version has no medium: A is the next one down that has both.
stage; release 0.1.20260914.00000000; release 0.1.20260915.abcdef01 payload; release 0.1.20260915.abcdef01.1
choose
[[ "$(b "$PAYLOAD_A")" = payload-0.1.20260914.00000000 ]] \
    && ok "a previous release without a medium is passed over for one that has it" || bad "A=$(b "$PAYLOAD_A")"

# An explicit medium is the release under test; A is found below it.
stage; release 0.1.20260914.00000000; release 0.1.20260915.abcdef01; release 0.1.20260915.abcdef01.1
choose "$IMGDIR/kryptik-0.1.20260915.abcdef01-usb.img"
[[ "$VER" = 0.1.20260915.abcdef01 && "$(b "$PAYLOAD_B")" = payload-0.1.20260915.abcdef01 && "$(b "$PAYLOAD_A")" = payload-0.1.20260914.00000000 ]] \
    && ok "an explicit medium is the release under test, and A is the release below it" || bad "explicit medium: VER=$VER A=$(b "$PAYLOAD_A") B=$(b "$PAYLOAD_B")"

# Explicit payloads win; a pair the wrong way round is refused.
stage; release 0.1.20260915.abcdef01; release 0.1.20260915.abcdef01.1
choose "" "$IMGDIR/payload-0.1.20260915.abcdef01.1" "$IMGDIR/payload-0.1.20260915.abcdef01"
[[ "$VER_A" = 0.1.20260915.abcdef01.1 && "$VER_B" = 0.1.20260915.abcdef01 ]] && ok "explicit payloads are taken as given" || bad "explicit payloads: A=$VER_A B=$VER_B"
[[ "$NEED" == *"not older"* ]] && ok "need_update refuses A newer than B" || bad "need_update: '$NEED'"

# A and B the same release: refused.
stage; release 0.1.20260915.abcdef01
choose "" "$IMGDIR/payload-0.1.20260915.abcdef01" "$IMGDIR/payload-0.1.20260915.abcdef01"
[[ "$NEED" == *"same version"* ]] && ok "need_update refuses A and B being one release" || bad "need_update: '$NEED'"

# No ISO for the release under test: an older release's is not used instead.
stage; release 0.1.20260914.00000000
: > "$IMGDIR/kryptik-0.1.20260915.abcdef01-usb.img"
choose
[[ "$VER" = 0.1.20260915.abcdef01 && -z "$MEDIA_ISO" ]] && ok "another release's ISO is never the ISO under test" || bad "ISO=$(b "$MEDIA_ISO") for VER=$VER"

# --- item(), its summary parser and the verdict ------------------------------
sed -n '/^R_SUITE=()/,/^# -* prereqs --$/p' "$ACC" > "$T/item.sh"
sed -n '/^need_host() /p; /^need_export() /p; /^need_notes() /p; /^verdict_of() {/,/^}/p; /^seal_export() {/,/^}/p; /^tested() /p; /^ran_on() /p; /^parts_disagree() {/,/^}/p' "$ACC" >> "$T/item.sh"
for fn in item checks_in need_host need_export need_notes verdict_of seal_export tested ran_on parts_disagree; do
    grep -q "^${fn}() " "$T/item.sh" || { echo "could not extract ${fn} from $ACC"; exit 1; }
done
# shellcheck disable=SC2034  # read by the sourced functions
{ OUT="$T/out"; ONLY=""; NOHOST=0; PARTS=(); }
mkdir -p "$OUT"
need_cargo() { :; }
# shellcheck source=/dev/null
. "$T/item.sh"
result_of() { local i; for i in "${!R_NAME[@]}"; do [[ "${R_NAME[$i]}" == "$1" ]] && echo "${R_RES[$i]}"; done; }
says() { printf '%s\n' "$SAY"; }
try() {   # try NAME MINPASS SUMMARY WANT WHAT: a driver that exits 0 and prints SUMMARY
    SAY="$3"; item t "$1" M host "$2" says > /dev/null
    [[ "$(result_of "$1")" == "$4" ]] && ok "$5" || bad "$5: got $(result_of "$1")"
}
try clean      0 '25 passed, 0 failed'                      PASS "exit 0 and no failure counted is a pass"
try counted    0 '25 passed, 3 failed'                      FAIL "exit 0 with 3 failed in its own summary is a failure"
try other      0 'passed 9, failed 1'                       FAIL "the same in the installer suite's wording"
try reversed   0 '2 check(s) failed, 40 passed'             FAIL "the same in the services suite's wording"
try suites     0 '17 suites: 15 passed, 1 failed, 1 did not run' FAIL "the same in the host suites' wording"
try thin      10 '5 passed, 0 failed'                       FAIL "fewer checks than the item's minimum is still a failure"
try silent    10 'nothing countable'                        FAIL "no summary at all, where a minimum is set, is a failure"
[[ "$(verdict_of)" == FAIL ]] && ok "one failed mandatory item fails the verdict" || bad "verdict $(verdict_of)"
# shellcheck disable=SC2034  # read by need_export and need_notes
EXPORT="$T/export-dir"
[[ "$(need_notes)" == *"has not passed"* ]] && ok "no release notes from a run that has not passed" || bad "need_notes on a failed run: '$(need_notes)'"

# shellcheck disable=SC2034  # the results so far, put away
{ R_SUITE=(); R_NAME=(); R_MAND=(); R_KIND=(); R_RES=(); R_CHECKS=(); R_RC=(); R_SECS=(); R_LOG=(); R_NOTE=(); }
try clean2 0 'All 12 checks passed' PASS "a clean item, alone"
[[ -z "$(need_notes)" ]] && ok "a run that has passed, with an export, gets its notes" || bad "need_notes on a passed run: '$(need_notes)'"
# shellcheck disable=SC2034  # read by need_notes
EXPORT=""
[[ "$(need_notes)" == *"no --export"* ]] && ok "no release notes without an export to hold them" || bad "need_notes without an export: '$(need_notes)'"
# shellcheck disable=SC2034  # read by need_host
NOHOST=1; item build host-suites M host 0 says need_host > /dev/null
[[ "$(result_of host-suites)" == INCOMPLETE ]] && ok "--no-host leaves a row, and it reads INCOMPLETE" || bad "--no-host: '$(result_of host-suites)'"
[[ "$(verdict_of)" == INCOMPLETE ]] && ok "a skipped mandatory item keeps the verdict from PASS" || bad "verdict $(verdict_of)"

# --- a split run, merged: each item's row comes from the part that ran it -----
# shellcheck disable=SC2034  # the results so far, put away
{ R_SUITE=(); R_NAME=(); R_MAND=(); R_KIND=(); R_RES=(); R_CHECKS=(); R_RC=(); R_SECS=(); R_LOG=(); R_NOTE=(); }
mkdir -p "$T/parts/a" "$T/parts/b"
row() { printf '%s\t%s\tM\tvm\t%s\t%s\t%s\t9\t%s\t%s\n' "$@"; }
{ echo header; row boot smoke PASS 38/0 0 /elsewhere/boot-smoke.log ""; row update upd INCOMPLETE - - - "not run (--only boot)"; } > "$T/parts/a/results.tsv"
{ echo header; row boot smoke INCOMPLETE - - - "not run (--only update)"; row update upd FAIL 20/2 1 /elsewhere/update-upd.log "exit 1"; } > "$T/parts/b/results.tsv"
# shellcheck disable=SC2034  # read by item and merged
PARTS=("$T/parts/a/results.tsv" "$T/parts/b/results.tsv")
runs() { : > "$T/ran"; }
{ item boot smoke M vm 25 runs; item update upd M vm 10 runs; item zones zt M vm 10 runs; } > /dev/null
[[ ! -e "$T/ran" ]] && ok "merged, an item is read from the parts, not run" || bad "merged: an item was run"
[[ "$(result_of smoke)/$(result_of upd)/$(result_of zt)" == PASS/FAIL/INCOMPLETE ]] \
    && ok "each row is the part that ran it; one no part ran is INCOMPLETE" || bad "merged: $(result_of smoke)/$(result_of upd)/$(result_of zt)"
[[ "${R_LOG[0]}" == "$OUT/boot-smoke.log" && "${R_CHECKS[1]}" == 20/2 ]] \
    && ok "a merged row keeps its checks, and its log is the copy beside the report" || bad "merged row: log ${R_LOG[0]} checks ${R_CHECKS[1]}"
item boot record M post 0 runs > /dev/null
[[ -e "$T/ran" && "$(result_of record)" == PASS ]] && ok "an item done after the suites runs in the merge itself" || bad "post item: $(result_of record)"
[[ "$(verdict_of)" == FAIL ]] && ok "a part's failure fails the merged verdict" || bad "merged verdict $(verdict_of)"

# A row cut short, or with a word other than the three, is never a pass.
# shellcheck disable=SC2034  # the results so far, put away
{ R_SUITE=(); R_NAME=(); R_MAND=(); R_KIND=(); R_RES=(); R_CHECKS=(); R_RC=(); R_SECS=(); R_LOG=(); R_NOTE=(); }
{ echo header; row boot smoke PASSED 38/0 0 - ""; printf 'update\tupd\tM\tvm\tPASS\n'; } > "$T/parts/a/results.tsv"
{ echo header; } > "$T/parts/b/results.tsv"
{ item boot smoke M vm 25 runs; item update upd M vm 10 runs; } > /dev/null
[[ "$(result_of smoke)/$(result_of upd)" == INCOMPLETE/INCOMPLETE && "${R_NOTE[0]}" == *malformed* ]] \
    && ok "a malformed row, or one cut short, is INCOMPLETE" || bad "malformed rows: $(result_of smoke)/$(result_of upd) '${R_NOTE[0]}'"
R_RES[0]=SKIPPED; R_RES[1]=PASS
[[ "$(verdict_of)" == INCOMPLETE ]] && ok "a result the verdict does not know keeps it from PASS" || bad "verdict over an unknown result: $(verdict_of)"

# Every part must have tested this revision on these media, and all of them
# on one firmware and one QEMU; the merging machine's own may differ.
# shellcheck disable=SC2034  # read by tested and ran_on
{ REV=abc; REV_DESC=abc; H_USB=u1; H_ISO=i1; H_FW=f1; FW_PKG="ovmf 1"; QEMU_VER="QEMU 9"; KVM=yes; }
part() { { tested; ran_on; } > "$T/parts/$1/identity"; }
part a; part b
[[ -z "$(parts_disagree)" ]] && ok "parts that tested one revision on one medium are one run" || bad "parts disagree: $(parts_disagree)"
sed -i 's/^usb .*/usb u2/' "$T/parts/b/identity"
[[ "$(parts_disagree)" == "the part in $T/parts/b tested"*"usb u2"* ]] && ok "a part that tested another medium is refused, by name" || bad "another medium: '$(parts_disagree)'"
part b
sed -i '/^qemu /d' "$T/parts/b/identity"
[[ "$(parts_disagree)" == "the part in $T/parts/b does not say its qemu" ]] && ok "a part that does not say what it ran on is refused" || bad "no qemu line: '$(parts_disagree)'"
part b
# shellcheck disable=SC2034  # read by ran_on
{ H_FW=f2; QEMU_VER="QEMU 10"; }
[[ -z "$(parts_disagree)" ]] && ok "a merging machine with newer firmware and QEMU than the parts takes them" || bad "the merger's own firmware refused the parts: $(parts_disagree)"
part a
[[ "$(parts_disagree)" == "the part in $T/parts/b ran on "*"QEMU 9;"*" but the part in $T/parts/a on "*"QEMU 10;"* ]] && ok "parts that ran on different QEMU are refused" || bad "parts on two QEMUs: '$(parts_disagree)'"
rm "$T/parts/a/identity"
[[ "$(parts_disagree)" == *"no identity"* ]] && ok "a results.tsv with no identity beside it is refused" || bad "no identity: '$(parts_disagree)'"
# shellcheck disable=SC2034  # back to a run of its own
PARTS=()

# --- the export's list covers every file in it but itself ---------------------
E="$T/export"; mkdir -p "$E/acceptance-logs"
for f in kryptik-1-usb.img manifest-1 manifest-1.sig INSTRUCTIONS.md RELEASE.txt ACCEPTANCE-REPORT.md acceptance-logs/results.tsv; do echo "$f" > "$E/$f"; done
( cd "$E" && sha256sum ./kryptik-1-usb.img ) > "$E/SHA256SUMS"   # it_export's line
seal_export "$E"
( cd "$E" && sha256sum --quiet -c SHA256SUMS ) && ok "every line of the export's list verifies" || bad "the export's list does not verify"
missing="$(cd "$E" && find . -type f ! -name SHA256SUMS | while read -r f; do grep -qF "  $f" SHA256SUMS || echo "$f"; done)"
[[ -z "$missing" ]] && ok "manifests, signatures, the report and the results are all on the list" || bad "not on the list: $missing"
[[ "$(sort "$E/SHA256SUMS" | uniq -d | wc -l)" -eq 0 ]] && ok "no file is listed twice" || bad "a file is listed twice"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
