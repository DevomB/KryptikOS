#!/usr/bin/env bash
# Tests for tools/release-notes.sh against a fixture tree, run and payload.

set -uo pipefail
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="${ROOT}/tools/check-commit-identity.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

for t in git python3 sha256sum; do
    command -v "$t" >/dev/null 2>&1 || { echo "${t} required"; exit 1; }
done
NAME="$(sed -n 's/^ALLOWED_NAME="\(.*\)"$/\1/p' "$CHECKER")"
EMAIL="$(sed -n 's/^ALLOWED_EMAIL="\(.*\)"$/\1/p' "$CHECKER")"
[[ -n "$NAME" && -n "$EMAIL" ]] || { echo "could not read the permitted identity from ${CHECKER}"; exit 1; }

W="$(mktemp -d)"
OUT="${W}/out"
ERR="${W}/err"
trap 'rm -rf "$W"' EXIT
show() { sed 's/^/        /' "$ERR"; }

# --- a tree at the release's revision ------------------------------------------
T="${W}/tree"
mkdir -p "${T}/tools" "${T}/build/lib" "${T}/build/config/kernel" "${T}/docs"
cp "${ROOT}/tools/release-notes.sh" "${T}/tools/"
cp "${ROOT}/build/lib/common.sh" "${T}/build/lib/"
cat > "${T}/docs/status.md" <<'EOF'
# Status

## What is tested

| Area | State |
| --- | --- |

## Known gaps

- Nothing has run on physical hardware.
- A second line of the same
  gap, wrapped.

## Afterwards

Not a gap.
EOF
printf '# why\nkconfig  CONFIG_A   # a reason\ncmdline  b          # another\n' > "${T}/build/config/kernel/checker-accepted.txt"
printf 'pkg  flag  # why\n' > "${T}/build/config/hardening-exceptions.txt"
printf '/usr/bin/su  # why\n/usr/bin/passwd  # why\n' > "${T}/build/config/setuid-allowlist.txt"
printf '# none\n' > "${T}/build/config/capability-allowlist.txt"
cat > "${T}/build/config/artifact-accepted.txt" <<'EOF'
# accepted findings
NO-CET  usr/bin/kryptikd          # rustc marks nothing for CET
NO-CET  usr/bin/kryptik-wlproxy   # the same
RPATH   usr/lib/gconv/*.so  $ORIGIN   # glibc's converters load helpers beside them
EOF
git -C "$T" init -q
git -C "$T" config user.name "$NAME"
git -C "$T" config user.email "$EMAIL"
git -C "$T" config core.autocrlf false
git -C "$T" add -A && git -C "$T" commit -q -m "The previous release"
PREV="$(git -C "$T" rev-parse HEAD)"
git -C "$T" commit -q --allow-empty -m "Merge zone-fix into build-ci (#9): a zone's window keeps its border"
git -C "$T" commit -q --allow-empty -m "Merge remote-tracking branch 'origin/main' into build-ci"
git -C "$T" commit -q --allow-empty -m "The update suite flips a byte"
REV="$(git -C "$T" rev-parse HEAD)"

# --- the run that passed it, and its payload -----------------------------------
USB_SUM="$(printf 'usb' | sha256sum | cut -c1-64)"; ISO_SUM="$(printf 'iso' | sha256sum | cut -c1-64)"
make_run() {   # make_run DIR [VERDICT]
    mkdir -p "$1"
    cat > "$1/REPORT.md" <<EOF
# Kryptik acceptance 20270302T140500

Verdict: **${2:-PASS}**

| what | value |
|---|---|
| source revision | \`${REV}\` (${REV:0:7}) |
| USB medium | /w/images/kryptik-1.0.3-usb.img (sha256 \`${USB_SUM}\`) |
| ISO | /w/images/kryptik-1.0.3.iso (sha256 \`${ISO_SUM}\`) |
| release under test | 1.0.3 (payload B: /w/images/payload-1.0.3) |
| firmware | /usr/share/OVMF/OVMF_CODE_4M.secboot.fd (sha256 \`00\`); ovmf 2024.02-2ubuntu0.9 |
| QEMU | QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds); kvm=yes |
| run as | uid 0 on runner at 2027-03-02T14:05:00+00:00 |
EOF
    printf 'suite\titem\tmandatory\tkind\tresult\tchecks\texit\tseconds\tlog\tnote\n' > "$1/results.tsv"
    printf '%s\t%s\tM\t%s\tPASS\t%s\t0\t1\tx.log\t\n' \
        inputs revision host - build host-suites host 41/0 install install-test vm 43/0 \
        install state-test vm 54/0 release export post - >> "$1/results.tsv"
    cat > "$1/artifact-hardening.json" <<'EOF'
{
  "objects": 1320, "executables": 766, "libraries": 554,
  "findings": { "RPATH": 1, "NO-CET": 2, "HAS-SSP": 1233, "HAS-FORTIFY": 854 },
  "hard": [], "reported": [],
  "accepted": [ "  NO-CET  usr/bin/kryptikd", "  NO-CET  usr/bin/kryptik-wlproxy", "  RPATH  usr/lib/gconv/EUC-KR.so  [$ORIGIN]" ],
  "stale": []
}
EOF
}
RUN="${W}/run"; make_run "$RUN"
P="${W}/payload"; mkdir -p "$P"
printf 'KRYPTIK-MANIFEST-1\nname: kryptik\nversion: 1.0.3\nrole: development\ncreated: 2027-03-02T12:00:00Z\nfiles: 0\n--\n' > "${P}/manifest"

notes() {   # notes [ARGS...]: the tool on the fixtures; stdout in $OUT, stderr in $ERR
    NO_COLOR=1 bash "${T}/tools/release-notes.sh" --run "${RUN}" --payload "$P" "$@" > "$OUT" 2> "$ERR"
}
has() { grep -qF -- "$1" "$OUT"; }

# --- what the notes say ----------------------------------------------------------
notes; rc=$?
if [[ "$rc" -eq 0 ]] && has "# Kryptik 1.0.3" && has "Released 2027-03-02, built from \`${REV}\`." \
    && has "A development release" && ! has "## Changes since"; then
    green "the notes name the version, the date, the revision and the role"
else
    red "the heading (exit ${rc})"; show
fi
if has "| install | PASS | 2 | 97 |" && has "| build | PASS | 1 | 41 |" && has "| inputs | PASS | 1 | - |" \
    && has "on 2027-03-02, under OVMF 2024.02-2ubuntu0.9 and QEMU 8.2.2, with KVM."; then
    green "one row per suite, with its checks summed, and what it ran under"
else
    red "the tested table"; sed 's/^/        /' "$OUT"
fi
if has "Kernel: 2 kernel-hardening-checker findings accepted" && has "Compiler flags: 1 exception to" \
    && has "setuid and setgid: 2 programs," && has "Programs with file capabilities: 0." \
    && has "(766 executables, 554 libraries). None refused, none reported, 3 accepted" && has "NO-CET, 2 objects:" \
    && has "\`usr/bin/kryptik-wlproxy\`: rustc marks nothing for CET" && has "RPATH, 1 object:" \
    && has "\`usr/lib/gconv/*.so\`, rpath \`\$ORIGIN\`: glibc's converters" \
    && has "Stack protector in 1233 objects, FORTIFY_SOURCE in 854."; then
    green "the audit's counts per list, and each accepted kind with its reasons"
else
    red "the hardening audit"; sed 's/^/        /' "$OUT"
fi
want=$'- Nothing has run on physical hardware.\n- A second line of the same\n  gap, wrapped.'
got="$(awk '/^## Known gaps$/ { on = 1; next } on && /^## / { exit } on' "$OUT" | sed '/^$/d')"
if [[ "$got" == "$want" ]] && ! has "Not a gap."; then
    green "the known gaps are status.md's, word for word, and nothing after them"
else
    red "the known gaps: ${got}"
fi
if has "\`source-${REV:0:12}.tar\`" && has "| kryptik-1.0.3-usb.img | \`${USB_SUM}\` |" && has "| kryptik-1.0.3.iso | \`${ISO_SUM}\` |"; then
    green "the source bundle and the media's SHA-256"
else
    red "the source and download sections"; sed 's/^/        /' "$OUT"
fi

notes --since "$PREV"; rc=$?
if [[ "$rc" -eq 0 ]] && has "## Changes since ${PREV:0:12}" \
    && [[ "$(grep '^- ' "$OUT" | head -2)" == $'- A zone\'s window keeps its border\n- The update suite flips a byte' ]] \
    && ! has "remote-tracking" && ! has "- The previous release"; then
    green "--since lists the changes in order, as sentences, without merges that say nothing"
else
    red "the changes section (exit ${rc})"; show; sed 's/^/        /' "$OUT"
fi

# --- what refuses notes ----------------------------------------------------------
refused() {   # refused WHAT GREP [ARGS...]: the tool must refuse, saying GREP, and print no notes
    local what="$1" grep="$2"; shift 2
    notes "$@"; rc=$?
    if [[ "$rc" -ne 0 && ! -s "$OUT" ]] && grep -q -- "$grep" "$ERR"; then green "refused: ${what}"; else red "not refused: ${what} (exit ${rc})"; show; fi
}
make_run "$RUN" FAIL
refused "a run whose verdict is FAIL" "verdict is not PASS"
make_run "$RUN"; sed -i '0,/\tPASS\t43\/0/s//\tFAIL\t43\/0/' "${RUN}/results.tsv"
refused "a run with a mandatory item failed" "not every mandatory item passed: install/install-test FAIL"
make_run "$RUN"; sed -i 's/^version: .*/version: 1.0.4/' "${P}/manifest"
refused "a payload the run did not test" "the run tested 1.0.3, and this payload is 1.0.4"
sed -i 's/^version: .*/version: 1.0.3/' "${P}/manifest"
python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); a["reported"]=["  NO-PIE  usr/bin/x"]; json.dump(a, open(sys.argv[1],"w"))' "${RUN}/artifact-hardening.json"
refused "an audit with a reported finding" "1 reported finding"
make_run "$RUN"; python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); a["stale"]=["RPATH usr/lib/gone"]; json.dump(a, open(sys.argv[1],"w"))' "${RUN}/artifact-hardening.json"
refused "an audit with a stale accepted entry" "1 stale finding"
make_run "$RUN"; sed -i 's/(sha256 `[0-9a-f]*`) |$/|/' "${RUN}/REPORT.md"
refused "a report without the media's SHA-256" "gives no SHA-256"
make_run "$RUN"
refused "a --since that is not an earlier revision" "is not an ancestor" --since "$(git -C "$T" hash-object -w "${T}/docs/status.md")"
printf '\n- an edit\n' >> "${T}/docs/status.md"
refused "a status.md that differs from the tested revision" "differs from"
git -C "$T" checkout -q -- docs/status.md
git -C "$T" commit -q --allow-empty -m "Later"
refused "a tree at another revision" "this tree is at"
git -C "$T" reset -q --hard "$REV"
mv "${T}/build/config/artifact-accepted.txt" "${W}/accepted.kept"; git -C "$T" commit -q -am "No list"
make_run "$RUN"; sed -i "s/${REV}/$(git -C "$T" rev-parse HEAD)/" "${RUN}/REPORT.md"
refused "accepted findings with no list to say why" "no build/config/artifact-accepted.txt"
git -C "$T" reset -q --hard "$REV"
sed -i '/^## Known gaps/,/^## Afterwards/{/^## Afterwards/!d}' "${T}/docs/status.md"; git -C "$T" commit -q -am "No gaps"
make_run "$RUN"; sed -i "s/${REV}/$(git -C "$T" rev-parse HEAD)/" "${RUN}/REPORT.md"
refused "a status.md with no known gaps to quote" "no '## Known gaps' section"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
