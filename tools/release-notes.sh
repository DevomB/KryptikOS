#!/usr/bin/env bash
# Write a release's notes from the acceptance run that passed it.
#
#   ./tools/release-notes.sh --run DIR --payload DIR [--since REV] > RELEASE-NOTES.md
#
# --run is a merged acceptance run (results.tsv, REPORT.md,
# artifact-hardening.json) and --payload the release's payload, whose manifest
# names the version. Only a run that passed every suite on this very version
# makes notes, and only from the tree of the revision it tested, so the known
# gaps quoted from docs/status.md and the counts of the accepted lists are
# that release's own. --since names the previous release's revision.
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"

usage() { sed -n '2,11p' "${BASH_SOURCE[0]}"; }

RUN="" PAYLOAD="" SINCE=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --run)     RUN="${2:?--run needs a directory}"; shift 2 ;;
        --payload) PAYLOAD="${2:?--payload needs a directory}"; shift 2 ;;
        --since)   SINCE="${2:?--since needs a revision}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ -n "$RUN" && -n "$PAYLOAD" ]] || { usage; exit 1; }
have python3 || die "python3 is required"
for f in results.tsv REPORT.md artifact-hardening.json; do
    [[ -f "${RUN}/${f}" ]] || die "no ${f} in ${RUN}: give a merged acceptance run"
done
[[ -f "${PAYLOAD}/manifest" ]] || die "no manifest in ${PAYLOAD}"

field() { awk -F': ' -v k="$2" '$1 == k { print $2; exit }' "$1"; }
# The verdict job is root on the runner's checkout, which git refuses unless
# told it is safe: this checkout alone, since git can run commands a
# repository's own config names.
TOP="$(cd "$KRYPTIK_ROOT" && pwd -P)"
g() { git -c safe.directory="$TOP" -C "$TOP" "$@"; }
row() {   # row LABEL: the value in REPORT.md's header row LABEL
    awk -F' [|] ' -v k="| $1" '$1 == k { v = $2; sub(/ [|]$/, "", v); print v; exit }' "${RUN}/REPORT.md"
}
entries() {   # entries FILE WORD: how many entries FILE holds, as "N WORD(s)"
    local n=0
    if [[ -f "$1" ]]; then n="$(grep -cv '^[[:space:]]*\(#\|$\)' "$1" || true)"; fi
    if [[ "$n" -eq 1 ]]; then echo "1 $2"; else echo "${n} ${2}s"; fi
}

# --- only this release, passed whole, from its own tree ------------------------
grep -qx 'Verdict: \*\*PASS\*\*' "${RUN}/REPORT.md" \
    || die "the run's verdict is not PASS: notes are made only for a release every suite passed"
bad="$(awk -F'\t' 'NR > 1 && $3 == "M" && $5 != "PASS" { printf "%s%s/%s %s", sep, $1, $2, $5; sep = ", " }' "${RUN}/results.tsv")"
[[ -z "$bad" ]] || die "not every mandatory item passed: ${bad}"
version="$(field "${PAYLOAD}/manifest" version)"
tested="$(row 'release under test' | awk '{ print $1 }')"
[[ -n "$version" && "$version" == "$tested" ]] \
    || die "the run tested ${tested:-no release}, and this payload is ${version:-unnamed}: notes come from the run that passed this very release"
rev="$(row 'source revision' | sed -n 's/^`\([0-9a-f]\{40\}\)`.*/\1/p')"
[[ -n "$rev" ]] || die "REPORT.md names no source revision"
head="$(g rev-parse HEAD 2>/dev/null)" || die "${KRYPTIK_ROOT} is not a git checkout"
[[ "$head" == "$rev" ]] || die "this tree is at ${head:0:12}, and the run tested ${rev:0:12}: check out the release's revision"
g diff --quiet HEAD -- docs/status.md build/config \
    || die "docs/status.md or build/config differs from ${rev:0:12}: the notes quote the release's own"

# --- what goes in them ----------------------------------------------------------
created="$(field "${PAYLOAD}/manifest" created)"
case "$(field "${PAYLOAD}/manifest" role)" in
    production)  role_line="A production release, signed with Kryptik's release key." ;;
    development) role_line="A development release: it is signed by keys its own build made, for testing and not for real machines." ;;
    *) die "the manifest names no role" ;;
esac
fw="$(row firmware)"; fw="${fw##*; }"; fw="OVMF ${fw#ovmf }"
qemu="$(row QEMU)"; kvm="${qemu##*kvm=}"; qemu="${qemu%; kvm=*}"; qemu="${qemu% (*}"; qemu="QEMU ${qemu##*version }"
[[ "$kvm" == yes ]] && qemu+=", with KVM"
ran="$(row 'run as')"; ran="${ran##* at }"
media_line() {   # media_line LABEL: "| name | sha256 |" from REPORT.md's header row
    local v path sum; v="$(row "$1")"
    path="${v%% (sha256*}"; sum="$(sed -n 's/.*(sha256 `\([0-9a-f]\{64\}\)`).*/\1/p' <<<"$v")"
    [[ -n "$sum" ]] || die "REPORT.md gives no SHA-256 for the ${1}"
    printf '| %s | `%s` |\n' "${path##*/}" "$sum"
}
usb_line="$(media_line 'USB medium')"; iso_line="$(media_line ISO)"
suites="$(awk -F'\t' 'NR > 1 {
    if (!($1 in items)) { order[++n] = $1; res[$1] = "PASS" }
    items[$1]++
    if ($5 != "PASS") res[$1] = $5
    if ($6 ~ /^[0-9]+\/[0-9]+$/) { split($6, pf, "/"); passed[$1] += pf[1]; counted[$1] = 1 }
  }
  END { for (i = 1; i <= n; i++) { s = order[i]; printf "| %s | %s | %d | %s |\n", s, res[s], items[s], (s in counted) ? passed[s] : "-" } }' "${RUN}/results.tsv")"

gaps="$(awk '/^## Known gaps[[:space:]]*$/ { on = 1; next } on && /^## / { exit } on' "${KRYPTIK_ROOT}/docs/status.md" \
        | awk 'NF { started = 1 } started { lines[++n] = $0 } END { while (n > 0 && lines[n] ~ /^[[:space:]]*$/) n--; for (i = 1; i <= n; i++) print lines[i] }')"
[[ -n "$gaps" ]] || die "docs/status.md has no '## Known gaps' section to quote"

changes="" since_name=""
if [[ -n "$SINCE" ]]; then
    g merge-base --is-ancestor "$SINCE" "$rev" 2>/dev/null \
        || die "--since ${SINCE} is not an ancestor of ${rev:0:12} here (a shallow clone lacks the history: fetch it)"
    since_name="$(g describe --exact-match --tags "$SINCE" 2>/dev/null \
                  || g rev-parse --short=12 "$SINCE")"
    # First-parent subjects are the merges' own sentences, less their
    # "Merge X into Y (#N): ". A merge with no sentence says nothing to a user.
    changes="$(g log --first-parent --reverse --format='%s' "${SINCE}..${rev}" \
               | sed 's/^Merge [^:]*: //' | grep -v '^Merge ' | sed 's/^./\U&/; s/^/- /' || true)"
fi

# The ELF audit: nothing refused, reported or stale, and each accepted kind
# with the reasons its list gives.
audit="$(python3 - "${RUN}/artifact-hardening.json" "${KRYPTIK_ROOT}/build/config/artifact-accepted.txt" <<'PY'
import json, sys, collections
def many(n, one, other=None):
    return f"{n} {one if n == 1 else (other or one + 's')}"
a = json.load(open(sys.argv[1]))
for name in ("hard", "reported", "stale"):
    if a.get(name):
        sys.exit(f"the artifact audit has {len(a[name])} {name} finding(s): a release has none")
kinds = collections.Counter(line.split()[0] for line in a.get("accepted", []))
reasons = collections.defaultdict(list)
if kinds:
    try:
        entries = open(sys.argv[2]).read().splitlines()
    except OSError:
        sys.exit("the audit accepted findings, and there is no build/config/artifact-accepted.txt to say why")
    for line in entries:
        if not line.strip() or line.lstrip().startswith("#") or "#" not in line:
            continue
        what, why = line.split("#", 1)
        fields, why = what.split(), why.strip()
        if why == "the same" and reasons[fields[0]]:
            why = reasons[fields[0]][-1][1]
        what = f"`{fields[1]}`" + (f", rpath `{fields[2]}`" if len(fields) > 2 else "")
        reasons[fields[0]].append((what, why))
f = a.get("findings", {})
print(f"- ELF objects: {a.get('objects', 0)} audited ({many(a.get('executables', 0), 'executable')}, "
      f"{many(a.get('libraries', 0), 'library', 'libraries')}). "
      f"None refused, none reported, {sum(kinds.values())} accepted"
      + (" (`build/config/artifact-accepted.txt`):" if kinds else "."))
for kind in sorted(kinds):
    print(f"  - {kind}, {many(kinds[kind], 'object')}:")
    for what, why in reasons.get(kind, []):
        print(f"    - {what}: {why}")
print(f"- Stack protector in {f.get('HAS-SSP', 0)} objects, FORTIFY_SOURCE in {f.get('HAS-FORTIFY', 0)}.")
PY
)" || die "the hardening audit does not allow notes"

# --- the notes ------------------------------------------------------------------
cat <<EOF
# Kryptik ${version}

Released ${created%%T*}, built from \`${rev}\`. ${role_line}
EOF
if [[ -n "$changes" ]]; then
    printf '\n## Changes since %s\n\n%s\n' "$since_name" "$changes"
fi
cat <<EOF

## What was tested

Every suite of \`make acceptance\` passed on the images this release ships,
on ${ran%%T*}, under ${fw} and ${qemu}.
\`ACCEPTANCE-REPORT.md\` beside these notes lists every item with its log.

| Suite | Result | Items | Checks passed |
| --- | --- | --- | --- |
${suites}

## Hardening audit

- Kernel: $(entries "${KRYPTIK_ROOT}/build/config/kernel/checker-accepted.txt" "kernel-hardening-checker finding") accepted, each with its reason (\`build/config/kernel/checker-accepted.txt\`).
- Compiler flags: $(entries "${KRYPTIK_ROOT}/build/config/hardening-exceptions.txt" exception) to the hardening set (\`build/config/hardening-exceptions.txt\`).
- setuid and setgid: $(entries "${KRYPTIK_ROOT}/build/config/setuid-allowlist.txt" program), each with the reason it keeps the bit (\`build/config/setuid-allowlist.txt\`). Programs with file capabilities: $(entries "${KRYPTIK_ROOT}/build/config/capability-allowlist.txt" program | cut -d' ' -f1).
${audit}

## Known gaps

${gaps}

## Source and licences

The corresponding source of \`${rev:0:12}\` is \`source-${rev:0:12}.tar\`, published
with this release: every upstream tarball with its signature, the vendored
Rust crates and Kryptik's own tree, with a MANIFEST of their SHA-256. The
licences of what the image holds are under \`/usr/share/licenses/\`, one
directory per source, Kryptik's own in \`kryptik/LICENSE\`.

## Checking a download

| File | SHA-256 |
| --- | --- |
${usb_line}
${iso_line}

\`SHA256SUMS\` beside them covers the rest of the release record.
EOF
