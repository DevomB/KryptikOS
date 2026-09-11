#!/usr/bin/env bash
# Focused tests for tools/provenance-inventory.sh.
#
#   ./tools/test-provenance-inventory.sh
#
# Deterministic and offline. The inventory computes no verification itself - it
# runs the two verification tools with --report=FILE and aggregates - so what
# there is to test is the aggregation: which assurance class each source lands
# in, that a failure outranks every established assertion, that the lock state
# is computed from the bytes on disk, and that no single coverage figure is
# ever printed.
#
# The evidence is therefore supplied rather than collected, through a gated
# self-test hook. Real evidence collection is covered by
# tools/test-verify-signatures.sh and tools/test-verify-provenance.sh.

set -uo pipefail

# See the same note in the other suites: common.sh prefers these over anything
# derived from KRYPTIK_ROOT, so an exported one would silently redirect the
# inventory at the real tree.
unset KRYPTIK_SOURCES KRYPTIK_WORK KRYPTIK_LOCK KRYPTIK_OUT KRYPTIK_ROOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${ROOT}/tools/provenance-inventory.sh"

PASS=0
FAIL=0
green() { printf '\033[32m  PASS\033[0m  %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '\033[31m  FAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }

W="$(mktemp -d)"
OUT="${W}/out"
RC=0
trap 'rm -rf "$W"' EXIT

show() { sed 's/^/        /' "$OUT"; }

FAKE="${W}/root"
EV="${W}/evidence"
mkdir -p "$EV"

# --- fixture tree -----------------------------------------------------------
#
# A stand-in manifest of eight sources, one per interesting class, plus the
# bytes and the lock entries needed to exercise lock-state reporting.

build_tree() {
    rm -rf "$FAKE"
    mkdir -p "${FAKE}/build/config" "${FAKE}/sources" "${FAKE}/tools"

    # provenance-inventory.sh asks fetch-sources.sh for the manifest. Point it
    # at a stub rather than reproducing 69 real rows: the inventory's input is
    # the three columns, and the real manifest is fetch-sources.sh's business.
    cat > "${FAKE}/tools/fetch-sources.sh" <<'STUB'
#!/usr/bin/env bash
# Test stub: emits the same three columns as `fetch-sources.sh --list`.
cat <<'ROWS'
alloc        14         https://example.test/alloc/14.tar.gz
pinnedpkg    1.0        https://example.test/pinnedpkg-1.0.tar.gz
korgcert     2.0        https://example.test/korgcert-2.0.tar.gz
korgpub      3.0        https://example.test/korgpub-3.0.tar.gz
keyringpkg   4.0        https://example.test/keyringpkg-4.0.tar.gz
unauditedpkg 5.0        https://example.test/unauditedpkg-5.0.tar.gz
pubsha       6.0        https://example.test/pubsha-6.0.tar.gz
lockonly     7.0        https://example.test/lockonly-7.0.tar.gz
absentpkg    8.0        https://example.test/absentpkg-8.0.tar.gz
nolockpkg    9.0        https://example.test/nolockpkg-9.0.tar.gz
ROWS
STUB
    chmod 755 "${FAKE}/tools/fetch-sources.sh"

    : > "${FAKE}/build/config/versions.env"

    # Bytes on disk, and a lock that agrees with all but one of them.
    local f
    for f in 14 pinnedpkg-1.0 korgcert-2.0 korgpub-3.0 keyringpkg-4.0 \
             unauditedpkg-5.0 pubsha-6.0 lockonly-7.0 nolockpkg-9.0; do
        printf 'payload %s\n' "$f" > "${FAKE}/sources/${f}.tar.gz"
    done
    : > "${FAKE}/sources.lock"
    for f in 14 pinnedpkg-1.0 korgcert-2.0 korgpub-3.0 keyringpkg-4.0 \
             unauditedpkg-5.0 pubsha-6.0 lockonly-7.0; do
        printf '%s  %s.tar.gz\n' \
            "$(sha256sum "${FAKE}/sources/${f}.tar.gz" | cut -d' ' -f1)" "$f" \
            >> "${FAKE}/sources.lock"
    done
    # Locked but never downloaded.
    printf '%s  absentpkg-8.0.tar.gz\n' \
        0000000000000000000000000000000000000000000000000000000000000000 \
        >> "${FAKE}/sources.lock"
    # nolockpkg-9.0 is deliberately absent from the lock.
}

write_evidence() {
    cat > "${EV}/signatures.tsv" <<'TSV'
pinnedpkg	signature-pinned-key	Greg Kroah-Hartman (stable) (38DBBDC86092693E)
korgcert	signature-unaudited-key	Theodore Ts'o <tytso@mit.edu> (F2F95956950D81A3)
korgpub	signature-unaudited-key	Karel Zak <kzak@redhat.com> (E4B71D5EEC39C284)
keyringpkg	signature-keyring-key	Nick Clifton <nickc@redhat.com> (13FCEF89DD9E3C4F)
unauditedpkg	signature-unaudited-key	Someone <nobody@example.test> (DEADBEEFDEADBEEF)
pubsha	no-signature-upstream	none of .sig/.asc/.sign is published
lockonly	key-not-held	ABCDEF0123456789
absentpkg	not-downloaded	no local copy to check a signature against
nolockpkg	no-signature-upstream	none of .sig/.asc/.sign is published
TSV

    cat > "${EV}/provenance.tsv" <<'TSV'
alloc	lock:established	14.tar.gz matches sources.lock
alloc	sig:established	tag 14 carries a valid SSH signature
alloc	id:established	signed by the pinned contact@grapheneos.org key
alloc	tree:established	14.tar.gz reproduces the tree of the verified tag
pubsha	lock:established	pubsha-6.0.tar.gz matches sources.lock
pubsha	pub:established	publisher sha256 agrees with sources.lock
TSV

    cat > "${EV}/identity.tsv" <<'TSV'
korgcert	3AB057B7E78D945C8C5591FBD36F769BC11804F0	korg-published-and-certified	certified by Kroah-Hartman
korgpub	B0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284	korg-published	no certification by a reference key on the distributed material
TSV
}

run() {
    KRYPTIK_ROOT="$FAKE" \
    KRYPTIK_INVENTORY_SELFTEST=1 \
    KRYPTIK_INVENTORY_REPORTS="$EV" \
    NO_COLOR=1 \
    bash "$TOOL" "$@" > "$OUT" 2>&1
    RC=$?
}

# row <source> -> the inventory line for that source
row() { grep -E "^$1 " "$OUT" | head -1; }

expect_class() {
    local src="$1" klass="$2"
    local line; line="$(row "$src")"
    if [[ -z "$line" ]]; then
        red "${src}: no row in the inventory"; show
    elif ! printf '%s' "$line" | grep -qF " $klass "; then
        red "${src}: expected class ${klass}, got: ${line}"
    else
        green "${src} -> ${klass}"
    fi
}

echo "tools/provenance-inventory.sh"
echo

build_tree
write_evidence
run

if [[ "$RC" -ne 0 ]]; then
    red "the inventory exited ${RC} on evidence containing no failures"; show
else
    green "an inventory with no failed source exits 0"
fi

# --- one class per source, strongest established assertion wins -------------

expect_class alloc        signed-tree-pinned-key
expect_class pinnedpkg    signature-pinned-key
expect_class korgcert     signature-korg-certified-key
expect_class korgpub      signature-korg-published-key
expect_class keyringpkg   signature-keyring-key
expect_class unauditedpkg signature-unaudited-key
expect_class pubsha       publisher-checksum
expect_class lockonly     lock-only
expect_class absentpkg    not-downloaded

# The same signature evidence, three different classes, decided only by what
# the identity check found. This is the distinction the old coverage figure
# erased by adding all three together.
if [[ "$(row korgcert | wc -l)" -eq 1 ]] \
   && ! diff <(row korgcert | awk '{print $3}') <(row korgpub | awk '{print $3}') >/dev/null; then
    green "identity evidence separates otherwise identical signature results"
else
    red "korgcert and korgpub landed in the same class"; show
fi

# --- lock state is computed from the bytes, not from the evidence -----------

for pair in "pinnedpkg:lock OK" "absentpkg:locked, absent" \
            "nolockpkg:NO LOCK ENTRY"; do
    src="${pair%%:*}"; want="${pair#*:}"
    if printf '%s' "$(row "$src")" | grep -qF "$want"; then
        green "${src}: lock state reported as [${want}]"
    else
        red "${src}: expected lock state [${want}], got: $(row "$src")"
    fi
done

printf 'tampered\n' >> "${FAKE}/sources/pinnedpkg-1.0.tar.gz"
run
if printf '%s' "$(row pinnedpkg)" | grep -qF "LOCK MISMATCH"; then
    green "a modified download is reported as LOCK MISMATCH"
else
    red "a modified download was not reported: $(row pinnedpkg)"; show
fi
build_tree

# --- a failure outranks every established assertion -------------------------

write_evidence
cat >> "${EV}/provenance.tsv" <<'TSV'
alloc	tree:failed	14.tar.gz IS NOT THE SIGNED TREE
TSV
run
if [[ "$RC" -ne 0 ]]; then
    green "an inventory containing a failed source exits non-zero"
else
    red "a failed source did not affect the exit status"; show
fi
expect_class alloc signature-failed
write_evidence

# A source whose signature is bad is a failure even though its lock agrees.
cat > "${EV}/signatures.tsv" <<'TSV'
pinnedpkg	signature-bad	the file does not match its signature
TSV
run
expect_class pinnedpkg signature-failed
if [[ "$RC" -ne 0 ]]; then
    green "a bad signature fails the inventory despite a matching lock"
else
    red "a bad signature did not affect the exit status"; show
fi
write_evidence

# --- no single coverage figure ---------------------------------------------

run
if grep -qiE '[0-9]+ +(of|/) +[0-9]+' "$OUT"; then
    red "the inventory printed an N-of-M coverage figure"
    grep -inE '[0-9]+ +(of|/) +[0-9]+' "$OUT" | sed 's/^/        /'
else
    green "no N-of-M coverage figure is printed anywhere"
fi

if grep -qF "there is no total" "$OUT"; then
    green "the per-class counts say explicitly that they are not a total"
else
    red "the output does not state that the counts are not a total"; show
fi

# The counts depend on which keyring produced them, so the report has to say
# which one did. Under the self-test hook there is no signature log at all, and
# "unknown" is the honest answer rather than a silent omission.
if grep -qiE "keyring state for this run" "$OUT"; then
    green "the report states which keyring state produced the counts"
else
    red "the report does not say which keyring state it was measured against"; show
fi

# Strongest first, so a reader cannot mistake the order for arbitrary.
order="$(grep -oE '^  +[0-9]+  [a-z-]+' "$OUT" | awk '{print $2}' | tr '\n' ' ')"
case "$order" in
    "signed-tree-pinned-key signature-pinned-key signature-korg-certified-key"*)
        green "per-class counts are ordered strongest first" ;;
    *)  red "per-class order unexpected: ${order}" ;;
esac

# --- markdown ---------------------------------------------------------------

run --md
if grep -qF "| source | version | assurance class |" "$OUT" \
   && grep -qF '| `alloc` |' "$OUT"; then
    green "--md emits a markdown table"
else
    red "--md did not emit a markdown table"; show
fi

# The markdown is an artifact that gets committed, so progress chatter must not
# be in it. stdout is checked on its own here; stderr is where progress belongs.
KRYPTIK_ROOT="$FAKE" KRYPTIK_INVENTORY_SELFTEST=1 \
    KRYPTIK_INVENTORY_REPORTS="$EV" NO_COLOR=1 \
    bash "$TOOL" --md > "${W}/md.out" 2>/dev/null
# The keyring-state note is part of the artifact and comes first; what must
# NOT be there is the progress chatter, which belongs on stderr.
if [[ "$(head -1 "${W}/md.out")" == "**Keyring state for this run:**"* ]] \
   && grep -qF "| source | version | assurance class" "${W}/md.out" \
   && ! grep -qE '^(==>|  ok|warn|  manifest:|  running)' "${W}/md.out"; then
    green "--md keeps progress output off stdout"
else
    red "--md leaked progress into the artifact"
    sed 's/^/        /' "${W}/md.out" | head -8
fi

# --- --json -----------------------------------------------------------------

build_tree
write_evidence
KRYPTIK_ROOT="$FAKE" KRYPTIK_INVENTORY_SELFTEST=1 \
    KRYPTIK_INVENTORY_REPORTS="$EV" NO_COLOR=1 \
    bash "$TOOL" --json > "${W}/inv.json" 2>/dev/null
rc=$?
if [[ "$rc" -eq 0 ]] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" \
        "${W}/inv.json" 2>/dev/null; then
    green "--json emits a parseable document on stdout alone"
else
    red "--json did not emit parseable JSON (exit ${rc})"
    head -5 "${W}/inv.json" | sed 's/^/        /'
fi

python3 - "${W}/inv.json" > "${W}/jchk" 2>&1 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
out = []


def ck(name, cond):
    out.append(("ok " if cond else "no ") + name)


ck("schema is named", d.get("schema") == "kryptik-provenance-inventory-1")
ck("every source has a name and an assurance class",
   all(s.get("name") and s.get("assurance_class") for s in d["sources"]))
ck("per-class counts account for every row",
   sum(d["per_class_counts"].values()) == len(d["sources"]))
ck("no coverage ratio is published",
   not [k for k in d if "coverage" in k or "verified_total" in k])
ck("the document explains its own assurance classes",
   len(d["assurance_classes"]) >= 8
   and all("means" in c for c in d["assurance_classes"]))
ck("licence reads not-collected when it was not requested",
   all(s["licence"]["spdx"] == "not-collected" for s in d["sources"]))
ck("the keyring state is carried as a field", "keyring_state" in d)
ck("a locked hash is carried per source",
   any(s.get("sha256_locked") for s in d["sources"]))
print("\n".join(out))
PY
while read -r verdict rest; do
    if [[ "$verdict" == "ok" ]]; then green "--json: ${rest}"; else red "--json: ${rest}"; fi
done < "${W}/jchk"

# Licences requested: the field must carry evidence rather than not-collected.
KRYPTIK_ROOT="$FAKE" KRYPTIK_INVENTORY_SELFTEST=1 \
    KRYPTIK_INVENTORY_REPORTS="$EV" NO_COLOR=1 \
    bash "$TOOL" --json --licences > "${W}/inv2.json" 2>/dev/null
if python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
vals={s['licence']['method'] for s in d['sources']}
raise SystemExit(0 if vals and vals != {'not-collected'} else 1)
" "${W}/inv2.json" 2>/dev/null; then
    green "--licences replaces not-collected with a real method"
else
    red "--licences did not populate the licence method"
fi

# An artefact tree that does not exist is recorded as absent, not omitted:
# a missing artefact is a fact about the release, not a gap in the document.
KRYPTIK_ROOT="$FAKE" KRYPTIK_INVENTORY_SELFTEST=1 \
    KRYPTIK_INVENTORY_REPORTS="$EV" NO_COLOR=1 \
    bash "$TOOL" --json --artifacts=/nonexistent/tree > "${W}/inv3.json" 2>/dev/null
if python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
a=d['artifacts']
raise SystemExit(0 if len(a)==1 and a[0]['state']=='absent' else 1)
" "${W}/inv3.json" 2>/dev/null; then
    green "a missing artefact tree is recorded as absent, not omitted"
else
    red "a missing artefact tree was not recorded"
fi

KRYPTIK_ROOT="$FAKE" KRYPTIK_INVENTORY_SELFTEST=1 \
    KRYPTIK_INVENTORY_REPORTS="$EV" NO_COLOR=1 \
    bash "$TOOL" --json --md > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "different documents" "$OUT"; then
    green "--json with --md is refused rather than producing a hybrid"
else
    red "--json --md was accepted (exit ${rc})"; show
fi

# --- the selftest hook cannot be used by accident ---------------------------

KRYPTIK_ROOT="$FAKE" KRYPTIK_INVENTORY_REPORTS="$EV" NO_COLOR=1 \
    bash "$TOOL" > "$OUT" 2>&1
rc=$?
if [[ "$rc" -ne 0 ]] && grep -qF "Refusing to build an inventory" "$OUT"; then
    green "supplied evidence is refused without the selftest flag"
else
    red "supplied evidence was accepted without KRYPTIK_INVENTORY_SELFTEST"; show
fi

# --- recorded caveats -------------------------------------------------------
#
# A caveat records something true about a source that no assurance class can
# express: a recipe that rewrites upstream's files, or a signature whose signer
# upstream never designated. The one thing a caveat must never do is read as
# assurance, so the kinds are checked to stay out of the class counts.

NOTES="${W}/notes.tsv"
write_notes() { printf '%s\n' "$@" > "$NOTES"; }

write_notes \
    '# fixture caveats' \
    'lockonly  recipe-transformation  build/stages/04.sh:1-9  the recipe rewrites an upstream file and the result is compiled in' \
    'pubsha    undesignated-signer    https://example.test/   upstream designates nobody as its release signer'

run --offline --notes="$NOTES"
if [[ "$RC" -eq 0 ]] && grep -qF 'RECORDED CAVEATS' "$OUT"; then
    green "recorded caveats are printed in the text report"
else
    red "recorded caveats are printed in the text report (exit ${RC})"; show
fi
if grep -qF 'never added to the' "$OUT"; then
    green "labelled explicitly as not assurance classes"
else
    red "labelled explicitly as not assurance classes"; show
fi
if grep -qF 'recipe-transformation' "$OUT" && grep -qF 'undesignated-signer' "$OUT"; then
    green "both kinds appear in the report"
else
    red "both kinds appear in the report"; show
fi
if grep -qF 'build/stages/04.sh:1-9' "$OUT"; then
    green "and each caveat carries the location it was found at"
else
    red "and each caveat carries the location it was found at"; show
fi

run --offline --md --notes="$NOTES"
if grep -qF '### Recorded caveats' "$OUT"; then
    green "markdown output gets a caveats section"
else
    red "markdown output gets a caveats section"; show
fi

# The JSON document is on stdout; progress goes to stderr. Capturing both into
# one file is how an earlier draft of these six cases got ERR for every value.
NJSON="${W}/notes.json"
KRYPTIK_ROOT="$FAKE" KRYPTIK_INVENTORY_SELFTEST=1 \
    KRYPTIK_INVENTORY_REPORTS="$EV" NO_COLOR=1 \
    bash "$TOOL" --offline --json --notes="$NOTES" > "$NJSON" 2>/dev/null

jget() { python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(eval(sys.argv[2], {'d': d, 'json': json}))
" "$NJSON" "$1" 2>/dev/null || printf 'ERR'; }

got="$(jget "json.dumps(d.get('per_note_kind_counts'), sort_keys=True)")"
if [[ "$got" == '{"recipe-transformation": 1, "undesignated-signer": 1}' ]]; then
    green "per_note_kind_counts counts each kind once"
else
    red "per_note_kind_counts counts each kind once (got ${got})"
fi

got="$(jget "d.get('noted_source_count')")"
if [[ "$got" == "2" ]]; then
    green "noted_source_count counts the sources carrying caveats"
else
    red "noted_source_count counts the sources carrying caveats (got ${got})"
fi

got="$(jget "[n['kind'] for s in d['sources'] if s['name']=='lockonly' for n in s.get('notes',[])]")"
if [[ "$got" == "['recipe-transformation']" ]]; then
    green "the caveat is attached to the source it names"
else
    red "the caveat is attached to the source it names (got ${got})"
fi

got="$(jget "sorted(k for k in d['per_class_counts'] if 'transformation' in k or 'designated' in k)")"
if [[ "$got" == "[]" ]]; then
    green "caveat kinds never appear among the assurance classes"
else
    red "caveat kinds leaked into per_class_counts (${got})"
fi

got="$(jget "[s['assurance_class'] for s in d['sources'] if s['name']=='lockonly']")"
if [[ "$got" == "['lock-only']" ]]; then
    green "a caveat does not change the source's assurance class"
else
    red "a caveat changed the assurance class (got ${got})"
fi

got="$(jget "'notes' in [k for s in d['sources'] if s['name']=='korgcert' for k in s]")"
if [[ "$got" == "False" ]]; then
    green "sources with no caveat carry no notes field"
else
    red "sources with no caveat carry no notes field (got ${got})"
fi

# Positive control: caveats are optional, and a tree without the file is not an
# error. The fixture tree has no tools/source-notes.tsv.
run --offline
if [[ "$RC" -eq 0 ]] && ! grep -qF 'RECORDED CAVEATS' "$OUT"; then
    green "a tree with no caveat file inventories cleanly"
else
    red "a tree with no caveat file inventories cleanly (exit ${RC})"; show
fi

# --- a malformed caveat file is a tooling fault, not a provenance result -----

bad_note() {  # bad_note ROW NAME
    write_notes "$1"
    run --offline --notes="$NOTES"
    if [[ "$RC" -ne 0 ]] && grep -qF 'malformed' "$OUT"; then
        green "$2"
    else
        red "$2 (exit ${RC})"; show
    fi
}

bad_note 'lockonly  rewritten-somehow  build/x.sh:1  a kind nobody defined' \
         "an unknown caveat kind is refused"
bad_note 'lockonly  recipe-transformation  build/x.sh:1' \
         "a caveat with no note text is refused"
bad_note 'lockonly  recipe-transformation' \
         "a caveat missing its location is refused"
bad_note 'nosuchsource  recipe-transformation  build/x.sh:1  describes something not shipped' \
         "a caveat naming a source outside the manifest is refused"

write_notes 'lockonly  recipe-transformation  build/x.sh:1  fine' \
            'alsomissing  undesignated-signer  https://x.test/  stale'
run --offline --notes="$NOTES"
if [[ "$RC" -ne 0 ]] && grep -qE 'notes\.tsv:2|:2: ' "$OUT"; then
    green "the refusal names the offending line number"
else
    red "the refusal names the offending line number (exit ${RC})"; show
fi
if grep -qF 'not a provenance' "$OUT"; then
    green "and says nothing was reported rather than reporting a partial inventory"
else
    red "and says nothing was reported rather than reporting a partial inventory"; show
fi

run --offline --notes="${W}/no-such-notes.tsv"
if [[ "$RC" -ne 0 ]] && grep -qF 'named with --notes' "$OUT"; then
    green "a caveat file named explicitly but missing is refused"
else
    red "a caveat file named explicitly but missing is refused (exit ${RC})"; show
fi

# --- the shipped caveat file is itself valid --------------------------------
#
# Guards the real data rather than a fixture: a row added with an undefined
# kind, or naming a source that has since been dropped, must break here.
#
# KRYPTIK_SOURCES and KRYPTIK_WORK are set deliberately here, against this
# file's own rule, and only for this one invocation: pointing them at empty
# directories keeps the real KRYPTIK_ROOT (so the real manifest and the real
# caveat file are used) while skipping the sha256 of every tarball in
# sources/, which is gigabytes of hashing this check does not need.
mkdir -p "${W}/empty-sources" "${W}/realwork"
RC=0
KRYPTIK_SOURCES="${W}/empty-sources" KRYPTIK_WORK="${W}/realwork" NO_COLOR=1 \
    bash "$TOOL" --offline --json > "$OUT" 2>&1 || RC=$?
if [[ "$RC" -eq 0 ]] && ! grep -qF 'malformed' "$OUT"; then
    green "the shipped tools/source-notes.tsv is well formed against the real manifest"
else
    red "the shipped tools/source-notes.tsv is well formed against the real manifest (exit ${RC})"
    grep -F 'source-notes' "$OUT" | sed 's/^/        /' | head -5
fi

echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "${FAIL} of $((PASS + FAIL)) checks failed."
    exit 1
fi
echo "All ${PASS} checks passed."
