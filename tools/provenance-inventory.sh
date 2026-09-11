#!/usr/bin/env bash
# A source-by-source provenance inventory. One row per source, one assurance
# class per row, and deliberately no single coverage number.
#
#   ./tools/provenance-inventory.sh                 full inventory
#   ./tools/provenance-inventory.sh --offline       lock integrity only
#   ./tools/provenance-inventory.sh --identity      also check signer identity
#                                                   against kernel.org's
#                                                   published developer keys
#   ./tools/provenance-inventory.sh --md            markdown table
#   ./tools/provenance-inventory.sh --notes=FILE    caveats from FILE rather
#                                                   than tools/source-notes.tsv
#
# WHY THIS EXISTS, AND WHY IT REFUSES TO PRINT A TOTAL.
#
# docs/supply-chain.md has at various points said "54 of 69 sources verify" and
# "60 of 69 with some independent confirmation". Those numbers were arrived at
# by adding together things that are not the same thing. Of that 54, twenty
# were signatures checked against a key imported because the signature itself
# named it - which establishes that a file was signed by whoever signed it, and
# nothing whatever about who that is.
#
# A number like that is worse than no number, because it invites a reader to
# treat the weakest link as if it were the average. So this tool prints the
# class of every source and a count PER CLASS, and prints no total. The classes
# are ordered strongest first, and what each one is worth is stated next to it.
#
# It computes nothing itself. It runs the two verification tools with
# --report=FILE and aggregates what they found, so there is exactly one
# implementation of each check and this cannot drift away from it.

source "$(dirname "${BASH_SOURCE[0]}")/../build/lib/common.sh"
load_config

OFFLINE=0
IDENTITY=0
MD=0
JSON=0
LICENCES=0
ARTIFACTS=""
for a in "$@"; do
    case "$a" in
        --offline)  OFFLINE=1 ;;
        --identity) IDENTITY=1 ;;
        --md)       MD=1 ;;
        --json)     JSON=1 ;;
        --licences|--licenses) LICENCES=1 ;;
        --artifacts=*) ARTIFACTS="${a#--artifacts=}" ;;
        --notes=*)  NOTES_ARG="${a#--notes=}" ;;
        -h|--help)  sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done
[[ "$JSON" -eq 1 && "$MD" -eq 1 ]] && die "--json and --md are different documents; pick one"

have python3 || die "python3 required"

WORK="${KRYPTIK_WORK}/inventory"
rm -rf "$WORK"; mkdir -p "$WORK"

SIGREP="${WORK}/signatures.tsv"
PROVREP="${WORK}/provenance.tsv"
: > "$SIGREP"; : > "$PROVREP"

# ---------------------------------------------------------------------------
# 1. gather
# ---------------------------------------------------------------------------

# Under --md the output is an artifact that gets committed, so progress has to
# stay out of it. Park stdout on fd 3 and send everything up to the table to
# stderr, then put it back.
if [[ "$MD" -eq 1 || "$JSON" -eq 1 ]]; then exec 3>&1 1>&2; fi

log "Collecting per-source evidence"

MANIFEST="${WORK}/manifest.tsv"
"${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list \
    | awk '{printf "%s\t%s\t%s\n", $1, $2, $3}' > "$MANIFEST"
dim "  manifest: $(wc -l < "$MANIFEST") sources"

# ---------------------------------------------------------------------------
# 1b. recorded provenance caveats
# ---------------------------------------------------------------------------
#
# Some facts about a source are true, material, and invisible to every check:
# a build recipe that rewrites upstream's own files, or a signature verifying
# against a key upstream never designated. Those go in tools/source-notes.tsv.
#
# A NOTE IS A CAVEAT AND NEVER AN ASSURANCE CLASS. Notes are not added to the
# per-class counts and do not raise or lower any source's class.
#
# Resolved through KRYPTIK_ROOT, unlike scan-licenses.sh which is resolved
# through BASH_SOURCE. The difference is deliberate and it is the difference
# between a helper and data: the licence scanner is a tool this script needs
# wherever it runs, while caveats describe THE TREE BEING INVENTORIED. Pointing
# the inventory at another tree must pick up that tree's caveats, or their
# absence -- not carry this repository's caveats across and then reject them as
# naming sources the other tree does not ship.
#
# --notes=FILE names a different caveat file. The default is OPTIONAL: a tree
# without one simply has no recorded caveats. A file named explicitly and then
# missing is an error, because the caller asked for caveats that are not there
# and continuing would drop them silently.
NOTESF="${KRYPTIK_ROOT}/tools/source-notes.tsv"
if [[ -n "${NOTES_ARG:-}" ]]; then
    NOTESF="$NOTES_ARG"
    [[ -f "$NOTESF" ]] || die "no caveat file at ${NOTESF} (named with --notes)"
fi
NOTES_TSV="${WORK}/notes.tsv"
: > "$NOTES_TSV"
if [[ -f "$NOTESF" ]]; then
    nbad=0
    nline=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        nline=$((nline + 1))
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        read -r n_pkg n_kind n_loc n_note <<< "$line"

        nb=""
        [[ -n "$n_pkg" && -n "$n_kind" && -n "$n_loc" && -n "${n_note// }" ]] \
            || nb="expected a package, a kind, a location and a note"
        if [[ -z "$nb" ]]; then
            case "$n_kind" in
                recipe-transformation|undesignated-signer) ;;
                *) nb="unknown kind '${n_kind}'" ;;
            esac
        fi
        # A note about a source that is not in the manifest is a stale note,
        # and a stale caveat is worse than none: it describes something that
        # is not being shipped.
        if [[ -z "$nb" ]] \
           && ! awk -F'\t' -v p="$n_pkg" '$1==p{f=1} END{exit !f}' "$MANIFEST"; then
            nb="'${n_pkg}' is not a source in the manifest"
        fi

        if [[ -n "$nb" ]]; then
            err "${NOTESF}:${nline}: ${nb}"
            nbad=$((nbad + 1))
            continue
        fi
        printf '%s\t%s\t%s\t%s\n' "$n_pkg" "$n_kind" "$n_loc" "$n_note" >> "$NOTES_TSV"
    done < "$NOTESF"
    [[ "$nbad" -eq 0 ]] || die "${nbad} malformed row(s) in ${NOTESF}.
A caveat file that cannot be parsed is a tooling fault, not a provenance
result: reporting the inventory without it would drop recorded facts silently."
    dim "  notes: $(grep -c . "$NOTES_TSV" || true) recorded caveat(s)"
fi

# Self-test hook. tools/test-provenance-inventory.sh supplies pre-made report
# files so the classification and the per-class accounting - which is all this
# tool actually does - can be driven through every class offline. Gated, so an
# inventory cannot be quietly produced from hand-written evidence.
if [[ -n "${KRYPTIK_INVENTORY_REPORTS:-}" ]]; then
    [[ "${KRYPTIK_INVENTORY_SELFTEST:-0}" == "1" ]] || die \
"KRYPTIK_INVENTORY_REPORTS is set but KRYPTIK_INVENTORY_SELFTEST is not.
Refusing to build an inventory from substituted evidence."
    warn "SELF-TEST MODE: evidence is supplied, not collected"
    for f in signatures provenance identity; do
        [[ -f "${KRYPTIK_INVENTORY_REPORTS}/${f}.tsv" ]] \
            && cp "${KRYPTIK_INVENTORY_REPORTS}/${f}.tsv" "${WORK}/${f}.tsv"
    done
    IDREP_PRESET=1
elif [[ "$OFFLINE" -eq 1 ]]; then
    warn "--offline: signature and publisher evidence will not be collected."
    warn "Every source will therefore show only what sources.lock establishes."
else
    # Both tools are run informationally on purpose: this is an inventory, not
    # a gate. Their exit status is recorded rather than propagated, and the row
    # for each source says what was established either way.
    dim "  running tools/verify-signatures.sh"
    "${KRYPTIK_ROOT}/tools/verify-signatures.sh" --report="$SIGREP" \
        > "${WORK}/signatures.log" 2>&1 || true
    dim "  running tools/verify-provenance.sh"
    "${KRYPTIK_ROOT}/tools/verify-provenance.sh" --report="$PROVREP" \
        > "${WORK}/provenance.log" 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 2. signer identity, against a primary upstream source
# ---------------------------------------------------------------------------
#
# keys.manifest records keys accepted because a signature named them. The
# question that ledger exists to ask is "is this key really the maintainer's",
# and there is a primary source that can answer part of it:
#
#   https://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git
#
# whose README.rst states its purpose as distributing "Linux kernel developer
# PGP keys that have valid trust paths to Linus Torvalds", one ascii-armoured
# key per long key id under keys/.
#
# Every source in keys.manifest is hosted on kernel.org, so that repository is
# the right place to look. What a match there establishes, precisely: kernel.org
# publishes this exact key for a developer of that name. What it does not
# establish: anything confirmed out-of-band by a human, and nothing beyond the
# TLS/CA trust root for git.kernel.org.
#
# The repository's own HEAD commit is signed, which is a better anchor than the
# fetch, and this checks that too when the signing key is available.

IDREP="${WORK}/identity.tsv"
# Do not truncate what the self-test hook has already copied in.
[[ -n "${IDREP_PRESET:-}" ]] || : > "$IDREP"

KORG_KEYS="https://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git/plain/keys"

collect_identity() {
    local manifest="${KRYPTIK_ROOT}/keys.manifest"
    [[ -f "$manifest" ]] || { dim "  no keys.manifest; nothing to check"; return 0; }

    have gpg || { warn "gpg not available; skipping identity checks"; return 0; }

    local home="${WORK}/gnupg"
    mkdir -p "$home"; chmod 700 "$home"

    # Reference identities. Kryptik ALREADY relies on the stable key to verify
    # the kernel tarball, so a certification made by it is not a new trust
    # decision - it is the one already taken, reused.
    local ref rid
    for ref in "79BE3E4300411886:Torvalds" "38DBBDC86092693E:Kroah-Hartman" \
               "E63EDCA9329DD07E:Ryabitsev"; do
        rid="${ref%%:*}"
        curl -fsSL --max-time 30 "${KORG_KEYS}/${rid}.asc" -o "${WORK}/ref-${rid}.asc" \
            2>/dev/null || continue
        GNUPGHOME="$home" gpg --batch --quiet --import "${WORK}/ref-${rid}.asc" \
            >/dev/null 2>&1 || true
    done

    local pkg fpr rest id got certs hop
    while read -r pkg fpr rest; do
        [[ "$pkg" == \#* ]] && continue
        [[ "$fpr" =~ ^[0-9A-Fa-f]{40}$ ]] || continue
        id="${fpr: -16}"

        if ! curl -fsSL --max-time 30 "${KORG_KEYS}/${id}.asc" \
                 -o "${WORK}/k-${id}.asc" 2>/dev/null; then
            printf '%s\t%s\tnot-published\t-\n' "$pkg" "$fpr" >> "$IDREP"
            continue
        fi
        GNUPGHOME="$home" gpg --batch --quiet --import "${WORK}/k-${id}.asc" \
            >/dev/null 2>&1 || true

        got="$(GNUPGHOME="$home" gpg --batch --list-keys --with-colons "$fpr" 2>/dev/null \
               | awk -F: '$1=="fpr"{print $10; exit}')"
        if [[ "${got^^}" != "${fpr^^}" ]]; then
            printf '%s\t%s\tfingerprint-mismatch\t%s\n' "$pkg" "$fpr" "${got:-none}" >> "$IDREP"
            continue
        fi

        # Certifications present on the key material kernel.org distributes.
        # An absence here is not proof that no certification exists: a key
        # exported with export-minimal carries none.
        certs="$(GNUPGHOME="$home" gpg --batch --list-sigs --with-colons "$fpr" 2>/dev/null \
                 | awk -F: '$1=="sig"{print $5}' | sort -u)"
        hop=""
        printf '%s\n' "$certs" | grep -qi 79BE3E4300411886 && hop="${hop}Torvalds "
        printf '%s\n' "$certs" | grep -qi 38DBBDC86092693E && hop="${hop}Kroah-Hartman "
        printf '%s\n' "$certs" | grep -qi E63EDCA9329DD07E && hop="${hop}Ryabitsev "

        if [[ -n "$hop" ]]; then
            printf '%s\t%s\tkorg-published-and-certified\t%s\n' \
                "$pkg" "$fpr" "certified by ${hop% }" >> "$IDREP"
        else
            printf '%s\t%s\tkorg-published\t%s\n' "$pkg" "$fpr" \
                "no certification by a reference key on the distributed material" \
                >> "$IDREP"
        fi
    done < "$manifest"
}

if [[ -n "${IDREP_PRESET:-}" ]]; then
    dim "  identity evidence supplied by the self-test"
elif [[ "$IDENTITY" -eq 1 && "$OFFLINE" -eq 0 ]]; then
    log "Checking signer identity against kernel.org's published developer keys"
    collect_identity
    dim "  $(wc -l < "$IDREP") ledger entr$([[ "$(wc -l < "$IDREP")" == 1 ]] && echo y || echo ies) checked"
elif [[ "$IDENTITY" -eq 1 ]]; then
    warn "--identity needs the network; ignored under --offline"
fi

# ---------------------------------------------------------------------------
# 2b. licence evidence and built artefacts
# ---------------------------------------------------------------------------
#
# Licence detection is delegated to tools/scan-licenses.sh, which caches by
# tarball sha256 because listing a 154MB xz tarball means decompressing all of
# it. Off by default for that reason, and the field then reads `not-collected`
# rather than `unknown`, so "nobody looked" and "looked and could not tell"
# stay distinguishable.

LICREP="${WORK}/licences.tsv"
: > "$LICREP"
if [[ "$LICENCES" -eq 1 ]]; then
    log "Collecting licence evidence"
    # Resolved next to THIS script, not through KRYPTIK_ROOT. The manifest is a
    # property of the tree being inventoried, so fetch-sources.sh is found
    # through KRYPTIK_ROOT above; the licence scanner is an implementation
    # detail of this tool and travels with it. Going through KRYPTIK_ROOT meant
    # that pointing the inventory at any tree without a full tools/ directory
    # silently produced `not-collected` for every source.
    "$(dirname "${BASH_SOURCE[0]}")/scan-licenses.sh" > "$LICREP" 2>/dev/null || true
    dim "  $(grep -c . "$LICREP" || true) source(s) scanned"
fi

# A source inventory that cannot say what was produced from those sources is
# half an answer. This records the IDENTITY of a built tree when one is named -
# path, file count, size, the os-release BUILD_ID it carries, and the sha256 of
# the build tab's own artifact manifest if it sits beside it. It does not
# re-hash 30,000 files: that is `make verify-manifest` in the build worktree,
# and a second implementation of one check is how two answers start disagreeing.
ARTREP="${WORK}/artifacts.tsv"
: > "$ARTREP"
if [[ -n "$ARTIFACTS" ]]; then
    if [[ ! -d "$ARTIFACTS" ]]; then
        warn "--artifacts=${ARTIFACTS} is not a directory; recorded as absent"
        printf 'sysroot\t%s\tabsent\t-\t-\t-\t-\n' "$ARTIFACTS" >> "$ARTREP"
    else
        log "Recording built artefact identity"
        # `|| true` throughout: a sysroot built through a chroot contains
        # root-owned directories this process cannot descend, so find and du
        # exit non-zero while still producing a usable count. Under pipefail
        # that status reaches common.sh's ERR trap and aborts the inventory -
        # which is how an unreadable directory took the whole document down.
        # A partial count is recorded as partial below rather than as fact.
        art_files="$(find "$ARTIFACTS" -type f 2>/dev/null | wc -l || true)"
        art_readable=yes
        find "$ARTIFACTS" -type d >/dev/null 2>&1 || art_readable=partial
        art_size="$(du -sh "$ARTIFACTS" 2>/dev/null | cut -f1 || true)"
        art_id="$(sed -n 's/^BUILD_ID=//p' "${ARTIFACTS}/etc/os-release" 2>/dev/null | head -1)"
        art_man="${ARTIFACTS%/*}/artifact-manifest.txt"
        art_man_sha="-"
        [[ -f "$art_man" ]] && art_man_sha="$(sha256_of "$art_man")"
        printf 'sysroot\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$ARTIFACTS" "present-${art_readable}" "$art_files" "${art_size:--}" \
            "${art_id:--}" "$art_man_sha" >> "$ARTREP"
        dim "  ${art_files} files (${art_readable} read), BUILD_ID ${art_id:-none}"
    fi
fi

# ---------------------------------------------------------------------------
# 3. aggregate and print
# ---------------------------------------------------------------------------

if [[ "$MD" -eq 1 || "$JSON" -eq 1 ]]; then exec 1>&3 3>&-; fi

# WHICH KEYRING THIS WAS MEASURED AGAINST.
#
# The counts below depend on it, and not by a little. A keyring that a previous
# --fetch-unknown-keys run warmed up holds keys taken from the signatures
# themselves, which moves sources out of lock-only and into the unaudited and
# kernel.org classes. Measured on this tree: 31 keyring-verified and 30
# lock-only with the GNU keyring and the pinned keys alone, versus 47 and 9
# once sixteen signature-named keys are also present.
#
# An inventory that does not say which of those two runs produced it is the
# same kind of number as the "54 of 69" this tool exists to replace. So it
# says.
KEYSTATE="unknown"
if [[ -f "${WORK}/signatures.log" ]]; then
    KEYSTATE="$(grep -oE '(keyring ready \([0-9]+ public keys\)|using cached keyring \([0-9]+ keys\))' \
                "${WORK}/signatures.log" | head -1 || true)"
    [[ -n "$KEYSTATE" ]] || KEYSTATE="no keyring line in the signature log"
fi
if [[ "$JSON" -eq 1 ]]; then
    : # carried as the keyring_state field; printing it here would corrupt the
      # document, which is what happened the first time this was wired.
elif [[ "$MD" -eq 1 ]]; then
    printf '**Keyring state for this run:** %s.\n' "$KEYSTATE"
    printf 'A keyring warmed by a previous `--fetch-unknown-keys` run holds keys taken\n'
    printf 'from the signatures themselves and shifts these counts; run\n'
    printf '`verify-signatures.sh --refresh` first for the state a fresh checkout sees.\n\n'
else
    dim "keyring state for this run: ${KEYSTATE}"
    echo
fi

export KRYPTIK_LOCK KRYPTIK_SOURCES MD OFFLINE JSON KEYSTATE
INV_COMMIT="$(git -C "$KRYPTIK_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
export INV_COMMIT
python3 - "$MANIFEST" "$SIGREP" "$PROVREP" "$IDREP" "$LICREP" "$ARTREP" "$NOTES_TSV" <<'PYEOF'
import datetime
import hashlib
import json
import os
import sys

(manifest_path, sig_path, prov_path, id_path,
 lic_path, art_path, notes_path) = sys.argv[1:8]
lock_path = os.environ["KRYPTIK_LOCK"]
sources = os.environ["KRYPTIK_SOURCES"]
markdown = os.environ.get("MD") == "1"
offline = os.environ.get("OFFLINE") == "1"


def rows(path):
    try:
        with open(path) as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line:
                    yield line.split("\t")
    except OSError:
        return


# ---- assurance classes, strongest first ------------------------------------
#
# The order is the point. Each entry is (key, one-line statement of what it is
# worth). Nothing is ever summed across two of these.
CLASSES = [
    ("signed-tree-pinned-key",
     "signed tag by a key pinned in-tree, and the archive reproduces that tag's tree"),
    ("signature-pinned-key",
     "detached signature verified against a key pinned in-tree"),
    ("signature-korg-certified-key",
     "detached signature; signer key published by kernel.org AND certified by a reference key"),
    ("signature-korg-published-key",
     "detached signature; signer key published by kernel.org, no certification on the material"),
    ("signature-keyring-key",
     "detached signature verified against the network-fetched GNU keyring"),
    ("signature-unaudited-key",
     "detached signature verified against a key the signature itself named - circular"),
    ("publisher-checksum",
     "publisher's own .sha256 agrees with the lock - not a signature"),
    ("lock-only",
     "sources.lock alone: detects later tampering, says nothing about the first fetch"),
    ("signature-failed",
     "BAD SIGNATURE, a REVOKED key, or a tree that is not the signed one"),
    ("unverified",
     "could not be checked on this run - not a pass and not evidence of tampering"),
    ("not-downloaded",
     "no local copy, so nothing was checked at all"),
]
CLASS_ORDER = {k: i for i, (k, _) in enumerate(CLASSES)}

# ---- inputs ----------------------------------------------------------------

manifest = [(r[0], r[1], r[2]) for r in rows(manifest_path) if len(r) >= 3]

lock = {}
try:
    with open(lock_path) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2:
                lock[parts[1]] = parts[0]
except OSError:
    pass

sig = {}
for r in rows(sig_path):
    if len(r) >= 2:
        sig[r[0]] = (r[1], r[2] if len(r) > 2 else "")

prov = {}
for r in rows(prov_path):
    if len(r) >= 2:
        prov.setdefault(r[0], {})[r[1].split(":")[0]] = (r[1].split(":")[1], r[2] if len(r) > 2 else "")

# keys.manifest package name -> identity finding
ident = {}
for r in rows(id_path):
    if len(r) >= 3:
        ident[r[0]] = (r[2], r[3] if len(r) > 3 else "")

# ---- per-source classification --------------------------------------------

FAILED_SIG = {"signature-bad", "signature-revoked-key"}
UNVERIFIED_SIG = {"key-not-held", "no-signature-upstream", "signature-uncheckable",
                  "signature-unavailable", "inconclusive", "decompression-failed"}


def classify(name):
    """Return (class, detail). One class per source: the strongest ESTABLISHED
    assertion about it, or the failure if there is one."""
    s = sig.get(name)
    p = prov.get(name, {})

    # A failure outranks everything: it is not a weaker kind of success.
    if s and s[0] in FAILED_SIG:
        return "signature-failed", s[1]
    for a in ("tree", "id", "sig", "lock", "pub"):
        if p.get(a, ("", ""))[0] == "failed":
            return "signature-failed", "%s: %s" % (a, p[a][1])

    if s and s[0] == "not-downloaded":
        return "not-downloaded", s[1]

    # hardened_malloc: the tree binding is the strongest thing here.
    if p.get("tree", ("", ""))[0] == "established" and \
       p.get("id", ("", ""))[0] == "established":
        return "signed-tree-pinned-key", p["tree"][1]

    if s and s[0] == "signature-pinned-key":
        return "signature-pinned-key", s[1]

    if s and s[0] == "signature-unaudited-key":
        # keys.manifest entries are keyed by package name.
        finding = ident.get(name)
        if finding and finding[0] == "korg-published-and-certified":
            return "signature-korg-certified-key", "%s; %s" % (s[1], finding[1])
        if finding and finding[0] == "korg-published":
            return "signature-korg-published-key", "%s; %s" % (s[1], finding[1])
        return "signature-unaudited-key", s[1]

    if s and s[0] == "signature-keyring-key":
        return "signature-keyring-key", s[1]

    if p.get("pub", ("", ""))[0] == "established":
        return "publisher-checksum", p["pub"][1]

    if s and s[0] in UNVERIFIED_SIG:
        # Nothing but the lock was established for this source.
        return "lock-only", s[1]

    if offline:
        return "lock-only", "only sources.lock was consulted (--offline)"

    if not s and not p:
        return "unverified", "no evidence was collected for this source"

    return "unverified", (s[1] if s else "")


def lock_state(url):
    fname = url.rsplit("/", 1)[-1]
    want = lock.get(fname)
    if want is None:
        return "NO LOCK ENTRY"
    path = os.path.join(sources, fname)
    if not os.path.exists(path):
        return "locked, absent"
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "lock OK" if h.hexdigest() == want else "LOCK MISMATCH"


# licence evidence, keyed by source name
lic = {}
for r in rows(lic_path):
    if len(r) >= 6:
        lic[r[0]] = {"spdx": r[2], "multiple": r[3] == "yes",
                     "files": r[4], "method": r[5]}

# recorded caveats, keyed by source name. Validated in the shell above, so a
# row reaching here is well formed and names a source in the manifest.
notes = {}
for r in rows(notes_path):
    if len(r) >= 4:
        notes.setdefault(r[0], []).append(
            {"kind": r[1], "location": r[2], "note": r[3]})

artefacts = []
for r in rows(art_path):
    if len(r) >= 6:
        artefacts.append({
            "kind": r[0], "path": r[1], "state": r[2],
            "files": int(r[3]) if r[3].isdigit() else None,
            "size": r[4], "build_id": r[5],
            "build_manifest_sha256": r[6] if len(r) > 6 else "-",
            # A tree built through a chroot has root-owned directories this
            # process cannot descend, so the count is a floor, not a fact.
            "count_complete": not r[2].endswith("partial"),
        })

results = []
for name, ver, url in manifest:
    klass, detail = classify(name)
    results.append((name, ver, klass, lock_state(url), detail))

if os.environ.get("JSON") == "1":
    by_url = {n: u for n, _v, u in manifest}
    doc = {
        "schema": "kryptik-provenance-inventory-1",
        "generated": datetime.datetime.now(datetime.timezone.utc)
                             .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repository_commit": os.environ.get("INV_COMMIT", "unknown"),
        "keyring_state": os.environ.get("KEYSTATE", "unknown"),
        "offline": offline,
        "note": ("assurance_class is the strongest ESTABLISHED assertion about "
                 "each source. Classes are never summed and there is no total. "
                 "licence.method says how the licence was determined; it is "
                 "evidence, not a compliance judgement. A source's notes[] are "
                 "recorded CAVEATS and not classes: they are counted in "
                 "per_note_kind_counts and never in per_class_counts."),
        "assurance_classes": [{"id": k, "means": m} for k, m in CLASSES],
        "sources": [],
        "artifacts": artefacts,
    }
    for name, ver, klass, ls, detail in results:
        url = by_url.get(name, "")
        fname = url.rsplit("/", 1)[-1]
        entry = {
            "name": name,
            "version": ver,
            "file": fname,
            "url": url,
            "sha256_locked": lock.get(fname),
            "lockfile_state": ls,
            "assurance_class": klass,
            "assurance_detail": detail,
            "licence": lic.get(name, {"spdx": "not-collected", "multiple": False,
                                      "files": "-", "method": "not-collected"}),
        }
        if name in ident:
            entry["signer_identity"] = {"finding": ident[name][0],
                                        "detail": ident[name][1]}
        if name in notes:
            entry["notes"] = notes[name]
        doc["sources"].append(entry)

    counts = {}
    lic_counts = {}
    for src in doc["sources"]:
        counts[src["assurance_class"]] = counts.get(src["assurance_class"], 0) + 1
        k = src["licence"]["spdx"]
        lic_counts[k] = lic_counts.get(k, 0) + 1
    doc["per_class_counts"] = counts
    doc["per_licence_counts"] = lic_counts
    doc["source_count"] = len(doc["sources"])

    # Counted separately and deliberately never folded into per_class_counts:
    # a caveat is not a weaker class, and a class is not a caveat.
    note_counts = {}
    for src in doc["sources"]:
        for n in src.get("notes", []):
            note_counts[n["kind"]] = note_counts.get(n["kind"], 0) + 1
    doc["per_note_kind_counts"] = note_counts
    doc["noted_source_count"] = sum(1 for s in doc["sources"] if s.get("notes"))

    json.dump(doc, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write(chr(10))
    raise SystemExit(1 if counts.get("signature-failed", 0) else 0)

# ---- output ----------------------------------------------------------------

results.sort(key=lambda r: (CLASS_ORDER.get(r[2], 99), r[0]))

if markdown:
    print("| source | version | assurance class | sources.lock | detail |")
    print("|---|---|---|---|---|")
    for name, ver, klass, ls, detail in results:
        print("| `%s` | %s | `%s` | %s | %s |"
              % (name, ver, klass, ls, detail[:90].replace("|", "/")))
else:
    print()
    print("%-16s %-10s %-30s %-14s %s"
          % ("SOURCE", "VERSION", "ASSURANCE CLASS", "SOURCES.LOCK", "DETAIL"))
    print("-" * 118)
    for name, ver, klass, ls, detail in results:
        print("%-16s %-10s %-30s %-14s %s"
              % (name, ver[:10], klass, ls, detail[:44]))

counts = {}
for _, _, klass, _, _ in results:
    counts[klass] = counts.get(klass, 0) + 1

print()
print("PER-CLASS COUNTS - these are not added together, and there is no total.")
print()
for key, meaning in CLASSES:
    if key in counts:
        print("  %3d  %-30s %s" % (counts[key], key, meaning))
unknown = sorted(k for k in counts if k not in CLASS_ORDER)
for k in unknown:
    print("  %3d  %-30s (unrecognised class)" % (counts[k], k))

print()
print("No single coverage figure is printed. Adding a signature checked against")
print("a pinned key to one checked against a key the signature itself named")
print("produces a number whose meaning is the weakest term in it.")

if notes:
    print()
    if markdown:
        print("### Recorded caveats")
        print()
        print("A caveat is **not** an assurance class. These are counted")
        print("separately and never added to the per-class counts above: a class")
        print("says what was established, a caveat says what is true anyway.")
        print()
        print("| source | kind | location | note |")
        print("|---|---|---|---|")
        for nm in sorted(notes):
            for n in notes[nm]:
                print("| `%s` | `%s` | `%s` | %s |"
                      % (nm, n["kind"], n["location"],
                         n["note"].replace("|", "/")))
    else:
        print("RECORDED CAVEATS - not assurance classes, and never added to the")
        print("counts above. A class says what was established; a caveat says")
        print("what is true anyway.")
        print()
        for nm in sorted(notes):
            for n in notes[nm]:
                print("  %s  [%s]" % (nm, n["kind"]))
                print("      %s" % n["location"])
                line = "     "
                for w in n["note"].split():
                    if len(line) + len(w) + 1 > 76:
                        print(line)
                        line = "     "
                    line += " " + w
                if line.strip():
                    print(line)
                print()

bad = counts.get("signature-failed", 0)
if bad:
    print()
    print("%d source(s) FAILED verification. Do not build from these." % bad)
    raise SystemExit(1)
PYEOF
