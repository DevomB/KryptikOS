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
for a in "$@"; do
    case "$a" in
        --offline)  OFFLINE=1 ;;
        --identity) IDENTITY=1 ;;
        --md)       MD=1 ;;
        -h|--help)  sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $a" ;;
    esac
done

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
if [[ "$MD" -eq 1 ]]; then exec 3>&1 1>&2; fi

log "Collecting per-source evidence"

MANIFEST="${WORK}/manifest.tsv"
"${KRYPTIK_ROOT}/tools/fetch-sources.sh" --list \
    | awk '{printf "%s\t%s\t%s\n", $1, $2, $3}' > "$MANIFEST"
dim "  manifest: $(wc -l < "$MANIFEST") sources"

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
# 3. aggregate and print
# ---------------------------------------------------------------------------

if [[ "$MD" -eq 1 ]]; then exec 1>&3 3>&-; fi

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
if [[ "$MD" -eq 1 ]]; then
    printf '**Keyring state for this run:** %s.\n' "$KEYSTATE"
    printf 'A keyring warmed by a previous `--fetch-unknown-keys` run holds keys taken\n'
    printf 'from the signatures themselves and shifts these counts; run\n'
    printf '`verify-signatures.sh --refresh` first for the state a fresh checkout sees.\n\n'
else
    dim "keyring state for this run: ${KEYSTATE}"
    echo
fi

export KRYPTIK_LOCK KRYPTIK_SOURCES MD OFFLINE
python3 - "$MANIFEST" "$SIGREP" "$PROVREP" "$IDREP" <<'PYEOF'
import hashlib
import os
import sys

manifest_path, sig_path, prov_path, id_path = sys.argv[1:5]
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


results = []
for name, ver, url in manifest:
    klass, detail = classify(name)
    results.append((name, ver, klass, lock_state(url), detail))

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

bad = counts.get("signature-failed", 0)
if bad:
    print()
    print("%d source(s) FAILED verification. Do not build from these." % bad)
    raise SystemExit(1)
PYEOF
