# Supply Chain

Kryptik builds every shipped binary from source, which moves the trust question
from "do I trust this distro's build servers" to "do I trust these tarballs".

## Source integrity

`sources.lock` pins a SHA-256 for every upstream tarball.
`tools/fetch-sources.sh` refuses to proceed on a mismatch — it does not warn and
continue.

**The lock file alone is trust-on-first-use.** `--lock` records the hash of
whatever downloaded; it does not prove the download was authentic. That is what
`tools/verify-signatures.sh` is for — run it before committing a lock file or
changing an entry:

```sh
make verify
```

It verifies detached GPG signatures against the GNU keyring and kernel.org
maintainer keys — Nick Clifton for binutils, Jakub Jelinek for GCC, Greg
Kroah-Hartman for the kernel, and so on. The LFS FHS patch is the known
exception: upstream does not sign it individually.

**No coverage count is quoted in this document.** Three different ones used to
appear in it and a fourth in the README, and the tool producing them was
miscounting: imported keys are cached under `build/work/keys`, so a second run
found fetched keys already held, read an ordinary `GOODSIG`, and promoted them
to verified. Identical inputs gave 34 verified / 20 unaudited on the first run
and 54 / 0 on the second. The caching bug is fixed; quoting the number in prose
is not, and will not be. Run `make verify` and read its summary.

A lock file generated on an untrusted network and committed unaudited provides
the appearance of integrity without the substance. That is worse than no lock
file, because it stops people from looking.

## Checksums are not in versions.env

Deliberately. Keeping versions and hashes in separate files means a version bump
cannot silently carry a hash change through review — the lock diff is visible on
its own.

## Expired signing keys are not tampering

Five sources verify with keys the GNU keyring believes expired — glibc, gmp,
mpc, patch, ncurses. The signatures are cryptographically valid; the keyring
snapshot simply predates the maintainer extending their key.

`verify-signatures.sh` reports these as verified and lists them separately. It
does **not** fail the build on them, deliberately: a tool that cries tampering
at routine key expiry gets ignored, and an ignored tool protects nothing. Only
`BADSIG` (the file does not match its signature) and `REVKEYSIG` (the key was
revoked, which can mean compromise) stop a build.

## Not all valid signatures are equally strong

`verify-signatures.sh` reports a binary verified/unverified, but the strength
behind a "verified" varies and the difference is worth knowing:

| Source | Key | Assessment |
|---|---|---|
| Linux kernel | RSA-4096, Kroah-Hartman | Strong |
| binutils, gcc, glibc, bash, coreutils | RSA-4096 GNU maintainer keys | Strong |
| linux-hardened | RSA-4096, Levente Polyak | Strong |
| xz | RSA, Lasse Collin | Strong |
| **file** | **DSA-1024, SHA-1 digest, expired 2026-08-15** | **Weak** |

A DSA-1024 key signing with a SHA-1 digest is below what should be relied on in
2026. The signature on `file` is evidence, but not the same kind of evidence as
the others. It is recorded here rather than hidden behind a green checkmark.

## On xz specifically

Kryptik pins **xz 5.8.4**, not the 5.6.x line. xz 5.6.0 and 5.6.1 shipped the
CVE-2024-3094 backdoor; 5.6.2 removed it.

Pinning one patch past a build-system compromise is not the same as being clear
of it. The xz incident was an attack on the release process itself, carried out
over years by a co-maintainer, and the versions immediately following it were
produced while that process was still being audited. Kryptik pins well past
that window.

## Current verification coverage

Run `make verify` and `make verify-provenance`. Both print a per-source result.

Totals are deliberately absent here, and not only because the old ones were
wrong. A detached GPG signature from a maintainer key, a signed git tag bound
to an archive hash, and a publisher-published checksum are three different
strengths of evidence, and a single "60 of 69" figure adds them together as if
they were one. Sources resting on `sources.lock` alone are not failures, but
they are the weakest links and must be readable as such rather than averaged
into a reassuring fraction.

A source-by-source inventory that keeps the assurance levels separate is
tracked as a task rather than written here from memory.

The two that mattered most are now covered by `tools/verify-provenance.sh`,
which handles sources that publish no detached signature:

- **hardened_malloc** — the system allocator (ADR-005). The GitHub source
  archive is unsigned and GrapheneOS signs the release *tag*.

  Two corrections to what this section used to say. First, the tag is **not
  GPG-signed**: GrapheneOS signs it with `ssh-ed25519`. Second, and worse, the
  old check asked the GitHub API whether the tag was signed, printed
  `.tagger.name`, and called that verified — **nothing compared the tag to the
  tarball on this disk**. GitHub generates the source archive on request, so
  any substituted tarball whose hash was already in `sources.lock` passed. The
  check also passed when it could not check at all: a missing `gh`, an
  unresolvable tag or an unreachable API each counted as "skipped" and exited
  0. On the CI runner `gh` **is** installed — GitHub CLI ships in
  `actions/runner-images` for the Ubuntu that `ubuntu-latest` resolves to — but
  it is **not authenticated**: `GITHUB_TOKEN` is a secret rather than an
  exported variable, and `.github/workflows/ci.yml` sets no `GH_TOKEN` for that
  step, so `gh api` exits 4 asking for `gh auth login` even against a public
  repository. Either way the call failed, the check counted it as skipped and
  exited 0, and the CI step named "Provenance of unsigned sources" had been
  passing without ever making the assertion this document described as
  verified.

  (An earlier revision of this paragraph said `gh` was not installed. It is.
  The conclusion did not change but the reason did, and the wrong reason was
  published here before it was checked.)

  `tools/verify-provenance.sh` now binds the archive to the signed tree and
  fails rather than skipping. What it establishes is that the bytes on disk
  match the tree the signed tag covers. What it does **not** yet establish is
  that the signing key is one Kryptik chose in advance; the remaining signer
  identity work is tracked separately.
- **The s6 stack** — PID 1 and the service supervisor (ADR-006). skarnet ships
  a `.tar.gz.sha256` beside each release, which is an independent confirmation
  of the bytes: `sources.lock` records what Kryptik downloaded, the published
  checksum records what the publisher intended. All five match.

skarnet keeps a checksum only for the **current** release, which means an
outdated pin is also an unverifiable pin. That is why `versions.env` now
requires current versions for the s6 stack — the same reasoning as ADR-009
applied to PID 1 instead of the kernel. The pins were three to five releases
behind before this was noticed.

Neither mechanism is a GPG signature over the artifact itself, and the tool
says so in its own output rather than reporting a green tick.

Running `tools/verify-signatures.sh --fetch-unknown-keys` raises coverage by
importing the key each signature names. Be clear about what that establishes:
trusting a key because the signature it checks told you its id is circular. It
proves the file was signed by whoever signed it. Every key imported that way is
written to `keys.manifest` precisely so the fingerprints can be confirmed
out-of-band, and until they are, those entries are weaker than the rest.

## Open problems

- **The GNU keyring is fetched over the network.** This establishes "signed by
  whoever the keyring says" rather than "signed by the person you believe
  maintains this package". Verifying those keys out-of-band is still manual.
- **The kernel signing key comes from a keyserver**, pinned by fingerprint.
  Fingerprints are in `tools/verify-signatures.sh` and should be confirmed
  against kernel.org independently.
- **No reproducible builds.** Deferred past Phase 5 (docs/roadmap.md). Until
  then, "built from source" means trusting the machine that built it.
- **No bootstrappable-builds story.** The initial compiler comes from the host
  distro, so Thompson's "Reflections on Trusting Trust" applies in full.
  Mitigating it properly means something like `live-bootstrap`, which is a
  project of its own.
