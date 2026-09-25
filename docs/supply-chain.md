# Supply chain

Kryptik builds what it ships from source, which turns "do I trust this
distribution's build servers" into "do I trust these tarballs". The
exceptions:

- **Device firmware and CPU microcode** (ADR-012), selected by
  `build/config/firmware.list` from the pinned `linux-firmware` release. The
  tarball is signed by its kernel.org maintainer and verified like the
  kernel's, and each file's licence is the one its `WHENCE` records. That
  shows where the bytes came from, not what they do: they run on the device's
  own processor, behind the IOMMU (strict by default).
- **The Rust compiler**: kryptikd and kryptik-wlproxy are built from source
  by an upstream toolchain pinned by version, not one built here (ADR-010).

Two build tools that do not ship are special cases:

- **cmake** (the `cmake-bin` manifest row): Kitware's Linux binary generates
  json-c's build files in the stage 04 chroot, since compiling cmake cost a
  quarter of stage 04 for one package. Its hash in `sources.lock` was checked
  against Kitware's published SHA-256 list; it is unpacked under the build
  tree, never installed, and excluded from the image by stage 06. The source
  tarball stays in the manifest as the fallback.
- **kernel-hardening-checker** runs in stage 05 and CI on the resolved kernel
  configuration. Its upstream tags are lightweight and unsigned, so the hash
  of its GitHub archive in `sources.lock` is its only provenance, and
  `tools/check-kernel-hardening.sh` refuses a tarball that does not match.

## Source integrity

`sources.lock` pins a SHA-256 for every upstream tarball, and
`tools/fetch-sources.sh` refuses to proceed on a mismatch.

The lock alone is trust on first use: `--lock` records the hash of whatever
was downloaded. Before committing a lock file or changing an entry, run
`make verify` (`tools/verify-signatures.sh`), which checks detached GPG
signatures against the GNU keyring (Nick Clifton for binutils, Jakub Jelinek
for GCC, and so on) and against keys pinned by fingerprint in the script
(Greg Kroah-Hartman for the kernel, among others). LFS patches are the
exception: LFS publishes md5sums for the patch set, not per-patch signatures.
A lock file generated on an untrusted network and committed unaudited looks
like integrity without being it.

Hashes live in `sources.lock`, not `versions.env`, so a hash change shows up
as its own diff in review instead of riding along with a version bump.

`tools/scan-licenses.sh` records the top-level licence files each tarball
carries, with an SPDX identifier only where the text is unambiguous. It is not
a compliance scanner.

### Expired keys are not tampering

Some sources (glibc, gmp, mpc, patch and ncurses among them) are signed with
keys the keyring believes expired. The signatures are valid; the keyring's
copy predates the maintainer extending the key. `verify-signatures.sh` counts
them as verified and lists them separately, because a tool that cries
tampering at routine expiry gets ignored. `BADSIG` (the file does not match
its signature) and `REVKEYSIG` (the key was revoked, possibly compromised)
always fail; `--strict`, the release gate, also fails on anything unverified
or unaudited.

### Signature strength varies

| Source | Key | Strength |
| --- | --- | --- |
| Linux kernel | RSA-4096, Kroah-Hartman | strong |
| binutils, gcc, glibc, bash, coreutils | RSA-4096 GNU maintainer keys | strong |
| linux-hardened | RSA-4096, Levente Polyak | strong |
| xz | RSA, Lasse Collin | strong |
| file | DSA-1024, SHA-1 digest, expired 2026-08-15 | weak |

DSA-1024 over SHA-1 is below what should be relied on, so the signature on
`file` is weaker evidence than the rest.

### xz

xz is pinned at 5.8.4. 5.6.0 and 5.6.1 carried the CVE-2024-3094 backdoor,
planted through the release process by a co-maintainer over years, so Kryptik
stays well past the releases made while that process was being audited, not
one patch past the fix.

## Sources without a detached signature

`make verify-provenance` (`tools/verify-provenance.sh`) covers the two that
matter most:

- **hardened_malloc** (ADR-005). GrapheneOS signs the release tag, with an
  ssh-ed25519 key, not the archive. The tool fetches the tag, verifies it
  against the key pinned in the script (from grapheneos.org's
  `allowed_signers`) and requires the downloaded archive to reproduce the
  signed tree. The pin rests on TLS to grapheneos.org; its fingerprint has
  not been confirmed out of band.
- **The s6 stack** (ADR-006). skarnet publishes a `.sha256` beside each
  release: the publisher's statement of the bytes, though from the same host
  as the tarball. skarnet keeps it for the current release only, so an old pin
  cannot be checked, and `versions.env` keeps the s6 stack current for that
  reason.

Neither is a signature over the artifact, and the tool says so. Under
`--strict`, which CI uses on pushes, a check that could not run fails.

## Assurance per source

`tools/provenance-inventory.sh`, run in CI, prints each source's assurance
class, strongest first, from a key pinned in the tree down to `sources.lock`
alone. It counts per class and prints no total: a maintainer signature, a
signed tag and a publisher checksum are different strengths of evidence, and
one fraction would hide the weakest links. For the same reason this document
quotes no coverage figure.

`verify-signatures.sh --fetch-unknown-keys` imports whatever key a signature
names. That is circular: it proves the file was signed by whoever signed it.
Each such key is recorded in `keys.manifest` and counts as unaudited until its
fingerprint is confirmed out of band; `provenance-inventory.sh --identity`
checks them against kernel.org's published developer keys.

## Open problems

- The GNU keyring is fetched over the network, so a signature checked against
  it means "signed by whoever the keyring says". Checking those keys out of
  band is manual.
- The kernel.org signing keys are pinned by fingerprint in
  `tools/verify-signatures.sh`, and those fingerprints still need confirming
  against kernel.org independently.
- Builds are not reproducible, so "built from source" still means trusting the
  machine that built it.
- The first compiler comes from the host, so Thompson's "Reflections on
  Trusting Trust" applies in full. Fixing that means something like
  `live-bootstrap`, a project of its own.
