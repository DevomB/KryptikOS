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
maintainer keys. Current state of the committed `sources.lock`: **21 of 22
sources verified** against upstream maintainer signatures (Nick Clifton for
binutils, Jakub Jelinek for GCC, Greg Kroah-Hartman for the kernel, and so on).
The exception is the LFS FHS patch, which upstream does not sign individually.

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
